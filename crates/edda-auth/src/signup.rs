use edda_db::user_repo::InsertUserError;
use edda_db::{DbPool, OrganizationRepo, UserRepo};
use edda_domain::validation::is_valid_username;
use edda_domain::{RegistrationPolicy, User, UserId};

use crate::password::hash_password_async;

#[derive(Debug, thiserror::Error)]
pub enum SignupError {
    #[error("that email is already registered")]
    EmailTaken,
    #[error("that username is already taken")]
    UsernameTaken,
    #[error("username must be 1-39 characters, start and end with a letter or digit, and contain only letters, digits, '-' or '_'")]
    InvalidUsername,
    #[error("username, email and password can't be empty")]
    Empty,
    /// The instance's `RegistrationPolicy` is `Closed` — only an
    /// administrator can create accounts.
    #[error("registration is closed on this instance")]
    RegistrationClosed,
    /// The email's domain is not on the instance's allowlist.
    #[error("this instance only accepts registrations from an approved email domain")]
    EmailDomainNotAllowed,
    #[error(transparent)]
    Db(#[from] edda_db::DbError),
    #[error("{0}")]
    Hash(argon2::password_hash::Error),
}

impl From<argon2::password_hash::Error> for SignupError {
    fn from(err: argon2::password_hash::Error) -> Self {
        SignupError::Hash(err)
    }
}

impl From<InsertUserError> for SignupError {
    fn from(err: InsertUserError) -> Self {
        match err {
            InsertUserError::UsernameTaken => SignupError::UsernameTaken,
            InsertUserError::EmailTaken => SignupError::EmailTaken,
            InsertUserError::Db(err) => SignupError::Db(err),
        }
    }
}

/// The result of a successful `signup`, so the HTTP layer can tailor its
/// response and follow-up actions to the active [`RegistrationPolicy`].
#[derive(Debug)]
pub struct SignupOutcome {
    pub user: User,
    /// `true` when the account is `Approval`-mode and now waiting for an
    /// administrator — the caller should **not** start a session, and
    /// should tell the user their account is pending.
    pub pending_approval: bool,
    /// `Some(raw_token)` when email verification is required — the caller
    /// emails this as a confirmation link. The account can sign in but
    /// can't push / create repositories until it's used.
    pub verification_token: Option<String>,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs() as i64
}

/// Creates a new account, subject to `policy`. Email and username
/// uniqueness are enforced by their `UNIQUE` constraints in `edda-db`; a
/// violation there is reported as `EmailTaken`/`UsernameTaken`.
// `skip_all` and no explicit `fields(...)` here on purpose: `email` is
// personally-identifying and `password` is a credential — neither belongs
// on a span even though `email` alone isn't as sensitive as a password.
#[tracing::instrument(name = "authentication.signup", skip_all, err)]
pub async fn signup(
    pool: &DbPool,
    policy: &RegistrationPolicy,
    username: &str,
    email: &str,
    password: &str,
) -> Result<SignupOutcome, SignupError> {
    let username = username.trim();
    let email = email.trim();
    if username.is_empty() || email.is_empty() || password.is_empty() {
        return Err(SignupError::Empty);
    }
    if !policy.permits_signup() {
        return Err(SignupError::RegistrationClosed);
    }
    if !policy.email_domain_allowed(email) {
        return Err(SignupError::EmailDomainNotAllowed);
    }
    if !is_valid_username(username) {
        return Err(SignupError::InvalidUsername);
    }
    // Usernames and organization names share one global identifier
    // namespace — `edda-auth::organization::create_organization`
    // performs the same check in the other direction. See that module's
    // own doc comment for why this can't be a single database constraint.
    if OrganizationRepo::find_by_name(pool, username)
        .await?
        .is_some()
    {
        return Err(SignupError::UsernameTaken);
    }

    let password_hash = hash_password_async(password.to_string()).await?;
    let id = UserId::new();
    UserRepo::insert(pool, id, username, email, &password_hash).await?;

    let now = now_unix();
    let approved_at = policy.auto_approves().then_some(now);
    let email_verified_at = (!policy.require_email_verification).then_some(now);
    UserRepo::stamp_signup_status(pool, id, approved_at, email_verified_at).await?;

    let verification_token = if policy.require_email_verification {
        crate::email_verification::request(pool, id)
            .await?
            .map(|(_, raw)| raw)
    } else {
        None
    };

    Ok(SignupOutcome {
        user: User {
            id,
            username: username.to_string(),
            email: email.to_string(),
            is_admin: false,
            disabled_at: None,
        },
        pending_approval: !policy.auto_approves(),
        verification_token,
    })
}

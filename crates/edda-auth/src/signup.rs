use edda_db::user_repo::InsertUserError;
use edda_db::{DbPool, OrganizationRepo, UserRepo};
use edda_domain::validation::is_valid_username;
use edda_domain::{User, UserId};

use crate::password::hash_password;

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

/// Creates a new account. "Quick and dirty" by design: no email
/// verification, no password strength check beyond non-empty — signup is
/// instant. Email and username uniqueness are enforced by their
/// respective `UNIQUE` constraints in `edda-db`; a violation there is
/// reported as `EmailTaken`/`UsernameTaken`.
// `skip_all` and no explicit `fields(...)` here on purpose: `email` is
// personally-identifying and `password` is a credential — neither belongs
// on a span even though `email` alone isn't as sensitive as a password.
#[tracing::instrument(name = "authentication.signup", skip_all, err)]
pub async fn signup(
    pool: &DbPool,
    username: &str,
    email: &str,
    password: &str,
) -> Result<User, SignupError> {
    let username = username.trim();
    let email = email.trim();
    if username.is_empty() || email.is_empty() || password.is_empty() {
        return Err(SignupError::Empty);
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

    let password_hash = hash_password(password)?;
    let id = UserId::new();
    UserRepo::insert(pool, id, username, email, &password_hash).await?;
    Ok(User {
        id,
        username: username.to_string(),
        email: email.to_string(),
        is_admin: false,
        disabled_at: None,
    })
}

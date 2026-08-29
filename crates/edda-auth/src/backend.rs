use axum_login::{AuthUser, AuthnBackend};
use serde::Deserialize;

use edda_db::{DbPool, UserRepo};
use edda_domain::User;

use crate::password::{verify_dummy_async, verify_password_async};

/// The identity `axum_login` stores in a session — a domain `User` plus
/// the one credential field the domain type deliberately excludes (see
/// `edda_domain::User`'s doc comment). Never leaves `edda-auth`/the
/// session layer; every consumer downstream sees only `.user`.
#[derive(Debug, Clone)]
pub struct SessionUser {
    pub user: User,
    password_hash: String,
}

impl AuthUser for SessionUser {
    type Id = String;

    fn id(&self) -> Self::Id {
        self.user.id.to_string()
    }

    // Session validity is tied to the password hash: changing a password
    // invalidates every existing session for that user, which is what you
    // want (e.g. after a compromised-password reset).
    fn session_auth_hash(&self) -> &[u8] {
        self.password_hash.as_bytes()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Credentials {
    pub email: String,
    pub password: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error(transparent)]
    Db(#[from] edda_db::DbError),
    #[error("{0}")]
    Hash(argon2::password_hash::Error),
}

// Written by hand rather than `#[from]`: thiserror's `#[from]` also
// generates `Error::source()`, which needs `argon2::password_hash::Error`
// to implement `std::error::Error` — it only implements `Display`.
impl From<argon2::password_hash::Error> for AuthError {
    fn from(err: argon2::password_hash::Error) -> Self {
        AuthError::Hash(err)
    }
}

#[derive(Clone)]
pub struct Backend {
    pool: DbPool,
}

impl Backend {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &DbPool {
        &self.pool
    }
}

impl AuthnBackend for Backend {
    type User = SessionUser;
    type Credentials = Credentials;
    type Error = AuthError;

    async fn authenticate(&self, creds: Credentials) -> Result<Option<SessionUser>, AuthError> {
        let Some(row) = UserRepo::find_by_email(&self.pool, &creds.email).await? else {
            // Spend an Argon2 verification anyway, so a request for an
            // unknown email takes about as long as one for a known email
            // with a wrong password — no account-enumeration timing oracle
            // (L8).
            verify_dummy_async().await;
            return Ok(None);
        };
        // A disabled account fails the same way a wrong password does —
        // indistinguishable from "no such account," not a separate error,
        // so a login attempt can't be used to probe whether an email is
        // registered-but-disabled.
        if crate::require_enabled(&row.user).is_err() {
            verify_dummy_async().await;
            return Ok(None);
        }
        if verify_password_async(creds.password, row.password_hash.clone()).await {
            Ok(Some(SessionUser {
                user: row.user,
                password_hash: row.password_hash,
            }))
        } else {
            Ok(None)
        }
    }

    async fn get_user(&self, user_id: &String) -> Result<Option<SessionUser>, AuthError> {
        let Ok(id) = user_id.parse() else {
            return Ok(None);
        };
        let Some(row) = UserRepo::find_by_id(&self.pool, id).await? else {
            return Ok(None);
        };
        Ok(Some(SessionUser {
            user: row.user,
            password_hash: row.password_hash,
        }))
    }
}

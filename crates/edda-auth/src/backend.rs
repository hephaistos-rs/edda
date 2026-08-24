use axum_login::{AuthUser, AuthnBackend};
use serde::Deserialize;
use sqlx::SqlitePool;

use edda_db::UserRepo;
use edda_domain::User;

use crate::password::verify_password;

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
    Db(#[from] sqlx::Error),
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
    pool: SqlitePool,
}

impl Backend {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

impl AuthnBackend for Backend {
    type User = SessionUser;
    type Credentials = Credentials;
    type Error = AuthError;

    async fn authenticate(&self, creds: Credentials) -> Result<Option<SessionUser>, AuthError> {
        let Some(row) = UserRepo::find_by_email(&self.pool, &creds.email).await? else {
            return Ok(None);
        };
        if verify_password(&creds.password, &row.password_hash) {
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

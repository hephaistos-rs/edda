pub mod routes;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum_login::{AuthUser, AuthnBackend, UserId};
use serde::Deserialize;
use sqlx::SqlitePool;

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub password_hash: String,
}

impl AuthUser for User {
    type Id = String;

    fn id(&self) -> Self::Id {
        self.id.clone()
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
    #[error("that email is already registered")]
    EmailTaken,
    #[error("email and password can't be empty")]
    Empty,
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
}

impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = AuthError;

    async fn authenticate(&self, creds: Credentials) -> Result<Option<User>, AuthError> {
        let user = sqlx::query_as!(User, "SELECT id, email, password_hash FROM users WHERE email = ?", creds.email)
            .fetch_optional(&self.pool)
            .await?;

        let Some(user) = user else { return Ok(None) };
        if verify_password(&creds.password, &user.password_hash) {
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<User>, AuthError> {
        let user = sqlx::query_as!(User, "SELECT id, email, password_hash FROM users WHERE id = ?", user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }
}

/// Creates a new account. "Quick and dirty" by design: no email
/// verification, no password strength check beyond non-empty — signup is
/// instant. Email uniqueness is enforced by the `users.email` UNIQUE
/// constraint; a violation there is reported as `EmailTaken`.
pub async fn signup(pool: &SqlitePool, email: &str, password: &str) -> Result<User, AuthError> {
    let email = email.trim();
    if email.is_empty() || password.is_empty() {
        return Err(AuthError::Empty);
    }

    let password_hash = hash_password(password)?;
    let id = uuid::Uuid::now_v7().to_string();

    let result = sqlx::query!("INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)", id, email, password_hash).execute(pool).await;

    match result {
        Ok(_) => Ok(User { id, email: email.to_string(), password_hash }),
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => Err(AuthError::EmailTaken),
        Err(err) => Err(AuthError::Db(err)),
    }
}

fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default().hash_password(password.as_bytes(), &salt)?.to_string())
}

fn verify_password(password: &str, stored_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else { return false };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

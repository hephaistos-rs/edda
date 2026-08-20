pub mod routes;
pub mod tokens;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum_login::{AuthUser, AuthnBackend, UserId};
use serde::Deserialize;
use sqlx::SqlitePool;

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
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
    #[error("that username is already taken")]
    UsernameTaken,
    #[error("username must be 1-39 characters, start and end with a letter or digit, and contain only letters, digits, '-' or '_'")]
    InvalidUsername,
    #[error("username, email and password can't be empty")]
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
    pub(crate) pool: SqlitePool,
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
        let user = sqlx::query_as!(
            User,
            r#"SELECT id, username AS "username!", email, password_hash FROM users WHERE email = ?"#,
            creds.email
        )
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
        let user = sqlx::query_as!(
            User,
            r#"SELECT id, username AS "username!", email, password_hash FROM users WHERE id = ?"#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(user)
    }
}

/// Creates a new account. "Quick and dirty" by design: no email
/// verification, no password strength check beyond non-empty — signup is
/// instant. Email and username uniqueness are enforced by their respective
/// UNIQUE constraints; a violation there is reported as `EmailTaken` /
/// `UsernameTaken`.
// `skip_all` and no explicit `fields(...)` here on purpose: `email` is
// personally-identifying and `password` is a credential — neither belongs on
// a span even though `email` alone isn't as sensitive as a password. `username`
// is the one identity field that *is* meant to be public (it's about to become
// part of every repo URL under that account), but it travels with the rest of
// signup's arguments rather than being singled out onto the span. Argon2
// hashing inside `hash_password` legitimately shows up as the expensive part
// of this span's duration; that's useful for diagnosing signup latency and
// carries no secret (the span has no field with the password or its hash).
#[tracing::instrument(name = "authentication.signup", skip_all, err)]
pub async fn signup(pool: &SqlitePool, username: &str, email: &str, password: &str) -> Result<User, AuthError> {
    let username = username.trim();
    let email = email.trim();
    if username.is_empty() || email.is_empty() || password.is_empty() {
        return Err(AuthError::Empty);
    }
    if !is_valid_username(username) {
        return Err(AuthError::InvalidUsername);
    }

    let password_hash = hash_password(password)?;
    let id = uuid::Uuid::now_v7().to_string();

    let result = sqlx::query!(
        "INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)",
        id,
        username,
        email,
        password_hash
    )
    .execute(pool)
    .await;

    match result {
        Ok(_) => Ok(User { id, username: username.to_string(), email: email.to_string(), password_hash }),
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            if db_err.message().contains("users.username") {
                Err(AuthError::UsernameTaken)
            } else {
                Err(AuthError::EmailTaken)
            }
        }
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

/// Charset and shape a username (== a repo owner segment, see `git::mod`'s
/// `{owner}/{repo}` path validation) must satisfy: 1-39 ASCII letters,
/// digits, `-` or `_`, starting and ending with a letter or digit. Same
/// bound (39) GitHub uses for logins; starting/ending on an alnum keeps a
/// username unambiguous next to the `/` that will separate it from a repo
/// name in a URL.
pub fn is_valid_username(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 39 {
        return false;
    }
    let is_alnum = |b: u8| b.is_ascii_alphanumeric();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes.iter().all(|&b| is_alnum(b) || b == b'-' || b == b'_')
}

/// Turns an email address into a starting-point username: the local part
/// (before `@`), lowercased, with every character outside `[a-z0-9-_]`
/// mapped to `-`, then trimmed of leading/trailing `-`/`_` so the result
/// already satisfies `is_valid_username`'s start/end rule (falling back to
/// `"user"` if that leaves nothing, e.g. for a local part that was entirely
/// punctuation). Doesn't guarantee uniqueness — see `unique_username` for
/// the part of `backfill_usernames` that does.
fn derive_username_base(email: &str) -> String {
    let local = email.split('@').next().unwrap_or(email).to_lowercase();
    let mapped: String = local
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    let trimmed = mapped.trim_matches(['-', '_']);
    let truncated: String = trimmed.chars().take(39).collect();
    let truncated = truncated.trim_end_matches(['-', '_']);
    if truncated.is_empty() {
        "user".to_string()
    } else {
        truncated.to_string()
    }
}

/// Appends the smallest numeric suffix (2, 3, 4, ...) that makes `base`
/// unique against `taken` (compared case-insensitively, matching the
/// `COLLATE NOCASE` constraint on `users.username`), truncating `base` first
/// if the suffix would otherwise push the result past the 39-character
/// limit. Records the chosen username (lowercased) into `taken` before
/// returning it, so a caller assigning usernames to several rows in one pass
/// never hands out the same one twice.
fn unique_username(base: &str, taken: &mut std::collections::HashSet<String>) -> String {
    let key = base.to_lowercase();
    if taken.insert(key) {
        return base.to_string();
    }

    let mut suffix = 2u32;
    loop {
        let suffix_str = suffix.to_string();
        let max_base_len = 39usize.saturating_sub(suffix_str.len());
        let truncated_base: String = base.chars().take(max_base_len).collect();
        let candidate = format!("{truncated_base}{suffix_str}");
        let key = candidate.to_lowercase();
        if taken.insert(key) {
            return candidate;
        }
        suffix += 1;
    }
}

/// Assigns a username to every account that doesn't have one yet — existing
/// users created before this column existed. Called once at startup, right
/// after `migrations::run` applies the SQL migration that adds the (nullable)
/// `username` column; safe to call every startup like the migrations
/// themselves, since the `WHERE username IS NULL` filter makes it a no-op
/// once every row has one.
#[tracing::instrument(name = "authentication.backfill_usernames", skip_all, err)]
pub async fn backfill_usernames(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let existing = sqlx::query!(r#"SELECT username AS "username!" FROM users WHERE username IS NOT NULL"#).fetch_all(pool).await?;
    let mut taken: std::collections::HashSet<String> = existing.into_iter().map(|row| row.username.to_lowercase()).collect();

    let pending = sqlx::query!("SELECT id, email FROM users WHERE username IS NULL ORDER BY created_at ASC").fetch_all(pool).await?;

    for row in pending {
        let base = derive_username_base(&row.email);
        let username = unique_username(&base, &mut taken);
        sqlx::query!("UPDATE users SET username = ? WHERE id = ?", username, row.id).execute(pool).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_usernames() {
        assert!(is_valid_username("alice"));
        assert!(is_valid_username("a"));
        assert!(is_valid_username("alice-bob"));
        assert!(is_valid_username("alice_bob"));
        assert!(is_valid_username("a1"));
        assert!(is_valid_username(&"a".repeat(39)));
    }

    #[test]
    fn invalid_usernames() {
        assert!(!is_valid_username(""));
        assert!(!is_valid_username(&"a".repeat(40)));
        assert!(!is_valid_username("-alice"));
        assert!(!is_valid_username("alice-"));
        assert!(!is_valid_username("_alice"));
        assert!(!is_valid_username("alice_"));
        assert!(!is_valid_username("alice bob"));
        assert!(!is_valid_username("alice.bob"));
        assert!(!is_valid_username("alice/bob"));
        assert!(!is_valid_username("alïce"));
    }

    #[test]
    fn derives_base_from_email_local_part() {
        assert_eq!(derive_username_base("Alice@example.com"), "alice");
        assert_eq!(derive_username_base("alice.smith+tag@example.com"), "alice-smith-tag");
        assert_eq!(derive_username_base("-.-@example.com"), "user");
        assert_eq!(derive_username_base("no-at-sign"), "no-at-sign");
    }

    #[test]
    fn derived_base_is_always_valid() {
        for email in ["Alice@example.com", "alice.smith+tag@example.com", "-.-@example.com", "üñîçødé@example.com", "@example.com"] {
            assert!(is_valid_username(&derive_username_base(email)), "base for {email:?} should be valid");
        }
    }

    #[test]
    fn unique_username_appends_numeric_suffix_on_collision() {
        let mut taken = std::collections::HashSet::new();
        assert_eq!(unique_username("alice", &mut taken), "alice");
        assert_eq!(unique_username("alice", &mut taken), "alice2");
        assert_eq!(unique_username("alice", &mut taken), "alice3");
        assert_eq!(unique_username("Alice", &mut taken), "Alice4");
    }

    #[test]
    fn unique_username_stays_within_length_limit() {
        let mut taken = std::collections::HashSet::new();
        let base = "a".repeat(39);
        let first = unique_username(&base, &mut taken);
        assert_eq!(first.len(), 39);
        let second = unique_username(&base, &mut taken);
        assert!(second.len() <= 39, "expected <= 39 chars, got {} ({second})", second.len());
        assert!(is_valid_username(&second));
    }
}

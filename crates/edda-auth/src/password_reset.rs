//! Password reset: `request` issues a single-use token (invalidating any
//! previously outstanding one for the same account); `consume` verifies
//! it and sets a new password. Delivery of the reset link via email is
//! the caller's responsibility (`edda-web`, which owns the mailer and job
//! queue) — this module only ever produces the raw token, once, the same
//! "shown once" discipline already used for PATs (`tokens::create`) and
//! TOTP recovery codes (`totp::activate`).
//!
//! The `password_reset_tokens` table is defined by the `auth_hardening`
//! migration; this module is the request/consume flow that uses it.

use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::Engine;
use sha2::{Digest, Sha256};

use edda_db::{DbPool, PasswordResetTokenRepo, UserRepo};
use edda_domain::{PasswordResetTokenId, User, UserId};

use crate::password::hash_password;

const TOKEN_TTL_SECONDS: i64 = 3600;

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs() as i64
}

fn generate_raw_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Fast, not slow, on purpose — same reasoning as `tokens::hash_token`: a
/// 32-byte random token already has 256 bits of entropy.
fn hash_token(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Issues a fresh reset token for the account with `email`, if one
/// exists and is enabled. `None` for an unknown or disabled email —
/// **the caller must show the same "check your email" response either
/// way**, the same information-hiding discipline this workspace already
/// applies to private-repo existence (`AuthzError::NotFound`); this
/// function itself doesn't decide the HTTP response, only whether there's
/// a real account to email.
pub async fn request(
    pool: &DbPool,
    email: &str,
) -> Result<Option<(User, String)>, edda_db::DbError> {
    let Some(row) = UserRepo::find_by_email(pool, email).await? else {
        return Ok(None);
    };
    if crate::require_enabled(&row.user).is_err() {
        return Ok(None);
    }

    // Only one active reset link per account at a time.
    PasswordResetTokenRepo::invalidate_all_for_user(pool, row.user.id).await?;

    let raw = generate_raw_token();
    let token_hash = hash_token(&raw);
    let expires_at = now_unix() + TOKEN_TTL_SECONDS;
    PasswordResetTokenRepo::insert(
        pool,
        PasswordResetTokenId::new(),
        row.user.id,
        &token_hash,
        expires_at,
    )
    .await?;

    Ok(Some((row.user, raw)))
}

#[derive(Debug, thiserror::Error)]
pub enum ConsumeError {
    #[error("this reset link is invalid or has expired")]
    InvalidOrExpired,
    #[error("password can't be empty")]
    EmptyPassword,
    #[error("{0}")]
    Hash(argon2::password_hash::Error),
    #[error(transparent)]
    Db(#[from] edda_db::DbError),
}

impl From<argon2::password_hash::Error> for ConsumeError {
    fn from(err: argon2::password_hash::Error) -> Self {
        ConsumeError::Hash(err)
    }
}

/// Verifies `raw_token`, sets `new_password` as the account's password,
/// and marks the token used. Session invalidation is automatic — see
/// `UserRepo::update_password_hash`'s doc comment.
pub async fn consume(
    pool: &DbPool,
    raw_token: &str,
    new_password: &str,
) -> Result<UserId, ConsumeError> {
    if new_password.is_empty() {
        return Err(ConsumeError::EmptyPassword);
    }
    let token_hash = hash_token(raw_token);
    let Some((token_id, user_id)) =
        PasswordResetTokenRepo::find_valid_by_hash(pool, &token_hash, now_unix()).await?
    else {
        return Err(ConsumeError::InvalidOrExpired);
    };

    let new_hash = hash_password(new_password)?;
    UserRepo::update_password_hash(pool, user_id, &new_hash).await?;
    PasswordResetTokenRepo::mark_used(pool, token_id).await?;

    Ok(user_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn requesting_for_an_unknown_email_returns_none() {
        let pool = edda_db::test_pool().await;
        assert!(request(&pool, "nobody@example.com")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn a_full_request_and_consume_round_trip_changes_the_password() {
        let pool = edda_db::test_pool().await;
        let user_id = UserId::new();
        UserRepo::insert(
            &pool,
            user_id,
            "alice",
            "alice@example.com",
            &hash_password("old-pw").unwrap(),
        )
        .await
        .unwrap();

        let (user, raw) = request(&pool, "alice@example.com").await.unwrap().unwrap();
        assert_eq!(user.id, user_id);

        let updated_id = consume(&pool, &raw, "new-password").await.unwrap();
        assert_eq!(updated_id, user_id);

        let row = UserRepo::find_by_id(&pool, user_id).await.unwrap().unwrap();
        assert!(crate::password::verify_password(
            "new-password",
            &row.password_hash
        ));
        assert!(!crate::password::verify_password(
            "old-pw",
            &row.password_hash
        ));

        // Single-use: the same token can't be consumed again.
        assert!(matches!(
            consume(&pool, &raw, "third-password").await.unwrap_err(),
            ConsumeError::InvalidOrExpired
        ));
    }

    #[tokio::test]
    async fn requesting_a_second_time_invalidates_the_first_tokens_link() {
        let pool = edda_db::test_pool().await;
        let user_id = UserId::new();
        UserRepo::insert(&pool, user_id, "bob", "bob@example.com", "x")
            .await
            .unwrap();

        let (_, first_raw) = request(&pool, "bob@example.com").await.unwrap().unwrap();
        let (_, second_raw) = request(&pool, "bob@example.com").await.unwrap().unwrap();

        assert!(matches!(
            consume(&pool, &first_raw, "new-password")
                .await
                .unwrap_err(),
            ConsumeError::InvalidOrExpired
        ));
        assert!(consume(&pool, &second_raw, "new-password").await.is_ok());
    }

    #[tokio::test]
    async fn an_unknown_token_is_rejected() {
        let pool = edda_db::test_pool().await;
        assert!(matches!(
            consume(&pool, "not-a-real-token", "new-password")
                .await
                .unwrap_err(),
            ConsumeError::InvalidOrExpired
        ));
    }
}

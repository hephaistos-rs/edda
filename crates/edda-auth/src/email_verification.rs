//! Email verification (Phase 9): `request` issues a single-use token
//! (superseding any previously outstanding one for the account);
//! `consume` verifies it and stamps `users.email_verified_at`. Delivery
//! of the verification link by email is the caller's responsibility
//! (`edda-app`, which owns the mailer and job queue) — this module only
//! ever produces the raw token, once, the same "shown once" discipline
//! `password_reset` and `tokens` already use.
//!
//! Mirrors `password_reset` closely; the `email_verification_tokens`
//! table is defined by the `0001_baseline` migration.

use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::Engine;
use sha2::{Digest, Sha256};

use edda_db::{DbPool, EmailVerificationTokenRepo, UserRepo};
use edda_domain::{EmailVerificationTokenId, User, UserId};

/// 24 hours — long enough that a link delivered to a delayed inbox still
/// works, short enough that a leaked one doesn't linger.
const TOKEN_TTL_SECONDS: i64 = 24 * 3600;

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

fn hash_token(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Issues a fresh verification token for `user_id`, superseding any
/// outstanding one. Returns the account and the raw token (for the email
/// link). `None` if the account doesn't exist, is disabled, or is
/// already verified — nothing to do.
pub async fn request(
    pool: &DbPool,
    user_id: UserId,
) -> Result<Option<(User, String)>, edda_db::DbError> {
    let Some(row) = UserRepo::find_by_id(pool, user_id).await? else {
        return Ok(None);
    };
    if crate::require_enabled(&row.user).is_err() {
        return Ok(None);
    }
    match UserRepo::account_status(pool, user_id).await? {
        Some(status) if status.is_email_verified() => return Ok(None),
        None => return Ok(None),
        _ => {}
    }

    EmailVerificationTokenRepo::invalidate_all_for_user(pool, user_id).await?;

    let raw = generate_raw_token();
    let token_hash = hash_token(&raw);
    let expires_at = now_unix() + TOKEN_TTL_SECONDS;
    EmailVerificationTokenRepo::insert(
        pool,
        EmailVerificationTokenId::new(),
        user_id,
        &token_hash,
        expires_at,
    )
    .await?;

    Ok(Some((row.user, raw)))
}

#[derive(Debug, thiserror::Error)]
pub enum ConsumeError {
    #[error("this verification link is invalid or has expired")]
    InvalidOrExpired,
    #[error(transparent)]
    Db(#[from] edda_db::DbError),
}

/// Verifies `raw_token` and marks the account's email confirmed. Returns
/// the now-verified account's id. Idempotent for a token: the second
/// call fails `InvalidOrExpired` (single-use).
pub async fn consume(pool: &DbPool, raw_token: &str) -> Result<UserId, ConsumeError> {
    let token_hash = hash_token(raw_token);
    let Some((token_id, user_id)) =
        EmailVerificationTokenRepo::find_valid_by_hash(pool, &token_hash, now_unix()).await?
    else {
        return Err(ConsumeError::InvalidOrExpired);
    };

    UserRepo::mark_email_verified(pool, user_id).await?;
    EmailVerificationTokenRepo::mark_used(pool, token_id).await?;

    Ok(user_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A user who still needs to confirm their email — as
    /// `edda_auth::signup` leaves them when the policy requires
    /// verification (`email_verified_at` NULL). A plain `UserRepo::insert`
    /// leaves that column at its "now" default, i.e. already verified.
    async fn make_unverified_user(pool: &DbPool) -> UserId {
        let id = UserId::new();
        UserRepo::insert(pool, id, "alice", "alice@example.com", "hash")
            .await
            .unwrap();
        let now = now_unix();
        UserRepo::stamp_signup_status(pool, id, Some(now), None)
            .await
            .unwrap();
        id
    }

    #[tokio::test]
    async fn a_request_then_consume_round_trip_marks_the_email_verified() {
        let pool = edda_db::test_pool().await;
        let id = make_unverified_user(&pool).await;
        assert!(!UserRepo::account_status(&pool, id)
            .await
            .unwrap()
            .unwrap()
            .is_email_verified());

        let (_, raw) = request(&pool, id).await.unwrap().unwrap();
        assert_eq!(consume(&pool, &raw).await.unwrap(), id);
        assert!(UserRepo::account_status(&pool, id)
            .await
            .unwrap()
            .unwrap()
            .is_email_verified());

        // Single-use.
        assert!(matches!(
            consume(&pool, &raw).await.unwrap_err(),
            ConsumeError::InvalidOrExpired
        ));
    }

    #[tokio::test]
    async fn requesting_again_supersedes_the_first_link() {
        let pool = edda_db::test_pool().await;
        let id = make_unverified_user(&pool).await;
        let (_, first) = request(&pool, id).await.unwrap().unwrap();
        let (_, second) = request(&pool, id).await.unwrap().unwrap();
        assert!(matches!(
            consume(&pool, &first).await.unwrap_err(),
            ConsumeError::InvalidOrExpired
        ));
        assert!(consume(&pool, &second).await.is_ok());
    }

    #[tokio::test]
    async fn an_already_verified_account_gets_no_new_link() {
        let pool = edda_db::test_pool().await;
        let id = make_unverified_user(&pool).await;
        UserRepo::mark_email_verified(&pool, id).await.unwrap();
        assert!(request(&pool, id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_unknown_token_is_rejected() {
        let pool = edda_db::test_pool().await;
        assert!(matches!(
            consume(&pool, "not-a-real-token").await.unwrap_err(),
            ConsumeError::InvalidOrExpired
        ));
    }
}

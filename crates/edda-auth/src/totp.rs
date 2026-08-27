//! TOTP (RFC 6238) enrollment and verification. The shared secret is
//! encrypted at rest via `secret_box` before it ever reaches `edda-db` —
//! this module is the only place in the workspace that holds a decrypted
//! secret in memory, and only for as long as one enrollment/verification
//! call needs it.
//!
//! Recovery codes are hashed the same way access tokens are (SHA-256,
//! high-entropy, generated server-side, no brute-force-resistant hash
//! needed) — see `tokens::hash_token`'s identical reasoning.

use argon2::password_hash::rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, Builder, Secret, Totp};

use edda_db::{DbPool, PasswordResetTokenRepo, TotpRepo};
use edda_domain::UserId;

const RECOVERY_CODE_COUNT: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("that code was incorrect")]
    InvalidCode,
    #[error("TOTP is not enrolled for this account")]
    NotEnrolled,
    #[error(transparent)]
    SecretBox(#[from] crate::secret_box::SecretBoxError),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

fn hash_recovery_code(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn generate_recovery_code() -> String {
    let mut bytes = [0u8; 5];
    OsRng.fill_bytes(&mut bytes);
    // Base32-ish, human-typeable: hex is simplest and avoids ambiguous
    // characters (0/O, 1/I) a real base32 alphabet has to special-case.
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn build_totp(secret_bytes: Vec<u8>, account_name: &str) -> Totp {
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret_bytes)
        .with_issuer(Some("Edda"))
        .with_account_name(account_name.to_string())
        .build()
        .expect("a freshly generated or previously-stored secret is always valid TOTP input")
}

/// Starts (or restarts) enrollment: generates a fresh secret, encrypts it
/// at rest, and returns both the manual-entry secret (base32) and the
/// `otpauth://` URI for a QR code — neither is persisted anywhere except
/// as the encrypted blob; this is the only time the raw secret is ever
/// returned to a caller. Enrollment does not gate login until `activate`
/// succeeds.
pub async fn enroll(
    pool: &DbPool,
    user_id: UserId,
    account_name: &str,
) -> Result<(String, String), TotpError> {
    let secret = Secret::generate();
    let secret_bytes = secret.as_bytes().to_vec();
    let totp = build_totp(secret_bytes.clone(), account_name);

    let ciphertext = crate::secret_box::encrypt(&secret_bytes)?;
    TotpRepo::upsert_secret(pool, user_id, &ciphertext).await?;

    let otpauth_uri = totp
        .to_url()
        .expect("a freshly built Totp with a valid issuer/account name always renders a URL");
    Ok((secret.to_base32(), otpauth_uri))
}

/// Confirms enrollment with one real code, then — only on success —
/// generates and persists a fresh batch of recovery codes and returns
/// them once. Mirrors `tokens::create`'s "shown once, only the hash
/// retained" pattern: after this call returns, the raw codes exist only
/// in whatever the caller does with this return value.
pub async fn activate(
    pool: &DbPool,
    user_id: UserId,
    account_name: &str,
    submitted_code: &str,
) -> Result<Vec<String>, TotpError> {
    let (ciphertext, _activated_at) = TotpRepo::find_by_user(pool, user_id)
        .await?
        .ok_or(TotpError::NotEnrolled)?;
    let secret_bytes = crate::secret_box::decrypt(&ciphertext)?;
    let totp = build_totp(secret_bytes, account_name);

    if totp.check_current(submitted_code).is_none() {
        return Err(TotpError::InvalidCode);
    }

    TotpRepo::activate(pool, user_id).await?;
    // 2FA enrollment immediately invalidates outstanding password-reset
    // tokens — a reset link issued before 2FA was enabled must not bypass
    // the second factor the account now requires.
    PasswordResetTokenRepo::invalidate_all_for_user(pool, user_id).await?;

    let raw_codes: Vec<String> = (0..RECOVERY_CODE_COUNT)
        .map(|_| generate_recovery_code())
        .collect();
    let hashes: Vec<String> = raw_codes
        .iter()
        .map(|code| hash_recovery_code(code))
        .collect();
    TotpRepo::replace_recovery_codes(pool, user_id, &hashes).await?;

    Ok(raw_codes)
}

/// Verifies either a live 6-digit code or a recovery code against
/// `user_id`'s *activated* enrollment — used by the login flow's second
/// step. A recovery code, once accepted, is consumed and never valid
/// again.
pub async fn verify(
    pool: &DbPool,
    user_id: UserId,
    account_name: &str,
    submitted: &str,
) -> Result<bool, TotpError> {
    let (ciphertext, activated_at) = TotpRepo::find_by_user(pool, user_id)
        .await?
        .ok_or(TotpError::NotEnrolled)?;
    if activated_at.is_none() {
        return Err(TotpError::NotEnrolled);
    }

    let recovery_hash = hash_recovery_code(submitted);
    if TotpRepo::consume_recovery_code(pool, user_id, &recovery_hash).await? {
        return Ok(true);
    }

    let secret_bytes = crate::secret_box::decrypt(&ciphertext)?;
    let totp = build_totp(secret_bytes, account_name);
    Ok(totp.check_current(submitted).is_some())
}

/// Whether `user_id` has an activated TOTP credential — what the login
/// flow's first step checks to decide whether to challenge for a second
/// factor at all.
pub async fn is_activated(pool: &DbPool, user_id: UserId) -> Result<bool, sqlx::Error> {
    TotpRepo::is_activated(pool, user_id).await
}

/// Disables 2FA entirely for `user_id`.
pub async fn disable(pool: &DbPool, user_id: UserId) -> Result<(), sqlx::Error> {
    TotpRepo::delete(pool, user_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_test_key() {
        // Same fixed key `secret_box`'s own tests install; `init`'s
        // `OnceLock` reads whichever call lands first.
        crate::secret_box::init(Some([0u8; 32]));
    }

    /// Generates the code a real authenticator app would show right now,
    /// for a test to submit: an account with 2FA enrolled and activated
    /// can only complete login with a correct code, and enrollment alone
    /// (before activation) does not gate anything.
    fn current_code_for(secret_bytes: &[u8], account_name: &str) -> String {
        let totp = build_totp(secret_bytes.to_vec(), account_name);
        totp.generate_current().to_string()
    }

    #[tokio::test]
    async fn enrollment_does_not_gate_login_until_activated() {
        set_test_key();
        let pool = edda_db::test_pool().await;
        let user_id = UserId::new();
        edda_db::UserRepo::insert(&pool, user_id, "alice", "alice@example.com", "x")
            .await
            .unwrap();

        enroll(&pool, user_id, "alice@example.com").await.unwrap();
        assert!(!is_activated(&pool, user_id).await.unwrap());
    }

    #[tokio::test]
    async fn activation_requires_a_correct_code_and_then_gates_verification() {
        set_test_key();
        let pool = edda_db::test_pool().await;
        let user_id = UserId::new();
        edda_db::UserRepo::insert(&pool, user_id, "alice", "alice@example.com", "x")
            .await
            .unwrap();

        enroll(&pool, user_id, "alice@example.com").await.unwrap();

        // Wrong code doesn't activate.
        let err = activate(&pool, user_id, "alice@example.com", "000000")
            .await
            .unwrap_err();
        assert!(matches!(err, TotpError::InvalidCode));
        assert!(!is_activated(&pool, user_id).await.unwrap());

        // Recompute the real current code the way a real authenticator
        // app would, using the same secret this account was just
        // enrolled with.
        let (ciphertext, _) = TotpRepo::find_by_user(&pool, user_id)
            .await
            .unwrap()
            .unwrap();
        let secret_bytes = crate::secret_box::decrypt(&ciphertext).unwrap();
        let real_code = current_code_for(&secret_bytes, "alice@example.com");

        let recovery_codes = activate(&pool, user_id, "alice@example.com", &real_code)
            .await
            .unwrap();
        assert_eq!(recovery_codes.len(), RECOVERY_CODE_COUNT);
        assert!(is_activated(&pool, user_id).await.unwrap());

        // Now a login-time verification: wrong code fails, right code
        // succeeds, and a recovery code works exactly once.
        assert!(!verify(&pool, user_id, "alice@example.com", "000000")
            .await
            .unwrap());
        assert!(verify(&pool, user_id, "alice@example.com", &real_code)
            .await
            .unwrap());

        let recovery_code = &recovery_codes[0];
        assert!(verify(&pool, user_id, "alice@example.com", recovery_code)
            .await
            .unwrap());
        assert!(!verify(&pool, user_id, "alice@example.com", recovery_code)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn disabling_totp_means_verify_reports_not_enrolled_again() {
        set_test_key();
        let pool = edda_db::test_pool().await;
        let user_id = UserId::new();
        edda_db::UserRepo::insert(&pool, user_id, "alice", "alice@example.com", "x")
            .await
            .unwrap();

        enroll(&pool, user_id, "alice@example.com").await.unwrap();
        let (ciphertext, _) = TotpRepo::find_by_user(&pool, user_id)
            .await
            .unwrap()
            .unwrap();
        let secret_bytes = crate::secret_box::decrypt(&ciphertext).unwrap();
        let real_code = current_code_for(&secret_bytes, "alice@example.com");
        activate(&pool, user_id, "alice@example.com", &real_code)
            .await
            .unwrap();

        disable(&pool, user_id).await.unwrap();
        assert!(!is_activated(&pool, user_id).await.unwrap());
        assert!(matches!(
            verify(&pool, user_id, "alice@example.com", &real_code)
                .await
                .unwrap_err(),
            TotpError::NotEnrolled
        ));
    }
}

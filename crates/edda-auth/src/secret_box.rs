//! Symmetric at-rest encryption for secrets this workspace needs to
//! *recover*, not just verify: a user's TOTP shared secret (`totp_secrets.
//! secret_ciphertext`) and a webhook's HMAC signing secret
//! (`webhooks.secret_ciphertext`) — both have to be decrypted back to
//! their original bytes (to compute a fresh 6-digit code; to sign an
//! outgoing delivery) rather than merely verified, so neither can be a
//! one-way hash the way every other credential in this workspace is
//! stored. Nothing about the mechanism itself is TOTP-specific, so a
//! second caller needing the same "encrypt now, decrypt later" property
//! reuses it directly rather than growing a parallel implementation.
//!
//! # Configuration
//!
//! The key is the primary `EDDA_SECRET_KEYS` entry — a 32-byte AES-256
//! key. The composition root resolves and validates it via
//! `edda_http::config` and installs it here **once**, at startup, with
//! [`init`]. This module never reads the environment and never panics: an
//! instance that never configured a key simply cannot enroll 2FA or store
//! a webhook secret, and [`encrypt`]/[`decrypt`] say so with
//! [`SecretBoxError::NotConfigured`] rather than aborting a request.
//!
//! Deliberately **not** a random per-process key (unlike
//! `edda_http::lfs::transfer_auth`): a TOTP secret encrypted today must
//! still decrypt after a restart, so the key must be stable across runs.

use std::sync::OnceLock;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngExt;

const NONCE_LEN: usize = 12;

static CIPHER: OnceLock<Option<Aes256Gcm>> = OnceLock::new();

/// Installs the process's at-rest encryption key (the primary
/// `EDDA_SECRET_KEYS` entry), or `None` when the instance configured no
/// key. Call once from the composition root before any TOTP/webhook work.
/// The first call wins; later calls are ignored.
pub fn init(primary_key: Option<[u8; 32]>) {
    let _ = CIPHER.set(primary_key.map(|bytes| {
        let key = Key::<Aes256Gcm>::from(bytes);
        Aes256Gcm::new(&key)
    }));
}

/// Whether a usable key is installed. `false` before [`init`] runs, or
/// after `init(None)`.
pub fn is_configured() -> bool {
    matches!(CIPHER.get(), Some(Some(_)))
}

#[derive(Debug, thiserror::Error)]
pub enum SecretBoxError {
    #[error(
        "this instance has no EDDA_SECRET_KEYS configured — TOTP (2FA) and stored webhook \
         secrets are unavailable until one is set"
    )]
    NotConfigured,
    #[error("stored secret could not be decrypted — wrong EDDA_SECRET_KEYS or corrupted data")]
    Corrupted,
}

fn cipher() -> Result<&'static Aes256Gcm, SecretBoxError> {
    match CIPHER.get() {
        Some(Some(cipher)) => Ok(cipher),
        _ => Err(SecretBoxError::NotConfigured),
    }
}

/// Encrypts `plaintext`, returning `nonce || ciphertext` as a single
/// opaque byte string — exactly what gets stored in
/// `*.secret_ciphertext`; `edda-db` never sees the nonce or plaintext
/// separately. `Err(NotConfigured)` when no key is installed.
pub fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>, SecretBoxError> {
    let cipher = cipher()?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("AES-256-GCM encryption of an in-memory secret never fails");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Reverses [`encrypt`]. `Err(NotConfigured)` when no key is installed;
/// `Err(Corrupted)` on bad/stale ciphertext (untrusted-in-the-sense-of
/// "could be stale or corrupted" database content, not an in-memory value
/// this process just produced).
pub fn decrypt(stored: &[u8]) -> Result<Vec<u8>, SecretBoxError> {
    let cipher = cipher()?;
    if stored.len() < NONCE_LEN {
        return Err(SecretBoxError::Corrupted);
    }
    let (nonce_bytes, ciphertext) = stored.split_at(NONCE_LEN);
    let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .expect("split_at guarantees this length");
    let nonce = Nonce::from(nonce_bytes);
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| SecretBoxError::Corrupted)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every test in this process shares the same fixed key; `init`'s
    /// `OnceLock` reads it once regardless of how many tests call this.
    fn ensure_test_key() {
        init(Some([0u8; 32]));
    }

    #[test]
    fn a_secret_round_trips_through_encrypt_and_decrypt() {
        ensure_test_key();
        let plaintext = b"top secret totp seed";
        let ciphertext = encrypt(plaintext).expect("key installed");
        assert_ne!(ciphertext, plaintext);
        let decrypted = decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn corrupted_ciphertext_fails_to_decrypt_rather_than_returning_garbage() {
        ensure_test_key();
        let mut ciphertext = encrypt(b"some secret").expect("key installed");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;
        assert!(matches!(
            decrypt(&ciphertext),
            Err(SecretBoxError::Corrupted)
        ));
    }
}

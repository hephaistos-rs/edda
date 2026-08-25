//! Symmetric at-rest encryption for the one secret this workspace needs to
//! *recover*, not just verify: a user's TOTP shared secret (`totp_secrets.
//! secret_ciphertext`). Unlike a password hash or an access-token hash,
//! this value has to be decrypted back to its original bytes on every
//! login to compute a fresh 6-digit code, so it can't be a one-way hash
//! the way every other credential in this workspace is stored.
//!
//! Keyed by `EDDA_SECRET_KEY` — a 32-byte AES-256 key, hex-encoded (64 hex
//! characters), read once at first use and cached for the process's
//! lifetime. Deliberately **not** generated randomly at startup the way
//! the LFS transfer-auth token secret is (`edda_http::lfs::transfer_auth`):
//! that secret only ever needs to outlive one short-lived token within the
//! same process run, but a TOTP secret encrypted today must still decrypt
//! correctly after a server restart — a random per-process key would make
//! every enrolled account's 2FA permanently unrecoverable the moment the
//! process restarts. Missing or malformed, this fails loudly and
//! immediately (a `panic!` with a clear message) the first time anything
//! touches TOTP, rather than corrupting data or silently accepting a weak
//! key.

use std::sync::OnceLock;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngExt;

const NONCE_LEN: usize = 12;

fn cipher() -> &'static Aes256Gcm {
    static CIPHER: OnceLock<Aes256Gcm> = OnceLock::new();
    CIPHER.get_or_init(|| {
        let hex_key = std::env::var("EDDA_SECRET_KEY").unwrap_or_else(|_| {
            panic!(
                "EDDA_SECRET_KEY must be set to a 64-character hex-encoded 32-byte key before \
                 any TOTP enrollment/verification can run — generate one with, e.g., \
                 `openssl rand -hex 32`"
            )
        });
        let bytes = hex_decode(&hex_key).unwrap_or_else(|| {
            panic!(
                "EDDA_SECRET_KEY must be exactly 64 hex characters (32 bytes) — got {} characters",
                hex_key.trim().len()
            )
        });
        let key = Key::<Aes256Gcm>::from(bytes);
        Aes256Gcm::new(&key)
    })
}

fn hex_decode(input: &str) -> Option<[u8; 32]> {
    let input = input.trim();
    if input.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in input.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(byte_str, 16).ok()?;
    }
    Some(out)
}

/// Encrypts `plaintext`, returning `nonce || ciphertext` as a single
/// opaque byte string — this is exactly what gets stored in
/// `totp_secrets.secret_ciphertext`; `edda-db` never sees the nonce or
/// plaintext separately.
pub fn encrypt(plaintext: &[u8]) -> Vec<u8> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher()
        .encrypt(&nonce, plaintext)
        .expect("AES-256-GCM encryption of an in-memory secret never fails");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

#[derive(Debug, thiserror::Error)]
#[error("stored secret could not be decrypted — wrong EDDA_SECRET_KEY or corrupted data")]
pub struct DecryptError;

/// Reverses `encrypt`. Fails (rather than panics) on bad input, since the
/// input here is untrusted-in-the-sense-of-"could be stale or corrupted"
/// database content, not an in-memory value this process just produced.
pub fn decrypt(stored: &[u8]) -> Result<Vec<u8>, DecryptError> {
    if stored.len() < NONCE_LEN {
        return Err(DecryptError);
    }
    let (nonce_bytes, ciphertext) = stored.split_at(NONCE_LEN);
    let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .expect("split_at guarantees this length");
    let nonce = Nonce::from(nonce_bytes);
    cipher()
        .decrypt(&nonce, ciphertext)
        .map_err(|_| DecryptError)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_test_key() {
        // SAFETY (not literally unsafe, but env vars are process-global):
        // this is fine for a `#[cfg(test)]`-only helper — every test in
        // this process wants the same fixed test key, and `cipher()`'s
        // `OnceLock` only ever reads it once per process anyway.
        std::env::set_var(
            "EDDA_SECRET_KEY",
            "0000000000000000000000000000000000000000000000000000000000000000"
                .get(0..64)
                .unwrap(),
        );
    }

    #[test]
    fn a_secret_round_trips_through_encrypt_and_decrypt() {
        set_test_key();
        let plaintext = b"top secret totp seed";
        let ciphertext = encrypt(plaintext);
        assert_ne!(ciphertext, plaintext);
        let decrypted = decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn corrupted_ciphertext_fails_to_decrypt_rather_than_returning_garbage() {
        set_test_key();
        let mut ciphertext = encrypt(b"some secret");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;
        assert!(decrypt(&ciphertext).is_err());
    }
}

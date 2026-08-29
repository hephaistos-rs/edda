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
//! # Configuration & key rotation
//!
//! `EDDA_SECRET_KEYS` is a comma-separated list of `id:hex` entries — each
//! a stable short id and a 64-hex-char (32-byte) AES-256 key. The **first**
//! entry is the *primary*: new ciphertext is encrypted under it and stamped
//! with its id. Every listed key can *decrypt*, so an operator rotates by
//! prepending a new primary, running `edda-cli secrets rotate` to
//! re-encrypt the stored blobs under it, then dropping the old entry.
//!
//! The composition root resolves and validates the list via
//! `edda_app::config` and installs it here **once**, at startup, with
//! [`init`]. This module never reads the environment and never panics: an
//! instance that configured no key simply cannot enroll 2FA or store a
//! webhook secret, and [`encrypt`]/[`decrypt`] say so with
//! [`SecretBoxError::NotConfigured`] rather than aborting a request.
//!
//! Deliberately **not** a random per-process key (unlike
//! `edda_app::lfs::transfer_auth`): a TOTP secret encrypted today must
//! still decrypt after a restart, so the key must be stable across runs.
//!
//! ## Stored ciphertext format
//!
//! `0x01 || id_len:u8 || id_bytes || nonce(12) || AES-256-GCM(ct)`. The
//! `0x01` tag + a plausible `id_len` distinguish it from the pre-rotation
//! `nonce(12) || ct` layout, which [`decrypt`] still reads under the
//! primary key (a convenience for a developer's local database — there are
//! no deployments to migrate).

use std::collections::HashMap;
use std::sync::OnceLock;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngExt;

const NONCE_LEN: usize = 12;
const FORMAT_TAG: u8 = 0x01;
const MAX_ID_LEN: usize = 32;

/// The installed key set: every key by id (for `decrypt`), which id is
/// primary (for `encrypt`), and the primary's raw bytes (for
/// `crate::signing_keys`). `None` when the instance configured no key.
struct Keys {
    by_id: HashMap<String, Aes256Gcm>,
    primary_id: String,
    primary_bytes: [u8; 32],
}

static KEYS: OnceLock<Option<Keys>> = OnceLock::new();

/// Installs the process's at-rest encryption key set from `EDDA_SECRET_KEYS`
/// (`(id, key)` pairs, first = primary), or `None` when the instance
/// configured no key. Call once from the composition root before any
/// TOTP/webhook work. The first call wins; later calls are ignored.
pub fn init(keys: Vec<(String, [u8; 32])>, primary_id: Option<String>) {
    let resolved = match primary_id {
        Some(primary_id) if !keys.is_empty() => {
            let primary_bytes = keys
                .iter()
                .find(|(id, _)| *id == primary_id)
                .map(|(_, bytes)| *bytes)
                .expect("edda_app::config guarantees the primary id is in the key list");
            let by_id = keys
                .into_iter()
                .map(|(id, bytes)| (id, Aes256Gcm::new(&Key::<Aes256Gcm>::from(bytes))))
                .collect();
            Some(Keys {
                by_id,
                primary_id,
                primary_bytes,
            })
        }
        _ => None,
    };
    let _ = KEYS.set(resolved);
}

/// Whether a usable key is installed. `false` before [`init`] runs, or
/// after `init(vec![], None)`.
pub fn is_configured() -> bool {
    matches!(KEYS.get(), Some(Some(_)))
}

/// The id of the primary key — what fresh ciphertext is stamped with.
/// `None` when no key is installed.
pub fn active_key_id() -> Option<&'static str> {
    match KEYS.get() {
        Some(Some(keys)) => Some(keys.primary_id.as_str()),
        _ => None,
    }
}

/// The primary key's raw bytes, for callers that derive a *purpose-keyed*
/// value from it rather than using [`encrypt`]/[`decrypt`] directly
/// (`crate::signing_keys`). `None` when no key is installed.
pub(crate) fn primary_key_bytes() -> Option<[u8; 32]> {
    match KEYS.get() {
        Some(Some(keys)) => Some(keys.primary_bytes),
        _ => None,
    }
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

fn keys() -> Result<&'static Keys, SecretBoxError> {
    match KEYS.get() {
        Some(Some(keys)) => Ok(keys),
        _ => Err(SecretBoxError::NotConfigured),
    }
}

/// Encrypts `plaintext` under the primary key, returning a single opaque
/// byte string in the [module format](self#stored-ciphertext-format) —
/// exactly what gets stored in `*.secret_ciphertext`; `edda-db` never sees
/// the nonce, key id, or plaintext separately. `Err(NotConfigured)` when no
/// key is installed.
pub fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>, SecretBoxError> {
    let keys = keys()?;
    let cipher = keys
        .by_id
        .get(&keys.primary_id)
        .expect("primary id always resolves to a key");
    let id = keys.primary_id.as_bytes();

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("AES-256-GCM encryption of an in-memory secret never fails");

    let mut out = Vec::with_capacity(2 + id.len() + NONCE_LEN + ciphertext.len());
    out.push(FORMAT_TAG);
    out.push(u8::try_from(id.len()).expect("a key id is at most 32 bytes"));
    out.extend_from_slice(id);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Reverses [`encrypt`], selecting the key by the id stamped into the
/// blob. `Err(NotConfigured)` when no key is installed; `Err(Corrupted)`
/// on a blob whose key id isn't in the current `EDDA_SECRET_KEYS`, or on
/// bad/stale ciphertext.
pub fn decrypt(stored: &[u8]) -> Result<Vec<u8>, SecretBoxError> {
    let keys = keys()?;
    let (cipher, nonce_bytes, ciphertext) = match parse_versioned(stored) {
        Some((id, nonce, ct)) => (
            keys.by_id.get(id).ok_or(SecretBoxError::Corrupted)?,
            nonce,
            ct,
        ),
        // Pre-rotation `nonce || ct` — try the primary key.
        None => {
            if stored.len() < NONCE_LEN {
                return Err(SecretBoxError::Corrupted);
            }
            let (nonce, ct) = stored.split_at(NONCE_LEN);
            (
                keys.by_id
                    .get(&keys.primary_id)
                    .expect("primary id always resolves"),
                nonce,
                ct,
            )
        }
    };
    let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .expect("a 12-byte nonce slice is 12 bytes");
    cipher
        .decrypt(&Nonce::from(nonce_bytes), ciphertext)
        .map_err(|_| SecretBoxError::Corrupted)
}

/// Decrypts `stored` under whatever key it was written with, then
/// re-encrypts it under the current primary — the primitive behind
/// `edda-cli secrets rotate`. A blob already on the primary is returned
/// re-encrypted with a fresh nonce (harmless).
pub fn reencrypt(stored: &[u8]) -> Result<Vec<u8>, SecretBoxError> {
    let plaintext = decrypt(stored)?;
    encrypt(&plaintext)
}

/// Splits a versioned blob into `(key_id, nonce, ciphertext)`, or `None`
/// if it isn't in the versioned format (so the caller falls back to the
/// legacy layout).
fn parse_versioned(stored: &[u8]) -> Option<(&str, &[u8], &[u8])> {
    let [FORMAT_TAG, id_len, rest @ ..] = stored else {
        return None;
    };
    let id_len = *id_len as usize;
    if id_len == 0 || id_len > MAX_ID_LEN || rest.len() < id_len + NONCE_LEN + 1 {
        return None;
    }
    let (id, rest) = rest.split_at(id_len);
    let id = std::str::from_utf8(id).ok()?;
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    Some((id, nonce, ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: [u8; 32] = [0xAA; 32];
    const KEY_B: [u8; 32] = [0xBB; 32];

    /// The whole test binary shares one `OnceLock`; every case installs
    /// the same two-key set so ordering between tests doesn't matter.
    fn ensure_keys() {
        init(
            vec![("v2".to_string(), KEY_B), ("v1".to_string(), KEY_A)],
            Some("v2".to_string()),
        );
    }

    #[test]
    fn a_secret_round_trips_through_encrypt_and_decrypt() {
        ensure_keys();
        let plaintext = b"top secret totp seed";
        let ciphertext = encrypt(plaintext).expect("key installed");
        assert_ne!(ciphertext, plaintext);
        assert_eq!(decrypt(&ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn fresh_ciphertext_is_stamped_with_the_primary_key_id() {
        ensure_keys();
        let blob = encrypt(b"x").unwrap();
        let (id, _, _) = parse_versioned(&blob).expect("versioned format");
        assert_eq!(id, "v2");
        assert_eq!(active_key_id(), Some("v2"));
    }

    #[test]
    fn a_blob_written_under_a_non_primary_key_still_decrypts() {
        // Install with `v1` primary, encrypt, then re-install with `v2`
        // primary — the `v1` blob must still decrypt because `v1` is still
        // in the set. (`OnceLock` ignores the second `init`, so simulate
        // by hand-stamping a `v1` blob via the same code path.)
        ensure_keys();
        // Build a `v1`-stamped blob directly.
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(KEY_A));
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill(&mut nonce);
        let ct = cipher
            .encrypt(&Nonce::from(nonce), b"legacy-keyed".as_slice())
            .unwrap();
        let mut blob = vec![FORMAT_TAG, 2, b'v', b'1'];
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        assert_eq!(decrypt(&blob).unwrap(), b"legacy-keyed");
    }

    #[test]
    fn reencrypt_moves_a_blob_onto_the_primary_key() {
        ensure_keys();
        // A `v1`-stamped blob.
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(KEY_A));
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill(&mut nonce);
        let ct = cipher
            .encrypt(&Nonce::from(nonce), b"seed".as_slice())
            .unwrap();
        let mut old = vec![FORMAT_TAG, 2, b'v', b'1'];
        old.extend_from_slice(&nonce);
        old.extend_from_slice(&ct);

        let rotated = reencrypt(&old).unwrap();
        assert_eq!(parse_versioned(&rotated).unwrap().0, "v2");
        assert_eq!(decrypt(&rotated).unwrap(), b"seed");
    }

    #[test]
    fn an_unknown_key_id_is_corrupted_not_a_panic() {
        ensure_keys();
        let mut blob = vec![FORMAT_TAG, 2, b'v', b'9'];
        blob.extend_from_slice(&[0u8; NONCE_LEN + 16]);
        assert!(matches!(decrypt(&blob), Err(SecretBoxError::Corrupted)));
    }

    #[test]
    fn a_legacy_unversioned_blob_decrypts_under_the_primary() {
        ensure_keys();
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(KEY_B));
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill(&mut nonce);
        let ct = cipher
            .encrypt(&Nonce::from(nonce), b"pre-rotation".as_slice())
            .unwrap();
        let mut legacy = nonce.to_vec();
        legacy.extend_from_slice(&ct);
        assert_eq!(decrypt(&legacy).unwrap(), b"pre-rotation");
    }

    #[test]
    fn corrupted_ciphertext_fails_to_decrypt_rather_than_returning_garbage() {
        ensure_keys();
        let mut ciphertext = encrypt(b"some secret").expect("key installed");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;
        assert!(matches!(
            decrypt(&ciphertext),
            Err(SecretBoxError::Corrupted)
        ));
    }
}

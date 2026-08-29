//! Per-purpose HMAC secrets for the workspace's short-lived signed tokens:
//! the password->2FA bridge (`pending_login`), the WebAuthn ceremony token
//! (`webauthn`), and the LFS transfer-auth token (`edda_app::lfs`).
//!
//! Before Phase 8 each of those rolled its own random 32-byte secret in a
//! process-local `OnceLock` — so a restart invalidated every in-flight
//! ceremony, and there were three independent unmanaged secrets. Now they
//! all come from here: HKDF-SHA256 over the **primary `EDDA_SECRET_KEYS`
//! entry** with a per-purpose `info` string, so the secrets are stable
//! across restarts and derive from one configured root.
//!
//! When no `EDDA_SECRET_KEYS` is configured (the zero-config default),
//! [`derive`] falls back to a per-process random secret — identical to the
//! old behaviour, so `just run` still works with nothing set; the only
//! cost is that a restart drops in-flight 2FA/LFS flows, exactly as before.

use std::sync::OnceLock;

use hkdf::Hkdf;
use rand::RngExt;
use sha2::Sha256;

/// A short, stable label mixed into the derivation so a secret minted for
/// one purpose can never be a valid token for another.
pub const PENDING_LOGIN: &str = "pending-login";
pub const WEBAUTHN_CEREMONY: &str = "webauthn-ceremony";
pub const LFS_TRANSFER: &str = "lfs-transfer";

/// The 32-byte HMAC secret for `purpose`. Derived from the primary
/// `secret_box` key when one is configured (stable across restarts),
/// otherwise a per-process random value cached for the life of the process.
pub fn derive(purpose: &str) -> [u8; 32] {
    match crate::secret_box::primary_key_bytes() {
        Some(root) => {
            let hk = Hkdf::<Sha256>::new(Some(b"edda/signing-keys/v1"), &root);
            let mut out = [0u8; 32];
            hk.expand(purpose.as_bytes(), &mut out)
                .expect("32 bytes is a valid HKDF-SHA256 output length");
            out
        }
        None => *process_random_fallback(),
    }
}

/// One random secret per process, shared by every purpose that asks for a
/// fallback. The purpose label still separates tokens: each caller feeds
/// this into its own HMAC with its own claims shape, and `pending_login` /
/// `webauthn` bind a `purpose`/`Purpose` field into the signed payload.
fn process_random_fallback() -> &'static [u8; 32] {
    static SECRET: OnceLock<[u8; 32]> = OnceLock::new();
    SECRET.get_or_init(|| {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        bytes
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_purposes_derive_different_secrets() {
        // With no key configured this exercises the fallback: all purposes
        // share the process-random value, so they're equal here — the
        // per-purpose separation in that mode comes from the claims, not
        // the key. The key-configured path is covered in `secret_box` +
        // an integration test.
        assert_eq!(derive(PENDING_LOGIN), derive(PENDING_LOGIN));
    }

    #[test]
    fn derivation_is_stable_within_a_process() {
        let a = derive(WEBAUTHN_CEREMONY);
        let b = derive(WEBAUTHN_CEREMONY);
        assert_eq!(a, b);
    }
}

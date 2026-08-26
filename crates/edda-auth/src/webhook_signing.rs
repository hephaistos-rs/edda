//! HMAC-SHA256 signing for outgoing webhook payloads — directly modeled
//! on Forgejo's confirmed `X-Forgejo-Signature` pattern: a per-webhook
//! secret (encrypted at rest via `secret_box`, decrypted here only for
//! the duration of one signing call), a hex-encoded digest of the exact
//! request body, sent as a header the receiving end verifies against its
//! own copy of the secret. Edda is only ever the sender here — there is
//! no corresponding `verify` function because Edda never receives a
//! webhook it would need to authenticate.

use argon2::password_hash::rand_core::{OsRng, RngCore};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// A fresh, high-entropy signing secret for a new webhook — shown once at
/// creation (the same "shown once, only the encrypted form retained"
/// discipline already used for PATs and TOTP recovery codes), then
/// immediately encrypted at rest via `secret_box::encrypt` by the caller.
pub fn generate_secret() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `secret` is the *decrypted* signing secret (the caller has already
/// called `secret_box::decrypt` on the stored ciphertext); `payload` is
/// the exact bytes being sent as the request body — signing anything else
/// (e.g. a re-serialized copy) risks a mismatch if serialization isn't
/// perfectly deterministic.
pub fn sign(secret: &[u8], payload: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts a key of any length");
    mac.update(payload);
    let digest = mac.finalize().into_bytes();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_is_deterministic_for_the_same_secret_and_payload() {
        let a = sign(b"a-secret", b"the payload");
        let b = sign(b"a-secret", b"the payload");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "hex-encoded SHA-256 digest is 64 characters");
    }

    #[test]
    fn generated_secrets_are_high_entropy_hex_and_distinct() {
        let a = generate_secret();
        let b = generate_secret();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn a_different_secret_or_payload_produces_a_different_signature() {
        let base = sign(b"a-secret", b"the payload");
        assert_ne!(base, sign(b"a-different-secret", b"the payload"));
        assert_ne!(base, sign(b"a-secret", b"a different payload"));
    }
}

//! # SECURITY-CRITICAL — hand-rolled WebAuthn Relying-Party verifier
//!
//! This module is Edda's WebAuthn RP implementation. It is bespoke **on
//! purpose** (plan.local.md C1: `webauthn-rs` pulls `openssl`/`openssl-sys`,
//! an unacceptable trade against this workspace's ring-only, zero-C-crypto
//! stance — verification V1). The residual risk of a bespoke verifier is
//! bounded by the checklist below and by
//! `crates/edda-auth/tests/webauthn_conformance.rs`.
//!
//! **Change checklist — every edit to this module must:**
//!  1. keep `cargo test -p edda-auth --test webauthn_conformance` green
//!     (it is CI-gated — `.github/workflows/ci.yml`);
//!  2. keep every negative test in this file's `mod tests` green — they
//!     encode the attacks this verifier defends against (wrong origin,
//!     wrong RP-ID hash, `crossOrigin`, absent UP/UV, stale sign counter,
//!     tampered signature, replayed ceremony token, wrong algorithm);
//!  3. not "tidy" the ordered check sequences in `finish_registration` /
//!     `finish_authentication` — order is load-bearing (challenge/user/
//!     purpose binding is verified before any attacker-influenced bytes are
//!     parsed);
//!  4. fold every failure into one opaque `WebauthnError` variant — a
//!     caller must not be able to tell *which* check failed.
//!
//! ## What it is
//!
//! WebAuthn/passkey second factor: registration and authentication
//! ceremonies, built on `passkey-types` (WebAuthn JSON/CTAP2 types) +
//! `coset` (COSE key access) + `p256` / `ed25519-dalek` / `rsa` (ES256 /
//! EdDSA / RS256 signature verification) — see the workspace `Cargo.toml`'s
//! WebAuthn dependency comment for why this set rather than `webauthn-rs`.
//! None of those crates is an off-the-shelf relying-party verifier
//! (`passkey-rs` is built for WebAuthn *clients*/authenticators), so
//! everything below — challenge issuance, origin/RP-ID/signature
//! verification, sign-counter tracking — is this module's own
//! responsibility.
//!
//! The persistence layer (`webauthn_credentials`/`edda_db::WebauthnRepo`)
//! predates this module and needed no schema change: `passkey_json` already
//! stored an opaque JSON blob per credential, which is exactly what
//! [`StoredCredential`] below (de)serializes into it.
//!
//! Ceremony state (the challenge a registration/authentication round trip
//! must prove possession of) is a short-lived signed token, not a database
//! row — same "stateless bridge" shape as `pending_login`'s password->2FA
//! token, for the same reason: it only needs to survive one client
//! round-trip, and a process restart between the two requests just makes
//! the client retry from the start. Binding a specific `user_id` and
//! `Purpose` into the token (and rejecting any mismatch on verification)
//! stops a token minted for one account or one ceremony kind from being
//! replayed against another.
//!
//! Three credential algorithms are supported: **ES256** (P-256 ECDSA),
//! **EdDSA** (Ed25519), and **RS256** (RSASSA-PKCS1-v1_5 w/ SHA-256) —
//! offered in that order via `pub_key_cred_params`, and the only ones
//! `finish_registration` will accept even if a non-conforming client
//! offers something else. ES256 alone already covers every mainstream
//! platform authenticator (Windows Hello, Touch ID, Android/Chrome) and
//! FIDO2 security key; EdDSA covers newer FIDO2 keys, RS256 covers older
//! TPM-backed Windows Hello. `StoredCredential` records `alg` so a future
//! algorithm is one more match arm, not a schema change.
//!
//! Attestation is requested as `none` (this instance never asks for or
//! verifies an attestation trust chain — the credential's own public key,
//! trusted on first registration, is what every later assertion is
//! verified against, the same trust-on-first-use model GitHub/GitLab use
//! for WebAuthn) — so registration only needs to parse the *authenticator
//! data* out of the attestation object, never the attestation statement
//! itself.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use coset::{iana, KeyType};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
// One `Verifier` method in scope per key type. Imported as `_` so the two
// same-named traits (from `p256`'s `signature` 3.x and `rsa`'s `signature`
// 2.x) don't collide — method resolution still picks the single trait
// actually implemented for each concrete key. Ed25519 uses the inherent
// `verify_strict`, so `ed25519-dalek`'s trait isn't needed here.
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use rand::RngExt;
use rsa::signature::Verifier as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use passkey_types::ctap2::{AuthenticatorData, Flags};
use passkey_types::webauthn::{
    AttestationConveyancePreference, AuthenticatorSelectionCriteria, ClientDataType,
    CollectedClientData, PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity,
    PublicKeyCredentialType, PublicKeyCredentialUserEntity, UserVerificationRequirement,
};
pub use passkey_types::webauthn::{
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, CredentialCreationOptions,
    CredentialRequestOptions, PublicKeyCredential,
};
use passkey_types::Bytes;

use edda_db::webauthn_repo::WebauthnCredentialRow;
use edda_db::{DbPool, WebauthnRepo};
use edda_domain::{UserId, WebauthnCredentialId};

/// IANA COSE algorithm identifiers for the three credential algorithms
/// this module verifies. See the module doc comment for the coverage
/// rationale. `-7` ES256 (ECDSA P-256 / SHA-256), `-8` EdDSA (Ed25519),
/// `-257` RS256 (RSASSA-PKCS1-v1_5 / SHA-256).
const COSE_ALG_ES256: i64 = -7;
const COSE_ALG_EDDSA: i64 = -8;
const COSE_ALG_RS256: i64 = -257;

/// The `alg` recorded for a credential registered before multi-algorithm
/// support existed — every such credential is ES256 (the only kind the old
/// code accepted).
fn default_stored_alg() -> i64 {
    COSE_ALG_ES256
}

/// How long a registration/authentication challenge stays valid. Short —
/// a real `navigator.credentials` round trip (including the user
/// physically touching a security key or completing a biometric prompt)
/// normally completes in a few seconds; this just bounds how long a
/// captured-but-unused challenge/response pair could be replayed.
const CEREMONY_TTL_SECONDS: u64 = 120;

#[derive(Debug, thiserror::Error)]
pub enum WebauthnError {
    #[error("that registration/authentication attempt has expired — start again")]
    CeremonyExpired,
    #[error("no passkey is registered for this account")]
    NoCredentials,
    #[error("that passkey response was not valid")]
    InvalidResponse,
    #[error(transparent)]
    Db(#[from] edda_db::DbError),
}

/// This instance's Relying Party identity. `rp_id` is the registrable
/// domain every credential gets scoped to (e.g. `example.com`); `origin`
/// is the exact scheme+host(+port) a browser reports in `clientDataJSON`
/// (e.g. `https://example.com`). A mismatch on either fails every
/// ceremony, so there's no sensible partial default — an instance that
/// hasn't configured both simply doesn't offer WebAuthn. Constructed by
/// `edda_app::config` from `EDDA_WEBAUTHN_RP_ID`/`EDDA_WEBAUTHN_ORIGIN`
/// and passed in via `AppState`; this crate never reads the environment.
#[derive(Debug, Clone)]
pub struct Config {
    pub rp_id: String,
    pub origin: String,
    /// Require the authenticator's User-Verified (UV) flag on every
    /// ceremony — a PIN, biometric, or equivalent, not just presence
    /// (`EDDA_WEBAUTHN_REQUIRE_UV`). Default `false`: UV is *requested* as
    /// `Preferred` either way, this makes it mandatory and also asks for it
    /// as `Required` up front so a client that can't do UV fails fast.
    pub require_uv: bool,
    /// Permit `clientDataJSON.crossOrigin == true`
    /// (`EDDA_WEBAUTHN_ALLOW_CROSS_ORIGIN`). Default `false` — a passkey
    /// prompt driven from a cross-origin `<iframe>` is rejected, which is
    /// what an ordinary same-origin deployment wants.
    pub allow_cross_origin: bool,
}

/// What actually gets persisted in `webauthn_credentials.passkey_json` —
/// only what's needed to verify a future assertion, not the full
/// `passkey_types::Passkey` shape (that type isn't `Serialize`/
/// `Deserialize` upstream, and carries fields — username, discoverable-
/// credential bookkeeping — this module doesn't need, since every
/// credential here is always looked up in the context of an
/// already-identified user, never a discoverable/usernameless login).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredCredential {
    /// base64url, no padding — the authenticator-assigned credential ID.
    credential_id: String,
    /// base64url, no padding — the credential's public key, encoded per
    /// [`Self::alg`]:
    ///  - ES256: SEC1 uncompressed point (`0x04 || X || Y`);
    ///  - EdDSA: the raw 32-byte Ed25519 public key;
    ///  - RS256: `<modulus-len:u16-be> || modulus || exponent` (both
    ///    big-endian, unsigned) — a self-contained encoding that needs no
    ///    ASN.1 to reconstruct the `RsaPublicKey`.
    ///
    /// `#[serde(alias)]`: rows written before multi-algorithm support used
    /// the key `public_key_sec1` for the same (always-SEC1) value.
    #[serde(alias = "public_key_sec1")]
    public_key: String,
    /// COSE algorithm identifier (`-7` ES256, `-8` EdDSA, `-257` RS256).
    /// Absent → ES256 (see [`default_stored_alg`]).
    #[serde(default = "default_stored_alg")]
    alg: i64,
    /// The authenticator's signature counter as of the last successful
    /// use. Many platform authenticators/passkeys never increment this
    /// (always report `0`) — see `finish_authentication`'s counter check
    /// for how that's distinguished from a real regression.
    sign_count: u32,
}

fn b64url_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, WebauthnError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| WebauthnError::InvalidResponse)
}

fn stored_from_row(row: &WebauthnCredentialRow) -> Result<StoredCredential, WebauthnError> {
    serde_json::from_str(&row.passkey_json).map_err(|_| WebauthnError::InvalidResponse)
}

fn random_challenge() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Purpose {
    Register,
    Authenticate,
}

#[derive(Debug, Serialize, Deserialize)]
struct CeremonyClaims {
    user_id: String,
    /// base64url — the challenge this ceremony was issued for.
    challenge: String,
    purpose: Purpose,
    exp: u64,
}

/// HS256 secret for the ceremony token — from `crate::signing_keys` (HKDF
/// over the primary `EDDA_SECRET_KEYS` entry, or a process-random fallback
/// when none is set), so with a key configured a restart mid-ceremony no
/// longer forces the client to start over.
fn ceremony_secret() -> [u8; 32] {
    crate::signing_keys::derive(crate::signing_keys::WEBAUTHN_CEREMONY)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs()
}

/// Mints a signed token asserting "this challenge was issued to this user
/// for this ceremony kind" — returned to the client alongside the
/// WebAuthn options and must be echoed back with the completed response.
fn issue_ceremony_token(user_id: UserId, challenge: &[u8], purpose: Purpose) -> String {
    let claims = CeremonyClaims {
        user_id: user_id.to_string(),
        challenge: b64url_encode(challenge),
        purpose,
        exp: now_unix() + CEREMONY_TTL_SECONDS,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&ceremony_secret()),
    )
    .expect("HMAC signing over an in-memory struct never fails")
}

/// Recovers the challenge a ceremony token was issued for, provided it's
/// still validly signed, unexpired, and matches the expected user and
/// ceremony kind — every mismatch is folded into one
/// [`WebauthnError::CeremonyExpired`] rather than distinguished, so a
/// caller can't use error content to probe which check failed.
fn verify_ceremony_token(
    token: &str,
    expected_purpose: Purpose,
    expected_user_id: UserId,
) -> Result<Vec<u8>, WebauthnError> {
    let validation = Validation::new(Algorithm::HS256);
    let data = decode::<CeremonyClaims>(
        token,
        &DecodingKey::from_secret(&ceremony_secret()),
        &validation,
    )
    .map_err(|_| WebauthnError::CeremonyExpired)?;
    let claims = data.claims;
    if claims.purpose != expected_purpose || claims.user_id != expected_user_id.to_string() {
        return Err(WebauthnError::CeremonyExpired);
    }
    b64url_decode(&claims.challenge)
}

/// The CBOR attestation object is `{"fmt": ..., "attStmt": ..., "authData":
/// <bytes>}` — since attestation is always requested as `none` (see this
/// module's doc comment), only `authData` is ever read; `fmt`/`attStmt`
/// are ignored regardless of what the authenticator actually sent.
fn extract_auth_data(attestation_object: &[u8]) -> Result<Vec<u8>, WebauthnError> {
    let value: coset::cbor::value::Value = coset::cbor::de::from_reader(attestation_object)
        .map_err(|_| WebauthnError::InvalidResponse)?;
    let coset::cbor::value::Value::Map(entries) = value else {
        return Err(WebauthnError::InvalidResponse);
    };
    entries
        .into_iter()
        .find_map(|(key, value)| match (key, value) {
            (coset::cbor::value::Value::Text(k), coset::cbor::value::Value::Bytes(bytes))
                if k == "authData" =>
            {
                Some(bytes)
            }
            _ => None,
        })
        .ok_or(WebauthnError::InvalidResponse)
}

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// Whether the base64url challenge echoed back in `clientDataJSON` equals
/// the one this ceremony issued — a **constant-time** compare (defence in
/// depth; the ceremony token's HMAC is the primary anti-replay gate). A
/// malformed base64url value simply doesn't match.
fn challenge_echoed_correctly(client_challenge_b64: &str, expected: &[u8]) -> bool {
    match b64url_decode(client_challenge_b64) {
        Ok(got) => got.ct_eq(expected).into(),
        Err(_) => false,
    }
}

/// Rejects `clientDataJSON.crossOrigin == true` unless the instance opted
/// in (`Config.allow_cross_origin`). Shared by both finish paths.
fn cross_origin_ok(client_data: &CollectedClientData, config: &Config) -> bool {
    config.allow_cross_origin || client_data.cross_origin != Some(true)
}

/// The `userVerification` value to advertise in the ceremony options —
/// `Required` when the instance mandates UV, otherwise `Preferred` (ask
/// for it, don't fail without it).
fn uv_requirement(config: &Config) -> UserVerificationRequirement {
    if config.require_uv {
        UserVerificationRequirement::Required
    } else {
        UserVerificationRequirement::Preferred
    }
}

/// Enforces `Config.require_uv` against an authenticator-data flags byte.
/// Backup-eligibility / backup-state (BE/BS) are logged for visibility but
/// not gated — a passkey synced across a user's devices is expected and
/// common.
fn user_verification_ok(flags: Flags, config: &Config) -> bool {
    if config.require_uv && !flags.contains(Flags::UV) {
        return false;
    }
    tracing::debug!(
        uv = flags.contains(Flags::UV),
        backup_eligible = flags.contains(Flags::BE),
        backed_up = flags.contains(Flags::BS),
        "webauthn ceremony authenticator flags"
    );
    true
}

/// One bstr value out of a COSE key's parameter list, by its IANA label.
fn cose_bstr_param(key: &coset::CoseKey, label: i64) -> Option<Vec<u8>> {
    key.params.iter().find_map(|(l, v)| match (l, v) {
        (coset::Label::Int(i), coset::cbor::value::Value::Bytes(bytes)) if *i == label => {
            Some(bytes.clone())
        }
        _ => None,
    })
}

/// `<modulus-len:u16-be> || modulus || exponent`, both big-endian unsigned
/// — the self-contained RS256 public-key encoding [`StoredCredential`]
/// keeps (no ASN.1 needed to rebuild the `RsaPublicKey`). Leading zero
/// bytes are trimmed so the split point is unambiguous.
fn encode_rsa_public_key(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>, WebauthnError> {
    let n = trim_leading_zeros(modulus);
    let e = trim_leading_zeros(exponent);
    let len = u16::try_from(n.len()).map_err(|_| WebauthnError::InvalidResponse)?;
    let mut out = Vec::with_capacity(2 + n.len() + e.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(n);
    out.extend_from_slice(e);
    Ok(out)
}

fn decode_rsa_public_key(bytes: &[u8]) -> Result<rsa::RsaPublicKey, WebauthnError> {
    if bytes.len() < 2 {
        return Err(WebauthnError::InvalidResponse);
    }
    let n_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    let rest = &bytes[2..];
    if rest.len() <= n_len {
        return Err(WebauthnError::InvalidResponse);
    }
    let (n, e) = rest.split_at(n_len);
    rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(n),
        rsa::BigUint::from_bytes_be(e),
    )
    .map_err(|_| WebauthnError::InvalidResponse)
}

fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    &bytes[first..]
}

/// Pulls the credential public key out of a freshly attested COSE key and
/// returns the algorithm-specific byte encoding [`StoredCredential`] keeps.
/// Also fully validates the key material now (rather than deferring the
/// failure to the first assertion). `alg` is the client-reported COSE
/// algorithm id, already checked against the offered set by the caller.
fn extract_public_key(alg: i64, key: &coset::CoseKey) -> Result<Vec<u8>, WebauthnError> {
    match alg {
        COSE_ALG_ES256 => {
            if key.kty != KeyType::Assigned(iana::KeyType::EC2) {
                return Err(WebauthnError::InvalidResponse);
            }
            let sec1 = key
                .clone()
                .to_sec1_octet_string()
                .map_err(|_| WebauthnError::InvalidResponse)?;
            P256VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| WebauthnError::InvalidResponse)?;
            Ok(sec1)
        }
        COSE_ALG_EDDSA => {
            if key.kty != KeyType::Assigned(iana::KeyType::OKP) {
                return Err(WebauthnError::InvalidResponse);
            }
            let x = cose_bstr_param(key, iana::OkpKeyParameter::X as i64)
                .ok_or(WebauthnError::InvalidResponse)?;
            let x: [u8; 32] = x
                .as_slice()
                .try_into()
                .map_err(|_| WebauthnError::InvalidResponse)?;
            ed25519_dalek::VerifyingKey::from_bytes(&x)
                .map_err(|_| WebauthnError::InvalidResponse)?;
            Ok(x.to_vec())
        }
        COSE_ALG_RS256 => {
            if key.kty != KeyType::Assigned(iana::KeyType::RSA) {
                return Err(WebauthnError::InvalidResponse);
            }
            let n = cose_bstr_param(key, iana::RsaKeyParameter::N as i64)
                .ok_or(WebauthnError::InvalidResponse)?;
            let e = cose_bstr_param(key, iana::RsaKeyParameter::E as i64)
                .ok_or(WebauthnError::InvalidResponse)?;
            let encoded = encode_rsa_public_key(&n, &e)?;
            decode_rsa_public_key(&encoded)?;
            Ok(encoded)
        }
        _ => Err(WebauthnError::InvalidResponse),
    }
}

/// Verifies an assertion signature over `signed_data`
/// (`authenticatorData || SHA-256(clientDataJSON)`) against a stored
/// credential's public key, dispatching on the stored `alg`. Every failure
/// mode — unknown algorithm, malformed key, malformed signature, bad
/// signature — is one opaque [`WebauthnError::InvalidResponse`].
fn verify_assertion_signature(
    alg: i64,
    public_key: &[u8],
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), WebauthnError> {
    match alg {
        COSE_ALG_ES256 => {
            let key = P256VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| WebauthnError::InvalidResponse)?;
            let sig =
                P256Signature::from_der(signature).map_err(|_| WebauthnError::InvalidResponse)?;
            key.verify(signed_data, &sig)
                .map_err(|_| WebauthnError::InvalidResponse)
        }
        COSE_ALG_EDDSA => {
            let key: [u8; 32] = public_key
                .try_into()
                .map_err(|_| WebauthnError::InvalidResponse)?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&key)
                .map_err(|_| WebauthnError::InvalidResponse)?;
            let sig = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|_| WebauthnError::InvalidResponse)?;
            key.verify_strict(signed_data, &sig)
                .map_err(|_| WebauthnError::InvalidResponse)
        }
        COSE_ALG_RS256 => {
            let key = decode_rsa_public_key(public_key)?;
            let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key);
            let sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| WebauthnError::InvalidResponse)?;
            verifying_key
                .verify(signed_data, &sig)
                .map_err(|_| WebauthnError::InvalidResponse)
        }
        _ => Err(WebauthnError::InvalidResponse),
    }
}

/// Starts a registration ceremony for an already-authenticated user:
/// returns the options to pass to `navigator.credentials.create()` plus a
/// ceremony token the client must echo back to `finish_registration`.
/// Existing credentials are listed in `excludeCredentials` so a user can't
/// accidentally register the same authenticator twice.
pub async fn begin_registration(
    pool: &DbPool,
    config: &Config,
    user_id: UserId,
    username: &str,
    display_name: &str,
) -> Result<(CredentialCreationOptions, String), WebauthnError> {
    let existing = WebauthnRepo::list_for_user(pool, user_id).await?;
    let mut exclude_credentials = Vec::with_capacity(existing.len());
    for row in &existing {
        let stored = stored_from_row(row)?;
        exclude_credentials.push(PublicKeyCredentialDescriptor {
            ty: PublicKeyCredentialType::PublicKey,
            id: Bytes::from(b64url_decode(&stored.credential_id)?),
            transports: None,
        });
    }

    let challenge = random_challenge();
    let options = PublicKeyCredentialCreationOptions {
        rp: PublicKeyCredentialRpEntity {
            id: Some(config.rp_id.clone()),
            name: "Edda".to_string(),
        },
        user: PublicKeyCredentialUserEntity {
            id: Bytes::from(user_id.as_uuid().as_bytes().to_vec()),
            display_name: display_name.to_string(),
            name: username.to_string(),
        },
        challenge: Bytes::from(challenge.to_vec()),
        pub_key_cred_params: vec![
            PublicKeyCredentialParameters::from(iana::Algorithm::ES256),
            PublicKeyCredentialParameters::from(iana::Algorithm::EdDSA),
            PublicKeyCredentialParameters::from(iana::Algorithm::RS256),
        ],
        timeout: None,
        exclude_credentials: (!exclude_credentials.is_empty()).then_some(exclude_credentials),
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
            authenticator_attachment: None,
            resident_key: None,
            require_resident_key: false,
            user_verification: uv_requirement(config),
        }),
        hints: None,
        attestation: AttestationConveyancePreference::None,
        attestation_formats: None,
        extensions: None,
    };
    let token = issue_ceremony_token(user_id, &challenge, Purpose::Register);
    Ok((
        CredentialCreationOptions {
            public_key: options,
        },
        token,
    ))
}

/// Verifies a completed registration ceremony and, only on success, stores
/// the new credential. Checks (in order): the ceremony token is valid,
/// unexpired, and issued to this exact user for a registration; the
/// client's `clientDataJSON` claims type `webauthn.create`, is not
/// cross-origin (unless the instance allows it), echoes back the exact
/// challenge this ceremony issued (constant-time), and reports this
/// instance's configured origin; the authenticator data's RP ID hash
/// matches this instance's `rp_id`, the user-present flag is set, and
/// user-verification is present if the instance requires it; the client
/// offered one of the three supported algorithms and the attested
/// credential's public key is well-formed for it.
pub async fn finish_registration(
    pool: &DbPool,
    config: &Config,
    state_token: &str,
    user_id: UserId,
    label: &str,
    credential: PublicKeyCredential<AuthenticatorAttestationResponse>,
) -> Result<(), WebauthnError> {
    let challenge = verify_ceremony_token(state_token, Purpose::Register, user_id)?;
    let response = &credential.response;

    let client_data: CollectedClientData = serde_json::from_slice(&response.client_data_json)
        .map_err(|_| WebauthnError::InvalidResponse)?;
    if client_data.ty != ClientDataType::Create {
        return Err(WebauthnError::InvalidResponse);
    }
    if !cross_origin_ok(&client_data, config) {
        return Err(WebauthnError::InvalidResponse);
    }
    if !challenge_echoed_correctly(&client_data.challenge, &challenge) {
        return Err(WebauthnError::InvalidResponse);
    }
    if client_data.origin != config.origin {
        return Err(WebauthnError::InvalidResponse);
    }

    let auth_data_bytes = extract_auth_data(&response.attestation_object)?;
    let auth_data = AuthenticatorData::from_slice(&auth_data_bytes)
        .map_err(|_| WebauthnError::InvalidResponse)?;
    if auth_data.rp_id_hash() != rp_id_hash(&config.rp_id) {
        return Err(WebauthnError::InvalidResponse);
    }
    if !auth_data.flags.contains(Flags::UP) {
        return Err(WebauthnError::InvalidResponse);
    }
    if !user_verification_ok(auth_data.flags, config) {
        return Err(WebauthnError::InvalidResponse);
    }
    let Some(attested) = &auth_data.attested_credential_data else {
        return Err(WebauthnError::InvalidResponse);
    };

    let alg = response.public_key_algorithm;
    if !matches!(alg, COSE_ALG_ES256 | COSE_ALG_EDDSA | COSE_ALG_RS256) {
        return Err(WebauthnError::InvalidResponse);
    }
    // Also fully validates the key material now, rather than deferring the
    // failure to the first authentication attempt.
    let public_key = extract_public_key(alg, &attested.key)?;

    let stored = StoredCredential {
        credential_id: b64url_encode(attested.credential_id()),
        public_key: b64url_encode(&public_key),
        alg,
        sign_count: auth_data.counter.unwrap_or(0),
    };
    let passkey_json = serde_json::to_string(&stored).expect("StoredCredential always serializes");

    WebauthnRepo::insert(
        pool,
        WebauthnCredentialId::new(),
        user_id,
        label,
        &passkey_json,
    )
    .await?;
    // 2FA enrollment immediately invalidates outstanding password-reset
    // tokens — same reasoning as `totp::activate`'s identical call.
    edda_db::PasswordResetTokenRepo::invalidate_all_for_user(pool, user_id).await?;
    Ok(())
}

/// Starts an authentication ceremony for a *known* user (this instance
/// never does discoverable/usernameless WebAuthn login — the caller
/// always already knows which account is authenticating, e.g. via a
/// password-verified `pending_login` token, the same precondition
/// TOTP's second-factor step has). Returns `Ok(None)` if the account has
/// no registered credentials, so a caller can fall back to another second
/// factor without treating "no passkey" as an error.
pub async fn begin_authentication(
    pool: &DbPool,
    config: &Config,
    user_id: UserId,
) -> Result<Option<(CredentialRequestOptions, String)>, WebauthnError> {
    let existing = WebauthnRepo::list_for_user(pool, user_id).await?;
    if existing.is_empty() {
        return Ok(None);
    }
    let mut allow_credentials = Vec::with_capacity(existing.len());
    for row in &existing {
        let stored = stored_from_row(row)?;
        allow_credentials.push(PublicKeyCredentialDescriptor {
            ty: PublicKeyCredentialType::PublicKey,
            id: Bytes::from(b64url_decode(&stored.credential_id)?),
            transports: None,
        });
    }

    let challenge = random_challenge();
    let options = PublicKeyCredentialRequestOptions {
        challenge: Bytes::from(challenge.to_vec()),
        timeout: None,
        rp_id: Some(config.rp_id.clone()),
        allow_credentials: Some(allow_credentials),
        user_verification: uv_requirement(config),
        hints: None,
        attestation: AttestationConveyancePreference::None,
        attestation_formats: None,
        extensions: None,
    };
    let token = issue_ceremony_token(user_id, &challenge, Purpose::Authenticate);
    Ok(Some((
        CredentialRequestOptions {
            public_key: options,
        },
        token,
    )))
}

/// Verifies a completed authentication ceremony. Checks (in order): the
/// ceremony token is valid, unexpired, and issued to this exact user for
/// an authentication; the returned credential ID matches one already
/// registered to this user; `clientDataJSON` claims type `webauthn.get`,
/// is not cross-origin (unless the instance allows it), echoes back the
/// exact challenge (constant-time), and reports this instance's configured
/// origin; the authenticator data's RP ID hash matches, the user-present
/// flag is set, and user-verification is present if the instance requires
/// it; the signature over `authenticatorData || SHA-256(clientDataJSON)`
/// verifies against the credential's stored public key using the
/// credential's own algorithm (ES256 / EdDSA / RS256); the signature
/// counter has not gone backwards (a cloned-authenticator indicator) —
/// unless neither side has ever reported a nonzero counter, since many
/// platform authenticators never implement one. On success, updates the
/// stored counter and `last_used_at`.
pub async fn finish_authentication(
    pool: &DbPool,
    config: &Config,
    state_token: &str,
    user_id: UserId,
    credential: PublicKeyCredential<AuthenticatorAssertionResponse>,
) -> Result<(), WebauthnError> {
    let challenge = verify_ceremony_token(state_token, Purpose::Authenticate, user_id)?;

    let existing = WebauthnRepo::list_for_user(pool, user_id).await?;
    if existing.is_empty() {
        return Err(WebauthnError::NoCredentials);
    }
    let raw_id_b64 = b64url_encode(&credential.raw_id);
    let mut matched: Option<(WebauthnCredentialId, StoredCredential)> = None;
    for row in &existing {
        let stored = stored_from_row(row)?;
        if stored.credential_id == raw_id_b64 {
            matched = Some((row.id, stored));
            break;
        }
    }
    let Some((credential_row_id, mut stored)) = matched else {
        return Err(WebauthnError::InvalidResponse);
    };

    let response = &credential.response;
    let client_data: CollectedClientData = serde_json::from_slice(&response.client_data_json)
        .map_err(|_| WebauthnError::InvalidResponse)?;
    if client_data.ty != ClientDataType::Get {
        return Err(WebauthnError::InvalidResponse);
    }
    if !cross_origin_ok(&client_data, config) {
        return Err(WebauthnError::InvalidResponse);
    }
    if !challenge_echoed_correctly(&client_data.challenge, &challenge) {
        return Err(WebauthnError::InvalidResponse);
    }
    if client_data.origin != config.origin {
        return Err(WebauthnError::InvalidResponse);
    }

    let auth_data = AuthenticatorData::from_slice(&response.authenticator_data)
        .map_err(|_| WebauthnError::InvalidResponse)?;
    if auth_data.rp_id_hash() != rp_id_hash(&config.rp_id) {
        return Err(WebauthnError::InvalidResponse);
    }
    if !auth_data.flags.contains(Flags::UP) {
        return Err(WebauthnError::InvalidResponse);
    }
    if !user_verification_ok(auth_data.flags, config) {
        return Err(WebauthnError::InvalidResponse);
    }

    let public_key_bytes = b64url_decode(&stored.public_key)?;
    let client_data_hash = Sha256::digest(&*response.client_data_json);
    let mut signed_data = response.authenticator_data.to_vec();
    signed_data.extend_from_slice(&client_data_hash);
    verify_assertion_signature(
        stored.alg,
        &public_key_bytes,
        &signed_data,
        &response.signature,
    )?;

    let new_counter = auth_data.counter.unwrap_or(0);
    if (stored.sign_count != 0 || new_counter != 0) && new_counter <= stored.sign_count {
        return Err(WebauthnError::InvalidResponse);
    }
    stored.sign_count = new_counter;

    let passkey_json = serde_json::to_string(&stored).expect("StoredCredential always serializes");
    WebauthnRepo::update_passkey(pool, credential_row_id, &passkey_json).await?;
    Ok(())
}

/// Lists the caller's own registered credentials — for a settings page to
/// show and revoke, or for the login flow to decide whether to offer a
/// passkey as a second factor at all.
pub async fn list(
    pool: &DbPool,
    user_id: UserId,
) -> Result<Vec<WebauthnCredentialRow>, edda_db::DbError> {
    WebauthnRepo::list_for_user(pool, user_id).await
}

pub async fn revoke(
    pool: &DbPool,
    user_id: UserId,
    id: WebauthnCredentialId,
) -> Result<bool, edda_db::DbError> {
    WebauthnRepo::delete(pool, user_id, id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One of the three supported credential algorithms, holding a real
    /// private key.
    enum FakeKey {
        Es256(p256::ecdsa::SigningKey),
        EdDsa(Box<ed25519_dalek::SigningKey>),
        Rs256(Box<rsa::RsaPrivateKey>),
    }

    /// A fake authenticator: holds a real keypair for one of the three
    /// algorithms and can produce spec-shaped attestation/assertion byte
    /// payloads for it, so these tests exercise the real CBOR/multi-
    /// algorithm signature verification path in `finish_registration`/
    /// `finish_authentication` without a browser or a hardware key.
    struct FakeAuthenticator {
        key: FakeKey,
        credential_id: Vec<u8>,
    }

    /// RustCrypto's own PKCS#8 RSA-2048 test vector — a fixed key keeps the
    /// RS256 tests deterministic and keygen-free (no RNG-version friction
    /// with the `rand` this workspace pins).
    const RS256_TEST_KEY_PEM: &str =
        include_str!("../tests/fixtures/webauthn/rs256_test_key.pkcs8.pem");

    fn random_credential_id() -> Vec<u8> {
        let mut id = vec![0u8; 24];
        rand::rng().fill(id.as_mut_slice());
        id
    }

    fn random_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        rand::rng().fill(&mut seed);
        seed
    }

    impl FakeAuthenticator {
        /// ES256 — the default; every pre-existing test uses this.
        fn new() -> Self {
            Self {
                key: FakeKey::Es256(
                    p256::ecdsa::SigningKey::from_slice(&random_seed())
                        .expect("a random 32-byte seed is a valid P-256 scalar w.h.p."),
                ),
                credential_id: random_credential_id(),
            }
        }

        fn new_eddsa() -> Self {
            Self {
                key: FakeKey::EdDsa(Box::new(ed25519_dalek::SigningKey::from_bytes(
                    &random_seed(),
                ))),
                credential_id: random_credential_id(),
            }
        }

        fn new_rs256() -> Self {
            use rsa::pkcs8::DecodePrivateKey;
            Self {
                key: FakeKey::Rs256(Box::new(
                    rsa::RsaPrivateKey::from_pkcs8_pem(RS256_TEST_KEY_PEM)
                        .expect("the bundled RSA test key parses"),
                )),
                credential_id: random_credential_id(),
            }
        }

        fn alg(&self) -> i64 {
            match self.key {
                FakeKey::Es256(_) => COSE_ALG_ES256,
                FakeKey::EdDsa(_) => COSE_ALG_EDDSA,
                FakeKey::Rs256(_) => COSE_ALG_RS256,
            }
        }

        fn cose_public_key(&self) -> coset::CoseKey {
            match &self.key {
                FakeKey::Es256(sk) => {
                    let point = sk.verifying_key().to_sec1_point(false);
                    coset::CoseKeyBuilder::new_ec2_pub_key(
                        iana::EllipticCurve::P_256,
                        point.x().unwrap().to_vec(),
                        point.y().unwrap().to_vec(),
                    )
                    .build()
                }
                FakeKey::EdDsa(sk) => coset::CoseKeyBuilder::new_okp_key()
                    .algorithm(iana::Algorithm::EdDSA)
                    .param(
                        iana::OkpKeyParameter::Crv as i64,
                        coset::cbor::value::Value::Integer(
                            (iana::EllipticCurve::Ed25519 as i64).into(),
                        ),
                    )
                    .param(
                        iana::OkpKeyParameter::X as i64,
                        coset::cbor::value::Value::Bytes(sk.verifying_key().to_bytes().to_vec()),
                    )
                    .build(),
                FakeKey::Rs256(sk) => {
                    use rsa::traits::PublicKeyParts;
                    let pubkey = sk.to_public_key();
                    coset::CoseKey {
                        kty: KeyType::Assigned(iana::KeyType::RSA),
                        alg: Some(coset::Algorithm::Assigned(iana::Algorithm::RS256)),
                        params: vec![
                            (
                                coset::Label::Int(iana::RsaKeyParameter::N as i64),
                                coset::cbor::value::Value::Bytes(pubkey.n().to_bytes_be()),
                            ),
                            (
                                coset::Label::Int(iana::RsaKeyParameter::E as i64),
                                coset::cbor::value::Value::Bytes(pubkey.e().to_bytes_be()),
                            ),
                        ],
                        ..Default::default()
                    }
                }
            }
        }

        /// Raw `authenticatorData` with attested credential data (as
        /// produced during registration), with the given flags OR-ed with
        /// `AT` (attested-credential-data present, always set here).
        fn auth_data_for_registration(&self, rp_id: &str, counter: u32, flags: Flags) -> Vec<u8> {
            let mut out = rp_id_hash(rp_id).to_vec();
            out.push((flags | Flags::AT).bits());
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(&[0u8; 16]); // AAGUID, zeroed (self attestation)
            out.extend_from_slice(
                &u16::try_from(self.credential_id.len())
                    .unwrap()
                    .to_be_bytes(),
            );
            out.extend_from_slice(&self.credential_id);
            let mut key_bytes = Vec::new();
            ciborium_ser_into(&self.cose_public_key(), &mut key_bytes);
            out.extend_from_slice(&key_bytes);
            out
        }

        /// Raw `authenticatorData` with no attested credential data (as
        /// produced during authentication).
        fn auth_data_for_assertion(&self, rp_id: &str, counter: u32, flags: Flags) -> Vec<u8> {
            let mut out = rp_id_hash(rp_id).to_vec();
            out.push(flags.bits());
            out.extend_from_slice(&counter.to_be_bytes());
            out
        }

        fn attestation_object(&self, rp_id: &str, counter: u32, flags: Flags) -> Vec<u8> {
            let auth_data = self.auth_data_for_registration(rp_id, counter, flags);
            let value = coset::cbor::value::Value::Map(vec![
                (
                    coset::cbor::value::Value::Text("fmt".into()),
                    coset::cbor::value::Value::Text("none".into()),
                ),
                (
                    coset::cbor::value::Value::Text("attStmt".into()),
                    coset::cbor::value::Value::Map(vec![]),
                ),
                (
                    coset::cbor::value::Value::Text("authData".into()),
                    coset::cbor::value::Value::Bytes(auth_data),
                ),
            ]);
            let mut bytes = Vec::new();
            coset::cbor::ser::into_writer(&value, &mut bytes).unwrap();
            bytes
        }

        fn sign(&self, message: &[u8]) -> Vec<u8> {
            match &self.key {
                FakeKey::Es256(sk) => {
                    use p256::ecdsa::signature::Signer;
                    let signature: P256Signature = sk.sign(message);
                    signature.to_der().as_ref().to_vec()
                }
                FakeKey::EdDsa(sk) => {
                    use ed25519_dalek::Signer;
                    sk.sign(message).to_bytes().to_vec()
                }
                FakeKey::Rs256(sk) => {
                    use rsa::signature::{SignatureEncoding, Signer};
                    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new((**sk).clone());
                    signing_key.sign(message).to_vec()
                }
            }
        }
    }

    fn ciborium_ser_into(key: &coset::CoseKey, out: &mut Vec<u8>) {
        use coset::AsCborValue;
        coset::cbor::ser::into_writer(&key.clone().to_cbor_value().unwrap(), out).unwrap();
    }

    const RP_ID: &str = "example.com";
    const ORIGIN: &str = "https://example.com";

    fn test_config() -> Config {
        Config {
            rp_id: RP_ID.to_string(),
            origin: ORIGIN.to_string(),
            require_uv: false,
            allow_cross_origin: false,
        }
    }

    fn client_data_json(ty: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        client_data_json_full(ty, challenge, origin, false)
    }

    fn client_data_json_full(
        ty: &str,
        challenge: &[u8],
        origin: &str,
        cross_origin: bool,
    ) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type": ty,
            "challenge": b64url_encode(challenge),
            "origin": origin,
            "crossOrigin": cross_origin,
        }))
        .unwrap()
    }

    async fn insert_user(pool: &DbPool, username: &str) -> UserId {
        let id = UserId::new();
        edda_db::UserRepo::insert(pool, id, username, &format!("{username}@example.com"), "x")
            .await
            .unwrap();
        id
    }

    fn build_attestation_credential(
        authenticator: &FakeAuthenticator,
        challenge: &[u8],
    ) -> PublicKeyCredential<AuthenticatorAttestationResponse> {
        build_attestation_credential_full(authenticator, challenge, ORIGIN, false, Flags::UP)
    }

    fn build_attestation_credential_full(
        authenticator: &FakeAuthenticator,
        challenge: &[u8],
        origin: &str,
        cross_origin: bool,
        flags: Flags,
    ) -> PublicKeyCredential<AuthenticatorAttestationResponse> {
        let client_data_json =
            client_data_json_full("webauthn.create", challenge, origin, cross_origin);
        let attestation_object = authenticator.attestation_object(RP_ID, 0, flags);
        PublicKeyCredential {
            id: b64url_encode(&authenticator.credential_id),
            raw_id: Bytes::from(authenticator.credential_id.clone()),
            ty: PublicKeyCredentialType::PublicKey,
            response: AuthenticatorAttestationResponse {
                client_data_json: Bytes::from(client_data_json),
                authenticator_data: Bytes::from(
                    authenticator.auth_data_for_registration(RP_ID, 0, flags),
                ),
                public_key: None,
                public_key_algorithm: authenticator.alg(),
                attestation_object: Bytes::from(attestation_object),
                transports: None,
            },
            authenticator_attachment: None,
            client_extension_results: Default::default(),
        }
    }

    fn build_assertion_credential(
        authenticator: &FakeAuthenticator,
        challenge: &[u8],
        counter: u32,
    ) -> PublicKeyCredential<AuthenticatorAssertionResponse> {
        build_assertion_credential_full(authenticator, challenge, counter, ORIGIN, false, Flags::UP)
    }

    fn build_assertion_credential_full(
        authenticator: &FakeAuthenticator,
        challenge: &[u8],
        counter: u32,
        origin: &str,
        cross_origin: bool,
        flags: Flags,
    ) -> PublicKeyCredential<AuthenticatorAssertionResponse> {
        let client_data_json =
            client_data_json_full("webauthn.get", challenge, origin, cross_origin);
        let auth_data = authenticator.auth_data_for_assertion(RP_ID, counter, flags);
        let client_data_hash = Sha256::digest(&client_data_json);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&client_data_hash);
        let signature = authenticator.sign(&signed);
        PublicKeyCredential {
            id: b64url_encode(&authenticator.credential_id),
            raw_id: Bytes::from(authenticator.credential_id.clone()),
            ty: PublicKeyCredentialType::PublicKey,
            response: AuthenticatorAssertionResponse {
                client_data_json: Bytes::from(client_data_json),
                authenticator_data: Bytes::from(auth_data),
                signature: Bytes::from(signature),
                user_handle: None,
                attestation_object: None,
            },
            authenticator_attachment: None,
            client_extension_results: Default::default(),
        }
    }

    /// Drives a full register → authenticate round trip for whichever
    /// algorithm `authenticator` carries — the shared body of the
    /// per-algorithm tests below.
    async fn round_trip(authenticator: &FakeAuthenticator, username: &str) {
        let pool = edda_db::test_pool().await;
        let config = test_config();
        let user_id = insert_user(&pool, username).await;

        let (_, reg_token) = begin_registration(&pool, &config, user_id, username, username)
            .await
            .unwrap();
        let reg_challenge = verify_ceremony_token(&reg_token, Purpose::Register, user_id).unwrap();
        let credential = build_attestation_credential(authenticator, &reg_challenge);
        finish_registration(&pool, &config, &reg_token, user_id, "key", credential)
            .await
            .unwrap();

        let (_, auth_token) = begin_authentication(&pool, &config, user_id)
            .await
            .unwrap()
            .expect("a credential is registered");
        let auth_challenge =
            verify_ceremony_token(&auth_token, Purpose::Authenticate, user_id).unwrap();
        let assertion = build_assertion_credential(authenticator, &auth_challenge, 1);
        finish_authentication(&pool, &config, &auth_token, user_id, assertion)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_registered_credential_can_then_authenticate() {
        let pool = edda_db::test_pool().await;
        let config = test_config();
        let user_id = insert_user(&pool, "alice").await;
        let authenticator = FakeAuthenticator::new();

        let (_, reg_token) = begin_registration(&pool, &config, user_id, "alice", "Alice")
            .await
            .unwrap();
        let reg_claims_challenge =
            verify_ceremony_token(&reg_token, Purpose::Register, user_id).unwrap();
        let credential = build_attestation_credential(&authenticator, &reg_claims_challenge);
        finish_registration(&pool, &config, &reg_token, user_id, "yubikey", credential)
            .await
            .unwrap();

        let creds = list(&pool, user_id).await.unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].label, "yubikey");

        let (_, auth_token) = begin_authentication(&pool, &config, user_id)
            .await
            .unwrap()
            .expect("a credential is registered");
        let auth_challenge =
            verify_ceremony_token(&auth_token, Purpose::Authenticate, user_id).unwrap();
        let assertion = build_assertion_credential(&authenticator, &auth_challenge, 1);
        finish_authentication(&pool, &config, &auth_token, user_id, assertion)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_user_with_no_credentials_has_no_authentication_options() {
        let pool = edda_db::test_pool().await;
        let config = test_config();
        let user_id = insert_user(&pool, "bob").await;

        let result = begin_authentication(&pool, &config, user_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn a_wrong_origin_is_rejected_at_registration() {
        let pool = edda_db::test_pool().await;
        let config = test_config();
        let user_id = insert_user(&pool, "carol").await;
        let authenticator = FakeAuthenticator::new();

        let (_, reg_token) = begin_registration(&pool, &config, user_id, "carol", "Carol")
            .await
            .unwrap();
        let challenge = verify_ceremony_token(&reg_token, Purpose::Register, user_id).unwrap();

        let mut credential = build_attestation_credential(&authenticator, &challenge);
        credential.response.client_data_json = Bytes::from(client_data_json(
            "webauthn.create",
            &challenge,
            "https://evil.example",
        ));

        let err = finish_registration(&pool, &config, &reg_token, user_id, "key", credential)
            .await
            .unwrap_err();
        assert!(matches!(err, WebauthnError::InvalidResponse));
        assert!(list(&pool, user_id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_tampered_signature_is_rejected_at_authentication() {
        let pool = edda_db::test_pool().await;
        let config = test_config();
        let user_id = insert_user(&pool, "dave").await;
        let authenticator = FakeAuthenticator::new();

        let (_, reg_token) = begin_registration(&pool, &config, user_id, "dave", "Dave")
            .await
            .unwrap();
        let reg_challenge = verify_ceremony_token(&reg_token, Purpose::Register, user_id).unwrap();
        let credential = build_attestation_credential(&authenticator, &reg_challenge);
        finish_registration(&pool, &config, &reg_token, user_id, "key", credential)
            .await
            .unwrap();

        let (_, auth_token) = begin_authentication(&pool, &config, user_id)
            .await
            .unwrap()
            .unwrap();
        let auth_challenge =
            verify_ceremony_token(&auth_token, Purpose::Authenticate, user_id).unwrap();
        let mut assertion = build_assertion_credential(&authenticator, &auth_challenge, 1);
        // Sign with a *different* key than the one that was registered.
        let other = FakeAuthenticator::new();
        let client_data_hash = Sha256::digest(&*assertion.response.client_data_json);
        let mut signed = assertion.response.authenticator_data.to_vec();
        signed.extend_from_slice(&client_data_hash);
        assertion.response.signature = Bytes::from(other.sign(&signed));

        let err = finish_authentication(&pool, &config, &auth_token, user_id, assertion)
            .await
            .unwrap_err();
        assert!(matches!(err, WebauthnError::InvalidResponse));
    }

    #[tokio::test]
    async fn a_ceremony_token_cannot_be_replayed_for_a_different_user() {
        let pool = edda_db::test_pool().await;
        let config = test_config();
        let alice = insert_user(&pool, "alice2").await;
        let eve = insert_user(&pool, "eve").await;
        let authenticator = FakeAuthenticator::new();

        let (_, reg_token) = begin_registration(&pool, &config, alice, "alice2", "Alice")
            .await
            .unwrap();
        let challenge = verify_ceremony_token(&reg_token, Purpose::Register, alice).unwrap();
        let credential = build_attestation_credential(&authenticator, &challenge);

        // Eve tries to use Alice's ceremony token to register a credential
        // on her own account.
        let err = finish_registration(&pool, &config, &reg_token, eve, "stolen", credential)
            .await
            .unwrap_err();
        assert!(matches!(err, WebauthnError::CeremonyExpired));
    }

    #[tokio::test]
    async fn a_stale_sign_counter_is_rejected_as_a_possible_clone() {
        let pool = edda_db::test_pool().await;
        let config = test_config();
        let user_id = insert_user(&pool, "frank").await;
        let authenticator = FakeAuthenticator::new();

        let (_, reg_token) = begin_registration(&pool, &config, user_id, "frank", "Frank")
            .await
            .unwrap();
        let reg_challenge = verify_ceremony_token(&reg_token, Purpose::Register, user_id).unwrap();
        let credential = build_attestation_credential(&authenticator, &reg_challenge);
        finish_registration(&pool, &config, &reg_token, user_id, "key", credential)
            .await
            .unwrap();

        // First authentication at counter 5 succeeds and is stored.
        let (_, auth_token) = begin_authentication(&pool, &config, user_id)
            .await
            .unwrap()
            .unwrap();
        let auth_challenge =
            verify_ceremony_token(&auth_token, Purpose::Authenticate, user_id).unwrap();
        let assertion = build_assertion_credential(&authenticator, &auth_challenge, 5);
        finish_authentication(&pool, &config, &auth_token, user_id, assertion)
            .await
            .unwrap();

        // A second authentication reporting a *lower* counter (as a
        // cloned authenticator replaying an earlier state would) fails.
        let (_, auth_token2) = begin_authentication(&pool, &config, user_id)
            .await
            .unwrap()
            .unwrap();
        let auth_challenge2 =
            verify_ceremony_token(&auth_token2, Purpose::Authenticate, user_id).unwrap();
        let assertion2 = build_assertion_credential(&authenticator, &auth_challenge2, 3);
        let err = finish_authentication(&pool, &config, &auth_token2, user_id, assertion2)
            .await
            .unwrap_err();
        assert!(matches!(err, WebauthnError::InvalidResponse));
    }

    #[tokio::test]
    async fn an_es256_credential_round_trips() {
        round_trip(&FakeAuthenticator::new(), "es256user").await;
    }

    #[tokio::test]
    async fn an_ed25519_credential_round_trips() {
        round_trip(&FakeAuthenticator::new_eddsa(), "eddsauser").await;
    }

    #[tokio::test]
    async fn an_rs256_credential_round_trips() {
        round_trip(&FakeAuthenticator::new_rs256(), "rs256user").await;
    }

    #[tokio::test]
    async fn a_cross_origin_client_data_is_rejected_at_registration() {
        let pool = edda_db::test_pool().await;
        let config = test_config();
        let user_id = insert_user(&pool, "xorigin_reg").await;
        let authenticator = FakeAuthenticator::new();

        let (_, reg_token) = begin_registration(&pool, &config, user_id, "x", "x")
            .await
            .unwrap();
        let challenge = verify_ceremony_token(&reg_token, Purpose::Register, user_id).unwrap();
        let credential =
            build_attestation_credential_full(&authenticator, &challenge, ORIGIN, true, Flags::UP);

        let err = finish_registration(&pool, &config, &reg_token, user_id, "key", credential)
            .await
            .unwrap_err();
        assert!(matches!(err, WebauthnError::InvalidResponse));
        assert!(list(&pool, user_id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_cross_origin_client_data_is_rejected_at_authentication() {
        let pool = edda_db::test_pool().await;
        let config = test_config();
        let user_id = insert_user(&pool, "xorigin_auth").await;
        let authenticator = FakeAuthenticator::new();

        let (_, reg_token) = begin_registration(&pool, &config, user_id, "x", "x")
            .await
            .unwrap();
        let reg_challenge = verify_ceremony_token(&reg_token, Purpose::Register, user_id).unwrap();
        finish_registration(
            &pool,
            &config,
            &reg_token,
            user_id,
            "key",
            build_attestation_credential(&authenticator, &reg_challenge),
        )
        .await
        .unwrap();

        let (_, auth_token) = begin_authentication(&pool, &config, user_id)
            .await
            .unwrap()
            .unwrap();
        let auth_challenge =
            verify_ceremony_token(&auth_token, Purpose::Authenticate, user_id).unwrap();
        let assertion = build_assertion_credential_full(
            &authenticator,
            &auth_challenge,
            1,
            ORIGIN,
            true,
            Flags::UP,
        );
        let err = finish_authentication(&pool, &config, &auth_token, user_id, assertion)
            .await
            .unwrap_err();
        assert!(matches!(err, WebauthnError::InvalidResponse));
    }

    #[tokio::test]
    async fn require_uv_rejects_a_user_present_only_assertion() {
        let pool = edda_db::test_pool().await;
        let config = Config {
            require_uv: true,
            ..test_config()
        };
        let user_id = insert_user(&pool, "uvuser").await;
        let authenticator = FakeAuthenticator::new();

        // Registration presents UP+UV so it's allowed to enrol.
        let (_, reg_token) = begin_registration(&pool, &config, user_id, "x", "x")
            .await
            .unwrap();
        let reg_challenge = verify_ceremony_token(&reg_token, Purpose::Register, user_id).unwrap();
        finish_registration(
            &pool,
            &config,
            &reg_token,
            user_id,
            "key",
            build_attestation_credential_full(
                &authenticator,
                &reg_challenge,
                ORIGIN,
                false,
                Flags::UP | Flags::UV,
            ),
        )
        .await
        .unwrap();

        // A UP-only assertion (no UV) is refused when the instance requires UV.
        let (_, auth_token) = begin_authentication(&pool, &config, user_id)
            .await
            .unwrap()
            .unwrap();
        let auth_challenge =
            verify_ceremony_token(&auth_token, Purpose::Authenticate, user_id).unwrap();
        let up_only = build_assertion_credential_full(
            &authenticator,
            &auth_challenge,
            1,
            ORIGIN,
            false,
            Flags::UP,
        );
        let err = finish_authentication(&pool, &config, &auth_token, user_id, up_only)
            .await
            .unwrap_err();
        assert!(matches!(err, WebauthnError::InvalidResponse));

        // The same assertion *with* UV set is accepted.
        let (_, auth_token2) = begin_authentication(&pool, &config, user_id)
            .await
            .unwrap()
            .unwrap();
        let auth_challenge2 =
            verify_ceremony_token(&auth_token2, Purpose::Authenticate, user_id).unwrap();
        let with_uv = build_assertion_credential_full(
            &authenticator,
            &auth_challenge2,
            2,
            ORIGIN,
            false,
            Flags::UP | Flags::UV,
        );
        finish_authentication(&pool, &config, &auth_token2, user_id, with_uv)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_credential_registered_with_one_algorithm_cannot_be_asserted_with_another() {
        let pool = edda_db::test_pool().await;
        let config = test_config();
        let user_id = insert_user(&pool, "algconfusion").await;

        let es256 = FakeAuthenticator::new();
        let (_, reg_token) = begin_registration(&pool, &config, user_id, "x", "x")
            .await
            .unwrap();
        let reg_challenge = verify_ceremony_token(&reg_token, Purpose::Register, user_id).unwrap();
        finish_registration(
            &pool,
            &config,
            &reg_token,
            user_id,
            "key",
            build_attestation_credential(&es256, &reg_challenge),
        )
        .await
        .unwrap();

        // Same credential id, but an Ed25519 keypair signing the assertion.
        let mut eddsa = FakeAuthenticator::new_eddsa();
        eddsa.credential_id = es256.credential_id.clone();
        let (_, auth_token) = begin_authentication(&pool, &config, user_id)
            .await
            .unwrap()
            .unwrap();
        let auth_challenge =
            verify_ceremony_token(&auth_token, Purpose::Authenticate, user_id).unwrap();
        let assertion = build_assertion_credential(&eddsa, &auth_challenge, 1);
        let err = finish_authentication(&pool, &config, &auth_token, user_id, assertion)
            .await
            .unwrap_err();
        assert!(matches!(err, WebauthnError::InvalidResponse));
    }

    // ===================================================================
    // Conformance-vector suite — CI-gated (`.github/workflows/ci.yml`).
    //
    // Each `tests/fixtures/webauthn/*.json` freezes one complete ceremony
    // at the byte level (the client's `clientDataJSON`, the authenticator's
    // `attestationObject` / `authenticatorData` + `signature`, the RP
    // config, and the expected accept/reject outcome). The consumer tests
    // below mint a fresh ceremony token for the fixture's challenge (the
    // token's HMAC secret is process-random, so it can't be checked in) and
    // then run the *real* `finish_registration` / `finish_authentication`
    // against the frozen bytes — so a future refactor of the CBOR parsing,
    // the multi-algorithm dispatch, or any check can't silently change what
    // this verifier accepts.
    //
    // The fixtures are (re)generated by `regenerate_conformance_fixtures`
    // below (`cargo test -p edda-auth -- --ignored regenerate_conformance`)
    // from the same `FakeAuthenticator` the unit tests use, with the RSA
    // key and the ES256/EdDSA seeds fixed so the output is deterministic
    // and reviewable in a diff. See `tests/fixtures/webauthn/README.md` for
    // where real browser/hardware-key captures slot in.
    // ===================================================================
    mod conformance {
        use super::*;
        use serde::Deserialize;

        const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/webauthn");

        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum Fixture {
            Registration(RegistrationFixture),
            Authentication(AuthenticationFixture),
        }

        #[derive(Deserialize)]
        struct RpConfig {
            rp_id: String,
            origin: String,
            #[serde(default)]
            require_uv: bool,
            #[serde(default)]
            allow_cross_origin: bool,
        }

        impl From<&RpConfig> for Config {
            fn from(c: &RpConfig) -> Self {
                Config {
                    rp_id: c.rp_id.clone(),
                    origin: c.origin.clone(),
                    require_uv: c.require_uv,
                    allow_cross_origin: c.allow_cross_origin,
                }
            }
        }

        #[derive(Deserialize)]
        struct RegistrationFixture {
            description: String,
            config: RpConfig,
            /// base64url — the challenge the fixture's `clientDataJSON`
            /// echoes; the test mints a matching ceremony token.
            challenge_b64: String,
            client_data_json_b64: String,
            attestation_object_b64: String,
            public_key_algorithm: i64,
            credential_id_b64: String,
            expect_accept: bool,
        }

        #[derive(Deserialize)]
        struct AuthenticationFixture {
            description: String,
            config: RpConfig,
            challenge_b64: String,
            client_data_json_b64: String,
            authenticator_data_b64: String,
            signature_b64: String,
            /// The credential row this assertion is checked against — the
            /// test pre-seeds it via `WebauthnRepo::insert`.
            stored_credential_id_b64: String,
            stored_public_key_b64: String,
            stored_alg: i64,
            stored_sign_count: u32,
            expect_accept: bool,
        }

        fn b64(s: &str) -> Vec<u8> {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s)
                .expect("fixture base64url decodes")
        }

        fn load_fixtures() -> Vec<(String, Fixture)> {
            let mut out = Vec::new();
            let dir = std::fs::read_dir(FIXTURE_DIR).expect("fixture dir exists");
            for entry in dir {
                let path = entry.unwrap().path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                let text = std::fs::read_to_string(&path).unwrap();
                let fixture: Fixture = serde_json::from_str(&text)
                    .unwrap_or_else(|e| panic!("fixture {name} is malformed: {e}"));
                out.push((name, fixture));
            }
            assert!(
                !out.is_empty(),
                "no conformance fixtures found in {FIXTURE_DIR}"
            );
            out.sort_by(|a, b| a.0.cmp(&b.0));
            out
        }

        #[tokio::test]
        async fn every_conformance_fixture_matches_its_expected_outcome() {
            let pool = edda_db::test_pool().await;
            for (name, fixture) in load_fixtures() {
                match fixture {
                    Fixture::Registration(f) => run_registration_fixture(&pool, &name, f).await,
                    Fixture::Authentication(f) => run_authentication_fixture(&pool, &name, f).await,
                }
            }
        }

        async fn run_registration_fixture(pool: &DbPool, name: &str, f: RegistrationFixture) {
            let config: Config = (&f.config).into();
            let user_id = super::insert_user(pool, &format!("fix_{}", sanitize(name))).await;
            let challenge = b64(&f.challenge_b64);
            let token = issue_ceremony_token(user_id, &challenge, Purpose::Register);

            let credential = PublicKeyCredential {
                id: f.credential_id_b64.clone(),
                raw_id: Bytes::from(b64(&f.credential_id_b64)),
                ty: PublicKeyCredentialType::PublicKey,
                response: AuthenticatorAttestationResponse {
                    client_data_json: Bytes::from(b64(&f.client_data_json_b64)),
                    authenticator_data: Bytes::from(Vec::new()),
                    public_key: None,
                    public_key_algorithm: f.public_key_algorithm,
                    attestation_object: Bytes::from(b64(&f.attestation_object_b64)),
                    transports: None,
                },
                authenticator_attachment: None,
                client_extension_results: Default::default(),
            };

            let result =
                finish_registration(pool, &config, &token, user_id, "fixture", credential).await;
            assert_eq!(
                result.is_ok(),
                f.expect_accept,
                "fixture {name} ({}): expected accept={}, got {result:?}",
                f.description,
                f.expect_accept
            );
        }

        async fn run_authentication_fixture(pool: &DbPool, name: &str, f: AuthenticationFixture) {
            let config: Config = (&f.config).into();
            let user_id = super::insert_user(pool, &format!("fix_{}", sanitize(name))).await;

            let stored = StoredCredential {
                credential_id: f.stored_credential_id_b64.clone(),
                public_key: f.stored_public_key_b64.clone(),
                alg: f.stored_alg,
                sign_count: f.stored_sign_count,
            };
            WebauthnRepo::insert(
                pool,
                WebauthnCredentialId::new(),
                user_id,
                "fixture",
                &serde_json::to_string(&stored).unwrap(),
            )
            .await
            .unwrap();

            let challenge = b64(&f.challenge_b64);
            let token = issue_ceremony_token(user_id, &challenge, Purpose::Authenticate);
            let credential = PublicKeyCredential {
                id: f.stored_credential_id_b64.clone(),
                raw_id: Bytes::from(b64(&f.stored_credential_id_b64)),
                ty: PublicKeyCredentialType::PublicKey,
                response: AuthenticatorAssertionResponse {
                    client_data_json: Bytes::from(b64(&f.client_data_json_b64)),
                    authenticator_data: Bytes::from(b64(&f.authenticator_data_b64)),
                    signature: Bytes::from(b64(&f.signature_b64)),
                    user_handle: None,
                    attestation_object: None,
                },
                authenticator_attachment: None,
                client_extension_results: Default::default(),
            };

            let result = finish_authentication(pool, &config, &token, user_id, credential).await;
            assert_eq!(
                result.is_ok(),
                f.expect_accept,
                "fixture {name} ({}): expected accept={}, got {result:?}",
                f.description,
                f.expect_accept
            );
        }

        fn sanitize(name: &str) -> String {
            name.chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect()
        }

        fn b64_encode(bytes: &[u8]) -> String {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        }

        fn alg_name(alg: i64) -> &'static str {
            match alg {
                COSE_ALG_ES256 => "ES256",
                COSE_ALG_EDDSA => "EdDSA",
                COSE_ALG_RS256 => "RS256",
                _ => "unknown",
            }
        }

        /// Regenerates every `tests/fixtures/webauthn/*.json` from the same
        /// `FakeAuthenticator` + `finish_registration` path the unit tests
        /// use, so each committed vector is a real ceremony this verifier
        /// produced *and then* accepted (or a byte-level mutation of one it
        /// then rejected). Not part of the normal run (`#[ignore]`); invoke
        /// deliberately after an intentional wire-shape change, then commit
        /// the diff:
        /// `cargo test -p edda-auth -- --ignored regenerate_conformance_fixtures`.
        ///
        /// ES256/EdDSA keys are random per run (RS256 is the fixed bundled
        /// key), so a regeneration churns the bytes — that's expected; the
        /// committed files are the artifact, not the RNG.
        #[tokio::test]
        #[ignore = "writes fixture files; run explicitly after a deliberate wire change"]
        async fn regenerate_conformance_fixtures() {
            std::fs::create_dir_all(FIXTURE_DIR).unwrap();
            for (label, authenticator) in [
                ("es256", FakeAuthenticator::new()),
                ("ed25519", FakeAuthenticator::new_eddsa()),
                ("rs256", FakeAuthenticator::new_rs256()),
            ] {
                let alg = authenticator.alg();
                let pool = edda_db::test_pool().await;
                let config = test_config();
                let user_id = super::insert_user(&pool, &format!("gen_{label}")).await;

                // A real registration: build → finish_registration → read
                // back exactly what got stored.
                let (_, reg_token) = begin_registration(&pool, &config, user_id, label, label)
                    .await
                    .unwrap();
                let reg_challenge =
                    verify_ceremony_token(&reg_token, Purpose::Register, user_id).unwrap();
                let reg_cred = build_attestation_credential_full(
                    &authenticator,
                    &reg_challenge,
                    ORIGIN,
                    false,
                    Flags::UP | Flags::UV,
                );
                let attestation_object_b64 = b64_encode(&reg_cred.response.attestation_object);
                let reg_client_data_b64 = b64_encode(&reg_cred.response.client_data_json);
                let credential_id_b64 = b64_encode(&authenticator.credential_id);
                finish_registration(&pool, &config, &reg_token, user_id, "gen", reg_cred)
                    .await
                    .expect("generator registration must be accepted");
                let stored_json = list(&pool, user_id).await.unwrap()[0].passkey_json.clone();
                let stored: StoredCredential = serde_json::from_str(&stored_json).unwrap();

                write_fixture(
                    &format!("register_{label}_accept"),
                    &serde_json::json!({
                        "kind": "registration",
                        "description": format!("{} registration, same-origin, UP+UV", alg_name(alg)),
                        "config": { "rp_id": RP_ID, "origin": ORIGIN },
                        "challenge_b64": b64_encode(&reg_challenge),
                        "client_data_json_b64": reg_client_data_b64,
                        "attestation_object_b64": attestation_object_b64,
                        "public_key_algorithm": alg,
                        "credential_id_b64": credential_id_b64,
                        "expect_accept": true,
                    }),
                );

                // The same registration bytes, but clientDataJSON says
                // crossOrigin: true — must be rejected.
                let xo_challenge = [3u8; 32];
                let xo_cred = build_attestation_credential_full(
                    &authenticator,
                    &xo_challenge,
                    ORIGIN,
                    true,
                    Flags::UP | Flags::UV,
                );
                write_fixture(
                    &format!("register_{label}_crossorigin_reject"),
                    &serde_json::json!({
                        "kind": "registration",
                        "description": format!("{} registration, crossOrigin=true", alg_name(alg)),
                        "config": { "rp_id": RP_ID, "origin": ORIGIN },
                        "challenge_b64": b64_encode(&xo_challenge),
                        "client_data_json_b64": b64_encode(&xo_cred.response.client_data_json),
                        "attestation_object_b64": b64_encode(&xo_cred.response.attestation_object),
                        "public_key_algorithm": alg,
                        "credential_id_b64": b64_encode(&authenticator.credential_id),
                        "expect_accept": false,
                    }),
                );

                // A real assertion, verified against the stored credential.
                let auth_challenge = [9u8; 32];
                let assertion = build_assertion_credential_full(
                    &authenticator,
                    &auth_challenge,
                    1,
                    ORIGIN,
                    false,
                    Flags::UP | Flags::UV,
                );
                let good_sig_b64 = b64_encode(&assertion.response.signature);
                let auth_data_b64 = b64_encode(&assertion.response.authenticator_data);
                let auth_client_data_b64 = b64_encode(&assertion.response.client_data_json);
                let base = serde_json::json!({
                    "kind": "authentication",
                    "config": { "rp_id": RP_ID, "origin": ORIGIN },
                    "challenge_b64": b64_encode(&auth_challenge),
                    "client_data_json_b64": auth_client_data_b64,
                    "authenticator_data_b64": auth_data_b64,
                    "stored_credential_id_b64": stored.credential_id,
                    "stored_public_key_b64": stored.public_key,
                    "stored_alg": stored.alg,
                    "stored_sign_count": 0,
                });
                let mut accept = base.clone();
                accept["description"] =
                    format!("{} assertion, valid signature", alg_name(alg)).into();
                accept["signature_b64"] = good_sig_b64.clone().into();
                accept["expect_accept"] = true.into();
                write_fixture(&format!("authenticate_{label}_accept"), &accept);

                let mut tampered = b64_decode(&good_sig_b64);
                *tampered.last_mut().unwrap() ^= 0xFF;
                let mut reject = base;
                reject["description"] =
                    format!("{} assertion, one signature byte flipped", alg_name(alg)).into();
                reject["signature_b64"] = b64_encode(&tampered).into();
                reject["expect_accept"] = false.into();
                write_fixture(&format!("authenticate_{label}_badsig_reject"), &reject);
            }
        }

        fn b64_decode(s: &str) -> Vec<u8> {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s)
                .unwrap()
        }

        fn write_fixture(name: &str, value: &serde_json::Value) {
            let path = format!("{FIXTURE_DIR}/{name}.json");
            std::fs::write(
                &path,
                format!("{}\n", serde_json::to_string_pretty(value).unwrap()),
            )
            .unwrap();
            eprintln!("wrote {path}");
        }
    }
}

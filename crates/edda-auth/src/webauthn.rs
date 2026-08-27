//! WebAuthn/passkey second factor: registration and authentication
//! ceremonies, built on `passkey-types` (WebAuthn JSON/CTAP2 types) +
//! `coset` (COSE key access) + `p256` (ES256 signature verification) — see
//! the workspace `Cargo.toml`'s WebAuthn dependency comment for why this
//! trio rather than `webauthn-rs`. None of those crates is an off-the-shelf
//! relying-party verifier (`passkey-rs` is built for WebAuthn
//! *clients*/authenticators), so everything below — challenge issuance,
//! origin/RP-ID/signature verification, sign-counter tracking — is this
//! module's own responsibility.
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
//! Only ES256 (P-256 ECDSA) credentials are supported — the algorithm this
//! module requests via `pub_key_cred_params`, and the only one
//! `finish_registration` will accept even if a non-conforming client
//! offers something else. This covers every mainstream platform
//! authenticator (Windows Hello, Touch ID, Android/Chrome) and FIDO2
//! security key; broader algorithm support (Ed25519, RS256) can be added
//! later without a schema change since `StoredCredential` isn't
//! algorithm-specific in its wire shape.
//!
//! Attestation is requested as `none` (this instance never asks for or
//! verifies an attestation trust chain — the credential's own public key,
//! trusted on first registration, is what every later assertion is
//! verified against, the same trust-on-first-use model GitHub/GitLab use
//! for WebAuthn) — so registration only needs to parse the *authenticator
//! data* out of the attestation object, never the attestation statement
//! itself.

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use coset::{iana, KeyType};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

/// The IANA COSE algorithm identifier for ES256 (ECDSA w/ SHA-256 over
/// P-256) — the only algorithm this module supports. See this module's own
/// doc comment for why.
const COSE_ALG_ES256: i64 = -7;

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
    Db(#[from] sqlx::Error),
}

/// This instance's Relying Party identity. `rp_id` is the registrable
/// domain every credential gets scoped to (e.g. `example.com`); `origin`
/// is the exact scheme+host(+port) a browser reports in `clientDataJSON`
/// (e.g. `https://example.com`). A mismatch on either fails every
/// ceremony, so there's no sensible partial default — an instance that
/// hasn't configured both simply doesn't offer WebAuthn. Constructed by
/// `edda_http::config` from `EDDA_WEBAUTHN_RP_ID`/`EDDA_WEBAUTHN_ORIGIN`
/// and passed in via `AppState`; this crate never reads the environment.
#[derive(Debug, Clone)]
pub struct Config {
    pub rp_id: String,
    pub origin: String,
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
    /// base64url, no padding — the SEC1 uncompressed point (`0x04 || X ||
    /// Y`) of the credential's ES256 (P-256) public key.
    public_key_sec1: String,
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

fn ceremony_secret() -> &'static [u8; 32] {
    static SECRET: OnceLock<[u8; 32]> = OnceLock::new();
    SECRET.get_or_init(|| {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        bytes
    })
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
        &EncodingKey::from_secret(ceremony_secret()),
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
        &DecodingKey::from_secret(ceremony_secret()),
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
        pub_key_cred_params: vec![PublicKeyCredentialParameters::from(iana::Algorithm::ES256)],
        timeout: None,
        exclude_credentials: (!exclude_credentials.is_empty()).then_some(exclude_credentials),
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
            authenticator_attachment: None,
            resident_key: None,
            require_resident_key: false,
            user_verification: UserVerificationRequirement::Preferred,
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
/// client's `clientDataJSON` claims type `webauthn.create`, echoes back
/// the exact challenge this ceremony issued, and reports this instance's
/// configured origin; the authenticator data's RP ID hash matches this
/// instance's `rp_id` and the user-present flag is set; the attested
/// credential's public key is a well-formed ES256 (P-256) key.
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
    if b64url_decode(&client_data.challenge)? != challenge {
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
    let Some(attested) = &auth_data.attested_credential_data else {
        return Err(WebauthnError::InvalidResponse);
    };

    if response.public_key_algorithm != COSE_ALG_ES256
        || attested.key.kty != KeyType::Assigned(iana::KeyType::EC2)
    {
        return Err(WebauthnError::InvalidResponse);
    }
    let public_key_sec1 = attested
        .key
        .to_sec1_octet_string()
        .map_err(|_| WebauthnError::InvalidResponse)?;
    // Validate it's actually a usable P-256 point now, rather than
    // deferring the failure to the first authentication attempt.
    VerifyingKey::from_sec1_bytes(&public_key_sec1).map_err(|_| WebauthnError::InvalidResponse)?;

    let stored = StoredCredential {
        credential_id: b64url_encode(attested.credential_id()),
        public_key_sec1: b64url_encode(&public_key_sec1),
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
        user_verification: UserVerificationRequirement::Preferred,
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
/// echoes back the exact challenge, and reports this instance's
/// configured origin; the authenticator data's RP ID hash matches and the
/// user-present flag is set; the signature over `authenticatorData ||
/// SHA-256(clientDataJSON)` verifies against the credential's stored
/// public key; the signature counter has not gone backwards (a cloned-
/// authenticator indicator) — unless neither side has ever reported a
/// nonzero counter, since many platform authenticators never implement
/// one. On success, updates the stored counter and `last_used_at`.
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
    if b64url_decode(&client_data.challenge)? != challenge {
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

    let public_key_bytes = b64url_decode(&stored.public_key_sec1)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
        .map_err(|_| WebauthnError::InvalidResponse)?;
    let signature =
        Signature::from_der(&response.signature).map_err(|_| WebauthnError::InvalidResponse)?;
    let client_data_hash = Sha256::digest(&*response.client_data_json);
    let mut signed_data = response.authenticator_data.to_vec();
    signed_data.extend_from_slice(&client_data_hash);
    verifying_key
        .verify(&signed_data, &signature)
        .map_err(|_| WebauthnError::InvalidResponse)?;

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
) -> Result<Vec<WebauthnCredentialRow>, sqlx::Error> {
    WebauthnRepo::list_for_user(pool, user_id).await
}

pub async fn revoke(
    pool: &DbPool,
    user_id: UserId,
    id: WebauthnCredentialId,
) -> Result<bool, sqlx::Error> {
    WebauthnRepo::delete(pool, user_id, id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake authenticator: holds a real P-256 keypair and can produce
    /// spec-shaped attestation/assertion byte payloads for it, so these
    /// tests exercise the real CBOR/signature verification path in
    /// `finish_registration`/`finish_authentication` without a browser.
    struct FakeAuthenticator {
        signing_key: p256::ecdsa::SigningKey,
        credential_id: Vec<u8>,
    }

    impl FakeAuthenticator {
        fn new() -> Self {
            let mut seed = [0u8; 32];
            rand::rng().fill(&mut seed);
            Self {
                signing_key: p256::ecdsa::SigningKey::from_slice(&seed).expect(
                    "a random 32-byte seed is a valid P-256 scalar with overwhelming probability",
                ),
                credential_id: {
                    let mut id = vec![0u8; 24];
                    rand::rng().fill(id.as_mut_slice());
                    id
                },
            }
        }

        fn cose_public_key(&self) -> coset::CoseKey {
            let point = self.signing_key.verifying_key().to_sec1_point(false);
            coset::CoseKeyBuilder::new_ec2_pub_key(
                iana::EllipticCurve::P_256,
                point.x().unwrap().to_vec(),
                point.y().unwrap().to_vec(),
            )
            .build()
        }

        /// Builds a raw `authenticatorData` byte string with attested
        /// credential data (as produced during registration).
        fn auth_data_for_registration(&self, rp_id: &str, counter: u32) -> Vec<u8> {
            let mut out = rp_id_hash(rp_id).to_vec();
            out.push((Flags::UP | Flags::AT).bits());
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(&[0u8; 16]); // AAGUID, zeroed (self attestation)
            out.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
            out.extend_from_slice(&self.credential_id);
            let mut key_bytes = Vec::new();
            ciborium_ser_into(&self.cose_public_key(), &mut key_bytes);
            out.extend_from_slice(&key_bytes);
            out
        }

        /// Builds a raw `authenticatorData` byte string with no attested
        /// credential data (as produced during authentication).
        fn auth_data_for_assertion(&self, rp_id: &str, counter: u32) -> Vec<u8> {
            let mut out = rp_id_hash(rp_id).to_vec();
            out.push(Flags::UP.bits());
            out.extend_from_slice(&counter.to_be_bytes());
            out
        }

        fn attestation_object(&self, rp_id: &str, counter: u32) -> Vec<u8> {
            let auth_data = self.auth_data_for_registration(rp_id, counter);
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
            use p256::ecdsa::signature::Signer;
            let signature: Signature = self.signing_key.sign(message);
            signature.to_der().as_ref().to_vec()
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
        }
    }

    fn client_data_json(ty: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type": ty,
            "challenge": b64url_encode(challenge),
            "origin": origin,
            "crossOrigin": false,
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
        let client_data_json = client_data_json("webauthn.create", challenge, ORIGIN);
        let attestation_object = authenticator.attestation_object(RP_ID, 0);
        PublicKeyCredential {
            id: b64url_encode(&authenticator.credential_id),
            raw_id: Bytes::from(authenticator.credential_id.clone()),
            ty: PublicKeyCredentialType::PublicKey,
            response: AuthenticatorAttestationResponse {
                client_data_json: Bytes::from(client_data_json),
                authenticator_data: Bytes::from(authenticator.auth_data_for_registration(RP_ID, 0)),
                public_key: None,
                public_key_algorithm: COSE_ALG_ES256,
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
        let client_data_json = client_data_json("webauthn.get", challenge, ORIGIN);
        let auth_data = authenticator.auth_data_for_assertion(RP_ID, counter);
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
}

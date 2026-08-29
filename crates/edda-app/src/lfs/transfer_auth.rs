//! Short-lived, HMAC-signed bearer tokens that authorize exactly one LFS
//! object transfer (one `(repo, oid, action)` triple), the way the Git LFS
//! batch API expects: a batch response hands the client a `href` plus an
//! `Authorization` header value to present back at that `href`, and the
//! server needs no session/cookie state to verify it — the token *is* the
//! authorization, scoped as narrowly as the one request it's for.
//!
//! The signing secret comes from `edda_auth::signing_keys` (HKDF over the
//! primary `EDDA_SECRET_KEYS` entry with an LFS-transfer `info` label, or a
//! per-process random fallback when no key is configured). A token is only
//! ever verified within the short window it was issued in
//! (`TRANSFER_TOKEN_TTL`) — in the fallback case a mid-transfer restart
//! invalidates outstanding tokens, which just makes the client retry the
//! batch call, not a correctness problem.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

const TRANSFER_TOKEN_TTL_SECONDS: u64 = 900;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferAction {
    Upload,
    Download,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    repo: String,
    oid: String,
    action: TransferAction,
    exp: u64,
}

fn secret() -> [u8; 32] {
    edda_auth::signing_keys::derive(edda_auth::signing_keys::LFS_TRANSFER)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs()
}

/// Mints a token authorizing `action` on `oid` within `repo` (the
/// `{owner}/{name}` identity), valid for `TRANSFER_TOKEN_TTL_SECONDS`.
pub fn issue(repo: &str, oid: &str, action: TransferAction) -> String {
    let claims = Claims {
        repo: repo.to_string(),
        oid: oid.to_string(),
        action,
        exp: now_unix() + TRANSFER_TOKEN_TTL_SECONDS,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&secret()),
    )
    .expect("HMAC signing over an in-memory struct never fails")
}

/// Verifies `token` authorizes `action` on `oid` within `repo` — checks
/// the signature, expiry (`jsonwebtoken`'s own default validation), and
/// that every claim matches the request it's presented against, not just
/// that it's *a* validly-signed token for *some* transfer.
pub fn verify(token: &str, repo: &str, oid: &str, action: TransferAction) -> bool {
    let validation = Validation::new(Algorithm::HS256);
    let Ok(data) = decode::<Claims>(token, &DecodingKey::from_secret(&secret()), &validation)
    else {
        return false;
    };
    data.claims.repo == repo && data.claims.oid == oid && data.claims.action == action
}

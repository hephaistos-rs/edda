//! The bridge between "password verified" and "session established" for
//! an account with an activated TOTP credential. `axum_login`'s
//! `AuthnBackend::authenticate` has no room for a "correct password, but
//! still need a second factor" intermediate state, and establishing the
//! session *is* what `authenticate` plus the route handler's
//! `auth.login(&user)` call do together — so this can't live inside
//! `Backend::authenticate` itself. Instead, the login route mints one of
//! these short-lived tokens after a correct password on a 2FA-enabled
//! account, and only completes the session on a second request presenting
//! a valid code plus this token.
//!
//! Same shape as `edda_app::lfs::transfer_auth`'s transfer tokens: HS256,
//! a short `exp`. The signing secret comes from `crate::signing_keys`
//! (HKDF over the primary `EDDA_SECRET_KEYS` entry, or a process-random
//! fallback when none is set), so with a key configured a restart no
//! longer drops an in-flight second-factor step.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

const PENDING_LOGIN_TTL_SECONDS: u64 = 300;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    user_id: String,
    exp: u64,
}

fn secret() -> [u8; 32] {
    crate::signing_keys::derive(crate::signing_keys::PENDING_LOGIN)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs()
}

/// Mints a token asserting "the password for `user_id` was already
/// verified," valid for `PENDING_LOGIN_TTL_SECONDS`.
pub fn issue(user_id: &str) -> String {
    let claims = Claims {
        user_id: user_id.to_string(),
        exp: now_unix() + PENDING_LOGIN_TTL_SECONDS,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&secret()),
    )
    .expect("HMAC signing over an in-memory struct never fails")
}

/// Recovers the user id a pending-login token was issued for, if it's
/// still validly signed and unexpired.
pub fn verify(token: &str) -> Option<String> {
    let validation = Validation::new(Algorithm::HS256);
    decode::<Claims>(token, &DecodingKey::from_secret(&secret()), &validation)
        .ok()
        .map(|data| data.claims.user_id)
}

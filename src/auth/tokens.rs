//! Personal access tokens: a git-CLI-friendly alternative to putting an
//! account password in `Authorization: Basic`. Revocable per-token, scoped
//! to nothing more than "acts as this user" for now — no per-token
//! permission scoping yet, matching the coarse trust level the rest of the
//! git-write path already assumes.

use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::Engine;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::auth::{AuthError, User};

const TOKEN_PREFIX: &str = "edda_pat_";

#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenInfo {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

fn generate_raw_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("{TOKEN_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Fast, not slow, on purpose — unlike a password, a 32-byte random token
/// already has 256 bits of entropy, so there's no low-entropy secret here
/// for a slow hash to protect against brute-forcing.
fn hash_token(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Creates a token for `user_id`. The raw token is returned once, here —
/// only its hash is ever stored, so this is the only chance to see it.
pub async fn create(pool: &SqlitePool, user_id: &str, name: &str) -> Result<(String, TokenInfo), AuthError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AuthError::Empty);
    }

    let raw = generate_raw_token();
    let token_hash = hash_token(&raw);
    let id = uuid::Uuid::now_v7().to_string();

    let row = sqlx::query!(
        "INSERT INTO tokens (id, user_id, name, token_hash) VALUES (?, ?, ?, ?) RETURNING created_at",
        id,
        user_id,
        name,
        token_hash
    )
    .fetch_one(pool)
    .await?;

    Ok((raw, TokenInfo { id, name: name.to_string(), created_at: row.created_at, last_used_at: None }))
}

pub async fn list(pool: &SqlitePool, user_id: &str) -> Result<Vec<TokenInfo>, AuthError> {
    let tokens = sqlx::query_as!(
        TokenInfo,
        "SELECT id, name, created_at, last_used_at FROM tokens WHERE user_id = ? ORDER BY created_at DESC",
        user_id
    )
    .fetch_all(pool)
    .await?;
    Ok(tokens)
}

/// `Ok(true)` if a token owned by `user_id` was revoked, `Ok(false)` if no
/// such token exists (already gone, wrong id, or — deliberately — owned by
/// someone else, which looks identical to "doesn't exist" from the outside).
pub async fn revoke(pool: &SqlitePool, user_id: &str, token_id: &str) -> Result<bool, AuthError> {
    let result = sqlx::query!("DELETE FROM tokens WHERE id = ? AND user_id = ?", token_id, user_id).execute(pool).await?;
    Ok(result.rows_affected() > 0)
}

/// Looks a raw token up by its hash and, if it matches, returns the user it
/// belongs to. Also best-effort records `last_used_at` — a failure to
/// record that shouldn't fail the authentication it's just accounting for.
pub async fn authenticate(pool: &SqlitePool, raw_token: &str) -> Option<User> {
    if !raw_token.starts_with(TOKEN_PREFIX) {
        return None;
    }
    let token_hash = hash_token(raw_token);

    let user = sqlx::query_as!(
        User,
        r#"SELECT users.id, users.username AS "username!", users.email, users.password_hash FROM users
         JOIN tokens ON tokens.user_id = users.id
         WHERE tokens.token_hash = ?"#,
        token_hash
    )
    .fetch_optional(pool)
    .await
    .ok()??;

    let _ = sqlx::query!("UPDATE tokens SET last_used_at = unixepoch() WHERE token_hash = ?", token_hash).execute(pool).await;

    Some(user)
}

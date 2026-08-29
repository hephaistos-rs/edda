//! Personal access tokens: a git-CLI-friendly alternative to putting an
//! account password in `Authorization: Basic`. A token carries two scope
//! axes — `RepositoryScope` (which repositories) and `TokenScope` (which
//! operations). [`create`] issues a fully-unscoped token (`All` on both);
//! [`create_scoped`] narrows the operation axis for a token-creation UI.

use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::Engine;
use sha2::{Digest, Sha256};

use edda_db::{AccessTokenRepo, DbPool};
use edda_domain::{AccessToken, AccessTokenId, RepositoryScope, TokenScope, User, UserId};

const TOKEN_PREFIX: &str = "edda_pat_";

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("token name can't be empty")]
    Empty,
    #[error(transparent)]
    Db(#[from] edda_db::DbError),
}

fn generate_raw_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!(
        "{TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Fast, not slow, on purpose — unlike a password, a 32-byte random token
/// already has 256 bits of entropy, so there's no low-entropy secret here
/// for a slow hash to protect against brute-forcing.
fn hash_token(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Creates a fully-unscoped token for `user_id` (`RepositoryScope::All` +
/// `TokenScope::All`) — every token issued before scopes existed.
pub async fn create(
    pool: &DbPool,
    user_id: UserId,
    name: &str,
) -> Result<(String, AccessToken), TokenError> {
    create_scoped(pool, user_id, name, TokenScope::All).await
}

/// Creates a token whose *operation* scope is `token_scope` (the
/// repository-set scope stays `All` — narrowing that is a later UI). The
/// raw token is returned once, here — only its hash is ever stored, so
/// this is the only chance to see it.
pub async fn create_scoped(
    pool: &DbPool,
    user_id: UserId,
    name: &str,
    token_scope: TokenScope,
) -> Result<(String, AccessToken), TokenError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(TokenError::Empty);
    }

    let raw = generate_raw_token();
    let token_hash = hash_token(&raw);
    let id = AccessTokenId::new();
    let repository_scope = RepositoryScope::All;

    let created_at = AccessTokenRepo::insert(
        pool,
        id,
        user_id,
        name,
        &token_hash,
        &repository_scope,
        token_scope,
    )
    .await?;
    Ok((
        raw,
        AccessToken {
            id,
            user_id,
            name: name.to_string(),
            repository_scope,
            token_scope,
            created_at,
            last_used_at: None,
        },
    ))
}

pub async fn list(pool: &DbPool, user_id: UserId) -> Result<Vec<AccessToken>, TokenError> {
    Ok(AccessTokenRepo::list_for_user(pool, user_id).await?)
}

pub async fn revoke(
    pool: &DbPool,
    user_id: UserId,
    token_id: AccessTokenId,
) -> Result<bool, TokenError> {
    Ok(AccessTokenRepo::revoke(pool, user_id, token_id).await?)
}

/// Looks a raw token up by its hash and, if it matches, returns the user
/// it belongs to and the token's two scope axes (repository-set +
/// operation).
pub async fn authenticate(
    pool: &DbPool,
    raw_token: &str,
) -> Option<(User, RepositoryScope, TokenScope)> {
    if !raw_token.starts_with(TOKEN_PREFIX) {
        return None;
    }
    let token_hash = hash_token(raw_token);
    let (user, repository_scope, token_scope) = AccessTokenRepo::find_by_hash(pool, &token_hash)
        .await
        .ok()
        .flatten()?;
    // Same "fails like an unknown credential, not a distinct error" reasoning
    // as `Backend::authenticate` — a disabled account's tokens simply stop
    // working, indistinguishable from a revoked/invalid token.
    crate::require_enabled(&user).ok()?;
    Some((user, repository_scope, token_scope))
}

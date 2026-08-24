use crate::access::RepositoryScope;
use crate::ids::{AccessTokenId, UserId};

/// A personal access token's identity and scope. The raw token secret
/// itself is never represented here — only its hash reaches `edda-db`,
/// and only `edda-auth` ever sees the raw value, and only once, at
/// creation (see `edda-auth::authn::tokens`).
#[derive(Debug, Clone)]
pub struct AccessToken {
    pub id: AccessTokenId,
    pub user_id: UserId,
    pub name: String,
    pub repository_scope: RepositoryScope,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

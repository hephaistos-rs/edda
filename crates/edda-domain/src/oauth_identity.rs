use crate::ids::{OAuthIdentityId, UserId};

/// A linked external OAuth2/OIDC identity — `provider` names which
/// configured provider issued it (an instance-config key, not a DB-stored
/// entity of its own: see `edda-auth::oauth`'s provider configuration),
/// `subject_id` is that provider's own immutable `sub` claim. Never
/// looked up or linked by email — see `edda-auth::oauth`'s
/// account-linking policy for why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthIdentity {
    pub id: OAuthIdentityId,
    pub user_id: UserId,
    pub provider: String,
    pub subject_id: String,
    pub created_at: i64,
}

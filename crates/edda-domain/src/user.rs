use crate::ids::UserId;

/// A user account's identity fields. Deliberately excludes `password_hash`
/// and any other authentication credential: those are `edda-auth`'s
/// concern (it fetches them from `edda-db` directly when verifying a
/// login), not something the rest of the domain — which only ever needs
/// to know *who* a user is, never how they prove it — should have to
/// carry around or accidentally serialize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub username: String,
    pub email: String,
    /// Instance-level administrator, distinct from any per-repository
    /// `RepoRole` — grants access to instance administration (user
    /// management, per `access::require_instance_admin`), not repository
    /// access. Never checked as an ad hoc `if user.is_admin` outside that
    /// function.
    pub is_admin: bool,
    /// When an administrator disabled this account, if ever. `None` means
    /// enabled. Checked by `edda_auth::authn` before a login (of any
    /// kind — password, token, SSH key, OAuth) succeeds. Deliberately
    /// does not force-invalidate an already-established session when
    /// set — only the *next* authentication attempt is refused, the same
    /// "takes effect on the next auth attempt, not live-connection-
    /// killing" behavior already used for revoking an SSH key or PAT.
    pub disabled_at: Option<i64>,
}

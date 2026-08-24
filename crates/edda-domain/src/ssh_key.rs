use crate::ids::{SshKeyId, UserId};

/// A registered SSH public key. Never carries private-key material — only
/// the public key (for display/audit) and its fingerprint (the actual
/// lookup key `edda-ssh`'s connection handler authenticates against).
#[derive(Debug, Clone)]
pub struct SshKey {
    pub id: SshKeyId,
    pub user_id: UserId,
    /// `SHA256:<base64>` form — the same format `ssh-keygen -lf` and every
    /// other real SSH tool prints, so a user comparing what they see in
    /// Edda's settings page against their own `ssh-add -l` output gets a
    /// value that actually matches.
    pub fingerprint: String,
    /// The full OpenSSH-format public key line (`ssh-ed25519 AAAA... title`),
    /// retained for display — the fingerprint alone doesn't let a user
    /// recognize *which* key is which beyond its title.
    pub public_key: String,
    pub title: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

use crate::ids::{DeployKeyId, RepositoryId};

/// An SSH public key that authenticates as one *repository* rather than a
/// user — for CI / automation that clones or pushes exactly one repo. Like
/// [`crate::SshKey`] it never carries private-key material.
#[derive(Debug, Clone)]
pub struct DeployKey {
    pub id: DeployKeyId,
    pub repository_id: RepositoryId,
    /// `SHA256:<base64>` form — the value every real SSH tool prints.
    pub fingerprint: String,
    /// The full OpenSSH-format public key line, retained for display.
    pub public_key: String,
    pub title: String,
    /// `true` → `git-upload-pack` only (clone/fetch); `false` → also
    /// `git-receive-pack` (push).
    pub read_only: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

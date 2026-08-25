//! SSH public-key authentication: fingerprinting, key registration, and
//! the fingerprint-to-user lookup `edda-ssh`'s connection handler
//! authenticates against. See this crate's `Cargo.toml` doc comment for
//! why `russh::keys` (not a standalone `ssh-key` dependency) is the type
//! used at this boundary.

use russh::keys::{HashAlg, PublicKey};

use edda_db::ssh_key_repo::InsertSshKeyError;
use edda_db::{DbPool, SshKeyRepo};
use edda_domain::{SshKey, SshKeyId, User, UserId};

#[derive(Debug, thiserror::Error)]
pub enum AddSshKeyError {
    #[error("key title can't be empty")]
    Empty,
    #[error("that doesn't look like a valid SSH public key")]
    InvalidKey,
    #[error("that key is already registered")]
    FingerprintTaken,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

impl From<InsertSshKeyError> for AddSshKeyError {
    fn from(err: InsertSshKeyError) -> Self {
        match err {
            InsertSshKeyError::FingerprintTaken => AddSshKeyError::FingerprintTaken,
            InsertSshKeyError::Db(err) => AddSshKeyError::Db(err),
        }
    }
}

/// The `SHA256:<base64>` form every real SSH tool (`ssh-keygen -lf`,
/// `ssh-add -l`) prints — used as both the stored lookup key and the
/// value a user can visually compare against their own tooling's output.
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// Parses and registers a new key for `user_id`. `public_key_openssh` is
/// the single-line OpenSSH format (`ssh-ed25519 AAAA... comment`) a user
/// pastes in from `~/.ssh/id_ed25519.pub` — parsing delegates entirely to
/// `russh::keys`' own OpenSSH-format parser — key-format parsing is not
/// hand-rolled here.
pub async fn add(
    pool: &DbPool,
    user_id: UserId,
    title: &str,
    public_key_openssh: &str,
) -> Result<SshKey, AddSshKeyError> {
    let title = title.trim();
    if title.is_empty() {
        return Err(AddSshKeyError::Empty);
    }
    let public_key_openssh = public_key_openssh.trim();
    let key =
        PublicKey::from_openssh(public_key_openssh).map_err(|_| AddSshKeyError::InvalidKey)?;
    let fp = fingerprint(&key);

    let id = SshKeyId::new();
    let created_at = SshKeyRepo::insert(pool, id, user_id, &fp, public_key_openssh, title).await?;
    Ok(SshKey {
        id,
        user_id,
        fingerprint: fp,
        public_key: public_key_openssh.to_string(),
        title: title.to_string(),
        created_at,
        last_used_at: None,
    })
}

pub async fn list(pool: &DbPool, user_id: UserId) -> Result<Vec<SshKey>, sqlx::Error> {
    SshKeyRepo::list_for_user(pool, user_id).await
}

pub async fn revoke(pool: &DbPool, user_id: UserId, key_id: SshKeyId) -> Result<bool, sqlx::Error> {
    SshKeyRepo::revoke(pool, user_id, key_id).await
}

/// Resolves an incoming SSH public key to the account it belongs to — the
/// entire authentication decision `edda-ssh`'s `Handler::auth_publickey`
/// delegates to. `None` for an unregistered key; the caller rejects the
/// same way regardless of *why* (unknown fingerprint vs. any other
/// reason), so this deliberately doesn't distinguish those cases.
pub async fn authenticate(pool: &DbPool, key: &PublicKey) -> Option<User> {
    let fp = fingerprint(key);
    SshKeyRepo::find_by_fingerprint(pool, &fp)
        .await
        .ok()
        .flatten()
}

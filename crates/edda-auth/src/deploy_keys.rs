//! Per-repository SSH deploy keys — the same "parse + fingerprint + look
//! up" shape as [`crate::ssh`], but the resolved identity is a repository
//! (with a read/write flag), not a user. `edda-ssh`'s `auth_publickey`
//! calls [`authenticate`] *after* [`crate::ssh::authenticate`] misses, so
//! a key that is registered as both a user key and a deploy key resolves
//! to the user.

use russh::keys::PublicKey;

use edda_db::deploy_key_repo::InsertDeployKeyError;
use edda_db::{DbPool, DeployKeyRepo};
use edda_domain::{DeployKey, DeployKeyId, RepositoryId};

use crate::ssh::fingerprint;

#[derive(Debug, thiserror::Error)]
pub enum AddDeployKeyError {
    #[error("key title can't be empty")]
    Empty,
    #[error("that doesn't look like a valid SSH public key")]
    InvalidKey,
    #[error("that key is already registered as a deploy key")]
    FingerprintTaken,
    #[error(transparent)]
    Db(#[from] edda_db::DbError),
}

impl From<InsertDeployKeyError> for AddDeployKeyError {
    fn from(err: InsertDeployKeyError) -> Self {
        match err {
            InsertDeployKeyError::FingerprintTaken => AddDeployKeyError::FingerprintTaken,
            InsertDeployKeyError::Db(err) => AddDeployKeyError::Db(err),
        }
    }
}

/// Parses and registers a deploy key on `repository_id`. `public_key_openssh`
/// is the single-line OpenSSH format a user pastes in; parsing delegates
/// entirely to `russh::keys`, the same as [`crate::ssh::add`].
pub async fn add(
    pool: &DbPool,
    repository_id: RepositoryId,
    title: &str,
    public_key_openssh: &str,
    read_only: bool,
) -> Result<DeployKey, AddDeployKeyError> {
    let title = title.trim();
    if title.is_empty() {
        return Err(AddDeployKeyError::Empty);
    }
    let public_key_openssh = public_key_openssh.trim();
    let key =
        PublicKey::from_openssh(public_key_openssh).map_err(|_| AddDeployKeyError::InvalidKey)?;
    let fp = fingerprint(&key);

    let id = DeployKeyId::new();
    let created_at = DeployKeyRepo::insert(
        pool,
        id,
        repository_id,
        &fp,
        public_key_openssh,
        title,
        read_only,
    )
    .await?;
    Ok(DeployKey {
        id,
        repository_id,
        fingerprint: fp,
        public_key: public_key_openssh.to_string(),
        title: title.to_string(),
        read_only,
        created_at,
        last_used_at: None,
    })
}

pub async fn list(
    pool: &DbPool,
    repository_id: RepositoryId,
) -> Result<Vec<DeployKey>, edda_db::DbError> {
    DeployKeyRepo::list_for_repository(pool, repository_id).await
}

pub async fn revoke(
    pool: &DbPool,
    repository_id: RepositoryId,
    key_id: DeployKeyId,
) -> Result<bool, edda_db::DbError> {
    DeployKeyRepo::revoke(pool, repository_id, key_id).await
}

/// What a deploy key authenticates as: one repository, with a read/write
/// limit.
#[derive(Debug, Clone, Copy)]
pub struct DeployKeyResolution {
    pub repository_id: RepositoryId,
    pub read_only: bool,
}

/// Resolves an incoming SSH public key to the repository it is a deploy
/// key for. `None` for an unregistered key.
pub async fn authenticate(pool: &DbPool, key: &PublicKey) -> Option<DeployKeyResolution> {
    let fp = fingerprint(key);
    let (repository_id, read_only) = DeployKeyRepo::find_by_fingerprint(pool, &fp).await.ok()??;
    Some(DeployKeyResolution {
        repository_id,
        read_only,
    })
}

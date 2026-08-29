//! `deploy_keys` persistence — the same shape as `ssh_key_repo`, but keyed
//! by `repository_id` instead of `user_id`, and carrying a `read_only`
//! flag. `edda_auth::deploy_keys` layers key parsing / fingerprinting on
//! top; `edda-ssh`'s `auth_publickey` consults `find_by_fingerprint` after
//! a user-key lookup misses.

use edda_domain::{DeployKey, DeployKeyId, RepositoryId};

use crate::{get_bool, get_i64, get_opt_i64, get_string, Backend, DbConn, DbError};

#[derive(Debug, thiserror::Error)]
pub enum InsertDeployKeyError {
    #[error("that key is already registered")]
    FingerprintTaken,
    #[error(transparent)]
    Db(#[from] DbError),
}

pub struct DeployKeyRepo;

impl DeployKeyRepo {
    #[allow(clippy::too_many_arguments)]
    pub async fn insert<'c>(
        db: impl DbConn<'c>,
        id: DeployKeyId,
        repository_id: RepositoryId,
        fingerprint: &str,
        public_key: &str,
        title: &str,
        read_only: bool,
    ) -> Result<i64, InsertDeployKeyError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let repo_id_text = repository_id.to_string();
        let created_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO deploy_keys (id, repository_id, fingerprint, public_key, title, read_only, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO deploy_keys (id, repository_id, fingerprint, public_key, title, read_only, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
            }
        };
        match sqlx::query(sql)
            .bind(&id_text)
            .bind(&repo_id_text)
            .bind(fingerprint)
            .bind(public_key)
            .bind(title)
            .bind(i64::from(read_only))
            .bind(created_at)
            .execute(&mut *h.conn())
            .await
            .map_err(DbError::from)
        {
            Ok(_) => Ok(created_at),
            Err(DbError::UniqueViolation) => Err(InsertDeployKeyError::FingerprintTaken),
            Err(err) => Err(InsertDeployKeyError::Db(err)),
        }
    }

    pub async fn list_for_repository<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
    ) -> Result<Vec<DeployKey>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let repo_id_text = repository_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, fingerprint, public_key, title, read_only, created_at, last_used_at FROM deploy_keys WHERE repository_id = $1 ORDER BY created_at DESC"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, fingerprint, public_key, title, read_only, created_at, last_used_at FROM deploy_keys WHERE repository_id = ? ORDER BY created_at DESC"
            }
        };
        let rows = sqlx::query(sql)
            .bind(&repo_id_text)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(DeployKey {
                    id: get_string(&row, "id")?
                        .parse()
                        .expect("stored deploy key id is a valid UUID"),
                    repository_id,
                    fingerprint: get_string(&row, "fingerprint")?,
                    public_key: get_string(&row, "public_key")?,
                    title: get_string(&row, "title")?,
                    read_only: get_bool(&row, "read_only")?,
                    created_at: get_i64(&row, "created_at")?,
                    last_used_at: get_opt_i64(&row, "last_used_at")?,
                })
            })
            .collect()
    }

    /// `Ok(true)` if a key belonging to `repository_id` was revoked —
    /// scoped to that repo, same information-hiding reasoning as
    /// `SshKeyRepo::revoke`.
    pub async fn revoke<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
        key_id: DeployKeyId,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let repo_id_text = repository_id.to_string();
        let key_id_text = key_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => "DELETE FROM deploy_keys WHERE id = $1 AND repository_id = $2",
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM deploy_keys WHERE id = ? AND repository_id = ?"
            }
        };
        let result = sqlx::query(sql)
            .bind(&key_id_text)
            .bind(&repo_id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Resolves a public key's fingerprint to the repository it grants
    /// access to, plus whether that access is read-only. Best-effort
    /// records `last_used_at`, same reasoning as `SshKeyRepo`.
    pub async fn find_by_fingerprint<'c>(
        db: impl DbConn<'c>,
        fingerprint: &str,
    ) -> Result<Option<(RepositoryId, bool)>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let select_sql = match h.backend() {
            Backend::Postgres => {
                "SELECT repository_id, read_only FROM deploy_keys WHERE fingerprint = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT repository_id, read_only FROM deploy_keys WHERE fingerprint = ?"
            }
        };
        let row = sqlx::query(select_sql)
            .bind(fingerprint)
            .fetch_optional(&mut *h.conn())
            .await?;
        let Some(row) = row else { return Ok(None) };

        let last_used_at = crate::now_unix();
        let update_sql = match h.backend() {
            Backend::Postgres => "UPDATE deploy_keys SET last_used_at = $1 WHERE fingerprint = $2",
            Backend::Sqlite | Backend::MySql => {
                "UPDATE deploy_keys SET last_used_at = ? WHERE fingerprint = ?"
            }
        };
        let _ = sqlx::query(update_sql)
            .bind(last_used_at)
            .bind(fingerprint)
            .execute(&mut *h.conn())
            .await;

        Ok(Some((
            get_string(&row, "repository_id")?
                .parse()
                .expect("stored repository id is a valid UUID"),
            get_bool(&row, "read_only")?,
        )))
    }
}

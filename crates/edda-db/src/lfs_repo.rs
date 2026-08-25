use edda_domain::{LfsLock, LfsLockId, LfsObject, RepositoryId, UserId};

use crate::{get_i64, get_string, Backend, DbPool};

#[derive(Debug, thiserror::Error)]
pub enum CreateLockError {
    #[error("\"{0}\" is already locked")]
    AlreadyLocked(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

pub struct LfsRepo;

impl LfsRepo {
    /// Looks up one content-addressed object by its `(repository_id, oid)`
    /// key — this is what the LFS batch API's "does this object already
    /// exist" check (skipping a redundant upload) and download-href
    /// resolution both boil down to.
    pub async fn find_object(
        pool: &DbPool,
        repository_id: RepositoryId,
        oid: &str,
    ) -> Result<Option<LfsObject>, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT oid, size_bytes, storage_key FROM lfs_objects WHERE repository_id = $1 AND oid = $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT oid, size_bytes, storage_key FROM lfs_objects WHERE repository_id = ? AND oid = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&repository_id_text)
            .bind(oid)
            .fetch_optional(&pool.any)
            .await?;
        row.map(|row| {
            Ok(LfsObject {
                repository_id,
                oid: get_string(&row, "oid")?,
                size_bytes: get_i64(&row, "size_bytes")?,
                storage_key: get_string(&row, "storage_key")?,
            })
        })
        .transpose()
    }

    /// Records a newly-stored object. Content-addressed objects are
    /// immutable — the same `(repository_id, oid)` always describes the
    /// same bytes — so a conflict here means the upload handler's own
    /// "does it already exist" check (via `find_object`) raced with
    /// another upload of the same object, not a real error; "ignore if it
    /// already exists" is the correct outcome either way.
    pub async fn insert_object(
        pool: &DbPool,
        repository_id: RepositoryId,
        oid: &str,
        size_bytes: i64,
        storage_key: &str,
    ) -> Result<(), sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let created_at = crate::now_unix();
        let sql = match pool.backend {
            Backend::Sqlite => {
                "INSERT OR IGNORE INTO lfs_objects (repository_id, oid, size_bytes, storage_key, created_at) VALUES (?, ?, ?, ?, ?)"
            }
            Backend::Postgres => {
                "INSERT INTO lfs_objects (repository_id, oid, size_bytes, storage_key, created_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING"
            }
            Backend::MySql => {
                "INSERT IGNORE INTO lfs_objects (repository_id, oid, size_bytes, storage_key, created_at) VALUES (?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(sql)
            .bind(&repository_id_text)
            .bind(oid)
            .bind(size_bytes)
            .bind(storage_key)
            .bind(created_at)
            .execute(&pool.any)
            .await?;
        Ok(())
    }

    pub async fn create_lock(
        pool: &DbPool,
        id: LfsLockId,
        repository_id: RepositoryId,
        path: &str,
        owner_id: UserId,
    ) -> Result<(), CreateLockError> {
        let id_text = id.to_string();
        let repository_id_text = repository_id.to_string();
        let owner_id_text = owner_id.to_string();
        let created_at = crate::now_unix();
        let sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO lfs_locks (id, repository_id, path, owner_id, created_at) VALUES ($1, $2, $3, $4, $5)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO lfs_locks (id, repository_id, path, owner_id, created_at) VALUES (?, ?, ?, ?, ?)"
            }
        };
        let result = sqlx::query(sql)
            .bind(&id_text)
            .bind(&repository_id_text)
            .bind(path)
            .bind(&owner_id_text)
            .bind(created_at)
            .execute(&pool.any)
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                Err(CreateLockError::AlreadyLocked(path.to_string()))
            }
            Err(err) => Err(CreateLockError::Db(err)),
        }
    }

    pub async fn find_lock_by_path(
        pool: &DbPool,
        repository_id: RepositoryId,
        path: &str,
    ) -> Result<Option<LfsLock>, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT id, repository_id, path, owner_id, created_at FROM lfs_locks WHERE repository_id = $1 AND path = $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, repository_id, path, owner_id, created_at FROM lfs_locks WHERE repository_id = ? AND path = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&repository_id_text)
            .bind(path)
            .fetch_optional(&pool.any)
            .await?;
        row.map(row_to_lock).transpose()
    }

    pub async fn find_lock_by_id(
        pool: &DbPool,
        id: LfsLockId,
    ) -> Result<Option<LfsLock>, sqlx::Error> {
        let id_text = id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT id, repository_id, path, owner_id, created_at FROM lfs_locks WHERE id = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, repository_id, path, owner_id, created_at FROM lfs_locks WHERE id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&id_text)
            .fetch_optional(&pool.any)
            .await?;
        row.map(row_to_lock).transpose()
    }

    pub async fn list_locks(
        pool: &DbPool,
        repository_id: RepositoryId,
    ) -> Result<Vec<LfsLock>, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT id, repository_id, path, owner_id, created_at FROM lfs_locks WHERE repository_id = $1 ORDER BY created_at"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, repository_id, path, owner_id, created_at FROM lfs_locks WHERE repository_id = ? ORDER BY created_at"
            }
        };
        let rows = sqlx::query(sql)
            .bind(&repository_id_text)
            .fetch_all(&pool.any)
            .await?;
        rows.into_iter().map(row_to_lock).collect()
    }

    /// `Ok(true)` if a lock was actually removed — the caller (the LFS
    /// unlock handler) is responsible for checking the lock's `owner_id`
    /// against the requesting actor (or that the actor holds `Owner`, for
    /// a force-unlock) before calling this; this method itself makes no
    /// authorization decision, matching every other repo in this crate.
    pub async fn delete_lock(pool: &DbPool, id: LfsLockId) -> Result<bool, sqlx::Error> {
        let id_text = id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => "DELETE FROM lfs_locks WHERE id = $1",
            Backend::Sqlite | Backend::MySql => "DELETE FROM lfs_locks WHERE id = ?",
        };
        let result = sqlx::query(sql).bind(&id_text).execute(&pool.any).await?;
        Ok(result.rows_affected() > 0)
    }
}

fn row_to_lock(row: sqlx::any::AnyRow) -> Result<LfsLock, sqlx::Error> {
    Ok(LfsLock {
        id: get_string(&row, "id")?
            .parse()
            .expect("stored lfs_locks id is a valid UUID"),
        repository_id: get_string(&row, "repository_id")?
            .parse()
            .expect("stored repository id is a valid UUID"),
        path: get_string(&row, "path")?,
        owner_id: get_string(&row, "owner_id")?
            .parse()
            .expect("stored user id is a valid UUID"),
        created_at: get_i64(&row, "created_at")?,
    })
}

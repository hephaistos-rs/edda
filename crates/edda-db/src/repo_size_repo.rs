//! `repo_sizes` persistence — one row per repository, (re)written by the
//! `UpdateRepoSize` job after a push and read by the receive path's quota
//! check.

use edda_domain::{RepoSize, RepositoryId};

use crate::{get_i64, Backend, DbConn, DbError};

pub struct RepoSizeRepo;

impl RepoSizeRepo {
    /// The recorded size for a repository, or `None` if it has never been
    /// measured (a brand-new repo, before its first `UpdateRepoSize` job).
    pub async fn get<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
    ) -> Result<Option<RepoSize>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT git_bytes, lfs_bytes, computed_at FROM repo_sizes WHERE repository_id = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT git_bytes, lfs_bytes, computed_at FROM repo_sizes WHERE repository_id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(repository_id.to_string())
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(|row| {
            Ok(RepoSize {
                repository_id,
                git_bytes: get_i64(&row, "git_bytes")?,
                lfs_bytes: get_i64(&row, "lfs_bytes")?,
                computed_at: get_i64(&row, "computed_at")?,
            })
        })
        .transpose()
    }

    /// Inserts or overwrites a repository's size row.
    pub async fn upsert<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
        git_bytes: i64,
        lfs_bytes: i64,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let repo_text = repository_id.to_string();
        let now = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO repo_sizes (repository_id, git_bytes, lfs_bytes, computed_at) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (repository_id) DO UPDATE \
                   SET git_bytes = $2, lfs_bytes = $3, computed_at = $4"
            }
            Backend::Sqlite => {
                "INSERT INTO repo_sizes (repository_id, git_bytes, lfs_bytes, computed_at) \
                 VALUES (?, ?, ?, ?) \
                 ON CONFLICT (repository_id) DO UPDATE \
                   SET git_bytes = excluded.git_bytes, lfs_bytes = excluded.lfs_bytes, \
                       computed_at = excluded.computed_at"
            }
            Backend::MySql => {
                "INSERT INTO repo_sizes (repository_id, git_bytes, lfs_bytes, computed_at) \
                 VALUES (?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE \
                   git_bytes = VALUES(git_bytes), lfs_bytes = VALUES(lfs_bytes), \
                   computed_at = VALUES(computed_at)"
            }
        };
        sqlx::query(sql)
            .bind(&repo_text)
            .bind(git_bytes)
            .bind(lfs_bytes)
            .bind(now)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }
}

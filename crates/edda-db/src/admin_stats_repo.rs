//! A one-shot snapshot of instance-wide counts for the admin "system
//! info" panel (Phase 12). Cheap `COUNT(*)` / `SUM` aggregates, run on
//! demand — not a metrics pipeline (that is `/metrics`, later in the
//! phase).

use crate::{get_i64, Backend, DbConn, DbError};

/// Instance-wide totals, all as of the moment [`AdminStatsRepo::snapshot`]
/// ran.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdminStats {
    pub users: i64,
    pub repositories: i64,
    pub organizations: i64,
    pub open_pull_requests: i64,
    pub open_issues: i64,
    /// Jobs waiting to run (`status = 'pending'`).
    pub pending_jobs: i64,
    /// Jobs that exhausted their retry budget (`status = 'failed'`).
    pub dead_jobs: i64,
    /// Sum of the last-measured git directory sizes across all
    /// repositories (`repo_sizes.git_bytes`); `0` before any
    /// `UpdateRepoSize` job has run.
    pub tracked_git_bytes: i64,
    pub tracked_lfs_bytes: i64,
}

pub struct AdminStatsRepo;

impl AdminStatsRepo {
    pub async fn snapshot<'c>(db: impl DbConn<'c>) -> Result<AdminStats, DbError> {
        let mut h = crate::conn::open(db).await?;
        let backend = h.backend();
        let conn = h.conn();

        async fn count(conn: &mut sqlx::AnyConnection, sql: &str) -> Result<i64, DbError> {
            let row = sqlx::query(sql).fetch_one(&mut *conn).await?;
            Ok(get_i64(&row, "n")?)
        }

        // `SUM` over a `BIGINT` column decodes as `NUMERIC`/`DECIMAL` on
        // Postgres and MySQL (not `i64`), so the aggregate is cast back to
        // an integer per dialect before it crosses `sqlx::Any`.
        let sum_col = |col: &str| match backend {
            Backend::Postgres => {
                format!("SELECT COALESCE(SUM({col}), 0)::bigint AS n FROM repo_sizes")
            }
            Backend::MySql => {
                format!("SELECT CAST(COALESCE(SUM({col}), 0) AS SIGNED) AS n FROM repo_sizes")
            }
            Backend::Sqlite => format!("SELECT COALESCE(SUM({col}), 0) AS n FROM repo_sizes"),
        };

        Ok(AdminStats {
            users: count(&mut *conn, "SELECT COUNT(*) AS n FROM users").await?,
            repositories: count(&mut *conn, "SELECT COUNT(*) AS n FROM repositories").await?,
            organizations: count(&mut *conn, "SELECT COUNT(*) AS n FROM organizations").await?,
            open_pull_requests: count(
                &mut *conn,
                "SELECT COUNT(*) AS n FROM pull_requests WHERE state IN ('open', 'draft')",
            )
            .await?,
            open_issues: count(
                &mut *conn,
                "SELECT COUNT(*) AS n FROM issues WHERE state = 'open'",
            )
            .await?,
            pending_jobs: count(
                &mut *conn,
                "SELECT COUNT(*) AS n FROM jobs WHERE status = 'pending'",
            )
            .await?,
            dead_jobs: count(
                &mut *conn,
                "SELECT COUNT(*) AS n FROM jobs WHERE status = 'failed'",
            )
            .await?,
            tracked_git_bytes: count(&mut *conn, &sum_col("git_bytes")).await?,
            tracked_lfs_bytes: count(&mut *conn, &sum_col("lfs_bytes")).await?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_fresh_instance_reports_all_zeros() {
        let pool = crate::test_pool().await;
        let stats = AdminStatsRepo::snapshot(&pool).await.unwrap();
        assert_eq!(stats, AdminStats::default());
    }

    #[tokio::test]
    async fn counts_reflect_inserted_rows() {
        let pool = crate::test_pool().await;
        let uid = edda_domain::UserId::new();
        crate::UserRepo::insert(&pool, uid, "alice", "a@example.com", "x")
            .await
            .unwrap();
        let repo = edda_domain::Repository {
            id: edda_domain::RepositoryId::new(),
            owner: edda_domain::RepositoryOwner::User(uid),
            name: "demo".to_string(),
            description: None,
            visibility: edda_domain::Visibility::Public,
            forked_from: None,
        };
        crate::RepositoryRepo::insert_with_owner(&pool, &repo, uid)
            .await
            .unwrap();

        let stats = AdminStatsRepo::snapshot(&pool).await.unwrap();
        assert_eq!(stats.users, 1);
        assert_eq!(stats.repositories, 1);
        assert_eq!(stats.organizations, 0);
    }
}

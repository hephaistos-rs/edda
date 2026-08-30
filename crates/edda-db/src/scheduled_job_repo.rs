//! `scheduled_jobs` persistence — the fixed-interval maintenance
//! scheduler's state (Phase 12). One row per periodic task: its interval,
//! when it is next due, and the outcome of its last run. `edda-jobs`'s
//! `spawn_scheduler` seeds the default rows on startup, polls
//! [`ScheduledJobRepo::due`], and stamps each run through
//! [`ScheduledJobRepo::mark_ran`]. The admin API exposes `list` /
//! `run_now` / `set_enabled`.

use crate::{get_bool, get_i64, get_opt_i64, get_opt_string, get_string, Backend, DbConn, DbError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledJob {
    pub name: String,
    pub interval_seconds: i64,
    pub enabled: bool,
    pub next_run_at: i64,
    pub last_run_at: Option<i64>,
    /// `"queued"` once the scheduler has enqueued the work, or a terminal
    /// status a later phase's handler might write back; `None` before the
    /// first run.
    pub last_status: Option<String>,
    pub last_detail: Option<String>,
}

fn row_to_job(row: &sqlx::any::AnyRow) -> Result<ScheduledJob, DbError> {
    Ok(ScheduledJob {
        name: get_string(row, "name")?,
        interval_seconds: get_i64(row, "interval_seconds")?,
        enabled: get_bool(row, "enabled")?,
        next_run_at: get_i64(row, "next_run_at")?,
        last_run_at: get_opt_i64(row, "last_run_at")?,
        last_status: get_opt_string(row, "last_status")?,
        last_detail: get_opt_string(row, "last_detail")?,
    })
}

pub struct ScheduledJobRepo;

impl ScheduledJobRepo {
    /// Inserts each `(name, interval_seconds)` task that has no row yet,
    /// due immediately (`next_run_at = 0`). An existing row — including
    /// one an admin has disabled or re-timed — is left untouched.
    pub async fn ensure_seeded<'c>(
        db: impl DbConn<'c>,
        tasks: &[(&str, i64)],
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let backend = h.backend();
        for (name, interval) in tasks {
            let sql = match backend {
                Backend::Postgres => {
                    "INSERT INTO scheduled_jobs (name, interval_seconds, enabled, next_run_at) \
                     VALUES ($1, $2, 1, 0) ON CONFLICT (name) DO NOTHING"
                }
                Backend::Sqlite => {
                    "INSERT INTO scheduled_jobs (name, interval_seconds, enabled, next_run_at) \
                     VALUES (?, ?, 1, 0) ON CONFLICT (name) DO NOTHING"
                }
                Backend::MySql => {
                    "INSERT IGNORE INTO scheduled_jobs (name, interval_seconds, enabled, next_run_at) \
                     VALUES (?, ?, 1, 0)"
                }
            };
            sqlx::query(sql)
                .bind(*name)
                .bind(*interval)
                .execute(&mut *h.conn())
                .await?;
        }
        Ok(())
    }

    /// Every scheduled task, name order — the admin list.
    pub async fn list<'c>(db: impl DbConn<'c>) -> Result<Vec<ScheduledJob>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let rows = sqlx::query(
            "SELECT name, interval_seconds, enabled, next_run_at, last_run_at, last_status, \
                    last_detail FROM scheduled_jobs ORDER BY name",
        )
        .fetch_all(&mut *h.conn())
        .await?;
        rows.iter().map(row_to_job).collect()
    }

    /// The enabled tasks whose `next_run_at` has passed — what the
    /// scheduler enqueues on each tick.
    pub async fn due<'c>(db: impl DbConn<'c>, now: i64) -> Result<Vec<ScheduledJob>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT name, interval_seconds, enabled, next_run_at, last_run_at, last_status, \
                        last_detail FROM scheduled_jobs WHERE enabled = 1 AND next_run_at <= $1 \
                 ORDER BY name"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT name, interval_seconds, enabled, next_run_at, last_run_at, last_status, \
                        last_detail FROM scheduled_jobs WHERE enabled = 1 AND next_run_at <= ? \
                 ORDER BY name"
            }
        };
        let rows = sqlx::query(sql).bind(now).fetch_all(&mut *h.conn()).await?;
        rows.iter().map(row_to_job).collect()
    }

    /// Records that `name` just ran: stamps `last_run_at` / `last_status`
    /// / `last_detail` and pushes `next_run_at` to `next_run_at`.
    pub async fn mark_ran<'c>(
        db: impl DbConn<'c>,
        name: &str,
        last_run_at: i64,
        next_run_at: i64,
        status: &str,
        detail: Option<&str>,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "UPDATE scheduled_jobs SET last_run_at = $1, next_run_at = $2, last_status = $3, \
                        last_detail = $4 WHERE name = $5"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE scheduled_jobs SET last_run_at = ?, next_run_at = ?, last_status = ?, \
                        last_detail = ? WHERE name = ?"
            }
        };
        sqlx::query(sql)
            .bind(last_run_at)
            .bind(next_run_at)
            .bind(status)
            .bind(detail)
            .bind(name)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// Admin action: make `name` due on the next scheduler tick. Returns
    /// whether the task exists.
    pub async fn run_now<'c>(db: impl DbConn<'c>, name: &str) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => "UPDATE scheduled_jobs SET next_run_at = 0 WHERE name = $1",
            Backend::Sqlite | Backend::MySql => {
                "UPDATE scheduled_jobs SET next_run_at = 0 WHERE name = ?"
            }
        };
        let affected = sqlx::query(sql)
            .bind(name)
            .execute(&mut *h.conn())
            .await?
            .rows_affected();
        Ok(affected > 0)
    }

    /// Admin action: enable or disable `name`. Returns whether the task
    /// exists.
    pub async fn set_enabled<'c>(
        db: impl DbConn<'c>,
        name: &str,
        enabled: bool,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => "UPDATE scheduled_jobs SET enabled = $1 WHERE name = $2",
            Backend::Sqlite | Backend::MySql => {
                "UPDATE scheduled_jobs SET enabled = ? WHERE name = ?"
            }
        };
        let affected = sqlx::query(sql)
            .bind(i64::from(enabled))
            .bind(name)
            .execute(&mut *h.conn())
            .await?
            .rows_affected();
        Ok(affected > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn seeding_is_idempotent_and_preserves_admin_edits() {
        let pool = crate::test_pool().await;
        ScheduledJobRepo::ensure_seeded(&pool, &[("prune_x", 3600), ("prune_y", 86400)])
            .await
            .unwrap();
        // An admin disables one and re-times it.
        assert!(ScheduledJobRepo::set_enabled(&pool, "prune_x", false)
            .await
            .unwrap());
        // A second seed with a different interval must not clobber it.
        ScheduledJobRepo::ensure_seeded(&pool, &[("prune_x", 60), ("prune_y", 86400)])
            .await
            .unwrap();

        let mut list = ScheduledJobRepo::list(&pool).await.unwrap();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(list.len(), 2);
        let prune_x = &list[0];
        assert_eq!(prune_x.name, "prune_x");
        assert_eq!(
            prune_x.interval_seconds, 3600,
            "the original interval stands"
        );
        assert!(!prune_x.enabled, "the admin's disable stands");
    }

    #[tokio::test]
    async fn due_returns_only_enabled_overdue_tasks_and_mark_ran_pushes_the_next_run() {
        let pool = crate::test_pool().await;
        ScheduledJobRepo::ensure_seeded(&pool, &[("a", 3600), ("b", 3600)])
            .await
            .unwrap();
        ScheduledJobRepo::set_enabled(&pool, "b", false)
            .await
            .unwrap();

        // Both seeded at next_run_at = 0, so `a` (enabled) is due, `b` is not.
        let due = ScheduledJobRepo::due(&pool, 1_000).await.unwrap();
        assert_eq!(
            due.iter().map(|j| j.name.as_str()).collect::<Vec<_>>(),
            ["a"]
        );

        ScheduledJobRepo::mark_ran(&pool, "a", 1_000, 1_000 + 3600, "queued", None)
            .await
            .unwrap();
        assert!(ScheduledJobRepo::due(&pool, 2_000)
            .await
            .unwrap()
            .is_empty());
        assert!(!ScheduledJobRepo::due(&pool, 1_000 + 3600 + 1)
            .await
            .unwrap()
            .is_empty());

        // `run_now` forces it due again immediately.
        assert!(ScheduledJobRepo::run_now(&pool, "a").await.unwrap());
        assert!(!ScheduledJobRepo::run_now(&pool, "nope").await.unwrap());
        assert_eq!(ScheduledJobRepo::due(&pool, 5).await.unwrap()[0].name, "a");
    }
}

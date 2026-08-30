//! The `jobs` table's persistence boundary — `edda-jobs`'s poller claims
//! and completes rows through this repo; it never issues SQL itself (SQL
//! stays inside `edda-db`, everywhere in this workspace).
//!
//! Claiming a batch is a compare-and-swap loop over individually-claimed
//! candidate rows (`UPDATE ... WHERE id = ? AND status = 'pending'`), not
//! a single `UPDATE ... RETURNING` — the same portable idiom
//! `RepoNumberRepo`/`apply_ref_update` already use, needed here because
//! MySQL has no `RETURNING` clause at all (not just an `sqlx::Any`
//! limitation the way MySQL's `TEXT`-decodes-as-`BLOB` quirk is).

use edda_domain::{JobId, JobPayload, JobRecord, JobStatus};

use crate::{get_i64, get_opt_string, get_string, Backend, DbConn, DbError};

fn payload_to_json(payload: &JobPayload) -> String {
    serde_json::to_string(payload).expect("JobPayload always serializes")
}

fn payload_from_json(json: &str) -> JobPayload {
    serde_json::from_str(json)
        .expect("stored job payload is valid JSON for a known JobPayload shape")
}

#[allow(clippy::too_many_arguments)]
fn row_to_record(
    id: String,
    payload_json: String,
    status: String,
    attempts: i64,
    max_attempts: i64,
    run_at: i64,
    last_error: Option<String>,
    created_at: i64,
) -> JobRecord {
    JobRecord {
        id: id.parse().expect("stored job id is a valid UUID"),
        payload: payload_from_json(&payload_json),
        status: JobStatus::from_db_str(&status).expect("stored job status is a known value"),
        attempts: attempts as u32,
        max_attempts: max_attempts as u32,
        run_at,
        last_error,
        created_at,
    }
}

pub struct JobRepo;

impl JobRepo {
    pub async fn enqueue<'c>(
        db: impl DbConn<'c>,
        id: JobId,
        payload: &JobPayload,
        run_at: i64,
        max_attempts: u32,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let payload_json = payload_to_json(payload);
        let created_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO jobs (id, payload, status, attempts, max_attempts, run_at, created_at)
                 VALUES ($1, $2, 'pending', 0, $3, $4, $5)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO jobs (id, payload, status, attempts, max_attempts, run_at, created_at)
                 VALUES (?, ?, 'pending', 0, ?, ?, ?)"
            }
        };
        sqlx::query(sql)
            .bind(&id_text)
            .bind(&payload_json)
            .bind(max_attempts as i64)
            .bind(run_at)
            .bind(created_at)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// Up to `limit` due (`run_at <= now`), still-`pending` jobs, each
    /// individually claimed (moved to `running`) before being returned —
    /// a job this call returns will never be handed to a second caller,
    /// even if two pollers ran concurrently (not a real deployment shape
    /// today, per this workspace's single-process positioning, but the
    /// claim is still correct if that ever changes).
    pub async fn claim_batch<'c>(
        db: impl DbConn<'c>,
        now: i64,
        limit: i64,
    ) -> Result<Vec<JobRecord>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let select_sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, payload, status, attempts, max_attempts, run_at, last_error, created_at
                 FROM jobs WHERE status = 'pending' AND run_at <= $1 ORDER BY run_at LIMIT $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, payload, status, attempts, max_attempts, run_at, last_error, created_at
                 FROM jobs WHERE status = 'pending' AND run_at <= ? ORDER BY run_at LIMIT ?"
            }
        };
        let candidates = sqlx::query(select_sql)
            .bind(now)
            .bind(limit)
            .fetch_all(&mut *h.conn())
            .await?;

        let claim_sql = match h.backend() {
            Backend::Postgres => {
                "UPDATE jobs SET status = 'running' WHERE id = $1 AND status = 'pending'"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE jobs SET status = 'running' WHERE id = ? AND status = 'pending'"
            }
        };

        let mut claimed = Vec::new();
        for row in candidates {
            let id = get_string(&row, "id")?;
            let result = sqlx::query(claim_sql)
                .bind(&id)
                .execute(&mut *h.conn())
                .await?;
            if result.rows_affected() > 0 {
                claimed.push(row_to_record(
                    id,
                    get_string(&row, "payload")?,
                    "running".to_string(),
                    get_i64(&row, "attempts")?,
                    get_i64(&row, "max_attempts")?,
                    get_i64(&row, "run_at")?,
                    get_opt_string(&row, "last_error")?,
                    get_i64(&row, "created_at")?,
                ));
            }
        }
        Ok(claimed)
    }

    pub async fn mark_succeeded<'c>(db: impl DbConn<'c>, id: JobId) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => "UPDATE jobs SET status = 'succeeded' WHERE id = $1",
            Backend::Sqlite | Backend::MySql => "UPDATE jobs SET status = 'succeeded' WHERE id = ?",
        };
        sqlx::query(sql)
            .bind(id.to_string())
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// Reschedules a failed attempt for retry (`status` back to
    /// `'pending'`, a fresh `run_at`, `attempts` incremented) — called
    /// when the caller's own `attempts + 1 < max_attempts` check says
    /// there's budget left; see `mark_dead` for the terminal case.
    pub async fn mark_retry<'c>(
        db: impl DbConn<'c>,
        id: JobId,
        attempts: u32,
        run_at: i64,
        error: &str,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "UPDATE jobs SET status = 'pending', attempts = $1, run_at = $2, last_error = $3 WHERE id = $4"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE jobs SET status = 'pending', attempts = ?, run_at = ?, last_error = ? WHERE id = ?"
            }
        };
        sqlx::query(sql)
            .bind(attempts as i64)
            .bind(run_at)
            .bind(error)
            .bind(id.to_string())
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// Terminal failure — `max_attempts` exhausted. The row is retained
    /// (`status = 'failed'`), visible as a dead letter in admin tooling,
    /// never silently dropped.
    pub async fn mark_dead<'c>(
        db: impl DbConn<'c>,
        id: JobId,
        attempts: u32,
        error: &str,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "UPDATE jobs SET status = 'failed', attempts = $1, last_error = $2 WHERE id = $3"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE jobs SET status = 'failed', attempts = ?, last_error = ? WHERE id = ?"
            }
        };
        sqlx::query(sql)
            .bind(attempts as i64)
            .bind(error)
            .bind(id.to_string())
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// Most recent `limit` jobs regardless of status, newest first — the
    /// admin-visible dead-letter/activity list.
    pub async fn list_recent<'c>(
        db: impl DbConn<'c>,
        limit: i64,
    ) -> Result<Vec<JobRecord>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, payload, status, attempts, max_attempts, run_at, last_error, created_at
                 FROM jobs ORDER BY created_at DESC LIMIT $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, payload, status, attempts, max_attempts, run_at, last_error, created_at
                 FROM jobs ORDER BY created_at DESC LIMIT ?"
            }
        };
        let rows = sqlx::query(sql)
            .bind(limit)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(row_to_record(
                    get_string(&row, "id")?,
                    get_string(&row, "payload")?,
                    get_string(&row, "status")?,
                    get_i64(&row, "attempts")?,
                    get_i64(&row, "max_attempts")?,
                    get_i64(&row, "run_at")?,
                    get_opt_string(&row, "last_error")?,
                    get_i64(&row, "created_at")?,
                ))
            })
            .collect()
    }

    /// The most recent `limit` jobs in one status, newest first — the
    /// admin dead-letter view passes `"failed"`.
    pub async fn list_by_status<'c>(
        db: impl DbConn<'c>,
        status: JobStatus,
        limit: i64,
    ) -> Result<Vec<JobRecord>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, payload, status, attempts, max_attempts, run_at, last_error, created_at
                 FROM jobs WHERE status = $1 ORDER BY created_at DESC LIMIT $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, payload, status, attempts, max_attempts, run_at, last_error, created_at
                 FROM jobs WHERE status = ? ORDER BY created_at DESC LIMIT ?"
            }
        };
        let rows = sqlx::query(sql)
            .bind(status.as_db_str())
            .bind(limit)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(row_to_record(
                    get_string(&row, "id")?,
                    get_string(&row, "payload")?,
                    get_string(&row, "status")?,
                    get_i64(&row, "attempts")?,
                    get_i64(&row, "max_attempts")?,
                    get_i64(&row, "run_at")?,
                    get_opt_string(&row, "last_error")?,
                    get_i64(&row, "created_at")?,
                ))
            })
            .collect()
    }

    /// How many jobs sit in each of `pending` / `running` / `failed` —
    /// the admin "system info" queue gauges. `succeeded` rows are not
    /// counted (they are historical, not backlog).
    pub async fn queue_depths<'c>(db: impl DbConn<'c>) -> Result<(i64, i64, i64), DbError> {
        let mut h = crate::conn::open(db).await?;
        let rows = sqlx::query(
            "SELECT status, COUNT(*) AS n FROM jobs \
             WHERE status IN ('pending', 'running', 'failed') GROUP BY status",
        )
        .fetch_all(&mut *h.conn())
        .await?;
        let (mut pending, mut running, mut failed) = (0, 0, 0);
        for row in &rows {
            match get_string(row, "status")?.as_str() {
                "pending" => pending = get_i64(row, "n")?,
                "running" => running = get_i64(row, "n")?,
                "failed" => failed = get_i64(row, "n")?,
                _ => {}
            }
        }
        Ok((pending, running, failed))
    }

    /// Admin action: return a dead-lettered (`failed`) job to the queue
    /// with a fresh retry budget, due now. No-op (returns `false`) for a
    /// job in any other state.
    pub async fn requeue<'c>(db: impl DbConn<'c>, id: JobId) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let now = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "UPDATE jobs SET status = 'pending', run_at = $1, attempts = 0, last_error = NULL \
                 WHERE id = $2 AND status = 'failed'"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE jobs SET status = 'pending', run_at = ?, attempts = 0, last_error = NULL \
                 WHERE id = ? AND status = 'failed'"
            }
        };
        let affected = sqlx::query(sql)
            .bind(now)
            .bind(id.to_string())
            .execute(&mut *h.conn())
            .await?
            .rows_affected();
        Ok(affected > 0)
    }

    /// The `run_at` of the oldest still-pending job, or `None` when the
    /// queue is empty — the `/metrics` "how far behind is the poller"
    /// gauge.
    pub async fn oldest_pending_run_at<'c>(db: impl DbConn<'c>) -> Result<Option<i64>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let row = sqlx::query("SELECT MIN(run_at) AS m FROM jobs WHERE status = 'pending'")
            .fetch_one(&mut *h.conn())
            .await?;
        Ok(crate::get_opt_i64(&row, "m")?)
    }

    /// Admin action: drop a job that isn't currently executing. Returns
    /// whether a row was removed (`false` if it was `running` or already
    /// gone).
    pub async fn delete<'c>(db: impl DbConn<'c>, id: JobId) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => "DELETE FROM jobs WHERE id = $1 AND status <> 'running'",
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM jobs WHERE id = ? AND status <> 'running'"
            }
        };
        let affected = sqlx::query(sql)
            .bind(id.to_string())
            .execute(&mut *h.conn())
            .await?
            .rows_affected();
        Ok(affected > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edda_domain::WebhookEvent;

    fn sample_payload() -> JobPayload {
        JobPayload::SendEmail {
            to_email: "a@example.com".to_string(),
            subject: "hi".to_string(),
            body_text: "hi".to_string(),
        }
    }

    #[tokio::test]
    async fn a_due_job_is_claimed_and_moved_to_running() {
        let pool = crate::test_pool().await;
        let id = JobId::new();
        JobRepo::enqueue(&pool, id, &sample_payload(), 0, 5)
            .await
            .unwrap();

        let claimed = JobRepo::claim_batch(&pool, 1, 10).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].id, id);
        assert_eq!(claimed[0].status, JobStatus::Running);

        // A second claim attempt sees nothing pending left.
        let again = JobRepo::claim_batch(&pool, 1, 10).await.unwrap();
        assert!(again.is_empty());
    }

    #[tokio::test]
    async fn a_future_job_is_not_claimed_yet() {
        let pool = crate::test_pool().await;
        let id = JobId::new();
        JobRepo::enqueue(&pool, id, &sample_payload(), 1_000_000, 5)
            .await
            .unwrap();

        let claimed = JobRepo::claim_batch(&pool, 0, 10).await.unwrap();
        assert!(claimed.is_empty());
    }

    #[tokio::test]
    async fn a_retried_job_becomes_claimable_again_at_its_new_run_at() {
        let pool = crate::test_pool().await;
        let id = JobId::new();
        JobRepo::enqueue(&pool, id, &sample_payload(), 0, 5)
            .await
            .unwrap();
        let claimed = JobRepo::claim_batch(&pool, 1, 10).await.unwrap();
        assert_eq!(claimed.len(), 1);

        JobRepo::mark_retry(&pool, id, 1, 50, "transient failure")
            .await
            .unwrap();

        assert!(JobRepo::claim_batch(&pool, 1, 10).await.unwrap().is_empty());
        let reclaimed = JobRepo::claim_batch(&pool, 50, 10).await.unwrap();
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].attempts, 1);
    }

    #[tokio::test]
    async fn a_dead_lettered_job_is_never_reclaimed_but_stays_listed() {
        let pool = crate::test_pool().await;
        let id = JobId::new();
        JobRepo::enqueue(&pool, id, &sample_payload(), 0, 1)
            .await
            .unwrap();
        JobRepo::claim_batch(&pool, 1, 10).await.unwrap();
        JobRepo::mark_dead(&pool, id, 1, "gave up").await.unwrap();

        assert!(JobRepo::claim_batch(&pool, 1_000_000, 10)
            .await
            .unwrap()
            .is_empty());
        let recent = JobRepo::list_recent(&pool, 10).await.unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].status, JobStatus::Failed);
        assert_eq!(recent[0].last_error.as_deref(), Some("gave up"));
    }

    #[tokio::test]
    async fn a_succeeded_job_round_trips_its_payload_shape() {
        let pool = crate::test_pool().await;
        let id = JobId::new();
        let payload = JobPayload::DeliverWebhook {
            webhook_id: edda_domain::WebhookId::new(),
            event: WebhookEvent::PullRequestMerged,
            payload_json: "{}".to_string(),
        };
        JobRepo::enqueue(&pool, id, &payload, 0, 5).await.unwrap();
        let claimed = JobRepo::claim_batch(&pool, 1, 10).await.unwrap();
        assert_eq!(claimed[0].payload, payload);
        JobRepo::mark_succeeded(&pool, id).await.unwrap();

        let recent = JobRepo::list_recent(&pool, 10).await.unwrap();
        assert_eq!(recent[0].status, JobStatus::Succeeded);
    }
}

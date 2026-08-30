//! The fixed-interval maintenance scheduler (Phase 12).
//!
//! A sibling of the poller and the dispatcher: a `tokio::spawn`ed loop
//! that, every tick, asks `edda_db::ScheduledJobRepo` which periodic
//! tasks have come due and turns each into an ordinary
//! [`JobPayload::RunMaintenance`] row for the poller to run. The
//! *schedule* lives here; the *work* is a job handler registered by the
//! composition root, same as every other handler (this crate never
//! touches `edda-auth` / the filesystem / an HTTP client — see the
//! `Cargo.toml` doc comment).
//!
//! The task set and their default cadences:
//!
//! | task | default interval |
//! |------|------------------|
//! | `prune_quarantine`         | hourly  |
//! | `session_gc`               | hourly  |
//! | `prune_webhook_deliveries` | daily   |
//! | `prune_expired_tokens`     | daily   |
//! | `sweep_repo_sizes`         | daily   |
//! | `optimize_database`        | daily   |
//! | `repo_gc_sweep`            | weekly  |
//!
//! An operator can disable a task or change its interval by editing its
//! `scheduled_jobs` row (via the admin API); re-seeding on the next
//! startup never overwrites an existing row.

use std::time::Duration;

use edda_db::{DbPool, ScheduledJobRepo};
use edda_domain::JobPayload;

const HOUR: i64 = 3_600;
const DAY: i64 = 86_400;
const WEEK: i64 = 7 * DAY;

/// `(task name, default interval in seconds)`. The name doubles as the
/// `RunMaintenance { task }` discriminant the handler dispatches on.
pub const DEFAULT_TASKS: &[(&str, i64)] = &[
    ("prune_quarantine", HOUR),
    ("session_gc", HOUR),
    ("prune_webhook_deliveries", DAY),
    ("prune_expired_tokens", DAY),
    ("sweep_repo_sizes", DAY),
    ("optimize_database", DAY),
    ("repo_gc_sweep", WEEK),
];

pub struct SchedulerConfig {
    /// How often to check for due tasks. Small relative to the task
    /// intervals — a task fires within one tick of its due time.
    pub tick_interval: Duration,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_secs(60),
        }
    }
}

/// Seeds the default `scheduled_jobs` rows (idempotent), then runs the
/// due-check loop on a new task. Returns its handle; like the poller, the
/// composition root holds it only for a clean shutdown.
pub fn spawn_scheduler(pool: DbPool, config: SchedulerConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(err) = ScheduledJobRepo::ensure_seeded(&pool, DEFAULT_TASKS).await {
            tracing::error!(error = %err, "could not seed the scheduled_jobs table; the scheduler is idle");
            return;
        }
        loop {
            tokio::time::sleep(config.tick_interval).await;
            if let Err(err) = run_due(&pool).await {
                tracing::error!(error = %err, "a scheduler tick failed; will retry next tick");
            }
        }
    })
}

/// One tick: enqueue a job for every due task and push its `next_run_at`.
/// Split out so a test can drive it directly.
pub(crate) async fn run_due(pool: &DbPool) -> Result<(), edda_db::DbError> {
    let now = crate::now_unix();
    for task in ScheduledJobRepo::due(pool, now).await? {
        crate::enqueue(
            pool,
            JobPayload::RunMaintenance {
                task: task.name.clone(),
            },
        )
        .await?;
        let next = now.saturating_add(task.interval_seconds.max(60));
        ScheduledJobRepo::mark_ran(pool, &task.name, now, next, "queued", None).await?;
        tracing::debug!(task = %task.name, next_run_at = next, "maintenance task enqueued");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use edda_domain::{JobKind, JobStatus};

    #[tokio::test]
    async fn a_tick_enqueues_one_job_per_due_task_and_reschedules_it() {
        let pool = edda_db::test_pool().await;
        ScheduledJobRepo::ensure_seeded(&pool, DEFAULT_TASKS)
            .await
            .unwrap();
        // Everything is seeded due (next_run_at = 0).
        run_due(&pool).await.unwrap();

        let jobs = edda_db::JobRepo::list_recent(&pool, 100).await.unwrap();
        assert_eq!(jobs.len(), DEFAULT_TASKS.len());
        assert!(
            jobs.iter()
                .all(|j| j.payload.kind() == JobKind::RunMaintenance
                    && j.status == JobStatus::Pending)
        );

        // Nothing is due on an immediate second tick — every row was
        // pushed forward.
        run_due(&pool).await.unwrap();
        let after = edda_db::JobRepo::list_recent(&pool, 100).await.unwrap();
        assert_eq!(after.len(), DEFAULT_TASKS.len(), "no new jobs");

        let listed = ScheduledJobRepo::list(&pool).await.unwrap();
        assert!(listed
            .iter()
            .all(|t| t.last_status.as_deref() == Some("queued") && t.next_run_at > 0));
    }
}

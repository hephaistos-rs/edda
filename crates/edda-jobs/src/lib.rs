//! The background-job poller: a hand-rolled
//! `tokio::spawn` + polling loop over `edda-db`'s `jobs` table, claimed via
//! `edda_db::JobRepo`'s compare-and-swap batch claim. This crate owns the
//! generic machinery — the handler-registration table, the poll/claim/
//! dispatch/retry loop, and (`dispatcher`) the `events` outbox → `jobs`
//! fan-out — never the handler *logic* itself ("send this webhook," "send
//! this email"), which needs `edda-auth`/an HTTP client and is registered
//! in from `edda-web`'s composition root instead (see this crate's
//! `Cargo.toml` doc comment for why the dependency has to run that
//! direction).

mod dispatcher;

pub use dispatcher::{spawn_dispatcher, DispatcherConfig};

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use rand::RngExt;
use tokio::sync::Semaphore;

use edda_db::{DbPool, EventRepo, JobRepo};
use edda_domain::{
    next_retry_at, DomainEvent, EventId, JobId, JobKind, JobPayload, JobRecord, RepositoryId,
    UserId,
};

pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
type Handler = Arc<dyn Fn(JobPayload) -> HandlerFuture + Send + Sync>;

/// A `HashMap<JobKind, Handler>` — a plain function-pointer map, not a
/// trait-object-per-job-kind hierarchy, since the set of job kinds is
/// small and closed.
#[derive(Default)]
pub struct HandlerRegistry {
    handlers: HashMap<JobKind, Handler>,
}

impl HandlerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<F, Fut>(&mut self, kind: JobKind, handler: F)
    where
        F: Fn(JobPayload) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let boxed: Handler =
            Arc::new(move |payload: JobPayload| -> HandlerFuture { Box::pin(handler(payload)) });
        self.handlers.insert(kind, boxed);
    }
}

pub(crate) const DEFAULT_MAX_ATTEMPTS: u32 = 5;

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs() as i64
}

fn jitter_unit() -> f64 {
    let mut buf = [0u8; 4];
    rand::rng().fill(&mut buf);
    (u32::from_le_bytes(buf) as f64) / (u32::MAX as f64)
}

/// Enqueues one job, due immediately, with this crate's default retry
/// budget. The narrow primitive a handler that itself needs to enqueue
/// follow-up work builds on (the outbox fan-out in `dispatcher` enqueues
/// through `JobRepo` directly, so its enqueue shares the event-claiming
/// transaction).
pub async fn enqueue(pool: &DbPool, payload: JobPayload) -> Result<(), edda_db::DbError> {
    let id = JobId::new();
    JobRepo::enqueue(pool, id, &payload, now_unix(), DEFAULT_MAX_ATTEMPTS).await
}

/// Records a completed `git push` for asynchronous fan-out: one
/// [`DomainEvent::BranchPushed`] per updated `refs/heads/*` ref, plus a
/// single `UpdateRepoSize` job — all in **one** transaction with the
/// event append, so a crash between the ref transaction and this call is
/// the only window that loses the fan-out, and a crash *during* this call
/// rolls the whole thing back to be retried by the caller.
///
/// The transport (git-HTTP or SSH) calls this after `run_receive_pack`
/// returns a non-empty applied-ref list. `updated_refs` entries are
/// `(full_ref_name, old_hex, new_hex)`; non-branch refs (tags) are
/// ignored here.
pub async fn record_push(
    pool: &DbPool,
    repository_id: RepositoryId,
    pusher_id: Option<UserId>,
    updated_refs: &[(String, String, String)],
) -> Result<(), edda_db::DbError> {
    let branch_refs: Vec<&(String, String, String)> = updated_refs
        .iter()
        .filter(|(name, _, _)| name.starts_with("refs/heads/"))
        .collect();
    if branch_refs.is_empty() {
        return Ok(());
    }

    let mut tx = pool.begin().await?;
    for (ref_name, old, new) in &branch_refs {
        EventRepo::append(
            &mut tx,
            EventId::new(),
            &DomainEvent::BranchPushed {
                repository_id,
                ref_name: (*ref_name).clone(),
                old: (*old).clone(),
                new: (*new).clone(),
                pusher_id,
            },
        )
        .await?;
    }
    JobRepo::enqueue(
        &mut tx,
        JobId::new(),
        &JobPayload::UpdateRepoSize { repository_id },
        now_unix(),
        DEFAULT_MAX_ATTEMPTS,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub struct PollerConfig {
    pub poll_interval: Duration,
    pub batch_size: i64,
    pub max_concurrent: usize,
}

impl Default for PollerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(5),
            batch_size: 20,
            max_concurrent: 8,
        }
    }
}

/// Starts the poll/claim/dispatch loop on a new task, returning its
/// handle (the composition root holds it only to let the process exit
/// cleanly on shutdown; the loop itself runs until the process ends).
/// Concurrency within one claimed batch is bounded by
/// `config.max_concurrent` (a `Semaphore`, not an unbounded `tokio::spawn`
/// loop), the same bounded-concurrency approach `edda-git`'s pack-building
/// path already uses.
pub fn spawn_poller(
    pool: DbPool,
    handlers: Arc<HandlerRegistry>,
    config: PollerConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));
        loop {
            tokio::time::sleep(config.poll_interval).await;
            let claimed = match JobRepo::claim_batch(&pool, now_unix(), config.batch_size).await {
                Ok(jobs) => jobs,
                Err(err) => {
                    tracing::error!(error = %err, "failed to claim a batch of due jobs");
                    continue;
                }
            };
            for job in claimed {
                let Ok(permit) = semaphore.clone().acquire_owned().await else {
                    break;
                };
                let pool = pool.clone();
                let handlers = handlers.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    run_one(&pool, &handlers, job).await;
                });
            }
        }
    })
}

async fn run_one(pool: &DbPool, handlers: &HandlerRegistry, job: JobRecord) {
    let kind = job.payload.kind();
    let id = job.id;
    let attempts = job.attempts;
    let max_attempts = job.max_attempts;
    let span = tracing::info_span!("jobs.run", job.id = %id, job.kind = kind.as_metric_label());
    let _guard = span.enter();

    let Some(handler) = handlers.handlers.get(&kind) else {
        tracing::error!(
            job.kind = kind.as_metric_label(),
            "no handler registered for this job kind"
        );
        let _ = JobRepo::mark_dead(pool, id, attempts, "no handler registered").await;
        return;
    };

    let start = std::time::Instant::now();
    let result = handler(job.payload).await;
    let elapsed = start.elapsed();
    let status = if result.is_ok() { "success" } else { "error" };
    edda_telemetry::metrics::record_job(kind.as_metric_label(), status, elapsed);

    match result {
        Ok(()) => {
            let _ = JobRepo::mark_succeeded(pool, id).await;
        }
        Err(err) => {
            let next_attempts = attempts + 1;
            if next_attempts >= max_attempts {
                tracing::warn!(job.id = %id, attempts = next_attempts, error = %err, "job exhausted its retry budget — dead-lettered");
                let _ = JobRepo::mark_dead(pool, id, next_attempts, &err).await;
            } else {
                let run_at = next_retry_at(next_attempts, jitter_unit(), now_unix());
                tracing::warn!(job.id = %id, attempts = next_attempts, error = %err, run_at, "job failed — scheduled for retry");
                let _ = JobRepo::mark_retry(pool, id, next_attempts, run_at, &err).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn record_push_appends_one_event_per_branch_and_a_single_size_job() {
        let pool = edda_db::test_pool().await;
        let alice = edda_domain::UserId::new();
        edda_db::UserRepo::insert(&pool, alice, "alice", "alice@example.com", "x")
            .await
            .unwrap();
        let repo = edda_domain::Repository {
            id: RepositoryId::new(),
            owner: edda_domain::RepositoryOwner::User(alice),
            name: "demo".to_string(),
            description: None,
            visibility: edda_domain::Visibility::Public,
            forked_from: None,
        };
        edda_db::RepositoryRepo::insert_with_owner(&pool, &repo, alice)
            .await
            .unwrap();

        record_push(
            &pool,
            repo.id,
            Some(alice),
            &[
                (
                    "refs/heads/main".to_string(),
                    "a".repeat(40),
                    "b".repeat(40),
                ),
                (
                    "refs/heads/feature".to_string(),
                    "0".repeat(40),
                    "c".repeat(40),
                ),
                // A tag update is not a branch — ignored.
                ("refs/tags/v1".to_string(), "0".repeat(40), "d".repeat(40)),
            ],
        )
        .await
        .unwrap();

        let events = edda_db::EventRepo::fetch_unprocessed(&pool, 10)
            .await
            .unwrap();
        assert_eq!(events.len(), 2, "one BranchPushed per refs/heads/* ref");
        assert!(events
            .iter()
            .all(|e| matches!(e.event, edda_domain::DomainEvent::BranchPushed { .. })));

        let jobs = JobRepo::claim_batch(&pool, now_unix(), 10).await.unwrap();
        assert_eq!(jobs.len(), 1);
        assert!(matches!(
            jobs[0].payload,
            JobPayload::UpdateRepoSize { repository_id } if repository_id == repo.id
        ));
    }

    #[tokio::test]
    async fn the_poller_runs_a_registered_handler_and_marks_the_job_succeeded() {
        let pool = edda_db::test_pool().await;
        enqueue(
            &pool,
            JobPayload::SendEmail {
                to_email: "a@example.com".to_string(),
                subject: "hi".to_string(),
                body_text: "hi".to_string(),
            },
        )
        .await
        .unwrap();

        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran_clone = ran.clone();
        let mut registry = HandlerRegistry::new();
        registry.register(JobKind::SendEmail, move |_payload| {
            let ran = ran_clone.clone();
            async move {
                ran.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        });

        let job = JobRepo::claim_batch(&pool, now_unix(), 10).await.unwrap();
        assert_eq!(job.len(), 1);
        run_one(&pool, &registry, job.into_iter().next().unwrap()).await;

        assert!(ran.load(std::sync::atomic::Ordering::SeqCst));
        let recent = JobRepo::list_recent(&pool, 10).await.unwrap();
        assert_eq!(recent[0].status, edda_domain::JobStatus::Succeeded);
    }

    #[tokio::test]
    async fn a_failing_handler_is_rescheduled_and_eventually_dead_lettered() {
        let pool = edda_db::test_pool().await;
        let id = JobId::new();
        JobRepo::enqueue(
            &pool,
            id,
            &JobPayload::SendEmail {
                to_email: "a@example.com".to_string(),
                subject: "hi".to_string(),
                body_text: "hi".to_string(),
            },
            0,
            1,
        )
        .await
        .unwrap();

        let mut registry = HandlerRegistry::new();
        registry.register(JobKind::SendEmail, |_payload| async {
            Err("boom".to_string())
        });

        let job = JobRepo::claim_batch(&pool, now_unix(), 10).await.unwrap();
        run_one(&pool, &registry, job.into_iter().next().unwrap()).await;

        // `max_attempts` was 1, so the single failure already exhausts it.
        let recent = JobRepo::list_recent(&pool, 10).await.unwrap();
        assert_eq!(recent[0].status, edda_domain::JobStatus::Failed);
        assert_eq!(recent[0].last_error.as_deref(), Some("boom"));
    }
}

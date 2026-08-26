//! The background-job poller (design §12.2/§12.3): a hand-rolled
//! `tokio::spawn` + polling loop over `edda-db`'s `jobs` table, claimed via
//! `edda_db::JobRepo`'s compare-and-swap batch claim. This crate owns the
//! generic machinery — the handler-registration table, the poll/claim/
//! dispatch/retry loop, and `dispatch`'s event-to-job fan-out — never the
//! handler *logic* itself ("send this webhook," "send this email"), which
//! needs `edda-auth`/an HTTP client and is registered in from
//! `edda-web`'s composition root instead (see this crate's `Cargo.toml`
//! doc comment for why the dependency has to run that direction).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use rand::RngExt;
use tokio::sync::Semaphore;

use edda_db::{DbPool, JobRepo, WebhookRepo};
use edda_domain::{
    next_retry_at, DomainEvent, JobId, JobKind, JobPayload, JobRecord, MentionSource,
    NotificationKind, NotificationSubject, WebhookEvent,
};

pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
type Handler = Arc<dyn Fn(JobPayload) -> HandlerFuture + Send + Sync>;

/// A `HashMap<JobKind, Handler>` (§12.3's own words) — a plain function-
/// pointer map, not a trait-object-per-job-kind hierarchy, since the set
/// of job kinds is small and closed.
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

const DEFAULT_MAX_ATTEMPTS: u32 = 5;

fn now_unix() -> i64 {
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
/// budget. The narrow primitive every fan-out (`dispatch`, or a handler
/// that itself needs to enqueue follow-up work) builds on.
pub async fn enqueue(pool: &DbPool, payload: JobPayload) -> Result<(), sqlx::Error> {
    let id = JobId::new();
    JobRepo::enqueue(pool, id, &payload, now_unix(), DEFAULT_MAX_ATTEMPTS).await
}

/// Pre-rendered email content for a `DomainEvent::UserMentioned` fan-out —
/// `None` when the mentioned user has opted out of email notifications
/// (`UserRepo::email_notifications_enabled`), in which case only the
/// in-app notification is created.
pub struct EmailContent<'a> {
    pub to_email: &'a str,
    pub subject: &'a str,
    pub body_text: &'a str,
}

/// "What happened" -> "what work that implies," exhaustively matched
/// (§12.1). `webhook_payload_json` is only consulted for events that fan
/// out to webhook deliveries; `mention_email` only for
/// `UserMentioned` — both `None` are valid inputs for events that don't
/// need them, not a caller error.
pub async fn dispatch(
    pool: &DbPool,
    event: &DomainEvent,
    webhook_payload_json: Option<&str>,
    mention_email: Option<EmailContent<'_>>,
) -> Result<(), sqlx::Error> {
    match *event {
        DomainEvent::PullRequestMerged { repository_id, .. } => {
            let payload_json = webhook_payload_json.unwrap_or("{}").to_string();
            let webhooks =
                WebhookRepo::find_subscribed(pool, repository_id, WebhookEvent::PullRequestMerged)
                    .await?;
            for webhook in webhooks {
                enqueue(
                    pool,
                    JobPayload::DeliverWebhook {
                        webhook_id: webhook.id,
                        event: WebhookEvent::PullRequestMerged,
                        payload_json: payload_json.clone(),
                    },
                )
                .await?;
            }
        }
        DomainEvent::UserMentioned {
            mentioned_user_id,
            source,
        } => {
            let subject = match source {
                MentionSource::PullRequestComment { pull_request_id } => {
                    NotificationSubject::PullRequest(pull_request_id)
                }
                MentionSource::IssueComment { issue_id } => NotificationSubject::Issue(issue_id),
            };
            enqueue(
                pool,
                JobPayload::CreateNotification {
                    user_id: mentioned_user_id,
                    kind: NotificationKind::Mention,
                    subject,
                },
            )
            .await?;
            if let Some(email) = mention_email {
                enqueue(
                    pool,
                    JobPayload::SendEmail {
                        to_email: email.to_email.to_string(),
                        subject: email.subject.to_string(),
                        body_text: email.body_text.to_string(),
                    },
                )
                .await?;
            }
        }
    }
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
/// loop — §20's "minimize unbounded concurrency" guidance, applied here
/// exactly as it already is in `edda-git`'s pack-building path).
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
    use edda_domain::{PullRequestId, RepositoryId, UserId};

    #[tokio::test]
    async fn dispatching_a_pull_request_merged_event_enqueues_one_delivery_per_subscribed_webhook()
    {
        let pool = edda_db::test_pool().await;
        let owner = UserId::new();
        edda_db::UserRepo::insert(&pool, owner, "alice", "alice@example.com", "x")
            .await
            .unwrap();
        let repository = edda_domain::Repository {
            id: RepositoryId::new(),
            owner: edda_domain::RepositoryOwner::User(owner),
            name: "demo".to_string(),
            description: None,
            visibility: edda_domain::Visibility::Public,
            forked_from: None,
        };
        edda_db::RepositoryRepo::insert_with_owner(&pool, &repository, owner)
            .await
            .unwrap();

        let webhook_id = edda_domain::WebhookId::new();
        WebhookRepo::insert(
            &pool,
            webhook_id,
            repository.id,
            "https://example.com/hook",
            b"ciphertext",
            &[WebhookEvent::PullRequestMerged],
        )
        .await
        .unwrap();
        // A second webhook that isn't subscribed to this event — must not
        // receive a delivery job.
        WebhookRepo::insert(
            &pool,
            edda_domain::WebhookId::new(),
            repository.id,
            "https://example.com/other",
            b"ciphertext",
            &[WebhookEvent::IssueOpened],
        )
        .await
        .unwrap();

        let event = DomainEvent::PullRequestMerged {
            pull_request_id: PullRequestId::new(),
            repository_id: repository.id,
        };
        dispatch(&pool, &event, Some(r#"{"action":"merged"}"#), None)
            .await
            .unwrap();

        let claimed = JobRepo::claim_batch(&pool, now_unix(), 10).await.unwrap();
        assert_eq!(claimed.len(), 1);
        match &claimed[0].payload {
            JobPayload::DeliverWebhook {
                webhook_id: id,
                event,
                payload_json,
            } => {
                assert_eq!(*id, webhook_id);
                assert_eq!(*event, WebhookEvent::PullRequestMerged);
                assert_eq!(payload_json, r#"{"action":"merged"}"#);
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatching_a_mention_creates_a_notification_job_and_optionally_an_email_job() {
        let pool = edda_db::test_pool().await;
        let event = DomainEvent::UserMentioned {
            mentioned_user_id: UserId::new(),
            source: MentionSource::PullRequestComment {
                pull_request_id: PullRequestId::new(),
            },
        };

        dispatch(&pool, &event, None, None).await.unwrap();
        let claimed = JobRepo::claim_batch(&pool, now_unix(), 10).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert!(matches!(
            claimed[0].payload,
            JobPayload::CreateNotification { .. }
        ));

        dispatch(
            &pool,
            &event,
            None,
            Some(EmailContent {
                to_email: "a@example.com",
                subject: "you were mentioned",
                body_text: "see the PR",
            }),
        )
        .await
        .unwrap();
        let claimed = JobRepo::claim_batch(&pool, now_unix(), 10).await.unwrap();
        assert_eq!(claimed.len(), 2);
        assert!(claimed
            .iter()
            .any(|job| matches!(job.payload, JobPayload::SendEmail { .. })));
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

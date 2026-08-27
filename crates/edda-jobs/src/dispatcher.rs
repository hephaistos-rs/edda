//! The event dispatcher: the `events` outbox → `jobs` bridge.
//!
//! [`spawn_dispatcher`] polls `EventRepo::fetch_unprocessed`, and for each
//! event opens **one** transaction that both claims the event
//! (`EventRepo::mark_processed`, a `WHERE processed_at IS NULL` CAS) and
//! enqueues the jobs it fans out to. So:
//!
//! - a crash between a service committing its state change and this task
//!   running does not lose the event — it is a committed `events` row,
//!   picked up on the next poll (the failure mode the old
//!   `dispatch`-immediately-after-commit call had);
//! - a crash *during* fan-out rolls back the claim and the enqueues
//!   together, so the event is retried whole, never half-processed;
//! - a second dispatcher (or a re-run after restart) that reaches an
//!   already-claimed event enqueues nothing — the CAS returns "not me".
//!
//! At-least-once fan-out + idempotent handlers (`WebhookDelivery` rows,
//! `NotificationRepo::insert_if_new`) = at-most-once *effect*.

use std::time::Duration;

use edda_db::{
    DbPool, EventRecord, EventRepo, JobRepo, OrganizationRepo, PullRequestRepo, RepositoryRepo,
    UserRepo, WebhookRepo,
};
use edda_domain::{
    DomainEvent, JobId, JobPayload, MentionSource, NotificationKind, NotificationSubject,
    RepositoryOwner, WebhookEvent,
};

use crate::{now_unix, DEFAULT_MAX_ATTEMPTS};

/// How often the dispatcher polls the outbox, and how many events it takes
/// per poll. The interval is shorter than the poller's (an event fanning
/// out to a webhook should not wait a full poller cycle *plus* a
/// dispatcher cycle before the delivery job even exists).
pub struct DispatcherConfig {
    pub poll_interval: Duration,
    pub batch_size: i64,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(2),
            batch_size: 50,
        }
    }
}

/// Starts the outbox-draining loop on a new task, returning its handle
/// (held by the composition root only so the process can exit cleanly).
/// Runs until the process ends.
pub fn spawn_dispatcher(pool: DbPool, config: DispatcherConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(config.poll_interval).await;
            let batch = match EventRepo::fetch_unprocessed(&pool, config.batch_size).await {
                Ok(batch) => batch,
                Err(err) => {
                    tracing::error!(error = %err, "event dispatcher: could not read the outbox backlog");
                    continue;
                }
            };
            for record in batch {
                if let Err(err) = process_one(&pool, &record).await {
                    tracing::error!(
                        event.id = %record.id,
                        event.kind = record.event.kind().as_db_str(),
                        error = %err,
                        "event dispatcher: fan-out failed; the event stays unprocessed for the next poll"
                    );
                }
            }
        }
    })
}

/// Claim one event and enqueue its fan-out atomically. Reads that *build*
/// the fan-out run first, outside the transaction — they are idempotent,
/// and keeping them out of the transaction keeps it short.
async fn process_one(pool: &DbPool, record: &EventRecord) -> Result<(), edda_db::DbError> {
    let payloads = fan_out(pool, &record.event).await?;

    let mut tx = pool.begin().await?;
    if !EventRepo::mark_processed(&mut tx, record.id).await? {
        // Another dispatcher already handled this one.
        tx.rollback().await?;
        return Ok(());
    }
    for payload in &payloads {
        JobRepo::enqueue(
            &mut tx,
            JobId::new(),
            payload,
            now_unix(),
            DEFAULT_MAX_ATTEMPTS,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// "What happened" → "what background work that implies," exhaustively
/// matched over `DomainEvent`. Returns the job payloads to enqueue;
/// `process_one` owns the transaction that persists them. An empty vec is
/// a valid outcome (no webhooks subscribed, the aggregate was since
/// deleted) — the event is still marked processed.
async fn fan_out(pool: &DbPool, event: &DomainEvent) -> Result<Vec<JobPayload>, edda_db::DbError> {
    match *event {
        DomainEvent::PullRequestMerged {
            pull_request_id,
            repository_id,
        } => {
            let webhooks =
                WebhookRepo::find_subscribed(pool, repository_id, WebhookEvent::PullRequestMerged)
                    .await?;
            if webhooks.is_empty() {
                return Ok(Vec::new());
            }
            let (Some(pr), Some(repo)) = (
                PullRequestRepo::find_by_id(pool, pull_request_id).await?,
                RepositoryRepo::find_by_id(pool, repository_id).await?,
            ) else {
                return Ok(Vec::new());
            };
            let owner = owner_display_name(pool, repo.owner).await?;
            let payload_json = serde_json::json!({
                "action": "merged",
                "repository": { "owner": owner, "name": repo.name },
                "pull_request": { "number": pr.number, "title": pr.title },
            })
            .to_string();
            Ok(webhooks
                .into_iter()
                .map(|webhook| JobPayload::DeliverWebhook {
                    webhook_id: webhook.id,
                    event: WebhookEvent::PullRequestMerged,
                    payload_json: payload_json.clone(),
                })
                .collect())
        }
        DomainEvent::UserMentioned {
            mentioned_user_id,
            mentioned_by_user_id,
            source,
        } => {
            let subject = match source {
                MentionSource::PullRequestComment { pull_request_id } => {
                    NotificationSubject::PullRequest(pull_request_id)
                }
                MentionSource::IssueComment { issue_id } => NotificationSubject::Issue(issue_id),
            };
            let mut jobs = vec![JobPayload::CreateNotification {
                user_id: mentioned_user_id,
                kind: NotificationKind::Mention,
                subject,
            }];

            let email_enabled = UserRepo::email_notifications_enabled(pool, mentioned_user_id)
                .await
                .unwrap_or(true);
            if email_enabled {
                if let Some(recipient) = UserRepo::find_by_id(pool, mentioned_user_id).await? {
                    let by = UserRepo::find_by_id(pool, mentioned_by_user_id)
                        .await?
                        .map_or_else(
                            || "Someone".to_string(),
                            |row| format!("@{}", row.user.username),
                        );
                    jobs.push(JobPayload::SendEmail {
                        to_email: recipient.user.email,
                        subject: "You were mentioned on Edda".to_string(),
                        body_text: format!("{by} mentioned you in a comment."),
                    });
                }
            }
            Ok(jobs)
        }
    }
}

/// A repository owner's `{owner}` display segment — a username or an
/// organization name. Falls back to the raw id if the owner row has since
/// been deleted (the webhook body is best-effort, not a place to fail the
/// whole fan-out).
async fn owner_display_name(
    pool: &DbPool,
    owner: RepositoryOwner,
) -> Result<String, edda_db::DbError> {
    Ok(match owner {
        RepositoryOwner::User(id) => UserRepo::find_by_id(pool, id)
            .await?
            .map_or_else(|| id.to_string(), |row| row.user.username),
        RepositoryOwner::Organization(id) => OrganizationRepo::find_by_id(pool, id)
            .await?
            .map_or_else(|| id.to_string(), |org| org.name),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use edda_domain::{
        EventId, PullRequestId, Repository, RepositoryId, UserId, Visibility, WebhookId,
    };

    async fn insert_user(pool: &DbPool, username: &str) -> UserId {
        let id = UserId::new();
        UserRepo::insert(pool, id, username, &format!("{username}@example.com"), "x")
            .await
            .unwrap();
        id
    }

    async fn insert_repo(pool: &DbPool, owner: UserId, name: &str) -> RepositoryId {
        let repository = Repository {
            id: RepositoryId::new(),
            owner: RepositoryOwner::User(owner),
            name: name.to_string(),
            description: None,
            visibility: Visibility::Public,
            forked_from: None,
        };
        RepositoryRepo::insert_with_owner(pool, &repository, owner)
            .await
            .unwrap();
        repository.id
    }

    /// The whole point of the outbox: a committed `events` row is fanned
    /// out even though nothing dispatched it at emit time. One delivery
    /// job per subscribed webhook, none for an unsubscribed one, and the
    /// event leaves the backlog.
    #[tokio::test]
    async fn a_pull_request_merged_event_fans_out_one_delivery_per_subscribed_webhook() {
        let pool = edda_db::test_pool().await;
        let owner = insert_user(&pool, "alice").await;
        let repo_id = insert_repo(&pool, owner, "demo").await;

        let subscribed = WebhookId::new();
        WebhookRepo::insert(
            &pool,
            subscribed,
            repo_id,
            "https://example.com/hook",
            b"ciphertext",
            &[WebhookEvent::PullRequestMerged],
        )
        .await
        .unwrap();
        WebhookRepo::insert(
            &pool,
            WebhookId::new(),
            repo_id,
            "https://example.com/other",
            b"ciphertext",
            &[WebhookEvent::IssueOpened],
        )
        .await
        .unwrap();

        // A merged PR to name in the body.
        let pr_id = PullRequestId::new();
        PullRequestRepo::insert(
            &pool,
            pr_id,
            repo_id,
            edda_db::NewPullRequest {
                title: "Add a thing",
                body: None,
                author_id: owner,
                source: &edda_domain::PrRef {
                    repository_id: repo_id,
                    branch: "feature".to_string(),
                },
                target: "main",
                draft: false,
            },
        )
        .await
        .unwrap();

        let event = DomainEvent::PullRequestMerged {
            pull_request_id: pr_id,
            repository_id: repo_id,
        };
        EventRepo::append(&pool, EventId::new(), &event)
            .await
            .unwrap();

        let record = &EventRepo::fetch_unprocessed(&pool, 10).await.unwrap()[0];
        process_one(&pool, record).await.unwrap();

        let claimed = JobRepo::claim_batch(&pool, now_unix(), 10).await.unwrap();
        assert_eq!(claimed.len(), 1);
        match &claimed[0].payload {
            JobPayload::DeliverWebhook {
                webhook_id,
                event,
                payload_json,
            } => {
                assert_eq!(*webhook_id, subscribed);
                assert_eq!(*event, WebhookEvent::PullRequestMerged);
                assert!(payload_json.contains("\"alice\""));
                assert!(payload_json.contains("Add a thing"));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
        assert!(EventRepo::fetch_unprocessed(&pool, 10)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn a_mention_event_fans_out_a_notification_and_an_email_when_enabled() {
        let pool = edda_db::test_pool().await;
        let commenter = insert_user(&pool, "carol").await;
        let mentioned = insert_user(&pool, "dave").await;

        let event = DomainEvent::UserMentioned {
            mentioned_user_id: mentioned,
            mentioned_by_user_id: commenter,
            source: MentionSource::PullRequestComment {
                pull_request_id: PullRequestId::new(),
            },
        };
        EventRepo::append(&pool, EventId::new(), &event)
            .await
            .unwrap();
        let record = &EventRepo::fetch_unprocessed(&pool, 10).await.unwrap()[0];
        process_one(&pool, record).await.unwrap();

        let claimed = JobRepo::claim_batch(&pool, now_unix(), 10).await.unwrap();
        assert_eq!(claimed.len(), 2);
        assert!(claimed
            .iter()
            .any(|job| matches!(job.payload, JobPayload::CreateNotification { .. })));
        let email = claimed
            .iter()
            .find_map(|job| match &job.payload {
                JobPayload::SendEmail {
                    to_email,
                    body_text,
                    ..
                } => Some((to_email.clone(), body_text.clone())),
                _ => None,
            })
            .expect("an email job");
        assert_eq!(email.0, "dave@example.com");
        assert!(email.1.contains("@carol"));
    }

    #[tokio::test]
    async fn a_mentioned_user_who_opted_out_of_email_gets_only_the_notification() {
        let pool = edda_db::test_pool().await;
        let commenter = insert_user(&pool, "erin").await;
        let mentioned = insert_user(&pool, "frank").await;
        UserRepo::set_email_notifications_enabled(&pool, mentioned, false)
            .await
            .unwrap();

        let event = DomainEvent::UserMentioned {
            mentioned_user_id: mentioned,
            mentioned_by_user_id: commenter,
            source: MentionSource::IssueComment {
                issue_id: edda_domain::IssueId::new(),
            },
        };
        EventRepo::append(&pool, EventId::new(), &event)
            .await
            .unwrap();
        let record = &EventRepo::fetch_unprocessed(&pool, 10).await.unwrap()[0];
        process_one(&pool, record).await.unwrap();

        let claimed = JobRepo::claim_batch(&pool, now_unix(), 10).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert!(matches!(
            claimed[0].payload,
            JobPayload::CreateNotification { .. }
        ));
    }

    /// Exactly-once: re-running `process_one` on an event a previous run
    /// already committed (the "process crashed after commit, restarted,
    /// and re-read the same batch" case) enqueues nothing further.
    #[tokio::test]
    async fn reprocessing_an_already_claimed_event_enqueues_nothing_more() {
        let pool = edda_db::test_pool().await;
        let mentioned = insert_user(&pool, "grace").await;
        let commenter = insert_user(&pool, "heidi").await;
        let event = DomainEvent::UserMentioned {
            mentioned_user_id: mentioned,
            mentioned_by_user_id: commenter,
            source: MentionSource::IssueComment {
                issue_id: edda_domain::IssueId::new(),
            },
        };
        EventRepo::append(&pool, EventId::new(), &event)
            .await
            .unwrap();
        let record = EventRepo::fetch_unprocessed(&pool, 10).await.unwrap()[0].clone();

        process_one(&pool, &record).await.unwrap();
        let first = JobRepo::claim_batch(&pool, now_unix(), 10).await.unwrap();
        assert_eq!(first.len(), 2);

        // Same record object, processed again — simulating a restart that
        // re-read a row already handled and committed by the prior run.
        process_one(&pool, &record).await.unwrap();
        let second = JobRepo::claim_batch(&pool, now_unix(), 10).await.unwrap();
        assert!(second.is_empty());
    }
}

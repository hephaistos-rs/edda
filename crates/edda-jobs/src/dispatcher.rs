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
    BranchProtectionRepo, DbPool, EventRecord, EventRepo, IssueAssigneeRepo, IssueRepo, JobRepo,
    OrganizationRepo, PrReviewRepo, PullRequestRepo, ReleaseRepo, RepositoryRepo, UserRepo,
    WatchRepo, WebhookRepo,
};
use edda_domain::{
    DomainEvent, JobId, JobPayload, MentionSource, NotificationKind, NotificationSubject,
    PullRequestId, RepositoryId, RepositoryOwner, UserId, WatchLevel, WatchSubject, WebhookEvent,
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
    match event {
        DomainEvent::PullRequestMerged {
            pull_request_id,
            repository_id,
        } => {
            let webhooks =
                WebhookRepo::find_subscribed(pool, *repository_id, WebhookEvent::PullRequestMerged)
                    .await?;
            let (Some(pr), Some(repo)) = (
                PullRequestRepo::find_by_id(pool, *pull_request_id).await?,
                RepositoryRepo::find_by_id(pool, *repository_id).await?,
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
            let mut jobs: Vec<JobPayload> = webhooks
                .into_iter()
                .map(|webhook| JobPayload::DeliverWebhook {
                    webhook_id: webhook.id,
                    event: WebhookEvent::PullRequestMerged,
                    payload_json: payload_json.clone(),
                })
                .collect();
            // The merging user is not carried on this (older) event, so
            // pass a nil actor — the PR author still gets notified, which
            // is the case that matters.
            jobs.extend(
                notify_watchers(
                    pool,
                    *repository_id,
                    NotificationSubject::PullRequest(*pull_request_id),
                    NotificationKind::PrMerged,
                    None,
                    &[pr.author_id],
                    "A pull request you follow was merged",
                    &format!("merged pull request #{}: {}", pr.number, pr.title),
                )
                .await?,
            );
            Ok(jobs)
        }
        DomainEvent::UserMentioned {
            mentioned_user_id,
            mentioned_by_user_id,
            source,
        } => {
            let subject = match source {
                MentionSource::PullRequestComment { pull_request_id } => {
                    NotificationSubject::PullRequest(*pull_request_id)
                }
                MentionSource::IssueComment { issue_id } => NotificationSubject::Issue(*issue_id),
            };
            let mut jobs = vec![JobPayload::CreateNotification {
                user_id: *mentioned_user_id,
                kind: NotificationKind::Mention,
                subject,
            }];

            let email_enabled = UserRepo::email_notifications_enabled(pool, *mentioned_user_id)
                .await
                .unwrap_or(true);
            if email_enabled {
                if let Some(recipient) = UserRepo::find_by_id(pool, *mentioned_user_id).await? {
                    let by = UserRepo::find_by_id(pool, *mentioned_by_user_id)
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
        DomainEvent::BranchPushed {
            repository_id,
            ref_name,
            old,
            new,
            ..
        } => fan_out_branch_pushed(pool, *repository_id, ref_name, old, new).await,
        DomainEvent::IssueAssigned {
            issue_id,
            assignee_id,
            assigned_by_id,
            ..
        } => {
            let (number, title) = IssueRepo::find_by_id(pool, *issue_id)
                .await?
                .map_or((0, String::new()), |issue| (issue.number, issue.title));
            Ok(notify(
                pool,
                *assignee_id,
                Some(*assigned_by_id),
                NotificationKind::IssueAssigned,
                NotificationSubject::Issue(*issue_id),
                "You were assigned an issue on Edda",
                &format!("assigned you issue #{number}: {title}"),
            )
            .await)
        }
        DomainEvent::ReviewRequested {
            pull_request_id,
            reviewer_id,
            requested_by_id,
            ..
        } => {
            let number = PullRequestRepo::find_by_id(pool, *pull_request_id)
                .await?
                .map_or(0, |pr| pr.number);
            Ok(notify(
                pool,
                *reviewer_id,
                Some(*requested_by_id),
                NotificationKind::PrReviewRequested,
                NotificationSubject::PullRequest(*pull_request_id),
                "Your review was requested on Edda",
                &format!("requested your review on pull request #{number}"),
            )
            .await)
        }
        DomainEvent::IssueOpened {
            issue_id,
            repository_id,
            opened_by_id,
        } => {
            issue_activity(
                pool,
                *issue_id,
                *repository_id,
                *opened_by_id,
                WebhookEvent::IssueOpened,
                "opened",
                None,
            )
            .await
        }
        DomainEvent::IssueCommented {
            issue_id,
            repository_id,
            comment_author_id,
        } => {
            issue_activity(
                pool,
                *issue_id,
                *repository_id,
                *comment_author_id,
                WebhookEvent::IssueCommented,
                "commented on",
                None,
            )
            .await
        }
        DomainEvent::IssueClosed {
            issue_id,
            repository_id,
            closed_by_id,
            via_pull_request,
        } => {
            let via = match via_pull_request {
                Some(pr_id) => PullRequestRepo::find_by_id(pool, *pr_id)
                    .await?
                    .map(|pr| format!(" via pull request #{}", pr.number))
                    .unwrap_or_default(),
                None => String::new(),
            };
            issue_activity(
                pool,
                *issue_id,
                *repository_id,
                *closed_by_id,
                WebhookEvent::IssueClosed,
                &format!("closed{via}"),
                Some((
                    NotificationKind::IssueClosed,
                    "An issue you follow was closed",
                )),
            )
            .await
        }
        DomainEvent::PullRequestOpened {
            pull_request_id,
            repository_id,
            opened_by_id,
        } => {
            pr_activity(
                pool,
                *pull_request_id,
                *repository_id,
                *opened_by_id,
                Some(WebhookEvent::PullRequestOpened),
                "opened",
                None,
            )
            .await
        }
        DomainEvent::PullRequestClosed {
            pull_request_id,
            repository_id,
            closed_by_id,
        } => {
            pr_activity(
                pool,
                *pull_request_id,
                *repository_id,
                *closed_by_id,
                Some(WebhookEvent::PullRequestClosed),
                "closed",
                Some((
                    NotificationKind::PrClosed,
                    "A pull request you follow was closed",
                )),
            )
            .await
        }
        DomainEvent::PullRequestReopened {
            pull_request_id,
            repository_id,
            reopened_by_id,
        } => {
            pr_activity(
                pool,
                *pull_request_id,
                *repository_id,
                *reopened_by_id,
                Some(WebhookEvent::PullRequestReopened),
                "reopened",
                None,
            )
            .await
        }
        DomainEvent::PullRequestReviewSubmitted {
            pull_request_id,
            repository_id,
            reviewer_id,
            state,
        } => {
            pr_activity(
                pool,
                *pull_request_id,
                *repository_id,
                *reviewer_id,
                Some(WebhookEvent::PullRequestReviewSubmitted),
                &format!("submitted a {} review on", state.as_db_str()),
                None,
            )
            .await
        }
        DomainEvent::ReleasePublished {
            release_id,
            repository_id,
            published_by_id,
        } => release_activity(pool, *release_id, *repository_id, *published_by_id).await,
    }
}

/// Everyone who should be notified of activity on a repository's issue or
/// pull request: the repository's `watching` subscribers plus the
/// `involved` set (the entity's author, its assignees), minus anyone
/// `ignoring` the repository and minus the actor who did the thing.
#[allow(clippy::too_many_arguments)]
async fn notify_watchers(
    pool: &DbPool,
    repository_id: RepositoryId,
    subject: NotificationSubject,
    kind: NotificationKind,
    actor_id: Option<UserId>,
    involved: &[UserId],
    email_subject: &str,
    action: &str,
) -> Result<Vec<JobPayload>, edda_db::DbError> {
    let watches = WatchRepo::watchers_of(pool, WatchSubject::Repository(repository_id)).await?;
    let ignoring: std::collections::HashSet<UserId> = watches
        .iter()
        .filter(|w| w.level == WatchLevel::Ignoring)
        .map(|w| w.user_id)
        .collect();
    let mut recipients: Vec<UserId> = watches
        .iter()
        .filter(|w| w.level == WatchLevel::Watching)
        .map(|w| w.user_id)
        .chain(involved.iter().copied())
        .filter(|id| Some(*id) != actor_id && !ignoring.contains(id))
        .collect();
    recipients.sort_unstable();
    recipients.dedup();

    let mut jobs = Vec::new();
    for recipient in recipients {
        jobs.extend(
            notify(
                pool,
                recipient,
                actor_id,
                kind,
                subject,
                email_subject,
                action,
            )
            .await,
        );
    }
    Ok(jobs)
}

/// Fan an issue lifecycle event out to the `issue.*` webhook and — when
/// `notification` is `Some` — to repository watchers, the issue author,
/// and its assignees. `action` is the verb fragment for both the webhook
/// `action` field and the notification line ("opened", "closed", …).
async fn issue_activity(
    pool: &DbPool,
    issue_id: edda_domain::IssueId,
    repository_id: RepositoryId,
    actor_id: UserId,
    webhook_event: WebhookEvent,
    action: &str,
    notification: Option<(NotificationKind, &str)>,
) -> Result<Vec<JobPayload>, edda_db::DbError> {
    let (Some(issue), Some(repo)) = (
        IssueRepo::find_by_id(pool, issue_id).await?,
        RepositoryRepo::find_by_id(pool, repository_id).await?,
    ) else {
        return Ok(Vec::new());
    };
    let owner = owner_display_name(pool, repo.owner).await?;

    let mut jobs = Vec::new();
    let webhooks = WebhookRepo::find_subscribed(pool, repository_id, webhook_event).await?;
    if !webhooks.is_empty() {
        let payload_json = serde_json::json!({
            "action": action,
            "repository": { "owner": owner, "name": repo.name },
            "issue": { "number": issue.number, "title": issue.title },
        })
        .to_string();
        jobs.extend(
            webhooks
                .into_iter()
                .map(|webhook| JobPayload::DeliverWebhook {
                    webhook_id: webhook.id,
                    event: webhook_event,
                    payload_json: payload_json.clone(),
                }),
        );
    }

    if let Some((kind, email_subject)) = notification {
        let mut involved = IssueAssigneeRepo::list_for_issue(pool, issue_id).await?;
        involved.push(issue.author_id);
        jobs.extend(
            notify_watchers(
                pool,
                repository_id,
                NotificationSubject::Issue(issue_id),
                kind,
                Some(actor_id),
                &involved,
                email_subject,
                &format!("{action} issue #{}: {}", issue.number, issue.title),
            )
            .await?,
        );
    }
    Ok(jobs)
}

/// The pull-request analogue of [`issue_activity`]. `webhook_event` is
/// `None` for `PullRequestMerged` (whose payload shape is a legacy the
/// existing consumers depend on — it keeps its own arm).
async fn pr_activity(
    pool: &DbPool,
    pull_request_id: PullRequestId,
    repository_id: RepositoryId,
    actor_id: UserId,
    webhook_event: Option<WebhookEvent>,
    action: &str,
    notification: Option<(NotificationKind, &str)>,
) -> Result<Vec<JobPayload>, edda_db::DbError> {
    let (Some(pr), Some(repo)) = (
        PullRequestRepo::find_by_id(pool, pull_request_id).await?,
        RepositoryRepo::find_by_id(pool, repository_id).await?,
    ) else {
        return Ok(Vec::new());
    };
    let owner = owner_display_name(pool, repo.owner).await?;

    let mut jobs = Vec::new();
    if let Some(webhook_event) = webhook_event {
        let webhooks = WebhookRepo::find_subscribed(pool, repository_id, webhook_event).await?;
        if !webhooks.is_empty() {
            let payload_json = serde_json::json!({
                "action": action,
                "repository": { "owner": owner, "name": repo.name },
                "pull_request": { "number": pr.number, "title": pr.title },
            })
            .to_string();
            jobs.extend(
                webhooks
                    .into_iter()
                    .map(|webhook| JobPayload::DeliverWebhook {
                        webhook_id: webhook.id,
                        event: webhook_event,
                        payload_json: payload_json.clone(),
                    }),
            );
        }
    }

    if let Some((kind, email_subject)) = notification {
        jobs.extend(
            notify_watchers(
                pool,
                repository_id,
                NotificationSubject::PullRequest(pull_request_id),
                kind,
                Some(actor_id),
                &[pr.author_id],
                email_subject,
                &format!("{action} pull request #{}: {}", pr.number, pr.title),
            )
            .await?,
        );
    }
    Ok(jobs)
}

/// `release.published` webhook + a `ReleasePublished` notification to
/// repository watchers.
async fn release_activity(
    pool: &DbPool,
    release_id: edda_domain::ReleaseId,
    repository_id: RepositoryId,
    actor_id: UserId,
) -> Result<Vec<JobPayload>, edda_db::DbError> {
    let (Some(release), Some(repo)) = (
        ReleaseRepo::find_by_id(pool, release_id).await?,
        RepositoryRepo::find_by_id(pool, repository_id).await?,
    ) else {
        return Ok(Vec::new());
    };
    let owner = owner_display_name(pool, repo.owner).await?;

    let mut jobs = Vec::new();
    let webhooks =
        WebhookRepo::find_subscribed(pool, repository_id, WebhookEvent::ReleasePublished).await?;
    if !webhooks.is_empty() {
        let payload_json = serde_json::json!({
            "action": "published",
            "repository": { "owner": owner, "name": repo.name },
            "release": { "tag_name": release.tag_name, "name": release.name },
        })
        .to_string();
        jobs.extend(
            webhooks
                .into_iter()
                .map(|webhook| JobPayload::DeliverWebhook {
                    webhook_id: webhook.id,
                    event: WebhookEvent::ReleasePublished,
                    payload_json: payload_json.clone(),
                }),
        );
    }

    jobs.extend(
        notify_watchers(
            pool,
            repository_id,
            NotificationSubject::Release(release_id),
            NotificationKind::ReleasePublished,
            Some(actor_id),
            &[release.author_id],
            "A new release was published",
            &format!("published release {}", release.tag_name),
        )
        .await?,
    );
    Ok(jobs)
}

/// The standard "one person did something to another person" fan-out: an
/// in-app notification plus, when the recipient hasn't opted out, an
/// email. `action` is the sentence fragment after "@actor " (e.g.
/// "assigned you issue #5: …"). `actor_id` is `None` when the acting user
/// is unknown (an older event that didn't carry it).
async fn notify(
    pool: &DbPool,
    recipient_id: UserId,
    actor_id: Option<UserId>,
    kind: NotificationKind,
    subject: NotificationSubject,
    email_subject: &str,
    action: &str,
) -> Vec<JobPayload> {
    let mut jobs = vec![JobPayload::CreateNotification {
        user_id: recipient_id,
        kind,
        subject,
    }];
    let email_enabled = UserRepo::email_notifications_enabled(pool, recipient_id)
        .await
        .unwrap_or(true);
    if email_enabled {
        if let Ok(Some(recipient)) = UserRepo::find_by_id(pool, recipient_id).await {
            let actor = match actor_id {
                Some(id) => UserRepo::find_by_id(pool, id)
                    .await
                    .ok()
                    .flatten()
                    .map_or_else(
                        || "Someone".to_string(),
                        |row| format!("@{}", row.user.username),
                    ),
                None => "Someone".to_string(),
            };
            jobs.push(JobPayload::SendEmail {
                to_email: recipient.user.email,
                subject: email_subject.to_string(),
                body_text: format!("{actor} {action}."),
            });
        }
    }
    jobs
}

/// A `refs/heads/*` update landed. Two reactions: deliver the `push`
/// webhook, and — for any open PR whose *source* is this branch — dismiss
/// its stale approvals when the target branch's protection rule says to.
///
/// The dismissal is a write done here rather than a returned job: it is
/// idempotent (`WHERE dismissed_at IS NULL`), so re-running it after a
/// dispatcher retry is harmless, matching how this function already does
/// non-transactional work before the claim.
async fn fan_out_branch_pushed(
    pool: &DbPool,
    repository_id: RepositoryId,
    ref_name: &str,
    old: &str,
    new: &str,
) -> Result<Vec<JobPayload>, edda_db::DbError> {
    let branch = ref_name.strip_prefix("refs/heads/").unwrap_or(ref_name);
    const ZERO: &str = "0000000000000000000000000000000000000000";
    let action = if old == ZERO {
        "created"
    } else if new == ZERO {
        "deleted"
    } else {
        "updated"
    };

    // Dismiss stale approvals on any open PR sourced from this branch.
    let prs = PullRequestRepo::list_open_with_source_branch(pool, repository_id, branch).await?;
    for pr in &prs {
        if new == ZERO {
            continue;
        }
        let rule = BranchProtectionRepo::find_matching(pool, pr.repository_id, &pr.target).await?;
        if rule.is_some_and(|rule| rule.dismiss_stale_reviews) {
            let dismissed = PrReviewRepo::dismiss_all_for_pull_request(pool, pr.id).await?;
            if dismissed > 0 {
                tracing::info!(
                    pull_request.id = %pr.id,
                    dismissed,
                    "dismissed stale approvals after a push to the PR's source branch"
                );
            }
        }
    }

    let webhooks = WebhookRepo::find_subscribed(pool, repository_id, WebhookEvent::Push).await?;
    if webhooks.is_empty() {
        return Ok(Vec::new());
    }
    let Some(repo) = RepositoryRepo::find_by_id(pool, repository_id).await? else {
        return Ok(Vec::new());
    };
    let owner = owner_display_name(pool, repo.owner).await?;
    let payload_json = serde_json::json!({
        "action": action,
        "ref": ref_name,
        "before": old,
        "after": new,
        "repository": { "owner": owner, "name": repo.name },
    })
    .to_string();
    Ok(webhooks
        .into_iter()
        .map(|webhook| JobPayload::DeliverWebhook {
            webhook_id: webhook.id,
            event: WebhookEvent::Push,
            payload_json: payload_json.clone(),
        })
        .collect())
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
        // Exactly one webhook delivery — to the subscribed hook only.
        let deliveries: Vec<_> = claimed
            .iter()
            .filter_map(|job| match &job.payload {
                JobPayload::DeliverWebhook {
                    webhook_id,
                    event,
                    payload_json,
                } => Some((*webhook_id, *event, payload_json.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].0, subscribed);
        assert_eq!(deliveries[0].1, WebhookEvent::PullRequestMerged);
        assert!(deliveries[0].2.contains("\"alice\""));
        assert!(deliveries[0].2.contains("Add a thing"));
        // The PR author is notified of the merge.
        assert!(claimed.iter().any(|job| matches!(
            &job.payload,
            JobPayload::CreateNotification { user_id, kind, .. }
                if *user_id == owner && *kind == NotificationKind::PrMerged
        )));
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

    /// A `BranchPushed` event delivers the `push` webhook and, when the PR
    /// sourced from that branch targets a `dismiss_stale_reviews` branch,
    /// clears its existing approvals.
    #[tokio::test]
    async fn a_branch_pushed_event_delivers_the_push_webhook_and_dismisses_stale_approvals() {
        use edda_db::{BranchProtectionRepo, BranchProtectionSettings, PrReviewRepo};
        use edda_domain::{PrRef, ReviewState};

        let pool = edda_db::test_pool().await;
        let alice = insert_user(&pool, "alice").await;
        let reviewer = insert_user(&pool, "rob").await;
        let repo_id = insert_repo(&pool, alice, "demo").await;

        WebhookRepo::insert(
            &pool,
            WebhookId::new(),
            repo_id,
            "https://example.com/push-hook",
            b"ciphertext",
            &[WebhookEvent::Push],
        )
        .await
        .unwrap();

        let pr_id = PullRequestId::new();
        PullRequestRepo::insert(
            &pool,
            pr_id,
            repo_id,
            edda_db::NewPullRequest {
                title: "Add a thing",
                body: None,
                author_id: alice,
                source: &PrRef {
                    repository_id: repo_id,
                    branch: "feature".to_string(),
                },
                target: "main",
                draft: false,
            },
        )
        .await
        .unwrap();
        PrReviewRepo::insert(
            &pool,
            edda_domain::PrReviewId::new(),
            pr_id,
            reviewer,
            ReviewState::Approved,
            None,
        )
        .await
        .unwrap();
        BranchProtectionRepo::upsert_by_pattern(
            &pool,
            edda_domain::BranchProtectionRuleId::new(),
            repo_id,
            "main",
            &BranchProtectionSettings {
                required_approvals: 1,
                dismiss_stale_reviews: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let event = DomainEvent::BranchPushed {
            repository_id: repo_id,
            ref_name: "refs/heads/feature".to_string(),
            old: "a".repeat(40),
            new: "b".repeat(40),
            pusher_id: Some(alice),
        };
        EventRepo::append(&pool, EventId::new(), &event)
            .await
            .unwrap();
        let record = EventRepo::fetch_unprocessed(&pool, 10).await.unwrap()[0].clone();
        process_one(&pool, &record).await.unwrap();

        let claimed = JobRepo::claim_batch(&pool, now_unix(), 10).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert!(matches!(
            &claimed[0].payload,
            JobPayload::DeliverWebhook { event, payload_json, .. }
                if *event == WebhookEvent::Push && payload_json.contains("refs/heads/feature")
        ));

        let reviews = PrReviewRepo::list_for_pull_request(&pool, pr_id)
            .await
            .unwrap();
        assert!(
            reviews.iter().all(|r| r.dismissed_at.is_some()),
            "the approval should have been dismissed by the push"
        );
        assert!(!reviews[0].is_active_approval());
    }

    #[tokio::test]
    async fn an_issue_assigned_event_notifies_the_assignee_in_app_and_by_email() {
        let pool = edda_db::test_pool().await;
        let assigner = insert_user(&pool, "alice").await;
        let assignee = insert_user(&pool, "bob").await;
        let repo_id = insert_repo(&pool, assigner, "demo").await;
        let issue_id = edda_domain::IssueId::new();
        IssueRepo::insert(&pool, issue_id, repo_id, "Bug", None, assigner)
            .await
            .unwrap();

        let event = DomainEvent::IssueAssigned {
            issue_id,
            repository_id: repo_id,
            assignee_id: assignee,
            assigned_by_id: assigner,
        };
        EventRepo::append(&pool, EventId::new(), &event)
            .await
            .unwrap();
        let record = EventRepo::fetch_unprocessed(&pool, 10).await.unwrap()[0].clone();
        process_one(&pool, &record).await.unwrap();

        let claimed = JobRepo::claim_batch(&pool, now_unix(), 10).await.unwrap();
        assert_eq!(claimed.len(), 2);
        assert!(claimed.iter().any(|job| matches!(
            &job.payload,
            JobPayload::CreateNotification { user_id, kind, .. }
                if *user_id == assignee && *kind == NotificationKind::IssueAssigned
        )));
        assert!(claimed.iter().any(|job| matches!(
            &job.payload,
            JobPayload::SendEmail { to_email, body_text, .. }
                if to_email == "bob@example.com" && body_text.contains("@alice")
        )));
    }

    #[tokio::test]
    async fn a_review_requested_event_notifies_the_reviewer() {
        let pool = edda_db::test_pool().await;
        let requester = insert_user(&pool, "alice").await;
        let reviewer = insert_user(&pool, "bob").await;
        let repo_id = insert_repo(&pool, requester, "demo").await;
        let pr_id = PullRequestId::new();
        PullRequestRepo::insert(
            &pool,
            pr_id,
            repo_id,
            edda_db::NewPullRequest {
                title: "Add a thing",
                body: None,
                author_id: requester,
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

        let event = DomainEvent::ReviewRequested {
            pull_request_id: pr_id,
            repository_id: repo_id,
            reviewer_id: reviewer,
            requested_by_id: requester,
        };
        EventRepo::append(&pool, EventId::new(), &event)
            .await
            .unwrap();
        let record = EventRepo::fetch_unprocessed(&pool, 10).await.unwrap()[0].clone();
        process_one(&pool, &record).await.unwrap();

        let claimed = JobRepo::claim_batch(&pool, now_unix(), 10).await.unwrap();
        assert!(claimed.iter().any(|job| matches!(
            &job.payload,
            JobPayload::CreateNotification { user_id, kind, .. }
                if *user_id == reviewer && *kind == NotificationKind::PrReviewRequested
        )));
    }

    #[tokio::test]
    async fn an_issue_closed_event_notifies_the_author_and_assignees_but_not_the_closer() {
        let pool = edda_db::test_pool().await;
        let author = insert_user(&pool, "alice").await;
        let assignee = insert_user(&pool, "bob").await;
        let closer = insert_user(&pool, "carol").await;
        let repo_id = insert_repo(&pool, author, "demo").await;
        let issue_id = edda_domain::IssueId::new();
        IssueRepo::insert(&pool, issue_id, repo_id, "Bug", None, author)
            .await
            .unwrap();
        IssueAssigneeRepo::assign(&pool, issue_id, assignee, Some(author))
            .await
            .unwrap();
        // The closer is also an assignee — they must not get a notification.
        IssueAssigneeRepo::assign(&pool, issue_id, closer, Some(author))
            .await
            .unwrap();

        let event = DomainEvent::IssueClosed {
            issue_id,
            repository_id: repo_id,
            closed_by_id: closer,
            via_pull_request: Some(PullRequestId::new()),
        };
        EventRepo::append(&pool, EventId::new(), &event)
            .await
            .unwrap();
        let record = EventRepo::fetch_unprocessed(&pool, 10).await.unwrap()[0].clone();
        process_one(&pool, &record).await.unwrap();

        let claimed = JobRepo::claim_batch(&pool, now_unix(), 20).await.unwrap();
        let notified: std::collections::HashSet<_> = claimed
            .iter()
            .filter_map(|job| match &job.payload {
                JobPayload::CreateNotification { user_id, kind, .. }
                    if *kind == NotificationKind::IssueClosed =>
                {
                    Some(*user_id)
                }
                _ => None,
            })
            .collect();
        assert!(notified.contains(&author));
        assert!(notified.contains(&assignee));
        assert!(!notified.contains(&closer), "the closer is not notified");
    }

    #[tokio::test]
    async fn an_issue_opened_event_delivers_the_issue_opened_webhook() {
        let pool = edda_db::test_pool().await;
        let author = insert_user(&pool, "alice").await;
        let repo_id = insert_repo(&pool, author, "demo").await;
        let issue_id = edda_domain::IssueId::new();
        IssueRepo::insert(&pool, issue_id, repo_id, "Bug", None, author)
            .await
            .unwrap();
        WebhookRepo::insert(
            &pool,
            WebhookId::new(),
            repo_id,
            "https://example.com/hook",
            b"ciphertext",
            &[WebhookEvent::IssueOpened],
        )
        .await
        .unwrap();

        let event = DomainEvent::IssueOpened {
            issue_id,
            repository_id: repo_id,
            opened_by_id: author,
        };
        EventRepo::append(&pool, EventId::new(), &event)
            .await
            .unwrap();
        let record = EventRepo::fetch_unprocessed(&pool, 10).await.unwrap()[0].clone();
        process_one(&pool, &record).await.unwrap();

        let claimed = JobRepo::claim_batch(&pool, now_unix(), 10).await.unwrap();
        assert!(claimed.iter().any(|job| matches!(
            &job.payload,
            JobPayload::DeliverWebhook { event, payload_json, .. }
                if *event == WebhookEvent::IssueOpened && payload_json.contains("\"opened\"")
        )));
    }

    #[tokio::test]
    async fn a_pull_request_closed_event_notifies_a_repository_watcher_with_pr_closed() {
        use edda_domain::{WatchId, WatchLevel, WatchSubject};

        let pool = edda_db::test_pool().await;
        let author = insert_user(&pool, "alice").await;
        let closer = insert_user(&pool, "bob").await;
        let watcher = insert_user(&pool, "carol").await;
        let repo_id = insert_repo(&pool, author, "demo").await;
        WatchRepo::set(
            &pool,
            WatchId::new(),
            watcher,
            WatchSubject::Repository(repo_id),
            WatchLevel::Watching,
        )
        .await
        .unwrap();

        let pr_id = PullRequestId::new();
        PullRequestRepo::insert(
            &pool,
            pr_id,
            repo_id,
            edda_db::NewPullRequest {
                title: "Add a thing",
                body: None,
                author_id: author,
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

        let event = DomainEvent::PullRequestClosed {
            pull_request_id: pr_id,
            repository_id: repo_id,
            closed_by_id: closer,
        };
        EventRepo::append(&pool, EventId::new(), &event)
            .await
            .unwrap();
        let record = EventRepo::fetch_unprocessed(&pool, 10).await.unwrap()[0].clone();
        process_one(&pool, &record).await.unwrap();

        let claimed = JobRepo::claim_batch(&pool, now_unix(), 20).await.unwrap();
        let notified: std::collections::HashSet<_> = claimed
            .iter()
            .filter_map(|job| match &job.payload {
                JobPayload::CreateNotification { user_id, kind, .. }
                    if *kind == NotificationKind::PrClosed =>
                {
                    Some(*user_id)
                }
                _ => None,
            })
            .collect();
        assert!(notified.contains(&watcher), "the repo watcher is notified");
        assert!(notified.contains(&author), "the PR author is notified");
        assert!(!notified.contains(&closer), "the closer is not notified");
    }
}

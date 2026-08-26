//! Shared by `pr_server`/`issue_server`: parses `@mentions` out of a
//! freshly posted comment body, resolves each to a real account (silently
//! dropping anything that doesn't match one — an unresolvable `@typo` is
//! not an error, just not a mention), and dispatches
//! `DomainEvent::UserMentioned` for each, with an email job attached only
//! for a mentioned user who hasn't opted out
//! (`UserRepo::email_notifications_enabled`).

use edda_db::DbPool;
use edda_domain::{parse_mentions, DomainEvent, MentionSource, UserId};

pub(crate) async fn dispatch_mentions(
    pool: &DbPool,
    body: &str,
    commenter_id: UserId,
    source: MentionSource,
    email_subject: &str,
    email_body: &str,
) {
    for username in parse_mentions(body) {
        let Ok(Some(mentioned)) = edda_db::UserRepo::find_by_username(pool, &username).await else {
            continue;
        };
        // A self-mention doesn't notify — you already know you wrote it.
        if mentioned.id == commenter_id {
            continue;
        }

        let email_enabled = edda_db::UserRepo::email_notifications_enabled(pool, mentioned.id)
            .await
            .unwrap_or(true);
        let mention_email = email_enabled.then_some(edda_jobs::EmailContent {
            to_email: mentioned.email.as_str(),
            subject: email_subject,
            body_text: email_body,
        });

        let event = DomainEvent::UserMentioned {
            mentioned_user_id: mentioned.id,
            source,
        };
        if let Err(err) = edda_jobs::dispatch(pool, &event, None, mention_email).await {
            tracing::error!(error = %err, mentioned.username = %username, "failed to dispatch mention notification");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edda_domain::{JobPayload, PullRequestId};

    async fn insert_user(pool: &DbPool, username: &str) -> UserId {
        let id = UserId::new();
        edda_db::UserRepo::insert(pool, id, username, &format!("{username}@example.com"), "x")
            .await
            .unwrap();
        id
    }

    /// Phase 7 exit criterion: "a user mentioned in a PR comment receives
    /// both an in-app notification and, if enabled, an email." This
    /// drives the exact function `pr_server::add_pull_request_comment`/
    /// `issue_server::add_issue_comment` call after inserting a comment,
    /// and inspects the real jobs it enqueues in the real `jobs` table —
    /// the same table the poller claims from in production.
    #[tokio::test]
    async fn a_mention_enqueues_a_notification_job_and_an_email_job_when_enabled() {
        let pool = edda_db::test_pool().await;
        let commenter = insert_user(&pool, "alice").await;
        let mentioned = insert_user(&pool, "bob").await;
        let pull_request_id = PullRequestId::new();

        dispatch_mentions(
            &pool,
            "hey @bob, take a look",
            commenter,
            MentionSource::PullRequestComment { pull_request_id },
            "you were mentioned",
            "alice mentioned you",
        )
        .await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claimed = edda_db::JobRepo::claim_batch(&pool, now, 10).await.unwrap();
        assert_eq!(
            claimed.len(),
            2,
            "expected one notification job and one email job"
        );

        let has_notification = claimed.iter().any(|job| match &job.payload {
            JobPayload::CreateNotification { user_id, .. } => *user_id == mentioned,
            _ => false,
        });
        let has_email = claimed.iter().any(|job| match &job.payload {
            JobPayload::SendEmail { to_email, .. } => to_email == "bob@example.com",
            _ => false,
        });
        assert!(
            has_notification,
            "expected an in-app notification job for the mentioned user"
        );
        assert!(
            has_email,
            "expected an email job for the mentioned user (opted in by default)"
        );
    }

    #[tokio::test]
    async fn opting_out_of_email_notifications_still_creates_the_in_app_notification_only() {
        let pool = edda_db::test_pool().await;
        let commenter = insert_user(&pool, "carol").await;
        let mentioned = insert_user(&pool, "dave").await;
        edda_db::UserRepo::set_email_notifications_enabled(&pool, mentioned, false)
            .await
            .unwrap();

        dispatch_mentions(
            &pool,
            "@dave please review",
            commenter,
            MentionSource::IssueComment {
                issue_id: edda_domain::IssueId::new(),
            },
            "you were mentioned",
            "carol mentioned you",
        )
        .await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claimed = edda_db::JobRepo::claim_batch(&pool, now, 10).await.unwrap();
        assert_eq!(
            claimed.len(),
            1,
            "only the in-app notification job, no email"
        );
        assert!(matches!(
            claimed[0].payload,
            JobPayload::CreateNotification { .. }
        ));
    }

    #[tokio::test]
    async fn a_self_mention_does_not_notify() {
        let pool = edda_db::test_pool().await;
        let commenter = insert_user(&pool, "erin").await;

        dispatch_mentions(
            &pool,
            "@erin noting this for myself",
            commenter,
            MentionSource::PullRequestComment {
                pull_request_id: PullRequestId::new(),
            },
            "subject",
            "body",
        )
        .await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claimed = edda_db::JobRepo::claim_batch(&pool, now, 10).await.unwrap();
        assert!(claimed.is_empty());
    }
}

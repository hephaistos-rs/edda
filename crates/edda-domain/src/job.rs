//! `JobPayload`: "what work a domain event implies," queued in
//! `edda-db`'s `jobs` table and executed by `edda-jobs`'s poller. A
//! deliberately small, closed set — see `event.rs`'s doc comment for why
//! this is a separate type from `DomainEvent` rather than the same enum.

use serde::{Deserialize, Serialize};

use crate::ids::{JobId, PullRequestId, RepositoryId, WebhookId};
use crate::notification::{NotificationKind, NotificationSubject};
use crate::webhook::WebhookEvent;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "job_kind", rename_all = "snake_case")]
pub enum JobPayload {
    DeliverWebhook {
        webhook_id: WebhookId,
        event: WebhookEvent,
        /// The already-serialized JSON body to send — built once at
        /// enqueue time from the triggering event's own data, not
        /// re-derived from scratch on every delivery attempt/retry (which
        /// could observe a different database state than the moment the
        /// event actually happened).
        payload_json: String,
    },
    CreateNotification {
        user_id: crate::ids::UserId,
        kind: NotificationKind,
        subject: NotificationSubject,
    },
    SendEmail {
        to_email: String,
        subject: String,
        body_text: String,
    },
    /// Recompute and store a repository's on-disk size (git objects + LFS)
    /// — enqueued by the receive path after a push, read by the next
    /// push's quota check.
    UpdateRepoSize { repository_id: RepositoryId },
    /// Reconcile one pull request's automatic review requests against its
    /// repository's CODEOWNERS file — enqueued by the receive path when a
    /// push updates the PR's source branch.
    SyncReviewRequests { pull_request_id: PullRequestId },
}

/// A `HashMap`-friendly discriminant for `JobPayload`: the job poller's
/// handler registry is a plain `HashMap<JobKind, Handler>` keyed by this,
/// not a trait-object-per-job-kind hierarchy, since the job-kind set is
/// small and closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobKind {
    DeliverWebhook,
    CreateNotification,
    SendEmail,
    UpdateRepoSize,
    SyncReviewRequests,
}

impl JobPayload {
    pub fn kind(&self) -> JobKind {
        match self {
            JobPayload::DeliverWebhook { .. } => JobKind::DeliverWebhook,
            JobPayload::CreateNotification { .. } => JobKind::CreateNotification,
            JobPayload::SendEmail { .. } => JobKind::SendEmail,
            JobPayload::UpdateRepoSize { .. } => JobKind::UpdateRepoSize,
            JobPayload::SyncReviewRequests { .. } => JobKind::SyncReviewRequests,
        }
    }
}

impl JobKind {
    /// A low-cardinality label for the `edda.jobs.duration` metric — never
    /// derived from a payload field, only this fixed, closed set.
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            JobKind::DeliverWebhook => "deliver_webhook",
            JobKind::CreateNotification => "create_notification",
            JobKind::SendEmail => "send_email",
            JobKind::UpdateRepoSize => "update_repo_size",
            JobKind::SyncReviewRequests => "sync_review_requests",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
}

impl JobStatus {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            JobStatus::Pending => "pending",
            JobStatus::Running => "running",
            JobStatus::Succeeded => "succeeded",
            JobStatus::Failed => "failed",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(JobStatus::Pending),
            "running" => Some(JobStatus::Running),
            "succeeded" => Some(JobStatus::Succeeded),
            "failed" => Some(JobStatus::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRecord {
    pub id: JobId,
    pub payload: JobPayload,
    pub status: JobStatus,
    pub attempts: u32,
    pub max_attempts: u32,
    pub run_at: i64,
    pub last_error: Option<String>,
    pub created_at: i64,
}

/// Exponential backoff with jitter: `min(base * 2^attempts, cap)`, then
/// scaled into `[50%, 100%]` of that ceiling by `jitter_unit` — a pure
/// function (the decision), not itself a source of randomness (the
/// scheduling shell, `edda-jobs`'s poller, supplies `jitter_unit` from a
/// real RNG and writes the result back to `jobs.run_at`). `jitter_unit` is
/// clamped to `[0.0, 1.0]` so an out-of-range caller can't produce a
/// retry time in the past or absurdly far in the future.
pub fn next_retry_at(attempts: u32, jitter_unit: f64, now_unix: i64) -> i64 {
    const BASE_SECONDS: i64 = 30;
    const CAP_SECONDS: i64 = 1800;
    let jitter_unit = jitter_unit.clamp(0.0, 1.0);
    let exponential = BASE_SECONDS.saturating_mul(1i64 << attempts.min(20));
    let backoff = exponential.clamp(1, CAP_SECONDS);
    let jittered = ((backoff as f64) * (0.5 + jitter_unit * 0.5)).round() as i64;
    now_unix + jittered.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_status_round_trips_through_its_db_string() {
        for status in [
            JobStatus::Pending,
            JobStatus::Running,
            JobStatus::Succeeded,
            JobStatus::Failed,
        ] {
            assert_eq!(JobStatus::from_db_str(status.as_db_str()), Some(status));
        }
    }

    #[test]
    fn next_retry_at_grows_exponentially_and_is_capped() {
        let now = 1_000_000;
        let first = next_retry_at(0, 0.0, now);
        let second = next_retry_at(1, 0.0, now);
        let capped = next_retry_at(20, 0.0, now);
        assert!(first > now);
        assert!(second - now > first - now);
        assert!(capped - now <= 1800);
    }

    #[test]
    fn next_retry_at_jitter_stays_within_the_backoff_window() {
        let now = 0;
        let min_jitter = next_retry_at(3, 0.0, now);
        let max_jitter = next_retry_at(3, 1.0, now);
        assert!(min_jitter <= max_jitter);
        // attempts=3 -> exponential = 30 * 2^3 = 240, so the window is
        // [120, 240].
        assert!((120..=240).contains(&min_jitter));
        assert!((120..=240).contains(&max_jitter));
    }

    #[test]
    fn job_payload_kind_matches_its_variant() {
        let payload = JobPayload::SendEmail {
            to_email: "a@example.com".to_string(),
            subject: "hi".to_string(),
            body_text: "hi".to_string(),
        };
        assert_eq!(payload.kind(), JobKind::SendEmail);
    }
}

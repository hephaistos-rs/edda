//! In-app notifications: a small, closed `kind` paired with a typed
//! `subject` (which entity this notification is about) rather than a
//! loosely-typed `(subject_type: String, subject_id: Uuid)` pair — the
//! same discipline already applied to `PrComment::anchor`/`MentionSource`.

use serde::{Deserialize, Serialize};

use crate::ids::{IssueId, NotificationId, PullRequestId, ReleaseId, UserId};

/// Every reason Edda raises an in-app notification. Grown additively as
/// each collaboration surface is wired (Phase 11 added everything past
/// `IssueAssigned`); the `notifications.kind` column carries no value
/// `CHECK` (dropped in migration `0004`), so this enum's `from_db_str` is
/// the single validated gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    Mention,
    PrReviewRequested,
    IssueAssigned,
    PrMerged,
    PrClosed,
    IssueClosed,
    ReleasePublished,
}

impl NotificationKind {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            NotificationKind::Mention => "mention",
            NotificationKind::PrReviewRequested => "pr_review_requested",
            NotificationKind::IssueAssigned => "issue_assigned",
            NotificationKind::PrMerged => "pr_merged",
            NotificationKind::PrClosed => "pr_closed",
            NotificationKind::IssueClosed => "issue_closed",
            NotificationKind::ReleasePublished => "release_published",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "mention" => Some(NotificationKind::Mention),
            "pr_review_requested" => Some(NotificationKind::PrReviewRequested),
            "issue_assigned" => Some(NotificationKind::IssueAssigned),
            "pr_merged" => Some(NotificationKind::PrMerged),
            "pr_closed" => Some(NotificationKind::PrClosed),
            "issue_closed" => Some(NotificationKind::IssueClosed),
            "release_published" => Some(NotificationKind::ReleasePublished),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NotificationSubject {
    PullRequest(PullRequestId),
    Issue(IssueId),
    Release(ReleaseId),
}

impl NotificationSubject {
    /// `notifications.subject_type` — the discriminant half of the
    /// `(subject_type, subject_id)` column pair `edda-db` stores this as.
    pub const fn subject_type_db_str(self) -> &'static str {
        match self {
            NotificationSubject::PullRequest(_) => "pull_request",
            NotificationSubject::Issue(_) => "issue",
            NotificationSubject::Release(_) => "release",
        }
    }

    pub fn subject_id(self) -> uuid::Uuid {
        match self {
            NotificationSubject::PullRequest(id) => id.as_uuid(),
            NotificationSubject::Issue(id) => id.as_uuid(),
            NotificationSubject::Release(id) => id.as_uuid(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notification {
    pub id: NotificationId,
    pub user_id: UserId,
    pub kind: NotificationKind,
    pub subject: NotificationSubject,
    pub read_at: Option<i64>,
    pub created_at: i64,
}

impl Notification {
    pub fn is_unread(&self) -> bool {
        self.read_at.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_kind_round_trips_through_its_db_string() {
        for kind in [
            NotificationKind::Mention,
            NotificationKind::PrReviewRequested,
            NotificationKind::IssueAssigned,
            NotificationKind::PrMerged,
            NotificationKind::PrClosed,
            NotificationKind::IssueClosed,
            NotificationKind::ReleasePublished,
        ] {
            assert_eq!(NotificationKind::from_db_str(kind.as_db_str()), Some(kind));
        }
        assert_eq!(NotificationKind::from_db_str("nope"), None);
    }

    #[test]
    fn a_notification_without_read_at_is_unread() {
        let notification = Notification {
            id: NotificationId::new(),
            user_id: UserId::new(),
            kind: NotificationKind::Mention,
            subject: NotificationSubject::PullRequest(PullRequestId::new()),
            read_at: None,
            created_at: 0,
        };
        assert!(notification.is_unread());
        assert!(!Notification {
            read_at: Some(1),
            ..notification
        }
        .is_unread());
    }
}

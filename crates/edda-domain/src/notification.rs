//! In-app notifications: a small, closed `kind` paired with a typed
//! `subject` (which entity this notification is about) rather than a
//! loosely-typed `(subject_type: String, subject_id: Uuid)` pair — the
//! same discipline already applied to `PrComment::anchor`/`MentionSource`.

use serde::{Deserialize, Serialize};

use crate::ids::{IssueId, NotificationId, PullRequestId, UserId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    Mention,
    PrReviewRequested,
    IssueAssigned,
}

impl NotificationKind {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            NotificationKind::Mention => "mention",
            NotificationKind::PrReviewRequested => "pr_review_requested",
            NotificationKind::IssueAssigned => "issue_assigned",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "mention" => Some(NotificationKind::Mention),
            "pr_review_requested" => Some(NotificationKind::PrReviewRequested),
            "issue_assigned" => Some(NotificationKind::IssueAssigned),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NotificationSubject {
    PullRequest(PullRequestId),
    Issue(IssueId),
}

impl NotificationSubject {
    /// `notifications.subject_type` — the discriminant half of the
    /// `(subject_type, subject_id)` column pair `edda-db` stores this as.
    pub const fn subject_type_db_str(self) -> &'static str {
        match self {
            NotificationSubject::PullRequest(_) => "pull_request",
            NotificationSubject::Issue(_) => "issue",
        }
    }

    pub fn subject_id(self) -> uuid::Uuid {
        match self {
            NotificationSubject::PullRequest(id) => id.as_uuid(),
            NotificationSubject::Issue(id) => id.as_uuid(),
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
        ] {
            assert_eq!(NotificationKind::from_db_str(kind.as_db_str()), Some(kind));
        }
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

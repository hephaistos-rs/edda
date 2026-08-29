//! Watch / subscribe (Phase 11): a user's standing interest in a
//! repository, issue, or pull request, which drives the notification
//! fan-out for activity on that subject.
//!
//! `Watching` is an explicit opt-in (or an auto-subscribe when a user
//! first participates — comments, is assigned, is asked to review);
//! `Ignoring` is an explicit mute that suppresses notifications even while
//! participating. The absence of a row means "default" — notified only for
//! direct involvement (`@mention`, assignment, review request).

use serde::{Deserialize, Serialize};

use crate::ids::{IssueId, PullRequestId, RepositoryId, UserId, WatchId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchLevel {
    /// Notified for all activity on the subject.
    Watching,
    /// Never notified for the subject — an explicit mute that overrides
    /// auto-subscribe.
    Ignoring,
}

impl WatchLevel {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            WatchLevel::Watching => "watching",
            WatchLevel::Ignoring => "ignoring",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "watching" => Some(WatchLevel::Watching),
            "ignoring" => Some(WatchLevel::Ignoring),
            _ => None,
        }
    }
}

/// What a watch is attached to — a typed `(subject_type, subject_id)` pair
/// rather than a loose string/uuid one, the same discipline
/// [`crate::notification::NotificationSubject`] uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchSubject {
    Repository(RepositoryId),
    Issue(IssueId),
    PullRequest(PullRequestId),
}

impl WatchSubject {
    /// `watches.subject_type` — the discriminant half of the
    /// `(subject_type, subject_id)` column pair `edda-db` stores.
    pub const fn subject_type_db_str(self) -> &'static str {
        match self {
            WatchSubject::Repository(_) => "repository",
            WatchSubject::Issue(_) => "issue",
            WatchSubject::PullRequest(_) => "pull_request",
        }
    }

    pub fn subject_id(self) -> uuid::Uuid {
        match self {
            WatchSubject::Repository(id) => id.as_uuid(),
            WatchSubject::Issue(id) => id.as_uuid(),
            WatchSubject::PullRequest(id) => id.as_uuid(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watch {
    pub id: WatchId,
    pub user_id: UserId,
    pub subject: WatchSubject,
    pub level: WatchLevel,
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_level_round_trips_through_its_db_string() {
        for level in [WatchLevel::Watching, WatchLevel::Ignoring] {
            assert_eq!(WatchLevel::from_db_str(level.as_db_str()), Some(level));
        }
        assert_eq!(WatchLevel::from_db_str("subscribed"), None);
    }

    #[test]
    fn watch_subject_reports_its_typed_columns() {
        let repo = RepositoryId::new();
        let subject = WatchSubject::Repository(repo);
        assert_eq!(subject.subject_type_db_str(), "repository");
        assert_eq!(subject.subject_id(), repo.as_uuid());
    }
}

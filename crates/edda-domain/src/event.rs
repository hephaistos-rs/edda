//! `DomainEvent`: "what happened," emitted by an application service in
//! the *same* transaction as the state change it describes and persisted
//! to the `events` outbox table (`edda_db::EventRepo::append`). A separate
//! task (`edda_jobs::spawn_dispatcher`) later reads unprocessed rows and
//! fans each one out to background `jobs` — so the event survives a crash
//! between the state change committing and the world being told, which the
//! previous "dispatch right after commit, log on failure" path did not.
//!
//! Exhaustively matched wherever it's dispatched; a new kind of thing
//! worth reacting to asynchronously is a new variant here, never a
//! catch-all `Other(String)`. Every variant carries enough to fan itself
//! out from a cold start (the dispatcher has only the row, not the request
//! context that emitted it) — e.g. `UserMentioned` names *who* mentioned,
//! not just who was mentioned.
//!
//! Deliberately a separate type from `edda_domain::job::JobPayload`:
//! this is "what happened," that is "what work that implies" — collapsing
//! them would force every event to imply exactly one job, which doesn't
//! hold once a single event fans out to more than one (`PullRequestMerged`
//! implies both webhook delivery *and* a merge notification).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ids::{IssueId, PullRequestId, ReleaseId, RepositoryId, UserId};
use crate::pull_request::ReviewState;

/// Where a `@mention` was written — the two comment surfaces this
/// workspace has today. Not `MentionSource::Other(String)`: a third
/// surface (e.g. a release body) becomes a new variant, not a stringly-
/// typed fallback nothing exhaustively matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "surface", rename_all = "snake_case")]
pub enum MentionSource {
    PullRequestComment { pull_request_id: PullRequestId },
    IssueComment { issue_id: IssueId },
}

/// `Clone` but not `Copy`: `BranchPushed` carries owned `String`s (a ref
/// name, two hex object ids), the same shape `JobPayload` already has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DomainEvent {
    PullRequestMerged {
        pull_request_id: PullRequestId,
        repository_id: RepositoryId,
    },
    UserMentioned {
        mentioned_user_id: UserId,
        /// The commenter who wrote the `@mention` — carried on the event
        /// so the dispatcher can render "@alice mentioned you" without the
        /// request context that emitted it.
        mentioned_by_user_id: UserId,
        source: MentionSource,
    },
    /// One `refs/heads/*` ref landed by a `git push`. Emitted once per
    /// updated branch by the receive path, after the ref transaction
    /// commits. `old`/`new` are hex object ids; an all-zero `old` is a
    /// branch create, an all-zero `new` a delete. `pusher_id` is `None`
    /// for a deploy-key push (no user identity).
    BranchPushed {
        repository_id: RepositoryId,
        ref_name: String,
        old: String,
        new: String,
        pusher_id: Option<UserId>,
    },
    /// A user was added as an assignee of an issue.
    IssueAssigned {
        issue_id: IssueId,
        repository_id: RepositoryId,
        assignee_id: UserId,
        assigned_by_id: UserId,
    },
    /// A user was asked to review a pull request (manually, or from a
    /// CODEOWNERS match — the event is the same).
    ReviewRequested {
        pull_request_id: PullRequestId,
        repository_id: RepositoryId,
        reviewer_id: UserId,
        requested_by_id: UserId,
    },
    /// An issue was closed. `via_pull_request` is `Some` when a merging
    /// pull request's `closes #N` reference did it (rather than a manual
    /// close).
    IssueClosed {
        issue_id: IssueId,
        repository_id: RepositoryId,
        closed_by_id: UserId,
        via_pull_request: Option<PullRequestId>,
    },
    /// An issue was opened.
    IssueOpened {
        issue_id: IssueId,
        repository_id: RepositoryId,
        opened_by_id: UserId,
    },
    /// A comment was posted on an issue (separate from any `@mention`s it
    /// also contains).
    IssueCommented {
        issue_id: IssueId,
        repository_id: RepositoryId,
        comment_author_id: UserId,
    },
    /// A pull request was opened (draft or ready).
    PullRequestOpened {
        pull_request_id: PullRequestId,
        repository_id: RepositoryId,
        opened_by_id: UserId,
    },
    /// A pull request was closed without merging.
    PullRequestClosed {
        pull_request_id: PullRequestId,
        repository_id: RepositoryId,
        closed_by_id: UserId,
    },
    /// A closed (not merged) pull request was reopened.
    PullRequestReopened {
        pull_request_id: PullRequestId,
        repository_id: RepositoryId,
        reopened_by_id: UserId,
    },
    /// A review was submitted on a pull request.
    PullRequestReviewSubmitted {
        pull_request_id: PullRequestId,
        repository_id: RepositoryId,
        reviewer_id: UserId,
        state: ReviewState,
    },
    /// A non-draft release was published (created directly as published,
    /// or a draft flipped to published).
    ReleasePublished {
        release_id: ReleaseId,
        repository_id: RepositoryId,
        published_by_id: UserId,
    },
}

/// The discriminant of [`DomainEvent`] — stored in the `events.kind`
/// column so the dispatcher and operators can filter without deserializing
/// every payload. The string form is kept in lockstep with the
/// `#[serde(tag = "kind")]` value on `DomainEvent` (a test asserts it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainEventKind {
    PullRequestMerged,
    UserMentioned,
    BranchPushed,
    IssueAssigned,
    ReviewRequested,
    IssueClosed,
    IssueOpened,
    IssueCommented,
    PullRequestOpened,
    PullRequestClosed,
    PullRequestReopened,
    PullRequestReviewSubmitted,
    ReleasePublished,
}

impl DomainEventKind {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            DomainEventKind::PullRequestMerged => "pull_request_merged",
            DomainEventKind::UserMentioned => "user_mentioned",
            DomainEventKind::BranchPushed => "branch_pushed",
            DomainEventKind::IssueAssigned => "issue_assigned",
            DomainEventKind::ReviewRequested => "review_requested",
            DomainEventKind::IssueClosed => "issue_closed",
            DomainEventKind::IssueOpened => "issue_opened",
            DomainEventKind::IssueCommented => "issue_commented",
            DomainEventKind::PullRequestOpened => "pull_request_opened",
            DomainEventKind::PullRequestClosed => "pull_request_closed",
            DomainEventKind::PullRequestReopened => "pull_request_reopened",
            DomainEventKind::PullRequestReviewSubmitted => "pull_request_review_submitted",
            DomainEventKind::ReleasePublished => "release_published",
        }
    }

    #[must_use]
    pub fn from_db_str(value: &str) -> Option<Self> {
        Some(match value {
            "pull_request_merged" => DomainEventKind::PullRequestMerged,
            "user_mentioned" => DomainEventKind::UserMentioned,
            "branch_pushed" => DomainEventKind::BranchPushed,
            "issue_assigned" => DomainEventKind::IssueAssigned,
            "review_requested" => DomainEventKind::ReviewRequested,
            "issue_closed" => DomainEventKind::IssueClosed,
            "issue_opened" => DomainEventKind::IssueOpened,
            "issue_commented" => DomainEventKind::IssueCommented,
            "pull_request_opened" => DomainEventKind::PullRequestOpened,
            "pull_request_closed" => DomainEventKind::PullRequestClosed,
            "pull_request_reopened" => DomainEventKind::PullRequestReopened,
            "pull_request_review_submitted" => DomainEventKind::PullRequestReviewSubmitted,
            "release_published" => DomainEventKind::ReleasePublished,
            _ => return None,
        })
    }
}

impl DomainEvent {
    /// This event's discriminant — for the `events.kind` column.
    #[must_use]
    pub const fn kind(&self) -> DomainEventKind {
        match self {
            DomainEvent::PullRequestMerged { .. } => DomainEventKind::PullRequestMerged,
            DomainEvent::UserMentioned { .. } => DomainEventKind::UserMentioned,
            DomainEvent::BranchPushed { .. } => DomainEventKind::BranchPushed,
            DomainEvent::IssueAssigned { .. } => DomainEventKind::IssueAssigned,
            DomainEvent::ReviewRequested { .. } => DomainEventKind::ReviewRequested,
            DomainEvent::IssueClosed { .. } => DomainEventKind::IssueClosed,
            DomainEvent::IssueOpened { .. } => DomainEventKind::IssueOpened,
            DomainEvent::IssueCommented { .. } => DomainEventKind::IssueCommented,
            DomainEvent::PullRequestOpened { .. } => DomainEventKind::PullRequestOpened,
            DomainEvent::PullRequestClosed { .. } => DomainEventKind::PullRequestClosed,
            DomainEvent::PullRequestReopened { .. } => DomainEventKind::PullRequestReopened,
            DomainEvent::PullRequestReviewSubmitted { .. } => {
                DomainEventKind::PullRequestReviewSubmitted
            }
            DomainEvent::ReleasePublished { .. } => DomainEventKind::ReleasePublished,
        }
    }

    /// The kind of entity this event is *about* — for the
    /// `events.aggregate_type` column. Paired with [`Self::aggregate_id`].
    #[must_use]
    pub const fn aggregate_type(&self) -> &'static str {
        match self {
            DomainEvent::PullRequestMerged { .. }
            | DomainEvent::ReviewRequested { .. }
            | DomainEvent::PullRequestOpened { .. }
            | DomainEvent::PullRequestClosed { .. }
            | DomainEvent::PullRequestReopened { .. }
            | DomainEvent::PullRequestReviewSubmitted { .. } => "pull_request",
            DomainEvent::BranchPushed { .. } => "repository",
            DomainEvent::ReleasePublished { .. } => "release",
            DomainEvent::IssueAssigned { .. }
            | DomainEvent::IssueClosed { .. }
            | DomainEvent::IssueOpened { .. }
            | DomainEvent::IssueCommented { .. } => "issue",
            DomainEvent::UserMentioned { source, .. } => match source {
                MentionSource::PullRequestComment { .. } => "pull_request",
                MentionSource::IssueComment { .. } => "issue",
            },
        }
    }

    /// The id of the entity this event is about — for the
    /// `events.aggregate_id` column. Not a foreign key (see the migration):
    /// events outlive the rows they name.
    #[must_use]
    pub fn aggregate_id(&self) -> Uuid {
        match self {
            DomainEvent::PullRequestMerged {
                pull_request_id, ..
            }
            | DomainEvent::ReviewRequested {
                pull_request_id, ..
            }
            | DomainEvent::PullRequestOpened {
                pull_request_id, ..
            }
            | DomainEvent::PullRequestClosed {
                pull_request_id, ..
            }
            | DomainEvent::PullRequestReopened {
                pull_request_id, ..
            }
            | DomainEvent::PullRequestReviewSubmitted {
                pull_request_id, ..
            } => pull_request_id.as_uuid(),
            DomainEvent::BranchPushed { repository_id, .. } => repository_id.as_uuid(),
            DomainEvent::ReleasePublished { release_id, .. } => release_id.as_uuid(),
            DomainEvent::IssueAssigned { issue_id, .. }
            | DomainEvent::IssueClosed { issue_id, .. }
            | DomainEvent::IssueOpened { issue_id, .. }
            | DomainEvent::IssueCommented { issue_id, .. } => issue_id.as_uuid(),
            DomainEvent::UserMentioned { source, .. } => match source {
                MentionSource::PullRequestComment { pull_request_id } => pull_request_id.as_uuid(),
                MentionSource::IssueComment { issue_id } => issue_id.as_uuid(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_string_matches_the_serde_tag() {
        let merged = DomainEvent::PullRequestMerged {
            pull_request_id: PullRequestId::new(),
            repository_id: RepositoryId::new(),
        };
        let json = serde_json::to_value(&merged).unwrap();
        assert_eq!(json["kind"], merged.kind().as_db_str());

        let mentioned = DomainEvent::UserMentioned {
            mentioned_user_id: UserId::new(),
            mentioned_by_user_id: UserId::new(),
            source: MentionSource::IssueComment {
                issue_id: IssueId::new(),
            },
        };
        let json = serde_json::to_value(&mentioned).unwrap();
        assert_eq!(json["kind"], mentioned.kind().as_db_str());
    }

    #[test]
    fn domain_event_kind_round_trips_through_its_string() {
        for kind in [
            DomainEventKind::PullRequestMerged,
            DomainEventKind::UserMentioned,
            DomainEventKind::BranchPushed,
            DomainEventKind::IssueAssigned,
            DomainEventKind::ReviewRequested,
            DomainEventKind::IssueClosed,
            DomainEventKind::IssueOpened,
            DomainEventKind::IssueCommented,
            DomainEventKind::PullRequestOpened,
            DomainEventKind::PullRequestClosed,
            DomainEventKind::PullRequestReopened,
            DomainEventKind::PullRequestReviewSubmitted,
            DomainEventKind::ReleasePublished,
        ] {
            assert_eq!(DomainEventKind::from_db_str(kind.as_db_str()), Some(kind));
        }
    }

    #[test]
    fn the_phase_11_events_round_trip_and_locate_their_aggregate() {
        let issue_id = IssueId::new();
        let assigned = DomainEvent::IssueAssigned {
            issue_id,
            repository_id: RepositoryId::new(),
            assignee_id: UserId::new(),
            assigned_by_id: UserId::new(),
        };
        assert_eq!(assigned.aggregate_type(), "issue");
        assert_eq!(assigned.aggregate_id(), issue_id.as_uuid());

        let pr_id = PullRequestId::new();
        let requested = DomainEvent::ReviewRequested {
            pull_request_id: pr_id,
            repository_id: RepositoryId::new(),
            reviewer_id: UserId::new(),
            requested_by_id: UserId::new(),
        };
        assert_eq!(requested.aggregate_type(), "pull_request");
        assert_eq!(requested.aggregate_id(), pr_id.as_uuid());

        for event in [assigned, requested] {
            let json = serde_json::to_string(&event).unwrap();
            assert_eq!(serde_json::from_str::<DomainEvent>(&json).unwrap(), event);
            assert_eq!(
                serde_json::to_value(&event).unwrap()["kind"],
                event.kind().as_db_str()
            );
        }
    }

    #[test]
    fn a_branch_pushed_event_round_trips_and_reports_its_repository_aggregate() {
        let repo_id = RepositoryId::new();
        let event = DomainEvent::BranchPushed {
            repository_id: repo_id,
            ref_name: "refs/heads/main".to_string(),
            old: "0".repeat(40),
            new: "a".repeat(40),
            pusher_id: Some(UserId::new()),
        };
        assert_eq!(event.aggregate_type(), "repository");
        assert_eq!(event.aggregate_id(), repo_id.as_uuid());
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(serde_json::from_str::<DomainEvent>(&json).unwrap(), event);
        assert_eq!(
            serde_json::to_value(&event).unwrap()["kind"],
            event.kind().as_db_str()
        );
    }

    #[test]
    fn a_domain_event_round_trips_through_json() {
        let event = DomainEvent::UserMentioned {
            mentioned_user_id: UserId::new(),
            mentioned_by_user_id: UserId::new(),
            source: MentionSource::PullRequestComment {
                pull_request_id: PullRequestId::new(),
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: DomainEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn aggregate_points_at_the_entity_the_event_is_about() {
        let pr_id = PullRequestId::new();
        let event = DomainEvent::PullRequestMerged {
            pull_request_id: pr_id,
            repository_id: RepositoryId::new(),
        };
        assert_eq!(event.aggregate_type(), "pull_request");
        assert_eq!(event.aggregate_id(), pr_id.as_uuid());

        let issue_id = IssueId::new();
        let event = DomainEvent::UserMentioned {
            mentioned_user_id: UserId::new(),
            mentioned_by_user_id: UserId::new(),
            source: MentionSource::IssueComment { issue_id },
        };
        assert_eq!(event.aggregate_type(), "issue");
        assert_eq!(event.aggregate_id(), issue_id.as_uuid());
    }
}

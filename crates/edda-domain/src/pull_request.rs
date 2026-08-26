//! Pull requests: the `PullRequest`/`PrReview`/`PrComment` entities and
//! `PrState`'s exhaustive state machine. This module models the *data*;
//! `access::can_merge_pull_request` (co-located with the rest of this
//! workspace's authorization decisions, not here) decides whether a given
//! merge attempt is allowed.
//!
//! **Minimal Phase 6 slice, by design, not a discovered limitation**:
//! only the merge-commit strategy exists
//! (`MergeStrategy` is a one-variant enum today, not a stringly-typed
//! column, so a squash/rebase fast-follow is an additive match arm, not a
//! migration); only same-repository pull requests are supported —
//! `PrRef` already carries a `repository_id` so a cross-repo (fork-
//! sourced) source is representable in the type, but `PullRequestRepo`
//! and every call site currently require `source.repository_id ==
//! target_repository_id`, enforced where a `PullRequest` is constructed.

use crate::ids::{PrCommentId, PrReviewId, PullRequestId, RepositoryId, UserId};

/// How a merged pull request's changes were combined into the target
/// branch. Deliberately a real enum, not a `String` column, even with a
/// single variant today — see this module's doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeStrategy {
    Merge,
}

impl MergeStrategy {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            MergeStrategy::Merge => "merge",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "merge" => Some(MergeStrategy::Merge),
            _ => None,
        }
    }
}

/// Why an issue or pull request was closed without merging — shared
/// between `PrState::Closed` and `crate::issue::IssueState::Closed`
/// since the same two reasons apply to both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Completed,
    NotPlanned,
}

impl CloseReason {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            CloseReason::Completed => "completed",
            CloseReason::NotPlanned => "not_planned",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "completed" => Some(CloseReason::Completed),
            "not_planned" => Some(CloseReason::NotPlanned),
            _ => None,
        }
    }
}

/// A pull request's source branch — a repository/branch pair rather than
/// just a branch name, so a future cross-repo (fork-sourced) PR is
/// representable without widening this type. See this module's doc
/// comment for the current same-repository-only restriction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrRef {
    pub repository_id: RepositoryId,
    pub branch: String,
}

/// Exhaustively matched everywhere a PR's state is consulted — each
/// variant carries exactly the data valid for that state, so e.g. reading
/// a merge commit out of an `Open` PR is a compile error, not a runtime
/// `None`-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrState {
    Open,
    Draft,
    Merged {
        merged_at: i64,
        merge_commit: String,
        strategy: MergeStrategy,
    },
    Closed {
        closed_at: i64,
        reason: CloseReason,
    },
}

impl PrState {
    pub fn is_open(&self) -> bool {
        matches!(self, PrState::Open | PrState::Draft)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequest {
    pub id: PullRequestId,
    pub repository_id: RepositoryId,
    /// Per-repository sequential number (`repositories/{owner}/{name}/
    /// pulls/{number}`) — shares its counter with `Issue::number` within
    /// the same repository, matching how real git hosts number the two
    /// interchangeably (`#5` may be either).
    pub number: i64,
    pub title: String,
    /// Markdown, rendered at read time (`edda-render`) — never stored
    /// pre-rendered, same reasoning as every other markdown field in this
    /// workspace.
    pub body: Option<String>,
    pub author_id: UserId,
    pub source: PrRef,
    /// A branch name within `repository_id` — always the *same*
    /// repository as `source.repository_id` in this phase's slice (see
    /// this module's doc comment).
    pub target: String,
    pub state: PrState,
    pub created_at: i64,
}

impl PullRequest {
    /// A `Merged`/`Closed` PR's source/target are logically immutable —
    /// there is currently no code path that would try to change them
    /// (no "edit PR branches" operation exists), so this exists as the
    /// named invariant a future such operation must check, not as a
    /// guard against something reachable today.
    pub fn is_finalized(&self) -> bool {
        !self.state.is_open()
    }
}

/// A reviewer's verdict on a pull request. Reviews are append-only —
/// submitting a new one never deletes an earlier one, so review history
/// is preserved; `latest_reviews` (a query-layer concern, not this type)
/// is what actually counts toward a required-approval count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewState {
    Approved,
    ChangesRequested,
    Commented,
}

impl ReviewState {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            ReviewState::Approved => "approved",
            ReviewState::ChangesRequested => "changes_requested",
            ReviewState::Commented => "commented",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "approved" => Some(ReviewState::Approved),
            "changes_requested" => Some(ReviewState::ChangesRequested),
            "commented" => Some(ReviewState::Commented),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrReview {
    pub id: PrReviewId,
    pub pull_request_id: PullRequestId,
    pub reviewer_id: UserId,
    pub state: ReviewState,
    pub body: Option<String>,
    pub created_at: i64,
}

/// Where an inline pull-request comment is anchored: a specific line (or
/// line range) of a specific file, as it appeared in a specific commit.
/// `commit_sha` is captured at comment-creation time deliberately — the
/// PR's source branch can move (more commits pushed) without silently
/// re-anchoring an existing comment to a line that no longer means the
/// same thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffAnchor {
    pub file_path: String,
    /// Inclusive `(start, end)`, 1-based — `(n, n)` for a single-line
    /// comment.
    pub line_range: (u32, u32),
    pub commit_sha: String,
}

/// A pull-request comment — either anchored to a diff line (`anchor:
/// Some`) or a general PR-level comment (`anchor: None`). Modeled as one
/// entity with an optional anchor rather than two separate tables, since
/// that's how they're actually consumed (one comment thread per PR, some
/// anchored, some not) — see this workspace's domain-entity notes on
/// avoiding a premature split for the full reasoning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrComment {
    pub id: PrCommentId,
    pub pull_request_id: PullRequestId,
    pub author_id: UserId,
    pub body: String,
    pub anchor: Option<DiffAnchor>,
    pub created_at: i64,
}

/// Reduces `reviews` to one entry per `reviewer_id` — their most recent
/// review by `created_at` — which is what actually counts toward a
/// required-approval-count decision (`access::can_merge_pull_request`).
/// Earlier reviews from the same reviewer are retained in the database
/// for history, but superseded here: a reviewer who requested changes
/// and then later approved counts as approved, not as both.
pub fn latest_reviews(reviews: &[PrReview]) -> Vec<&PrReview> {
    let mut latest: std::collections::HashMap<UserId, &PrReview> = std::collections::HashMap::new();
    for review in reviews {
        latest
            .entry(review.reviewer_id)
            .and_modify(|current| {
                if review.created_at >= current.created_at {
                    *current = review;
                }
            })
            .or_insert(review);
    }
    latest.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_open_and_draft_are_open() {
        assert!(PrState::Open.is_open());
        assert!(PrState::Draft.is_open());
        assert!(!PrState::Merged {
            merged_at: 0,
            merge_commit: "a".repeat(40),
            strategy: MergeStrategy::Merge,
        }
        .is_open());
        assert!(!PrState::Closed {
            closed_at: 0,
            reason: CloseReason::NotPlanned,
        }
        .is_open());
    }

    #[test]
    fn merge_strategy_round_trips_through_its_db_string() {
        assert_eq!(
            MergeStrategy::from_db_str(MergeStrategy::Merge.as_db_str()),
            Some(MergeStrategy::Merge)
        );
        assert_eq!(MergeStrategy::from_db_str("squash"), None);
    }

    #[test]
    fn close_reason_round_trips_through_its_db_string() {
        for reason in [CloseReason::Completed, CloseReason::NotPlanned] {
            assert_eq!(CloseReason::from_db_str(reason.as_db_str()), Some(reason));
        }
    }

    #[test]
    fn review_state_round_trips_through_its_db_string() {
        for state in [
            ReviewState::Approved,
            ReviewState::ChangesRequested,
            ReviewState::Commented,
        ] {
            assert_eq!(ReviewState::from_db_str(state.as_db_str()), Some(state));
        }
    }

    fn review(reviewer: UserId, state: ReviewState, created_at: i64) -> PrReview {
        PrReview {
            id: PrReviewId::new(),
            pull_request_id: PullRequestId::new(),
            reviewer_id: reviewer,
            state,
            body: None,
            created_at,
        }
    }

    #[test]
    fn latest_reviews_keeps_only_each_reviewers_most_recent_verdict() {
        let alice = UserId::new();
        let bob = UserId::new();
        let reviews = vec![
            review(alice, ReviewState::ChangesRequested, 100),
            review(alice, ReviewState::Approved, 200),
            review(bob, ReviewState::Approved, 150),
        ];

        let latest = latest_reviews(&reviews);
        assert_eq!(latest.len(), 2);
        let alice_latest = latest.iter().find(|r| r.reviewer_id == alice).unwrap();
        assert_eq!(alice_latest.state, ReviewState::Approved);
    }
}

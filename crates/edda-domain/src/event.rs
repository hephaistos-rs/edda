//! `DomainEvent`: "what happened," emitted by application code right
//! after a state-changing operation's persistence step commits (never
//! before — see `access::can_merge_pull_request`'s worked PR-merge
//! example for why event emission is ordered last). Exhaustively matched
//! wherever it's dispatched; a new kind of thing worth reacting to
//! asynchronously is a new variant here, never a catch-all `Other(String)`.
//!
//! Deliberately a separate type from `edda_domain::job::JobPayload`:
//! this is "what happened," that is "what work that implies" — collapsing
//! them would force every event to imply exactly one job, which doesn't
//! hold once a single event fans out to more than one (`PullRequestMerged`
//! implies both webhook delivery *and* a merge notification).

use crate::ids::{IssueId, PullRequestId, RepositoryId, UserId};

/// Where a `@mention` was written — the two comment surfaces this
/// workspace has today. Not `MentionSource::Other(String)`: a third
/// surface (e.g. a release body) becomes a new variant, not a stringly-
/// typed fallback nothing exhaustively matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MentionSource {
    PullRequestComment { pull_request_id: PullRequestId },
    IssueComment { issue_id: IssueId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainEvent {
    PullRequestMerged {
        pull_request_id: PullRequestId,
        repository_id: RepositoryId,
    },
    UserMentioned {
        mentioned_user_id: UserId,
        source: MentionSource,
    },
}

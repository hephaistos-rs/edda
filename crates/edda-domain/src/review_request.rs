//! Review request: a pending ask for one specific user to review a pull
//! request. Created automatically from a CODEOWNERS match when a PR's
//! source branch is pushed (Phase 10), or manually by a maintainer
//! (Phase 11). Distinct from a submitted `PrReview` — this is the
//! outstanding *request*, cleared once that reviewer submits.

use crate::ids::{PullRequestId, ReviewRequestId, UserId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewRequest {
    pub id: ReviewRequestId,
    pub pull_request_id: PullRequestId,
    pub reviewer_id: UserId,
    pub created_at: i64,
}

//! Branch protection: a rule naming one exact branch (no glob patterns —
//! see this module's own note in `access::can_merge_pull_request`'s doc
//! comment for why that's this phase's deliberate minimal slice) within a
//! repository. A rule's mere existence for a branch means two things,
//! both enforced by this workspace's authorization/git layers rather
//! than the database: direct pushes to that branch are rejected for
//! anyone below `RepoRole::Admin`, and merging a pull request that
//! targets it requires at least `required_approvals` latest-review
//! approvals (see `access::can_merge_pull_request`).

use crate::ids::{BranchProtectionRuleId, RepositoryId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchProtectionRule {
    pub id: BranchProtectionRuleId,
    pub repository_id: RepositoryId,
    pub branch: String,
    pub required_approvals: i64,
}

//! Branch protection: a rule whose `pattern` is a branch-name **glob**
//! (`main`, `release/*`, `v?.?`) within a repository. A rule matching a
//! branch means, all enforced by this workspace's authorization/git layers
//! rather than the database:
//!
//!   * direct pushes to a matched branch are rejected for anyone below
//!     `RepoRole::Admin` who is not in `push_allowlist` (see
//!     `edda_git`'s receive path and `edda_auth::authz`);
//!   * a push to a matched branch that would create a merge commit or a
//!     non-fast-forward is rejected when `require_linear_history`;
//!   * new commits landing on a matched branch must carry a valid
//!     signature when `require_signed_commits`;
//!   * merging a pull request whose target is a matched branch requires at
//!     least `required_approvals` latest-review approvals, every context in
//!     `required_status_checks` reporting success, and — when
//!     `require_up_to_date` — the PR branch already containing the target
//!     tip (see `access::can_merge_pull_request`);
//!   * when `dismiss_stale_reviews`, a push to a PR's source branch clears
//!     that PR's existing approvals.

use crate::access::AccessSubject;
use crate::ids::{BranchProtectionRuleId, RepositoryId};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BranchProtectionRule {
    pub id: BranchProtectionRuleId,
    pub repository_id: RepositoryId,
    /// A branch-name glob. An exact name (`main`) matches only itself; see
    /// [`branch_pattern_matches`].
    pub pattern: String,
    pub required_approvals: i64,
    pub require_linear_history: bool,
    pub require_signed_commits: bool,
    pub dismiss_stale_reviews: bool,
    pub require_up_to_date: bool,
    /// External CI check contexts that must each report success on a pull
    /// request's head commit before it may merge. Empty = no status gate.
    pub required_status_checks: Vec<String>,
    /// Subjects permitted to push directly to a matched branch despite the
    /// rule. Empty = only `RepoRole::Admin` and above may (the historical
    /// behaviour).
    pub push_allowlist: Vec<AccessSubject>,
}

impl BranchProtectionRule {
    /// Whether `subject` may push directly to a branch this rule matches —
    /// i.e. it appears in `push_allowlist`. Role-based bypass
    /// (`RepoRole::Admin`+) is decided by the caller, not here.
    #[must_use]
    pub fn allows_direct_push(&self, subject: AccessSubject) -> bool {
        self.push_allowlist.contains(&subject)
    }
}

/// Whether `branch` matches the glob `pattern`. `*` matches any run of
/// characters (path separators included, matching how mainstream git hosts
/// treat branch-protection globs); `?` matches exactly one character;
/// every other byte is literal. Branch names are short, so the plain
/// recursive backtracking matcher here is more than fast enough.
#[must_use]
pub fn branch_pattern_matches(pattern: &str, branch: &str) -> bool {
    glob_match(pattern.as_bytes(), branch.as_bytes())
}

fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) => {
            glob_match(rest, text) || (!text.is_empty() && glob_match(pattern, &text[1..]))
        }
        Some((b'?', rest)) => !text.is_empty() && glob_match(rest, &text[1..]),
        Some((byte, rest)) => text.first() == Some(byte) && glob_match(rest, &text[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_exact_pattern_matches_only_that_branch() {
        assert!(branch_pattern_matches("main", "main"));
        assert!(!branch_pattern_matches("main", "maintenance"));
        assert!(!branch_pattern_matches("main", "feature/main"));
    }

    #[test]
    fn a_star_matches_across_path_separators() {
        assert!(branch_pattern_matches("release/*", "release/1.2"));
        assert!(branch_pattern_matches("release/*", "release/1.2/rc1"));
        assert!(!branch_pattern_matches("release/*", "releases/1.2"));
        assert!(branch_pattern_matches("*", "anything/at/all"));
    }

    #[test]
    fn a_question_mark_matches_exactly_one_character() {
        assert!(branch_pattern_matches("v?.?", "v1.2"));
        assert!(!branch_pattern_matches("v?.?", "v1.22"));
        assert!(!branch_pattern_matches("v?.?", "v1."));
    }

    #[test]
    fn allowlist_membership_is_by_subject_identity() {
        let user = AccessSubject::User(crate::ids::UserId::new());
        let other = AccessSubject::User(crate::ids::UserId::new());
        let rule = BranchProtectionRule {
            push_allowlist: vec![user],
            ..Default::default()
        };
        assert!(rule.allows_direct_push(user));
        assert!(!rule.allows_direct_push(other));
    }
}

//! External commit status: a CI system's verdict on one commit, reported
//! through `POST /api/v1/repos/{owner}/{repo}/statuses/{sha}` and consulted
//! by `access::can_merge_pull_request` when the target branch's protection
//! rule lists `required_status_checks`. Edda never *runs* CI — this is the
//! reporting seam an external runner writes to.

use crate::ids::{CommitStatusId, RepositoryId};

/// A status's state. `Pending` is the initial "check started" report;
/// `Error` is an infrastructure failure (as distinct from `Failure`, the
/// check running and failing) — only `Success` satisfies a required check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitStatusState {
    Pending,
    Success,
    Failure,
    Error,
}

impl CommitStatusState {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            CommitStatusState::Pending => "pending",
            CommitStatusState::Success => "success",
            CommitStatusState::Failure => "failure",
            CommitStatusState::Error => "error",
        }
    }

    #[must_use]
    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(CommitStatusState::Pending),
            "success" => Some(CommitStatusState::Success),
            "failure" => Some(CommitStatusState::Failure),
            "error" => Some(CommitStatusState::Error),
            _ => None,
        }
    }

    /// Whether this state satisfies a required status check.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, CommitStatusState::Success)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitStatus {
    pub id: CommitStatusId,
    pub repository_id: RepositoryId,
    pub commit_sha: String,
    /// The check's identifier (`ci/build`, `lint`) — a repeat report for
    /// the same context overwrites the previous one.
    pub context: String,
    pub state: CommitStatusState,
    pub target_url: Option<String>,
    pub description: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Whether every context in `required` has a `Success` status among
/// `statuses` (the set already fetched for a pull request's head commit).
/// An empty `required` is trivially satisfied.
#[must_use]
pub fn required_checks_satisfied(required: &[String], statuses: &[CommitStatus]) -> bool {
    required.iter().all(|context| {
        statuses
            .iter()
            .any(|status| &status.context == context && status.state.is_success())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(context: &str, state: CommitStatusState) -> CommitStatus {
        CommitStatus {
            id: CommitStatusId::new(),
            repository_id: RepositoryId::new(),
            commit_sha: "a".repeat(40),
            context: context.to_string(),
            state,
            target_url: None,
            description: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn state_round_trips_through_its_db_string() {
        for state in [
            CommitStatusState::Pending,
            CommitStatusState::Success,
            CommitStatusState::Failure,
            CommitStatusState::Error,
        ] {
            assert_eq!(
                CommitStatusState::from_db_str(state.as_db_str()),
                Some(state)
            );
        }
        assert_eq!(CommitStatusState::from_db_str("bogus"), None);
    }

    #[test]
    fn no_required_checks_is_always_satisfied() {
        assert!(required_checks_satisfied(&[], &[]));
    }

    #[test]
    fn every_required_context_needs_its_own_success() {
        let required = vec!["ci/build".to_string(), "lint".to_string()];
        let statuses = vec![
            status("ci/build", CommitStatusState::Success),
            status("lint", CommitStatusState::Failure),
        ];
        assert!(!required_checks_satisfied(&required, &statuses));

        let statuses = vec![
            status("ci/build", CommitStatusState::Success),
            status("lint", CommitStatusState::Success),
            status("lint", CommitStatusState::Pending),
        ];
        // One `Success` for `lint` is enough even if another row is pending.
        assert!(required_checks_satisfied(&required, &statuses));
    }
}

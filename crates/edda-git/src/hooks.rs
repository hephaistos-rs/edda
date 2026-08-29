//! The receive-hook model: the structured extension point the receive
//! path consults to decide whether a push may land, and what it reports
//! back once it has.
//!
//! `edda-git` owns no notion of *why* a branch is protected or *who* is
//! pushing — it has no `edda-db`/`edda-auth` dependency (see the crate
//! root). The caller (each transport, via `edda_auth::authz`) resolves the
//! branch-protection rules, the pusher's role, the push allowlist, and the
//! size quota into a plain [`ReceiveChecks`], and this module enforces
//! them inside the blocking receive section:
//!
//!   * **before** the pack is ingested: the size quota and the
//!     direct-push block (glob-matched protected refs);
//!   * **after** the pack is promoted (so every new commit resolves): the
//!     linear-history and signed-commit shape checks.
//!
//! Any rejection fails the whole push atomically — the pack is rolled back
//! out and no ref moves.

use edda_domain::branch_pattern_matches;

use crate::history;
use crate::protocol::RefCommand;
use crate::ZERO_ID;

/// The resolved branch-protection / quota state a push is checked against.
/// Every field is plain data the caller assembles; an all-empty value
/// (the common case) means "no restriction".
#[derive(Debug, Default, Clone)]
pub struct ReceiveChecks {
    /// Full-ref-name globs (`refs/heads/release/*`) a direct push may not
    /// update. The caller has already removed rules this pusher bypasses
    /// (Admin/Owner, or listed in the rule's push allowlist).
    pub blocked_ref_patterns: Vec<String>,
    /// Full-ref-name globs whose branches must keep a linear history — a
    /// non-fast-forward update or an added merge commit is rejected.
    pub linear_history_ref_patterns: Vec<String>,
    /// Full-ref-name globs whose newly-pushed commits must each carry a
    /// signature header.
    pub signed_commit_ref_patterns: Vec<String>,
    /// Reject the push if promoting its pack would take the repository past
    /// this many bytes. `None` disables the quota.
    pub max_repo_bytes: Option<u64>,
    /// The repository's last-measured on-disk size (git objects + LFS).
    pub current_repo_bytes: u64,
}

impl ReceiveChecks {
    /// Nothing to enforce — the receive path can skip every hook step.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocked_ref_patterns.is_empty()
            && self.linear_history_ref_patterns.is_empty()
            && self.signed_commit_ref_patterns.is_empty()
            && self.max_repo_bytes.is_none()
    }
}

/// One ref update that actually landed — the input the transport's
/// post-receive fan-out (the `push` domain event, `UpdateRepoSize`, …)
/// works from. Hex ids; [`ZERO_ID`] for a create's `old` or a delete's
/// `new`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedRef {
    pub name: String,
    pub old: String,
    pub new: String,
}

impl AppliedRef {
    #[must_use]
    pub fn is_create(&self) -> bool {
        self.old == ZERO_ID
    }

    #[must_use]
    pub fn is_delete(&self) -> bool {
        self.new == ZERO_ID
    }

    /// The short branch name for a `refs/heads/*` update, else `None`.
    #[must_use]
    pub fn branch(&self) -> Option<&str> {
        self.name.strip_prefix("refs/heads/")
    }
}

/// What a completed `receive-pack` produced: the wire bytes to send back,
/// and the ref updates that landed (empty when the push was rejected).
#[derive(Debug)]
pub struct ReceiveOutcome {
    pub response: Vec<u8>,
    pub applied: Vec<AppliedRef>,
}

fn any_pattern_matches(patterns: &[String], ref_name: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| branch_pattern_matches(pattern, ref_name))
}

/// The size-quota gate — evaluated before the pack is ingested.
/// `incoming_pack_bytes` is the request's pack section length, a close
/// enough proxy for how much the store is about to grow.
pub(crate) fn quota_rejection(checks: &ReceiveChecks, incoming_pack_bytes: u64) -> Option<String> {
    let max = checks.max_repo_bytes?;
    let projected = checks
        .current_repo_bytes
        .saturating_add(incoming_pack_bytes);
    (projected > max).then(|| {
        format!(
            "push rejected: it would grow the repository to about {projected} bytes, \
             past the configured {max}-byte limit"
        )
    })
}

/// The direct-push block — evaluated before the pack is ingested. Returns
/// the rejection message for the first command that targets a blocked ref.
pub(crate) fn blocked_ref_rejection(
    checks: &ReceiveChecks,
    commands: &[RefCommand],
) -> Option<String> {
    commands.iter().find_map(|command| {
        any_pattern_matches(&checks.blocked_ref_patterns, &command.ref_name).then(|| {
            format!(
                "{}: protected branch — open a pull request instead",
                command.ref_name
            )
        })
    })
}

/// The history-shape checks (linear history, signed commits) — evaluated
/// after the pack is promoted, so every added commit resolves against the
/// live store. Returns the first rejection, or `None` if the push may
/// land. Inconclusive inspection (a walk that hit its bound, an
/// unreadable object) fails **open**: rejecting a legitimate large push is
/// the worse outcome.
pub(crate) fn history_rejection(
    repo: &gix::Repository,
    checks: &ReceiveChecks,
    commands: &[RefCommand],
) -> Option<String> {
    for command in commands {
        if command.new_id == ZERO_ID {
            continue;
        }
        let needs_linear =
            any_pattern_matches(&checks.linear_history_ref_patterns, &command.ref_name);
        let needs_signed =
            any_pattern_matches(&checks.signed_commit_ref_patterns, &command.ref_name);
        if !needs_linear && !needs_signed {
            continue;
        }

        let added = match history::added_commits(repo, &command.old_id, &command.new_id) {
            Ok(added) => added,
            Err(err) => {
                tracing::warn!(
                    ref_name = %command.ref_name,
                    error = %err,
                    "receive hook: could not inspect pushed history — accepting the push"
                );
                continue;
            }
        };

        if needs_linear {
            if !added.is_fast_forward {
                return Some(format!(
                    "{}: non-fast-forward push to a linear-history branch",
                    command.ref_name
                ));
            }
            if !added.truncated {
                if let Some(merge) = added
                    .commits
                    .iter()
                    .find(|id| history::is_merge_commit(repo, **id))
                {
                    return Some(format!(
                        "{}: merge commit {merge} — this branch requires a linear history",
                        command.ref_name
                    ));
                }
            }
        }

        if needs_signed && !added.truncated {
            if let Some(unsigned) = added
                .commits
                .iter()
                .find(|id| !history::commit_is_signed(repo, **id))
            {
                return Some(format!(
                    "{}: commit {unsigned} is unsigned — this branch requires signed commits",
                    command.ref_name
                ));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(ref_name: &str) -> RefCommand {
        RefCommand {
            old_id: ZERO_ID.to_string(),
            new_id: "a".repeat(40),
            ref_name: ref_name.to_string(),
        }
    }

    #[test]
    fn the_quota_gate_only_fires_over_the_limit() {
        let checks = ReceiveChecks {
            max_repo_bytes: Some(1_000),
            current_repo_bytes: 900,
            ..Default::default()
        };
        assert!(quota_rejection(&checks, 100).is_none());
        assert!(quota_rejection(&checks, 101).is_some());

        // No limit configured — never fires.
        let no_limit = ReceiveChecks {
            current_repo_bytes: 10_000_000,
            ..Default::default()
        };
        assert!(quota_rejection(&no_limit, 10_000_000).is_none());
    }

    #[test]
    fn the_direct_push_block_is_glob_matched() {
        let checks = ReceiveChecks {
            blocked_ref_patterns: vec!["refs/heads/release/*".to_string()],
            ..Default::default()
        };
        assert!(blocked_ref_rejection(&checks, &[update("refs/heads/release/1.2")]).is_some());
        assert!(blocked_ref_rejection(&checks, &[update("refs/heads/main")]).is_none());
        // Rejection message names the offending ref.
        let reason = blocked_ref_rejection(&checks, &[update("refs/heads/release/9")]).unwrap();
        assert!(reason.contains("refs/heads/release/9"));
    }

    #[test]
    fn empty_checks_are_a_noop() {
        assert!(ReceiveChecks::default().is_empty());
        assert!(!ReceiveChecks {
            max_repo_bytes: Some(1),
            ..Default::default()
        }
        .is_empty());
    }
}

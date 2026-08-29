//! Commit-graph inspection for the receive path's branch-protection
//! checks: what commits a ref update adds, whether it is a fast-forward,
//! and whether those commits carry signatures. Read-only, synchronous —
//! called from inside the blocking receive section after the pack is
//! promoted, so every object it names resolves against the live store.

use std::collections::HashSet;

use gix::ObjectId;

use crate::GitError;

/// Hard ceiling on the `old..new` walk. A push adding more commits than
/// this to a protected branch is unusual; rather than spend unbounded time
/// verifying it, the checks that use this fail **open** (accept the push)
/// and log — rejecting a legitimate large push is the worse outcome.
const MAX_WALK: usize = 4_000;

/// The commits a ref update from `old` to `new` adds, plus whether `old`
/// was an ancestor of `new` (a fast-forward).
pub struct AddedCommits {
    /// Commits reachable from `new` but not from `old` (or all of `new`'s
    /// history when `old` is `None` — a branch create), newest-first,
    /// capped at [`MAX_WALK`].
    pub commits: Vec<ObjectId>,
    /// `false` means the update is **not** a fast-forward (`old` is not an
    /// ancestor of `new`). Always `true` for a branch create.
    pub is_fast_forward: bool,
    /// The walk hit [`MAX_WALK`] before finishing — callers that must not
    /// reject a valid push should treat their check as inconclusive.
    pub truncated: bool,
}

/// Walks `old..new`. `old`/`new` are hex object ids; `old` empty (or
/// all-zero) means "no previous value" (a branch create).
pub fn added_commits(
    repo: &gix::Repository,
    old_hex: &str,
    new_hex: &str,
) -> Result<AddedCommits, GitError> {
    let new = ObjectId::from_hex(new_hex.as_bytes())
        .map_err(|_| GitError::Git(format!("not a valid object id: {new_hex}")))?;
    let old = if old_hex.is_empty() || old_hex.chars().all(|c| c == '0') {
        None
    } else {
        Some(
            ObjectId::from_hex(old_hex.as_bytes())
                .map_err(|_| GitError::Git(format!("not a valid object id: {old_hex}")))?,
        )
    };

    // Everything reachable from `old` is the boundary — we stop descending
    // there. Bounded the same way as the forward walk.
    let mut boundary: HashSet<ObjectId> = HashSet::new();
    if let Some(old) = old {
        let mut queue = vec![old];
        while let Some(id) = queue.pop() {
            if boundary.len() >= MAX_WALK {
                break;
            }
            if !boundary.insert(id) {
                continue;
            }
            if let Some(parents) = commit_parents(repo, id) {
                queue.extend(parents);
            }
        }
    }

    let mut commits = Vec::new();
    let mut seen: HashSet<ObjectId> = HashSet::new();
    let mut queue = vec![new];
    let mut truncated = false;
    while let Some(id) = queue.pop() {
        if boundary.contains(&id) || !seen.insert(id) {
            continue;
        }
        if commits.len() >= MAX_WALK {
            truncated = true;
            break;
        }
        commits.push(id);
        if let Some(parents) = commit_parents(repo, id) {
            queue.extend(parents);
        }
    }

    // A fast-forward iff `old` is reachable from `new`. The forward walk
    // above stops at the boundary, so reachability is checked with its own
    // bounded walk.
    let is_fast_forward = match old {
        None => true,
        Some(old) => is_ancestor(repo, old, new),
    };

    Ok(AddedCommits {
        commits,
        is_fast_forward,
        truncated,
    })
}

/// Whether `ancestor` is reachable from `descendant` (a bounded walk).
pub fn is_ancestor(repo: &gix::Repository, ancestor: ObjectId, descendant: ObjectId) -> bool {
    if ancestor == descendant {
        return true;
    }
    let mut seen: HashSet<ObjectId> = HashSet::new();
    let mut queue = vec![descendant];
    let mut steps = 0usize;
    while let Some(id) = queue.pop() {
        steps += 1;
        if steps > MAX_WALK {
            return false;
        }
        if !seen.insert(id) {
            continue;
        }
        if id == ancestor {
            return true;
        }
        if let Some(parents) = commit_parents(repo, id) {
            queue.extend(parents);
        }
    }
    false
}

/// A commit's parent ids, or `None` if `id` is not a commit / cannot be
/// read (a missing object is the fsck step's problem, not this one's).
fn commit_parents(repo: &gix::Repository, id: ObjectId) -> Option<Vec<ObjectId>> {
    let object = repo.find_object(id).ok()?;
    let commit = object.try_into_commit().ok()?;
    Some(commit.parent_ids().map(|id| id.detach()).collect())
}

/// Whether `id` is a merge commit (more than one parent).
pub fn is_merge_commit(repo: &gix::Repository, id: ObjectId) -> bool {
    commit_parents(repo, id).is_some_and(|parents| parents.len() > 1)
}

/// Whether the commit `id` carries a signature header (`gpgsig` /
/// `gpgsig-sha256` — git's names for both OpenPGP and SSH signatures).
/// Edda does not *verify* the signature against a keyring here — that
/// needs a per-user key store this phase does not build — only that one is
/// present, which is what `require_signed_commits` gates on for now.
pub fn commit_is_signed(repo: &gix::Repository, id: ObjectId) -> bool {
    let Ok(object) = repo.find_object(id) else {
        return false;
    };
    let Ok(commit) = gix_object::CommitRef::from_bytes(&object.data, gix_hash::Kind::Sha1) else {
        return false;
    };
    commit.extra_headers.iter().any(|(name, _)| {
        let name: &[u8] = name;
        name == b"gpgsig" || name == b"gpgsig-sha256"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "edda-git-history-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        gix::init_bare(&dir).unwrap();
        dir
    }

    fn empty_tree(repo: &gix::Repository) -> ObjectId {
        repo.write_object(gix_object::Tree::empty())
            .unwrap()
            .detach()
    }

    fn commit(
        repo: &gix::Repository,
        tree: ObjectId,
        parents: &[ObjectId],
        msg: &str,
        signed: bool,
    ) -> ObjectId {
        let sig = gix_actor::Signature {
            name: "t".into(),
            email: "t@e".into(),
            time: gix::date::Time::new(1_700_000_000, 0),
        };
        let extra_headers = if signed {
            vec![(
                "gpgsig".into(),
                "-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----".into(),
            )]
        } else {
            Vec::new()
        };
        repo.write_object(gix_object::Commit {
            tree,
            parents: parents.iter().copied().collect(),
            author: sig.clone(),
            committer: sig,
            encoding: None,
            message: msg.into(),
            extra_headers,
        })
        .unwrap()
        .detach()
    }

    #[test]
    fn added_commits_reports_only_the_new_range_and_fast_forward() {
        let dir = tmp("added");
        let repo = gix::open(&dir).unwrap();
        let tree = empty_tree(&repo);
        let c1 = commit(&repo, tree, &[], "one", false);
        let c2 = commit(&repo, tree, &[c1], "two", false);
        let c3 = commit(&repo, tree, &[c2], "three", false);

        let added = added_commits(&repo, &c1.to_string(), &c3.to_string()).unwrap();
        assert!(added.is_fast_forward);
        assert!(!added.truncated);
        assert_eq!(added.commits.len(), 2, "c2 and c3, not c1");
        assert!(added.commits.contains(&c2) && added.commits.contains(&c3));

        // A create (no old) walks the whole history.
        let created = added_commits(&repo, ZERO_HEX, &c3.to_string()).unwrap();
        assert!(created.is_fast_forward);
        assert_eq!(created.commits.len(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_diverged_update_is_not_a_fast_forward() {
        let dir = tmp("diverge");
        let repo = gix::open(&dir).unwrap();
        let tree = empty_tree(&repo);
        let base = commit(&repo, tree, &[], "base", false);
        let a = commit(&repo, tree, &[base], "branch a", false);
        let b = commit(&repo, tree, &[base], "branch b", false);

        assert!(
            !added_commits(&repo, &a.to_string(), &b.to_string())
                .unwrap()
                .is_fast_forward
        );
        assert!(
            added_commits(&repo, &base.to_string(), &b.to_string())
                .unwrap()
                .is_fast_forward
        );
    }

    #[test]
    fn merge_and_signature_predicates_read_the_commit_object() {
        let dir = tmp("merge-sig");
        let repo = gix::open(&dir).unwrap();
        let tree = empty_tree(&repo);
        let a = commit(&repo, tree, &[], "a", true);
        let b = commit(&repo, tree, &[], "b", false);
        let merge = commit(&repo, tree, &[a, b], "merge", false);

        assert!(is_merge_commit(&repo, merge));
        assert!(!is_merge_commit(&repo, a));
        assert!(commit_is_signed(&repo, a));
        assert!(!commit_is_signed(&repo, b));

        let _ = std::fs::remove_dir_all(&dir);
    }

    const ZERO_HEX: &str = "0000000000000000000000000000000000000000";
}

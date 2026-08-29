//! Pull-request merging — all four strategies a real git host offers:
//! merge commit, squash, rebase, and fast-forward-only. The three-way
//! tree merges go through `gix`'s own merge support
//! (`Repository::merge_commits` / `merge_trees`) — never a hand-rolled
//! three-way merge. `gix` 0.86's merge support was verified mature enough
//! for this (a real recursive three-way tree merge with rename tracking
//! and per-hunk text conflict detection, not a naive whole-file diff)
//! with a real `cargo build` in an isolated probe project before
//! adoption, the same discipline this workspace already applies to every
//! dependency decision — so there is no `git2`/libgit2 fallback here.
//!
//! The caller (`edda-app`'s `PullRequestService::merge`) is responsible
//! for holding `LockRegistry`'s per-repository lock for the *entire*
//! merge-and-record sequence, not just one of these calls — see that
//! service's own doc comment for why the lock must still be held while the
//! pull request's row is updated afterward.

use edda_domain::MergeStrategy;

use crate::diff::resolve_commit_id;
use crate::refs::{update_refs, RefUpdate};
use crate::store::RepoStore;
use crate::{open_repo_dir, record_git_op, GitError};

/// The upper bound on how many commits a rebase-merge will replay. A pull
/// request with more unique commits than this is pathological to rebase
/// one-by-one; the maintainer can still merge or squash it.
const MAX_REBASE_COMMITS: usize = 256;

#[derive(Debug)]
pub struct MergeOutcome {
    /// The new merge commit's id, hex-encoded.
    pub merge_commit: String,
}

/// Merges `source_branch` into `target_branch` with a real merge commit
/// (two parents: `target_branch`'s current tip, then `source_branch`'s) —
/// always, even when a fast-forward would be possible, matching what a
/// "create a merge commit" button on a real git host does. Updates
/// `target_branch` to point at the new commit. Returns
/// `GitError::Conflict` (not `Ok`) if the merge left any unresolved
/// conflict — there is no in-browser conflict-resolution UI, so a
/// conflicting merge simply cannot complete via this path.
pub fn merge_branches(
    store: &dyn RepoStore,
    name: &str,
    source_branch: &str,
    target_branch: &str,
    committer_name: &str,
    committer_email: &str,
    message: &str,
) -> Result<MergeOutcome, GitError> {
    merge_ref_into_branch(
        store,
        name,
        &format!("refs/heads/{source_branch}"),
        source_branch,
        target_branch,
        committer_name,
        committer_email,
        message,
    )
}

/// The strategy-aware entry point `PullRequestService::merge` calls. The
/// incoming side is an arbitrary fully-qualified ref — a plain
/// `refs/heads/…`, or the Edda-internal `refs/edda/pull-heads/…` that
/// [`crate::transfer::import_branch_tip`] writes for a fork-sourced pull
/// request. Everything is written into `name`'s repository only; a
/// fork-sourced merge never touches the fork.
///
/// - [`MergeStrategy::Merge`] — a two-parent merge commit ([`merge_ref_into_branch`]).
/// - [`MergeStrategy::Squash`] — one commit on `target`, single parent
///   `target`'s tip, tree = the merge result.
/// - [`MergeStrategy::Rebase`] — replay `source`'s unique first-parent
///   commits one-by-one onto `target`'s tip, preserving their authorship
///   and messages; no merge commit.
/// - [`MergeStrategy::FastForwardOnly`] — move `target` to `source`'s tip
///   iff that is a fast-forward, else `GitError::NotFastForward`.
#[allow(clippy::too_many_arguments)]
pub fn merge_pull_request(
    store: &dyn RepoStore,
    name: &str,
    source_ref: &str,
    source_label: &str,
    target_branch: &str,
    strategy: MergeStrategy,
    committer_name: &str,
    committer_email: &str,
    message: &str,
) -> Result<MergeOutcome, GitError> {
    match strategy {
        MergeStrategy::Merge => merge_ref_into_branch(
            store,
            name,
            source_ref,
            source_label,
            target_branch,
            committer_name,
            committer_email,
            message,
        ),
        MergeStrategy::Squash => squash_ref_into_branch(
            store,
            name,
            source_ref,
            source_label,
            target_branch,
            committer_name,
            committer_email,
            message,
        ),
        MergeStrategy::Rebase => rebase_ref_onto_branch(
            store,
            name,
            source_ref,
            target_branch,
            committer_name,
            committer_email,
        ),
        MergeStrategy::FastForwardOnly => {
            fast_forward_branch_to_ref(store, name, source_ref, target_branch)
        }
    }
}

/// Resolves both sides and runs the recursive three-way merge, returning
/// the merged tree's id. `GitError::Conflict` if it left any unresolved
/// conflict — nothing is written to a ref in that case.
fn three_way_merged_tree(
    repo: &gix::Repository,
    target_id: gix_hash::ObjectId,
    source_id: gix_hash::ObjectId,
    target_branch: &str,
    source_label: &str,
) -> Result<gix_hash::ObjectId, GitError> {
    let tree_merge_options = repo
        .tree_merge_options()
        .map_err(|err| GitError::Git(err.to_string()))?;
    let labels = gix::merge::blob::builtin_driver::text::Labels {
        ancestor: None,
        current: Some(target_branch.into()),
        other: Some(source_label.into()),
    };
    let outcome = repo
        .merge_commits(target_id, source_id, labels, tree_merge_options.into())
        .map_err(|err| GitError::Git(err.to_string()))?;
    if outcome
        .tree_merge
        .has_unresolved_conflicts(gix::merge::tree::TreatAsUnresolved::undecidable())
    {
        return Err(GitError::Conflict(outcome.tree_merge.conflicts.len()));
    }
    let mut tree_editor = outcome.tree_merge.tree;
    Ok(tree_editor
        .write()
        .map_err(|err| GitError::Git(err.to_string()))?
        .detach())
}

/// Like [`merge_branches`], but the incoming side is an arbitrary
/// fully-qualified ref rather than a local branch name. `source_label` is
/// the human name that appears in conflict markers for the incoming side
/// (`merge_branches` passes the branch name; the cross-repo caller passes
/// `owner:branch`).
#[allow(clippy::too_many_arguments)]
pub fn merge_ref_into_branch(
    store: &dyn RepoStore,
    name: &str,
    source_ref: &str,
    source_label: &str,
    target_branch: &str,
    committer_name: &str,
    committer_email: &str,
    message: &str,
) -> Result<MergeOutcome, GitError> {
    let repo = open_repo_dir(store, name)?;
    let span = tracing::info_span!(
        "git.merge",
        repo.name = %name,
        merge.source = %source_label,
        merge.target = %target_branch,
        merge.strategy = "merge",
    );
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let source_id = resolve_commit_id(&repo, source_ref)?;
        let target_ref_name = format!("refs/heads/{target_branch}");
        let target_id = resolve_commit_id(&repo, &target_ref_name)?;

        let tree_id =
            three_way_merged_tree(&repo, target_id, source_id, target_branch, source_label)?;
        let signature = signature_now(committer_name, committer_email);
        let commit = gix_object::Commit {
            tree: tree_id,
            parents: [target_id, source_id].into_iter().collect(),
            author: signature.clone(),
            committer: signature,
            encoding: None,
            message: message.into(),
            extra_headers: Vec::new(),
        };
        let commit_id = write_commit(&repo, commit)?;
        move_branch(&repo, &target_ref_name, target_id, commit_id, "merge")?;
        Ok(MergeOutcome {
            merge_commit: commit_id.to_string(),
        })
    })();
    record_git_op("git.merge", start, &result);
    result
}

/// Squash-merge: the same three-way merge as [`merge_ref_into_branch`],
/// but the new commit has a *single* parent (`target`'s tip), so the
/// source branch's individual commits do not enter `target`'s history.
#[allow(clippy::too_many_arguments)]
pub fn squash_ref_into_branch(
    store: &dyn RepoStore,
    name: &str,
    source_ref: &str,
    source_label: &str,
    target_branch: &str,
    committer_name: &str,
    committer_email: &str,
    message: &str,
) -> Result<MergeOutcome, GitError> {
    let repo = open_repo_dir(store, name)?;
    let span = tracing::info_span!(
        "git.merge",
        repo.name = %name,
        merge.source = %source_label,
        merge.target = %target_branch,
        merge.strategy = "squash",
    );
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let source_id = resolve_commit_id(&repo, source_ref)?;
        let target_ref_name = format!("refs/heads/{target_branch}");
        let target_id = resolve_commit_id(&repo, &target_ref_name)?;

        let tree_id =
            three_way_merged_tree(&repo, target_id, source_id, target_branch, source_label)?;
        let signature = signature_now(committer_name, committer_email);
        let commit = gix_object::Commit {
            tree: tree_id,
            parents: [target_id].into_iter().collect(),
            author: signature.clone(),
            committer: signature,
            encoding: None,
            message: message.into(),
            extra_headers: Vec::new(),
        };
        let commit_id = write_commit(&repo, commit)?;
        move_branch(&repo, &target_ref_name, target_id, commit_id, "squash")?;
        Ok(MergeOutcome {
            merge_commit: commit_id.to_string(),
        })
    })();
    record_git_op("git.merge", start, &result);
    result
}

/// Fast-forward-only: move `target_branch` to `source_ref`'s commit iff
/// `target` can reach it by fast-forward (no divergent history). No new
/// commit is written. `GitError::NotFastForward` if the histories have
/// diverged.
pub fn fast_forward_branch_to_ref(
    store: &dyn RepoStore,
    name: &str,
    source_ref: &str,
    target_branch: &str,
) -> Result<MergeOutcome, GitError> {
    let repo = open_repo_dir(store, name)?;
    let span = tracing::info_span!(
        "git.merge",
        repo.name = %name,
        merge.target = %target_branch,
        merge.strategy = "fast_forward",
    );
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let source_id = resolve_commit_id(&repo, source_ref)?;
        let target_ref_name = format!("refs/heads/{target_branch}");
        let target_id = resolve_commit_id(&repo, &target_ref_name)?;

        if source_id == target_id {
            return Ok(MergeOutcome {
                merge_commit: source_id.to_string(),
            });
        }
        let base = repo
            .merge_base(target_id, source_id)
            .map(gix::Id::detach)
            .map_err(|err| GitError::Git(err.to_string()))?;
        if base != target_id {
            return Err(GitError::NotFastForward);
        }
        move_branch(
            &repo,
            &target_ref_name,
            target_id,
            source_id,
            "fast-forward",
        )?;
        Ok(MergeOutcome {
            merge_commit: source_id.to_string(),
        })
    })();
    record_git_op("git.merge", start, &result);
    result
}

/// Rebase-merge: replay the commits unique to `source_ref` (its
/// first-parent chain back to the merge base with `target`) one-by-one
/// onto `target`'s tip, preserving each commit's original author and
/// message, then move `target_branch` to the last replayed commit. No
/// merge commit. `GitError::Conflict` if any replay step conflicts;
/// `GitError::Git` if the source has more than `MAX_REBASE_COMMITS` unique
/// commits.
pub fn rebase_ref_onto_branch(
    store: &dyn RepoStore,
    name: &str,
    source_ref: &str,
    target_branch: &str,
    committer_name: &str,
    committer_email: &str,
) -> Result<MergeOutcome, GitError> {
    let repo = open_repo_dir(store, name)?;
    let span = tracing::info_span!(
        "git.merge",
        repo.name = %name,
        merge.target = %target_branch,
        merge.strategy = "rebase",
    );
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let source_id = resolve_commit_id(&repo, source_ref)?;
        let target_ref_name = format!("refs/heads/{target_branch}");
        let target_id = resolve_commit_id(&repo, &target_ref_name)?;

        let base = repo
            .merge_base(source_id, target_id)
            .map(gix::Id::detach)
            .map_err(|err| GitError::Git(err.to_string()))?;

        // The first-parent chain from source back to (not including) the
        // merge base — the commits `source` adds over `target`.
        let mut to_replay = Vec::new();
        let mut cursor = source_id;
        while cursor != base {
            let commit = repo
                .find_commit(cursor)
                .map_err(|err| GitError::Git(err.to_string()))?;
            to_replay.push(cursor);
            if to_replay.len() > MAX_REBASE_COMMITS {
                return Err(GitError::Git(format!(
                    "refusing to rebase more than {MAX_REBASE_COMMITS} commits"
                )));
            }
            let first_parent = commit.parent_ids().next().map(|id| id.detach());
            match first_parent {
                Some(parent) => cursor = parent,
                None => break,
            }
        }
        to_replay.reverse();

        if to_replay.is_empty() {
            // `source` is already contained in `target`.
            return Ok(MergeOutcome {
                merge_commit: target_id.to_string(),
            });
        }

        let merge_options = repo
            .tree_merge_options()
            .map_err(|err| GitError::Git(err.to_string()))?;
        let mut tip = target_id;
        for original in &to_replay {
            let commit = repo
                .find_commit(*original)
                .map_err(|err| GitError::Git(err.to_string()))?;
            let first_parent = commit.parent_ids().next().map(|id| id.detach());
            let parent_tree = match first_parent {
                Some(parent) => tree_id_of(&repo, parent)?,
                None => repo.empty_tree().id().detach(),
            };
            let our_tree = tree_id_of(&repo, tip)?;
            let their_tree = tree_id_of(&repo, *original)?;
            let labels = gix::merge::blob::builtin_driver::text::Labels {
                ancestor: None,
                current: Some(target_branch.into()),
                other: Some("source".into()),
            };
            let merged = repo
                .merge_trees(
                    parent_tree,
                    our_tree,
                    their_tree,
                    labels,
                    merge_options.clone(),
                )
                .map_err(|err| GitError::Git(err.to_string()))?;
            if merged.has_unresolved_conflicts(gix::merge::tree::TreatAsUnresolved::undecidable()) {
                return Err(GitError::Conflict(merged.conflicts.len()));
            }
            let mut tree_editor = merged.tree;
            let new_tree = tree_editor
                .write()
                .map_err(|err| GitError::Git(err.to_string()))?
                .detach();

            let decoded = commit
                .decode()
                .map_err(|err| GitError::Git(err.to_string()))?;
            let author = decoded
                .author()
                .map_err(|err| GitError::Git(err.to_string()))?
                .to_owned()
                .map_err(|err| GitError::Git(err.to_string()))?;
            let replayed = gix_object::Commit {
                tree: new_tree,
                parents: [tip].into_iter().collect(),
                author,
                committer: signature_now(committer_name, committer_email),
                encoding: decoded.encoding.map(ToOwned::to_owned),
                message: decoded.message.to_owned(),
                extra_headers: Vec::new(),
            };
            tip = write_commit(&repo, replayed)?;
        }

        move_branch(&repo, &target_ref_name, target_id, tip, "rebase")?;
        Ok(MergeOutcome {
            merge_commit: tip.to_string(),
        })
    })();
    record_git_op("git.merge", start, &result);
    result
}

fn signature_now(name: &str, email: &str) -> gix_actor::Signature {
    gix_actor::Signature {
        name: name.into(),
        email: email.into(),
        time: gix::date::Time::now_utc(),
    }
}

fn write_commit(
    repo: &gix::Repository,
    commit: gix_object::Commit,
) -> Result<gix_hash::ObjectId, GitError> {
    Ok(repo
        .write_object(commit)
        .map_err(|err| GitError::Git(err.to_string()))?
        .detach())
}

fn tree_id_of(
    repo: &gix::Repository,
    commit_id: gix_hash::ObjectId,
) -> Result<gix_hash::ObjectId, GitError> {
    Ok(repo
        .find_commit(commit_id)
        .map_err(|err| GitError::Git(err.to_string()))?
        .tree_id()
        .map_err(|err| GitError::Git(err.to_string()))?
        .detach())
}

/// Atomically move `ref_name` from `expected_old` to `new` (packed-refs
/// aware compare-and-swap, with a reflog entry).
fn move_branch(
    repo: &gix::Repository,
    ref_name: &str,
    expected_old: gix_hash::ObjectId,
    new: gix_hash::ObjectId,
    reflog_message: &str,
) -> Result<(), GitError> {
    update_refs(
        repo,
        &[RefUpdate {
            name: ref_name.to_string(),
            expected_old: expected_old.to_string(),
            new: new.to_string(),
        }],
        reflog_message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LocalFsStore;
    use crate::{create_repo, force_set_ref, LockRegistry};
    use std::path::PathBuf;

    struct TestStore {
        store: LocalFsStore,
        root: PathBuf,
    }

    impl TestStore {
        fn new(unique: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "edda-git-merge-test-{unique}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            Self {
                store: LocalFsStore::new(root.clone()),
                root,
            }
        }
    }

    impl Drop for TestStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// Same hand-built commit-writing helper `diff.rs`'s tests use — see
    /// that module's identical helper for the full reasoning.
    fn commit_files(
        repo_dir: &std::path::Path,
        branch: &str,
        parent: Option<gix::ObjectId>,
        files: &[(&str, &[u8])],
    ) -> gix::ObjectId {
        let repo = gix::open(repo_dir).unwrap();

        let parent_tree_id = match parent {
            Some(id) => repo.find_commit(id).unwrap().tree_id().unwrap().detach(),
            None => repo.empty_tree().id().detach(),
        };
        let mut tree_editor = repo.edit_tree(parent_tree_id).unwrap();
        for (path, content) in files {
            let blob_id = repo.write_blob(*content).unwrap().detach();
            tree_editor
                .upsert(*path, gix_object::tree::EntryKind::Blob, blob_id)
                .unwrap();
        }
        let tree_id = tree_editor.write().unwrap().detach();

        let signature = gix_actor::Signature {
            name: "Test Author".into(),
            email: "author@example.com".into(),
            time: gix::date::Time::new(1_700_000_000, 0),
        };
        let commit = gix_object::Commit {
            tree: tree_id,
            parents: parent.into_iter().collect(),
            author: signature.clone(),
            committer: signature,
            encoding: None,
            message: "test commit".into(),
            extra_headers: Vec::new(),
        };
        let commit_id = repo.write_object(commit).unwrap().detach();

        force_set_ref(&repo, &format!("refs/heads/{branch}"), commit_id).unwrap();

        commit_id
    }

    #[tokio::test]
    async fn a_clean_merge_produces_a_two_parent_commit_and_moves_the_target_branch() {
        let test = TestStore::new("clean");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");

        let root = commit_files(&repo_dir, "main", None, &[("README.md", b"# Demo\n")]);
        commit_files(
            &repo_dir,
            "main",
            Some(root),
            &[("README.md", b"# Demo\n\nMore.\n")],
        );
        let feature_tip = commit_files(
            &repo_dir,
            "feature",
            Some(root),
            &[("feature.txt", b"new feature\n")],
        );

        let outcome = merge_branches(
            &test.store,
            "alice/demo",
            "feature",
            "main",
            "Bot",
            "bot@example.com",
            "Merge PR #1",
        )
        .unwrap();

        let repo = gix::open(&repo_dir).unwrap();
        let merge_commit = repo
            .find_commit(gix::ObjectId::from_hex(outcome.merge_commit.as_bytes()).unwrap())
            .unwrap();
        let parents: Vec<_> = merge_commit.parent_ids().map(|id| id.detach()).collect();
        assert_eq!(parents.len(), 2);
        assert!(parents.contains(&feature_tip));

        // `main` now points at the merge commit, and both files exist in
        // its tree.
        let main_tip = repo
            .find_reference("refs/heads/main")
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .id()
            .detach();
        assert_eq!(main_tip.to_string(), outcome.merge_commit);
        let tree = merge_commit.tree().unwrap();
        assert!(tree.lookup_entry_by_path("feature.txt").unwrap().is_some());
        assert!(tree.lookup_entry_by_path("README.md").unwrap().is_some());
    }

    #[tokio::test]
    async fn a_conflicting_merge_is_rejected_and_leaves_the_target_branch_untouched() {
        let test = TestStore::new("conflict");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");

        let root = commit_files(&repo_dir, "main", None, &[("README.md", b"line one\n")]);
        commit_files(
            &repo_dir,
            "main",
            Some(root),
            &[("README.md", b"line one, changed on main\n")],
        );
        commit_files(
            &repo_dir,
            "feature",
            Some(root),
            &[("README.md", b"line one, changed on feature\n")],
        );

        let err = merge_branches(
            &test.store,
            "alice/demo",
            "feature",
            "main",
            "Bot",
            "bot@example.com",
            "Merge PR #2",
        )
        .unwrap_err();
        assert!(matches!(err, GitError::Conflict(count) if count >= 1));

        let repo = gix::open(&repo_dir).unwrap();
        let main_tip = repo
            .find_reference("refs/heads/main")
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .id()
            .detach();
        // Still the pre-merge-attempt commit — a rejected merge writes no
        // objects reachable from any ref and moves no branch.
        let main_message = repo
            .find_commit(main_tip)
            .unwrap()
            .message()
            .unwrap()
            .summary()
            .to_string();
        assert_eq!(main_message, "test commit");
    }

    #[tokio::test]
    async fn a_fork_sourced_merge_lands_upstream_and_leaves_the_fork_untouched() {
        let test = TestStore::new("fork-merge");
        let locks = LockRegistry::new();

        // Upstream `main`, forked, then the fork adds a `feature` branch.
        create_repo(&test.store, &locks, "up/demo").await.unwrap();
        let up_dir = test.store.repo_dir("up/demo");
        let base = commit_files(&up_dir, "main", None, &[("README.md", b"# Demo\n")]);
        crate::fork_repo(&test.store, &locks, "up/demo", "carol/demo")
            .await
            .unwrap();
        let fork_dir = test.store.repo_dir("carol/demo");
        let feature_tip = commit_files(
            &fork_dir,
            "feature",
            Some(base),
            &[("feature.txt", b"a contribution\n")],
        );

        // The interim cross-object step, then a merge from the imported
        // pull-head ref.
        let head_ref = "refs/edda/pull-heads/merge-test";
        crate::import_branch_tip(&test.store, "carol/demo", "feature", "up/demo", head_ref)
            .unwrap();
        let outcome = merge_ref_into_branch(
            &test.store,
            "up/demo",
            head_ref,
            "carol:feature",
            "main",
            "Maintainer",
            "maint@example.com",
            "Merge pull request #1 from carol:feature",
        )
        .unwrap();

        // Upstream `main` is the merge commit; both files are in its tree.
        let up = gix::open(&up_dir).unwrap();
        let up_main = up
            .find_reference("refs/heads/main")
            .unwrap()
            .peel_to_commit()
            .unwrap();
        assert_eq!(up_main.id().detach().to_string(), outcome.merge_commit);
        let up_tree = up_main.tree().unwrap();
        assert!(up_tree
            .lookup_entry_by_path("feature.txt")
            .unwrap()
            .is_some());
        assert!(up_tree.lookup_entry_by_path("README.md").unwrap().is_some());

        // The fork is byte-identical: `feature` still at its own tip, no
        // `main` move, no merge commit, no stray pull-head ref.
        let fork = gix::open(&fork_dir).unwrap();
        assert_eq!(
            fork.find_reference("refs/heads/feature")
                .unwrap()
                .peel_to_commit()
                .unwrap()
                .id()
                .detach(),
            feature_tip
        );
        assert!(fork.find_reference(head_ref).is_err());
    }

    fn commit_count(repo: &gix::Repository, from: gix::ObjectId) -> usize {
        repo.rev_walk([from]).all().unwrap().count()
    }

    #[tokio::test]
    async fn a_squash_merge_produces_one_single_parent_commit() {
        let test = TestStore::new("squash");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");

        let root = commit_files(&repo_dir, "main", None, &[("README.md", b"# Demo\n")]);
        let f1 = commit_files(&repo_dir, "feature", Some(root), &[("a.txt", b"one\n")]);
        commit_files(&repo_dir, "feature", Some(f1), &[("b.txt", b"two\n")]);

        let outcome = squash_ref_into_branch(
            &test.store,
            "alice/demo",
            "refs/heads/feature",
            "feature",
            "main",
            "Maintainer",
            "maint@example.com",
            "Squash the feature (#7)",
        )
        .unwrap();

        let repo = gix::open(&repo_dir).unwrap();
        let squash = repo
            .find_commit(gix::ObjectId::from_hex(outcome.merge_commit.as_bytes()).unwrap())
            .unwrap();
        let parents: Vec<_> = squash.parent_ids().map(|id| id.detach()).collect();
        assert_eq!(parents, vec![root], "single parent = the target tip");
        // Both feature files landed in one commit; `main` is just root + 1.
        let tree = squash.tree().unwrap();
        assert!(tree.lookup_entry_by_path("a.txt").unwrap().is_some());
        assert!(tree.lookup_entry_by_path("b.txt").unwrap().is_some());
        assert_eq!(commit_count(&repo, squash.id().detach()), 2);
    }

    #[tokio::test]
    async fn a_rebase_merge_replays_each_commit_preserving_author_and_message() {
        let test = TestStore::new("rebase");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");

        let root = commit_files(&repo_dir, "main", None, &[("README.md", b"# Demo\n")]);
        // `main` moves on past the branch point so a fast-forward is impossible.
        commit_files(&repo_dir, "main", Some(root), &[("main.txt", b"on main\n")]);
        let f1 = commit_files(&repo_dir, "feature", Some(root), &[("a.txt", b"one\n")]);
        commit_files(&repo_dir, "feature", Some(f1), &[("b.txt", b"two\n")]);

        let outcome = rebase_ref_onto_branch(
            &test.store,
            "alice/demo",
            "refs/heads/feature",
            "main",
            "Maintainer",
            "maint@example.com",
        )
        .unwrap();

        let repo = gix::open(&repo_dir).unwrap();
        let tip = repo
            .find_commit(gix::ObjectId::from_hex(outcome.merge_commit.as_bytes()).unwrap())
            .unwrap();
        // No merge commit anywhere in the new history; all three feature +
        // main files are present; the two replayed commits are linear.
        assert_eq!(tip.parent_ids().count(), 1);
        let tree = tip.tree().unwrap();
        for path in ["a.txt", "b.txt", "main.txt", "README.md"] {
            assert!(tree.lookup_entry_by_path(path).unwrap().is_some(), "{path}");
        }
        // root, main.txt, a.txt, b.txt = 4 commits, no merge.
        assert_eq!(commit_count(&repo, tip.id().detach()), 4);
        let replayed = tip.decode().unwrap();
        assert_eq!(replayed.author().unwrap().name, "Test Author");
        assert_eq!(replayed.committer().unwrap().name, "Maintainer");
        assert_eq!(tip.message().unwrap().title.to_string(), "test commit");
    }

    #[tokio::test]
    async fn a_fast_forward_only_merge_moves_the_branch_without_a_commit() {
        let test = TestStore::new("ff-ok");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");

        let root = commit_files(&repo_dir, "main", None, &[("README.md", b"# Demo\n")]);
        let feature_tip = commit_files(&repo_dir, "feature", Some(root), &[("a.txt", b"one\n")]);

        let outcome =
            fast_forward_branch_to_ref(&test.store, "alice/demo", "refs/heads/feature", "main")
                .unwrap();
        assert_eq!(outcome.merge_commit, feature_tip.to_string());

        let repo = gix::open(&repo_dir).unwrap();
        let main_tip = repo
            .find_reference("refs/heads/main")
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .id()
            .detach();
        assert_eq!(
            main_tip, feature_tip,
            "main moved straight to the feature tip"
        );
    }

    #[tokio::test]
    async fn a_fast_forward_only_merge_rejects_a_diverged_history() {
        let test = TestStore::new("ff-diverged");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");

        let root = commit_files(&repo_dir, "main", None, &[("README.md", b"# Demo\n")]);
        commit_files(&repo_dir, "main", Some(root), &[("main.txt", b"on main\n")]);
        commit_files(&repo_dir, "feature", Some(root), &[("a.txt", b"one\n")]);

        let err =
            fast_forward_branch_to_ref(&test.store, "alice/demo", "refs/heads/feature", "main")
                .unwrap_err();
        assert!(matches!(err, GitError::NotFastForward));
        // `main` did not move.
        let repo = gix::open(&repo_dir).unwrap();
        assert_eq!(
            repo.find_reference("refs/heads/main")
                .unwrap()
                .peel_to_commit()
                .unwrap()
                .message()
                .unwrap()
                .title
                .to_string(),
            "test commit"
        );
    }
}

//! Pull-request merging: the merge-commit strategy, via `gix`'s own merge
//! support (`Repository::merge_commits`) — never a hand-rolled three-way
//! merge. `gix` 0.86's merge support was verified mature enough for this
//! (a real recursive three-way tree merge with rename tracking and
//! per-hunk text conflict detection, not a naive whole-file diff) with a
//! real `cargo build` in an isolated probe project before adoption, the
//! same discipline this workspace already applies to every dependency
//! decision — so there is no `git2`/libgit2 fallback here.
//!
//! The caller (`edda-app`'s merge handler) is responsible for holding
//! `LockRegistry`'s per-repository lock for the *entire* merge-and-record
//! sequence, not just this call — see that handler's own doc comment for
//! why the lock must still be held while the pull request's row is
//! updated afterward.

use crate::store::RepoStore;
use crate::{open_repo_dir, record_git_op, GitError};

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

/// Like [`merge_branches`], but the incoming side is an arbitrary
/// fully-qualified ref rather than a local branch name — a plain
/// `refs/heads/…`, or the Edda-internal `refs/edda/pull-heads/…` that
/// [`crate::transfer::import_branch_tip`] writes for a fork-sourced pull
/// request. `source_label` is the human name that appears in conflict
/// markers for the incoming side (`merge_branches` passes the branch name;
/// the cross-repo caller passes `owner:branch`). The merge commit and the
/// `target_branch` move are written into `name`'s repository only — a
/// fork-sourced merge never touches the fork.
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
    );
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let source_id = repo
            .find_reference(source_ref)
            .map_err(|err| GitError::Git(err.to_string()))?
            .peel_to_commit()
            .map_err(|err| GitError::Git(err.to_string()))?
            .id()
            .detach();
        let target_ref_name = format!("refs/heads/{target_branch}");
        let target_id = repo
            .find_reference(&target_ref_name)
            .map_err(|err| GitError::Git(err.to_string()))?
            .peel_to_commit()
            .map_err(|err| GitError::Git(err.to_string()))?
            .id()
            .detach();

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
        let tree_id = tree_editor
            .write()
            .map_err(|err| GitError::Git(err.to_string()))?
            .detach();

        let signature = gix_actor::Signature {
            name: committer_name.into(),
            email: committer_email.into(),
            time: gix::date::Time::now_utc(),
        };
        let commit = gix_object::Commit {
            tree: tree_id,
            parents: [target_id, source_id].into_iter().collect(),
            author: signature.clone(),
            committer: signature,
            encoding: None,
            message: message.into(),
            extra_headers: Vec::new(),
        };
        let commit_id = repo
            .write_object(commit)
            .map_err(|err| GitError::Git(err.to_string()))?
            .detach();

        crate::apply_ref_update(
            repo.git_dir(),
            &target_ref_name,
            &target_id.to_string(),
            &commit_id.to_string(),
        )
        .map_err(GitError::Git)?;

        Ok(MergeOutcome {
            merge_commit: commit_id.to_string(),
        })
    })();
    record_git_op("git.merge", start, &result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LocalFsStore;
    use crate::{apply_ref_update, create_repo, LockRegistry, ZERO_ID};
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

        let ref_name = format!("refs/heads/{branch}");
        // `old` is the *ref's own* previous value, not `parent` — the two
        // only coincide for a linear single-branch history; here, a
        // second branch's first commit shares `parent` with the first
        // branch but the second branch's ref itself doesn't exist yet.
        let old = repo
            .find_reference(&ref_name)
            .ok()
            .and_then(|mut r| r.peel_to_id().ok())
            .map(|id| id.detach().to_string())
            .unwrap_or_else(|| ZERO_ID.to_string());
        apply_ref_update(repo_dir, &ref_name, &old, &commit_id.to_string()).unwrap();

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
}

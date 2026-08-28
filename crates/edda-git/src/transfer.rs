//! Interim cross-repository object transfer for fork-sourced pull
//! requests. [`import_branch_tip`] copies the objects reachable from a
//! branch tip in one bare repository into another's object store — every
//! object the destination doesn't already have — and points an
//! Edda-internal ref there.
//!
//! A fork shares its entire common history (identical object ids) with its
//! upstream, and each object the destination already holds prunes its
//! whole subtree from the walk, so in practice only the fork's own new
//! commits/trees/blobs cross over. Whole-object loose writes, no pack
//! negotiation. Phase 14 replaces this with object-store *alternates* so
//! nothing is copied at all — this exists purely to make the merge/diff
//! paths resolve a fork's tip without teaching them about a second object
//! store yet.
//!
//! The caller must hold the destination repository's `LockRegistry` lock
//! for the duration of the call (same discipline [`crate::merge`]
//! documents) — this writes loose objects and a ref into it.

use std::collections::HashSet;

use gix_hash::ObjectId;
use gix_object::Write as _;

use crate::store::RepoStore;
use crate::{open_repo_dir, record_git_op, GitError};

/// A hard ceiling on how many objects a single import will copy, so a
/// pathologically large or malformed source can't run the destination out
/// of disk. Generous for the human-scale repositories Edda targets: a
/// legitimate fork PR copies only the contributor's own new objects.
const MAX_IMPORTED_OBJECTS: usize = 100_000;

/// Copies every object reachable from `source_branch`'s tip in
/// `source_name` that `dest_name` doesn't already have, then force-updates
/// `dest_ref` in `dest_name` to point at that tip. Returns the tip's hex
/// object id.
///
/// `dest_ref` (a fully-qualified ref name, e.g.
/// `refs/edda/pull-heads/<id>`) is set unconditionally — its previous
/// value is not checked — because it must track wherever the fork branch
/// currently points, including after the contributor pushes more commits
/// between opening the pull request and its merge.
pub fn import_branch_tip(
    store: &dyn RepoStore,
    source_name: &str,
    source_branch: &str,
    dest_name: &str,
    dest_ref: &str,
) -> Result<String, GitError> {
    let span = tracing::info_span!(
        "git.import_branch_tip",
        repo.source = %source_name,
        repo.dest = %dest_name,
        branch = %source_branch,
        objects_copied = tracing::field::Empty,
    );
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let src = open_repo_dir(store, source_name)?;
        let dst = open_repo_dir(store, dest_name)?;

        let tip = src
            .find_reference(&format!("refs/heads/{source_branch}"))
            .map_err(|err| GitError::Git(err.to_string()))?
            .peel_to_commit()
            .map_err(|err| GitError::Git(err.to_string()))?
            .id()
            .detach();

        let copied = copy_closure(&src, &dst, tip)?;
        span.record("objects_copied", copied);
        crate::force_set_ref(&dst, dest_ref, tip)?;
        Ok(tip.to_string())
    })();
    record_git_op("git.import_branch_tip", start, &result);
    result
}

/// Walks the object graph from `tip` in `src`, writing into `dst` every
/// object it doesn't already have. An object already present in `dst`
/// prunes its whole subtree: git objects are immutable and their closure
/// is complete, so if `dst` has a commit it has that commit's entire
/// history and trees too. Returns the number of objects written.
fn copy_closure(
    src: &gix::Repository,
    dst: &gix::Repository,
    tip: ObjectId,
) -> Result<usize, GitError> {
    let mut queue: Vec<ObjectId> = vec![tip];
    let mut seen: HashSet<ObjectId> = HashSet::new();
    let mut copied = 0usize;

    while let Some(id) = queue.pop() {
        if !seen.insert(id) || dst.has_object(id) {
            continue;
        }

        let object = src
            .find_object(id)
            .map_err(|err| GitError::Git(err.to_string()))?;

        // Decode only to discover children for the walk. The *write* below
        // is of the raw, canonical body bytes under `object.kind` — no
        // decode/re-encode round trip — so the id is guaranteed to come
        // back identical (`write_buf` hashes `kind` + these exact bytes).
        let decoded =
            gix_object::ObjectRef::from_bytes(&object.data, object.kind, gix_hash::Kind::Sha1)
                .map_err(|err| GitError::Git(err.to_string()))?;
        match &decoded {
            gix_object::ObjectRef::Commit(commit) => {
                queue.push(commit.tree());
                queue.extend(commit.parents());
            }
            gix_object::ObjectRef::Tree(tree) => {
                queue.extend(tree.entries.iter().map(|entry| entry.oid.to_owned()));
            }
            gix_object::ObjectRef::Tag(tag) => {
                queue.push(tag.target());
            }
            gix_object::ObjectRef::Blob(_) => {}
        }
        drop(decoded);

        let written = dst
            .objects
            .write_buf(object.kind, &object.data)
            .map_err(|err| GitError::Git(err.to_string()))?;
        debug_assert_eq!(
            written, id,
            "raw object copy must be content-address-stable"
        );
        let _ = written;

        copied += 1;
        if copied > MAX_IMPORTED_OBJECTS {
            return Err(GitError::Git(format!(
                "cross-repo import exceeded {MAX_IMPORTED_OBJECTS} objects — refusing to continue"
            )));
        }
    }
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LocalFsStore;
    use crate::{create_repo, force_set_ref, LockRegistry};
    use std::path::{Path, PathBuf};

    struct TestStore {
        store: LocalFsStore,
        root: PathBuf,
    }

    impl TestStore {
        fn new(unique: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "edda-git-transfer-test-{unique}-{}",
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

    /// Same hand-built commit helper the `diff`/`merge` tests use — no
    /// `git` binary, objects written straight into the bare repo.
    fn commit_files(
        repo_dir: &Path,
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
    async fn import_copies_only_the_forks_new_objects_and_points_the_ref_at_the_tip() {
        let test = TestStore::new("basic");
        let locks = LockRegistry::new();

        // Upstream: one commit on `main`.
        create_repo(&test.store, &locks, "up/demo").await.unwrap();
        let up_dir = test.store.repo_dir("up/demo");
        let base = commit_files(&up_dir, "main", None, &[("README.md", b"# Demo\n")]);

        // Fork: a byte-for-byte copy of upstream, then a new commit on a
        // `feature` branch — the shared `base` commit/tree/blob already
        // exist upstream; only the feature commit + its tree + the new
        // blob are genuinely new.
        crate::fork_repo(&test.store, &locks, "up/demo", "contributor/demo")
            .await
            .unwrap();
        let fork_dir = test.store.repo_dir("contributor/demo");
        let feature_tip = commit_files(
            &fork_dir,
            "feature",
            Some(base),
            &[("feature.txt", b"new feature\n")],
        );

        let dest_ref = "refs/edda/pull-heads/test-pr";
        let imported = import_branch_tip(
            &test.store,
            "contributor/demo",
            "feature",
            "up/demo",
            dest_ref,
        )
        .expect("import succeeds");
        assert_eq!(imported, feature_tip.to_string());

        // Upstream can now resolve the fork's tip, and the whole closure
        // is present (walk it: every reachable object exists locally).
        let up = gix::open(&up_dir).unwrap();
        let head = up
            .find_reference(dest_ref)
            .unwrap()
            .peel_to_commit()
            .unwrap();
        assert_eq!(head.id().detach(), feature_tip);
        assert!(up.has_object(base));
        let feature_blob = head
            .tree()
            .unwrap()
            .lookup_entry_by_path("feature.txt")
            .unwrap()
            .unwrap()
            .oid()
            .to_owned();
        assert!(up.has_object(feature_blob));

        // Re-importing after the fork moves its branch forward refreshes
        // the ref (force-update, previous value not checked).
        let feature_tip_2 = commit_files(
            &fork_dir,
            "feature",
            Some(feature_tip),
            &[("feature.txt", b"new feature, revised\n")],
        );
        let imported_2 = import_branch_tip(
            &test.store,
            "contributor/demo",
            "feature",
            "up/demo",
            dest_ref,
        )
        .unwrap();
        assert_eq!(imported_2, feature_tip_2.to_string());
        let head_2 = up
            .find_reference(dest_ref)
            .unwrap()
            .peel_to_commit()
            .unwrap();
        assert_eq!(head_2.id().detach(), feature_tip_2);
    }
}

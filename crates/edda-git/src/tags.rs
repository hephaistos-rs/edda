//! Lightweight tags: `list_tags`/`resolve_tag`/`create_tag`, following the
//! same shape as this crate's branch functions (`list_branches`,
//! `open_and_resolve`) — a tag is just a ref under `refs/tags/<name>`
//! pointing directly at a commit, no annotated-tag object. Used by
//! `edda-web`'s release-creation flow (a release's `target_commit` is
//! resolved once via `create_tag`/`resolve_tag`, then stored — see
//! `edda_domain::release::Release`'s doc comment for why a release
//! doesn't just follow its tag live).

use crate::store::RepoStore;
use crate::{open_repo_dir, record_git_op, GitError, ZERO_ID};

/// Git's own ref-name rules, the practically relevant subset: non-empty,
/// no whitespace or control characters, none of the path-hostile/
/// revision-syntax-colliding characters (`~^:?*[\`), no `..`, and not a
/// single `@`. Deliberately conservative — a tag name only needs to be
/// short and typeable, not maximally permissive.
fn is_valid_tag_name(tag: &str) -> bool {
    if tag.is_empty() || tag == "@" || tag.contains("..") {
        return false;
    }
    tag.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
        && !tag.starts_with('.')
        && !tag.starts_with('/')
        && !tag.ends_with('/')
        && !tag.ends_with('.')
}

pub fn list_tags(store: &dyn RepoStore, name: &str) -> Result<Vec<String>, GitError> {
    let repo = open_repo_dir(store, name)?;
    let mut names: Vec<String> = match repo.references() {
        Ok(refs) => match refs.tags() {
            Ok(tags) => tags
                .filter_map(Result::ok)
                .map(|r| r.name().shorten().to_string())
                .collect(),
            Err(_) => Vec::new(),
        },
        Err(_) => Vec::new(),
    };
    names.sort();
    Ok(names)
}

/// The commit id `tag` currently points at, hex-encoded.
pub fn resolve_tag(store: &dyn RepoStore, name: &str, tag: &str) -> Result<String, GitError> {
    let repo = open_repo_dir(store, name)?;
    let mut reference = repo
        .find_reference(&format!("refs/tags/{tag}"))
        .map_err(|_| GitError::NotFound(format!("tag {tag} in {name}")))?;
    let id = reference
        .peel_to_id()
        .map_err(|err| GitError::Git(err.to_string()))?;
    Ok(id.to_string())
}

/// Creates `refs/tags/<tag>` pointing at whatever `target` (a branch name,
/// a full/abbreviated commit id, or `HEAD`) resolves to — real revision
/// resolution via `gix`'s own `rev_parse_single`, not a hand-rolled
/// branch-name-only lookup, since a tag is more often created against an
/// arbitrary commit than always the tip of a named branch. Returns the
/// resolved commit id, hex-encoded, so the caller (release creation) can
/// store it as the release's immutable `target_commit` without a second
/// resolution round-trip. Rejects a `target` that resolves to something
/// other than a commit (e.g. a blob or tree id typed in directly) and a
/// `tag` name that already exists.
pub fn create_tag(
    store: &dyn RepoStore,
    name: &str,
    tag: &str,
    target: &str,
) -> Result<String, GitError> {
    if !is_valid_tag_name(tag) {
        return Err(GitError::InvalidName(tag.to_string()));
    }
    let repo = open_repo_dir(store, name)?;

    let span = tracing::info_span!("git.create_tag", repo.name = %name, tag = %tag);
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let ref_path = repo.git_dir().join("refs").join("tags").join(tag);
        if ref_path.exists() {
            return Err(GitError::AlreadyExists(format!("tag {tag} in {name}")));
        }

        let target_id = repo
            .rev_parse_single(target)
            .map_err(|err| GitError::Git(err.to_string()))?
            .detach();
        repo.find_commit(target_id)
            .map_err(|_| GitError::Git(format!("\"{target}\" does not resolve to a commit")))?;
        let target_hex = target_id.to_string();

        crate::refs::update_refs(
            &repo,
            &[crate::refs::RefUpdate {
                name: format!("refs/tags/{tag}"),
                expected_old: ZERO_ID.to_string(),
                new: target_hex.clone(),
            }],
            "tag: create",
        )?;

        Ok(target_hex)
    })();
    record_git_op("git.create_tag", start, &result);
    result
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
                "edda-git-tags-test-{unique}-{}",
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

    /// Same hand-built commit-writing helper `merge.rs`'s tests use.
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
    async fn a_tag_created_against_a_branch_name_resolves_to_that_branchs_tip() {
        let test = TestStore::new("branch-target");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");
        let tip = commit_files(&repo_dir, "main", None, &[("README.md", b"hello\n")]);

        let resolved = create_tag(&test.store, "alice/demo", "v1.0.0", "main").unwrap();
        assert_eq!(resolved, tip.to_string());
        assert_eq!(
            resolve_tag(&test.store, "alice/demo", "v1.0.0").unwrap(),
            tip.to_string()
        );
        assert_eq!(
            list_tags(&test.store, "alice/demo").unwrap(),
            vec!["v1.0.0".to_string()]
        );
    }

    #[tokio::test]
    async fn a_tag_created_against_a_raw_commit_id_resolves_to_that_commit() {
        let test = TestStore::new("commit-target");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");
        let root = commit_files(&repo_dir, "main", None, &[("a.txt", b"1\n")]);
        commit_files(&repo_dir, "main", Some(root), &[("a.txt", b"2\n")]);

        let resolved = create_tag(&test.store, "alice/demo", "v0.1.0", &root.to_string()).unwrap();
        assert_eq!(resolved, root.to_string());
    }

    #[tokio::test]
    async fn creating_a_tag_that_already_exists_is_rejected() {
        let test = TestStore::new("dup");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");
        commit_files(&repo_dir, "main", None, &[("a.txt", b"1\n")]);

        create_tag(&test.store, "alice/demo", "v1", "main").unwrap();
        let err = create_tag(&test.store, "alice/demo", "v1", "main").unwrap_err();
        assert!(matches!(err, GitError::AlreadyExists(_)));
    }

    #[tokio::test]
    async fn an_invalid_tag_name_is_rejected_before_touching_the_repository() {
        let test = TestStore::new("invalid-name");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();

        let err = create_tag(&test.store, "alice/demo", "../escape", "main").unwrap_err();
        assert!(matches!(err, GitError::InvalidName(_)));
    }
}

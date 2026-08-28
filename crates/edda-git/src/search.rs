//! Grep-tier code search: a case-insensitive plain-substring search over
//! every non-binary file in a branch's tree. Deliberately not an index —
//! this walks the tree and reads each blob fresh on every call, the same
//! cost profile `browse_tree`/`read_blob` already have for a single file.
//! A real index (ripgrep-over-a-checkout, or a dedicated search service) is
//! future work if usage ever demands it; this satisfies "basic code search
//! works," not "fast code search at scale."

use gix_object::tree::EntryKind;

use crate::store::RepoStore;
use crate::{is_binary_data, open_and_resolve, open_repo_dir, record_git_op, GitError};

#[derive(Debug, Clone, PartialEq)]
pub struct SearchMatch {
    pub path: String,
    /// 1-based.
    pub line_number: u32,
    pub line: String,
}

/// Hard cap on how many matches a single search returns. A query against a
/// large repository (or a very common substring) could otherwise produce an
/// unbounded response — this walks the *entire* tree unindexed, so nothing
/// else naturally limits the work or the result size. 200 is generous enough
/// to be useful (a caller almost never scrolls past that many results
/// anyway) while keeping one search request's cost bounded.
const MAX_SEARCH_MATCHES: usize = 200;

/// Searches every non-binary file in `branch`'s tree (or the default branch
/// if `None`) for `query`, case-insensitively, as a plain substring — no
/// regex, no tokenization. Results are capped at `MAX_SEARCH_MATCHES` and
/// returned in the tree-walk's own order (directories before files within
/// each directory, matching `browse_tree`'s sort — see `list_branch_names`'s
/// sibling logic), not ranked by relevance.
pub fn search_tree(
    store: &dyn RepoStore,
    name: &str,
    branch: Option<&str>,
    query: &str,
) -> Result<Vec<SearchMatch>, GitError> {
    let repo = open_repo_dir(store, name)?;
    let commit = open_and_resolve(&repo, branch)?;

    let span = tracing::info_span!("git.search_tree", repo.name = %name, query.len = query.len());
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let tree = commit
            .tree()
            .map_err(|err| GitError::Git(err.to_string()))?;
        let query_lower = query.to_lowercase();
        let mut matches = Vec::new();
        walk(&tree, "", &query_lower, &mut matches)?;
        Ok(matches)
    })();
    record_git_op("git.search_tree", start, &result);
    result
}

fn walk(
    tree: &gix::Tree<'_>,
    prefix: &str,
    query_lower: &str,
    matches: &mut Vec<SearchMatch>,
) -> Result<(), GitError> {
    for entry in tree.iter() {
        if matches.len() >= MAX_SEARCH_MATCHES {
            return Ok(());
        }
        let entry = entry.map_err(|err| GitError::Git(err.to_string()))?;
        let file_name = entry.filename().to_string();
        let path = if prefix.is_empty() {
            file_name
        } else {
            format!("{prefix}/{file_name}")
        };

        let object = entry
            .object()
            .map_err(|err| GitError::Git(err.to_string()))?;

        if entry.mode().kind() == EntryKind::Tree {
            walk(&object.into_tree(), &path, query_lower, matches)?;
            continue;
        }

        let data = &object.data;
        if is_binary_data(data) {
            continue;
        }
        let text = String::from_utf8_lossy(data);
        for (index, line) in text.lines().enumerate() {
            if matches.len() >= MAX_SEARCH_MATCHES {
                return Ok(());
            }
            if line.to_lowercase().contains(query_lower) {
                matches.push(SearchMatch {
                    path: path.clone(),
                    line_number: (index + 1) as u32,
                    line: line.to_string(),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LocalFsStore;
    use crate::{create_repo, LockRegistry};
    use std::path::PathBuf;

    struct TestStore {
        store: LocalFsStore,
        root: PathBuf,
    }

    impl TestStore {
        fn new(unique: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "edda-git-search-test-{unique}-{}",
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

    /// Same hand-built-commit approach `diff`'s tests use — see that
    /// module's `commit_files` doc comment for why.
    fn commit_files(repo_dir: &std::path::Path, files: &[(&str, &[u8])]) -> gix::ObjectId {
        let repo = gix::open(repo_dir).unwrap();
        let mut tree_editor = repo.edit_tree(repo.empty_tree().id().detach()).unwrap();
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
            parents: Default::default(),
            author: signature.clone(),
            committer: signature,
            encoding: None,
            message: "test commit".into(),
            extra_headers: Vec::new(),
        };
        let commit_id = repo.write_object(commit).unwrap().detach();
        crate::force_set_ref(&repo, "refs/heads/main", commit_id).unwrap();
        commit_id
    }

    #[tokio::test]
    async fn search_tree_finds_matches_case_insensitively_and_skips_non_matching_files() {
        let test = TestStore::new("basic");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");

        commit_files(
            &repo_dir,
            &[
                (
                    "src/lib.rs",
                    b"pub fn greet() {\n    println!(\"Hello, World\");\n}\n",
                ),
                ("src/other.rs", b"pub fn noop() {}\n"),
                ("notes.txt", b"nothing interesting here\nHELLO again\n"),
            ],
        );

        let matches = search_tree(&test.store, "alice/demo", None, "hello").unwrap();
        let paths: Vec<&str> = matches.iter().map(|m| m.path.as_str()).collect();
        assert!(paths.contains(&"src/lib.rs"));
        assert!(paths.contains(&"notes.txt"));
        assert!(!paths.contains(&"src/other.rs"));
        assert_eq!(matches.len(), 2);
    }

    #[tokio::test]
    async fn search_tree_skips_binary_files() {
        let test = TestStore::new("binary");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");

        commit_files(&repo_dir, &[("data.bin", b"needle\x00binary\x00stuff")]);

        let matches = search_tree(&test.store, "alice/demo", None, "needle").unwrap();
        assert!(matches.is_empty());
    }
}

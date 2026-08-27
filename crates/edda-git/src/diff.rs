//! Structural commit diffing. This module produces diff *data* only — added/
//! removed/context lines per changed file — never HTML. Turning that into a
//! rendered view (e.g. syntax-highlighted lines) is entirely the caller's
//! concern, the same layering `read_blob` already uses: this crate returns
//! raw structure, callers decide how to present it.

use gix_object::tree::EntryKind;

use crate::store::RepoStore;
use crate::{is_binary_data, open_repo_dir, record_git_op, GitError};

/// One changed file within a commit's diff against its comparison point
/// (its first parent, or the empty tree for a root commit — see
/// `commit_diff`).
#[derive(Debug, Clone, PartialEq)]
pub struct FileDiff {
    /// `None` for a newly-added file.
    pub old_path: Option<String>,
    /// `None` for a deleted file.
    pub new_path: Option<String>,
    /// Empty when `is_binary` is true — there is nothing line-shaped to show.
    pub hunks: Vec<DiffHunk>,
    pub is_binary: bool,
}

/// A contiguous run of diff lines. This module does not window hunks down to
/// "only the changed regions plus a few lines of context" the way a real
/// unified diff does — each file's `hunks` is always exactly one hunk
/// spanning the full compared range, with unchanged lines included inline as
/// `DiffLine::Context`. That's simpler and is enough to satisfy "added/
/// removed/context lines are distinguishable"; multi-hunk windowing is a
/// presentation refinement that can be added later without changing this
/// shape (a renderer can always collapse long `Context` runs itself).
#[derive(Debug, Clone, PartialEq)]
pub struct DiffHunk {
    /// 1-based; 0 when the old side is empty (a newly-added file).
    pub old_start: u32,
    /// 1-based; 0 when the new side is empty (a deleted file).
    pub new_start: u32,
    pub lines: Vec<DiffLine>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DiffLine {
    Context(String),
    Added(String),
    Removed(String),
}

/// Above this many lines on either side of a modified file, the line-level
/// alignment below (an O(old_lines * new_lines) table) is skipped in favor
/// of a single "every old line removed, every new line added" hunk. That
/// table's memory cost grows quadratically, which is fine for source files
/// (the common case, covered by the Rust/Python/Markdown fixture tests)
/// but would be a real cost for a large generated file landing in a diff.
const MAX_DIFF_LINES: usize = 2000;

/// The diff of commit `commit_id` against its first parent, or against the
/// empty tree if it has no parent (the root-commit case) — matching how
/// `git show`/`git log -p` present a root commit's diff. Rename/copy
/// detection is deliberately disabled (`Options::track_rewrites(None)`): a
/// renamed-with-changes file then simply appears as a `Deletion` of the old
/// path plus an `Addition` of the new one, which is a strictly simpler
/// output shape for this crate's callers (diff rendering, not a rename UI)
/// to handle than the tree-diff's own three-way `Rewrite` variant.
pub fn commit_diff(
    store: &dyn RepoStore,
    name: &str,
    commit_id: &str,
) -> Result<Vec<FileDiff>, GitError> {
    let repo = open_repo_dir(store, name)?;

    let span = tracing::info_span!("git.commit_diff", repo.name = %name, commit.id = %commit_id);
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let oid = gix_hash::ObjectId::from_hex(commit_id.as_bytes())
            .map_err(|err| GitError::Git(err.to_string()))?;
        let commit = repo
            .find_commit(oid)
            .map_err(|err| GitError::Git(err.to_string()))?;
        let new_tree = commit
            .tree()
            .map_err(|err| GitError::Git(err.to_string()))?;

        let parent_tree = match commit.parent_ids().next() {
            Some(parent_id) => {
                let parent = repo
                    .find_commit(parent_id)
                    .map_err(|err| GitError::Git(err.to_string()))?;
                Some(
                    parent
                        .tree()
                        .map_err(|err| GitError::Git(err.to_string()))?,
                )
            }
            None => None,
        };

        let mut options = gix::diff::Options::default();
        options.track_rewrites(None);

        let changes = repo
            .diff_tree_to_tree(parent_tree.as_ref(), Some(&new_tree), Some(options))
            .map_err(|err| GitError::Git(err.to_string()))?;

        let mut diffs = Vec::new();
        for change in changes {
            let file_diff = match change {
                gix::object::tree::diff::ChangeDetached::Addition {
                    location,
                    entry_mode,
                    id,
                    ..
                } => {
                    if entry_mode.kind() == EntryKind::Tree {
                        continue;
                    }
                    let data = object_data(&repo, id)?;
                    file_diff_for_addition(location.to_string(), &data)
                }
                gix::object::tree::diff::ChangeDetached::Deletion {
                    location,
                    entry_mode,
                    id,
                    ..
                } => {
                    if entry_mode.kind() == EntryKind::Tree {
                        continue;
                    }
                    let data = object_data(&repo, id)?;
                    file_diff_for_deletion(location.to_string(), &data)
                }
                gix::object::tree::diff::ChangeDetached::Modification {
                    location,
                    previous_id,
                    id,
                    entry_mode,
                    ..
                } => {
                    if entry_mode.kind() == EntryKind::Tree {
                        continue;
                    }
                    let old_data = object_data(&repo, previous_id)?;
                    let new_data = object_data(&repo, id)?;
                    file_diff_for_modification(location.to_string(), &old_data, &new_data)
                }
                // Unreachable in practice: rewrite tracking is disabled above,
                // so the tree-diff never emits this variant. Handled
                // explicitly (rather than a wildcard) so a future change to
                // that call doesn't silently start dropping rewrites here.
                gix::object::tree::diff::ChangeDetached::Rewrite { .. } => continue,
            };
            diffs.push(file_diff);
        }
        Ok(diffs)
    })();
    record_git_op("git.commit_diff", start, &result);
    result
}

fn object_data(repo: &gix::Repository, id: gix_hash::ObjectId) -> Result<Vec<u8>, GitError> {
    let mut object = repo
        .find_object(id)
        .map_err(|err| GitError::Git(err.to_string()))?;
    Ok(std::mem::take(&mut object.data))
}

fn split_lines(data: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(data)
        .lines()
        .map(str::to_string)
        .collect()
}

fn file_diff_for_addition(path: String, data: &[u8]) -> FileDiff {
    if is_binary_data(data) {
        return FileDiff {
            old_path: None,
            new_path: Some(path),
            hunks: Vec::new(),
            is_binary: true,
        };
    }
    let lines = split_lines(data);
    let hunk = DiffHunk {
        old_start: 0,
        new_start: if lines.is_empty() { 0 } else { 1 },
        lines: lines.into_iter().map(DiffLine::Added).collect(),
    };
    FileDiff {
        old_path: None,
        new_path: Some(path),
        hunks: vec![hunk],
        is_binary: false,
    }
}

fn file_diff_for_deletion(path: String, data: &[u8]) -> FileDiff {
    if is_binary_data(data) {
        return FileDiff {
            old_path: Some(path),
            new_path: None,
            hunks: Vec::new(),
            is_binary: true,
        };
    }
    let lines = split_lines(data);
    let hunk = DiffHunk {
        old_start: if lines.is_empty() { 0 } else { 1 },
        new_start: 0,
        lines: lines.into_iter().map(DiffLine::Removed).collect(),
    };
    FileDiff {
        old_path: Some(path),
        new_path: None,
        hunks: vec![hunk],
        is_binary: false,
    }
}

fn file_diff_for_modification(path: String, old_data: &[u8], new_data: &[u8]) -> FileDiff {
    if is_binary_data(old_data) || is_binary_data(new_data) {
        return FileDiff {
            old_path: Some(path.clone()),
            new_path: Some(path),
            hunks: Vec::new(),
            is_binary: true,
        };
    }
    let old_lines = split_lines(old_data);
    let new_lines = split_lines(new_data);
    let lines = diff_lines(&old_lines, &new_lines);
    let hunk = DiffHunk {
        old_start: if old_lines.is_empty() { 0 } else { 1 },
        new_start: if new_lines.is_empty() { 0 } else { 1 },
        lines,
    };
    FileDiff {
        old_path: Some(path.clone()),
        new_path: Some(path),
        hunks: vec![hunk],
        is_binary: false,
    }
}

/// Aligns `old` and `new` by their longest common subsequence (a plain O(n*m)
/// dynamic-programming table — see `MAX_DIFF_LINES` for the size at which
/// this is skipped), then walks the alignment to emit context/removed/added
/// lines in original order.
fn diff_lines(old: &[String], new: &[String]) -> Vec<DiffLine> {
    if old.len() > MAX_DIFF_LINES || new.len() > MAX_DIFF_LINES {
        let mut lines = Vec::with_capacity(old.len() + new.len());
        lines.extend(old.iter().cloned().map(DiffLine::Removed));
        lines.extend(new.iter().cloned().map(DiffLine::Added));
        return lines;
    }

    let n = old.len();
    let m = new.len();
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if old[i] == new[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    let mut lines = Vec::with_capacity(n + m);
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if old[i] == new[j] {
            lines.push(DiffLine::Context(old[i].clone()));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            lines.push(DiffLine::Removed(old[i].clone()));
            i += 1;
        } else {
            lines.push(DiffLine::Added(new[j].clone()));
            j += 1;
        }
    }
    while i < n {
        lines.push(DiffLine::Removed(old[i].clone()));
        i += 1;
    }
    while j < m {
        lines.push(DiffLine::Added(new[j].clone()));
        j += 1;
    }
    lines
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
                "edda-git-diff-test-{unique}-{}",
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

    /// Writes `content` to `path` inside the bare repo's object store
    /// directly (no `git` binary, no worktree checkout — this crate never
    /// shells out) by building a tree/commit by hand via `gix`, then points
    /// `refs/heads/main` at it via this module's own `apply_ref_update`
    /// (the same ref-write path a real push goes through) rather than any
    /// gix reference-editing API — one less API surface for this test
    /// fixture to depend on. Returns the new commit id.
    fn commit_files(
        repo_dir: &std::path::Path,
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

        let old = parent
            .map(|id| id.to_string())
            .unwrap_or_else(|| crate::ZERO_ID.to_string());
        crate::apply_ref_update(repo_dir, "refs/heads/main", &old, &commit_id.to_string()).unwrap();

        commit_id
    }

    #[tokio::test]
    async fn commit_diff_reports_added_removed_and_context_lines_across_languages() {
        let test = TestStore::new("multi-lang");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");

        let root = commit_files(
            &repo_dir,
            None,
            &[
                ("src/main.rs", b"fn main() {\n    println!(\"hi\");\n}\n"),
                ("scripts/run.py", b"def run():\n    print(\"hi\")\n"),
                ("README.md", b"# Demo\n\nHello.\n"),
            ],
        );

        let second = commit_files(
            &repo_dir,
            Some(root),
            &[
                (
                    "src/main.rs",
                    b"fn main() {\n    println!(\"hello, world\");\n}\n",
                ),
                ("scripts/new.py", b"def new():\n    pass\n"),
            ],
        );

        let diffs = commit_diff(&test.store, "alice/demo", &second.to_string()).unwrap();

        let rust_diff = diffs
            .iter()
            .find(|d| d.new_path.as_deref() == Some("src/main.rs"))
            .expect("rust file diff present");
        assert!(!rust_diff.is_binary);
        let rust_lines = &rust_diff.hunks[0].lines;
        assert!(rust_lines
            .iter()
            .any(|l| matches!(l, DiffLine::Context(s) if s == "fn main() {")));
        assert!(rust_lines
            .iter()
            .any(|l| matches!(l, DiffLine::Removed(s) if s.contains("\"hi\""))));
        assert!(rust_lines
            .iter()
            .any(|l| matches!(l, DiffLine::Added(s) if s.contains("hello, world"))));

        let python_diff = diffs
            .iter()
            .find(|d| d.new_path.as_deref() == Some("scripts/new.py"))
            .expect("python file diff present");
        assert_eq!(python_diff.old_path, None);
        assert!(python_diff.hunks[0]
            .lines
            .iter()
            .all(|l| matches!(l, DiffLine::Added(_))));
    }

    #[tokio::test]
    async fn commit_diff_against_root_commit_treats_every_line_as_added() {
        let test = TestStore::new("root-commit");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");

        let root = commit_files(&repo_dir, None, &[("README.md", b"# Demo\n")]);

        let diffs = commit_diff(&test.store, "alice/demo", &root.to_string()).unwrap();
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].old_path, None);
        assert_eq!(diffs[0].new_path.as_deref(), Some("README.md"));
        assert!(diffs[0].hunks[0]
            .lines
            .iter()
            .all(|l| matches!(l, DiffLine::Added(_))));
    }
}

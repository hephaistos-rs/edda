//! Structural commit diffing. This module produces diff *data* only — added/
//! removed/context lines per changed file — never HTML. Turning that into a
//! rendered view (e.g. syntax-highlighted lines) is entirely the caller's
//! concern, the same layering `read_blob` already uses: this crate returns
//! raw structure, callers decide how to present it.
//!
//! Line-level alignment for a modified file is `imara-diff`'s histogram
//! algorithm with Git's slider heuristics (`gix::diff::blob`), rendered as
//! real multi-hunk unified output with 3 lines of context — the same
//! engine gitoxide and Helix ship. A file whose either side exceeds
//! [`MAX_DIFF_BYTES`] is reported with `is_too_large` set and no hunks.

use gix_object::tree::EntryKind;

use crate::store::RepoStore;
use crate::{is_binary_data, open_repo_dir, record_git_op, GitError};

/// Symmetrical unified-diff context, in lines on each side of a change —
/// the `-U3` git default.
const DIFF_CONTEXT_LINES: u32 = 3;

/// One changed file within a commit's diff against its comparison point
/// (its first parent, or the empty tree for a root commit — see
/// `commit_diff`).
#[derive(Debug, Clone, PartialEq)]
pub struct FileDiff {
    /// `None` for a newly-added file. For a rename, the pre-rename path.
    pub old_path: Option<String>,
    /// `None` for a deleted file. For a rename, the post-rename path.
    pub new_path: Option<String>,
    /// Empty when `is_binary` or `is_too_large` is true — there is nothing
    /// line-shaped to show. Otherwise every changed region of the file,
    /// each windowed to [`DIFF_CONTEXT_LINES`] of surrounding context.
    pub hunks: Vec<DiffHunk>,
    pub is_binary: bool,
    /// The tree-diff's rewrite tracking matched this file to one at a
    /// different path (`old_path != new_path`); `hunks` still carries any
    /// content change between the two sides.
    pub is_rename: bool,
    /// Either side of the file is larger than [`MAX_DIFF_BYTES`] — `hunks`
    /// is empty and the caller shows "diff too large" rather than the file.
    pub is_too_large: bool,
}

/// One contiguous changed region of a file plus its surrounding context,
/// positioned by a unified-diff `@@ -old_start,old_lines +new_start,new_lines @@`
/// header.
#[derive(Debug, Clone, PartialEq)]
pub struct DiffHunk {
    /// 1-based first old-side line the hunk covers; 0 when the old side is
    /// empty (a newly-added file).
    pub old_start: u32,
    /// Old-side line span of the hunk.
    pub old_lines: u32,
    /// 1-based first new-side line the hunk covers; 0 when the new side is
    /// empty (a deleted file).
    pub new_start: u32,
    /// New-side line span of the hunk.
    pub new_lines: u32,
    pub lines: Vec<DiffLine>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DiffLine {
    Context(String),
    Added(String),
    Removed(String),
}

/// A file whose old or new blob exceeds this is reported as `is_too_large`
/// with no hunks — a byte budget, not a line count: the concern is the
/// cost of interning + serializing a giant generated file into a diff, and
/// bytes bound that directly regardless of line length.
const MAX_DIFF_BYTES: usize = 512 * 1024;

/// The diff of commit `commit_id` against its first parent, or against the
/// empty tree if it has no parent (the root-commit case) — matching how
/// `git show`/`git log -p` present a root commit's diff. Rename/copy
/// detection is on (`gix` rewrite tracking): a renamed file is one
/// `FileDiff` with `is_rename` set and distinct `old_path`/`new_path`,
/// carrying whatever content also changed, rather than an unrelated
/// delete + add pair.
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

        file_diffs_between(&repo, parent_tree.as_ref(), Some(&new_tree))
    })();
    record_git_op("git.commit_diff", start, &result);
    result
}

/// The diff a pull request shows: from the merge base of `base_ref` and
/// `head_ref` to `head_ref` (three-dot `base...head` semantics), across
/// the whole tree, in `name`'s repository. `base_ref`/`head_ref` are
/// fully-qualified refs — for a fork-sourced pull request `head_ref` is
/// the internal `refs/edda/pull-heads/…` that
/// [`crate::transfer::import_branch_tip`] wrote into this same repository,
/// so this function never needs to know a second object store exists.
/// If the two commits share no history, this falls back to a plain
/// `base..head` diff.
pub fn diff_refs(
    store: &dyn RepoStore,
    name: &str,
    base_ref: &str,
    head_ref: &str,
) -> Result<Vec<FileDiff>, GitError> {
    let repo = open_repo_dir(store, name)?;

    let span =
        tracing::info_span!("git.diff_refs", repo.name = %name, base = %base_ref, head = %head_ref);
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let base_id = resolve_commit_id(&repo, base_ref)?;
        let head_id = resolve_commit_id(&repo, head_ref)?;
        let from = repo
            .merge_base(base_id, head_id)
            .map(|id| id.detach())
            .unwrap_or(base_id);
        let from_tree = repo
            .find_commit(from)
            .map_err(|err| GitError::Git(err.to_string()))?
            .tree()
            .map_err(|err| GitError::Git(err.to_string()))?;
        let head_tree = repo
            .find_commit(head_id)
            .map_err(|err| GitError::Git(err.to_string()))?
            .tree()
            .map_err(|err| GitError::Git(err.to_string()))?;
        file_diffs_between(&repo, Some(&from_tree), Some(&head_tree))
    })();
    record_git_op("git.diff_refs", start, &result);
    result
}

fn resolve_commit_id(
    repo: &gix::Repository,
    ref_name: &str,
) -> Result<gix_hash::ObjectId, GitError> {
    Ok(repo
        .find_reference(ref_name)
        .map_err(|err| GitError::Git(err.to_string()))?
        .peel_to_commit()
        .map_err(|err| GitError::Git(err.to_string()))?
        .id()
        .detach())
}

/// Turns a tree-to-tree change set into this crate's `FileDiff` shape.
/// Shared by `commit_diff` (commit vs first parent) and `diff_refs`
/// (merge base vs head). Rewrite tracking is **on**: a renamed file is a
/// single `Rewrite` change (surfaced with `is_rename`), not an unrelated
/// delete + add pair.
fn file_diffs_between(
    repo: &gix::Repository,
    old_tree: Option<&gix::Tree<'_>>,
    new_tree: Option<&gix::Tree<'_>>,
) -> Result<Vec<FileDiff>, GitError> {
    let mut options = gix::diff::Options::default();
    options.track_rewrites(Some(gix::diff::Rewrites::default()));

    let changes = repo
        .diff_tree_to_tree(old_tree, new_tree, Some(options))
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
                let data = object_data(repo, id)?;
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
                let data = object_data(repo, id)?;
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
                let old_data = object_data(repo, previous_id)?;
                let new_data = object_data(repo, id)?;
                file_diff_for_modification(
                    Some(location.to_string()),
                    location.to_string(),
                    &old_data,
                    &new_data,
                    false,
                )
            }
            gix::object::tree::diff::ChangeDetached::Rewrite {
                source_location,
                source_id,
                location,
                id,
                entry_mode,
                ..
            } => {
                if entry_mode.kind() == EntryKind::Tree {
                    continue;
                }
                let old_path = source_location.to_string();
                let new_path = location.to_string();
                if source_id == id {
                    // A pure rename — no content change to diff.
                    FileDiff {
                        old_path: Some(old_path),
                        new_path: Some(new_path),
                        hunks: Vec::new(),
                        is_binary: false,
                        is_rename: true,
                        is_too_large: false,
                    }
                } else {
                    let old_data = object_data(repo, source_id)?;
                    let new_data = object_data(repo, id)?;
                    file_diff_for_modification(Some(old_path), new_path, &old_data, &new_data, true)
                }
            }
        };
        diffs.push(file_diff);
    }
    Ok(diffs)
}

fn object_data(repo: &gix::Repository, id: gix_hash::ObjectId) -> Result<Vec<u8>, GitError> {
    let mut object = repo
        .find_object(id)
        .map_err(|err| GitError::Git(err.to_string()))?;
    Ok(std::mem::take(&mut object.data))
}

/// Splits a blob into display lines the way the rest of this crate does —
/// `\n`-delimited, newline stripped, lossy UTF-8. Used only for the
/// whole-file hunks of a pure add / pure delete; a modification's lines
/// come from `imara-diff`'s own tokenizer.
fn split_lines(data: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(data)
        .lines()
        .map(str::to_string)
        .collect()
}

/// One `imara-diff` line token → a display `String`: the tokenizer keeps
/// the line's own `\n` (and any `\r`), which this crate's `DiffLine`s never
/// carry, so strip a single trailing EOL.
fn line_token_to_string(token: &[u8]) -> String {
    let text = String::from_utf8_lossy(token);
    text.strip_suffix('\n')
        .map(|rest| rest.strip_suffix('\r').unwrap_or(rest))
        .unwrap_or(&text)
        .to_string()
}

fn file_diff_for_addition(path: String, data: &[u8]) -> FileDiff {
    if is_binary_data(data) {
        return FileDiff {
            old_path: None,
            new_path: Some(path),
            hunks: Vec::new(),
            is_binary: true,
            is_rename: false,
            is_too_large: false,
        };
    }
    if data.len() > MAX_DIFF_BYTES {
        return FileDiff {
            old_path: None,
            new_path: Some(path),
            hunks: Vec::new(),
            is_binary: false,
            is_rename: false,
            is_too_large: true,
        };
    }
    let lines = split_lines(data);
    let hunk = DiffHunk {
        old_start: 0,
        old_lines: 0,
        new_start: if lines.is_empty() { 0 } else { 1 },
        new_lines: lines.len() as u32,
        lines: lines.into_iter().map(DiffLine::Added).collect(),
    };
    FileDiff {
        old_path: None,
        new_path: Some(path),
        hunks: vec![hunk],
        is_binary: false,
        is_rename: false,
        is_too_large: false,
    }
}

fn file_diff_for_deletion(path: String, data: &[u8]) -> FileDiff {
    if is_binary_data(data) {
        return FileDiff {
            old_path: Some(path),
            new_path: None,
            hunks: Vec::new(),
            is_binary: true,
            is_rename: false,
            is_too_large: false,
        };
    }
    if data.len() > MAX_DIFF_BYTES {
        return FileDiff {
            old_path: Some(path),
            new_path: None,
            hunks: Vec::new(),
            is_binary: false,
            is_rename: false,
            is_too_large: true,
        };
    }
    let lines = split_lines(data);
    let hunk = DiffHunk {
        old_start: if lines.is_empty() { 0 } else { 1 },
        old_lines: lines.len() as u32,
        new_start: 0,
        new_lines: 0,
        lines: lines.into_iter().map(DiffLine::Removed).collect(),
    };
    FileDiff {
        old_path: Some(path),
        new_path: None,
        hunks: vec![hunk],
        is_binary: false,
        is_rename: false,
        is_too_large: false,
    }
}

/// The line-level diff of one modified (or renamed-with-changes) file.
/// `old_path` is `None` only when the caller has none to give; `is_rename`
/// is threaded through from the tree-diff.
fn file_diff_for_modification(
    old_path: Option<String>,
    new_path: String,
    old_data: &[u8],
    new_data: &[u8],
    is_rename: bool,
) -> FileDiff {
    let base = |hunks: Vec<DiffHunk>, is_binary: bool, is_too_large: bool| FileDiff {
        old_path: old_path.clone(),
        new_path: Some(new_path.clone()),
        hunks,
        is_binary,
        is_rename,
        is_too_large,
    };

    if is_binary_data(old_data) || is_binary_data(new_data) {
        return base(Vec::new(), true, false);
    }
    if old_data.len() > MAX_DIFF_BYTES || new_data.len() > MAX_DIFF_BYTES {
        return base(Vec::new(), false, true);
    }
    base(histogram_hunks(old_data, new_data), false, false)
}

/// `imara-diff` histogram alignment (with Git's slider heuristics), split
/// into unified-diff hunks with [`DIFF_CONTEXT_LINES`] of context via
/// `gix-diff`'s `UnifiedDiff` renderer.
fn histogram_hunks(old_data: &[u8], new_data: &[u8]) -> Vec<DiffHunk> {
    use gix::diff::blob::unified_diff::{ConsumeHunk, ContextSize, DiffLineKind, HunkHeader};
    use gix::diff::blob::{diff_with_slider_heuristics, Algorithm, InternedInput, UnifiedDiff};

    let input = InternedInput::new(old_data, new_data);
    let diff = diff_with_slider_heuristics(Algorithm::Histogram, &input);

    #[derive(Default)]
    struct Collector(Vec<DiffHunk>);
    impl ConsumeHunk for Collector {
        type Out = Vec<DiffHunk>;
        fn consume_hunk(
            &mut self,
            header: HunkHeader,
            lines: &[(DiffLineKind, &[u8])],
        ) -> std::io::Result<()> {
            let lines = lines
                .iter()
                .map(|&(kind, content)| {
                    let text = line_token_to_string(content);
                    match kind {
                        DiffLineKind::Context => DiffLine::Context(text),
                        DiffLineKind::Add => DiffLine::Added(text),
                        DiffLineKind::Remove => DiffLine::Removed(text),
                    }
                })
                .collect();
            self.0.push(DiffHunk {
                old_start: header.before_hunk_start,
                old_lines: header.before_hunk_len,
                new_start: header.after_hunk_start,
                new_lines: header.after_hunk_len,
                lines,
            });
            Ok(())
        }
        fn finish(self) -> Self::Out {
            self.0
        }
    }

    UnifiedDiff::new(
        &diff,
        &input,
        Collector::default(),
        ContextSize::symmetrical(DIFF_CONTEXT_LINES),
    )
    .consume()
    // `Collector::consume_hunk` is infallible — the only `Err` path is a
    // delegate that returns one, which this one never does.
    .unwrap_or_default()
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
    /// `refs/heads/main` at it via `crate::force_set_ref` (the same
    /// `gix-ref` transaction path a real push now goes through). Returns
    /// the new commit id.
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
        crate::force_set_ref(&repo, "refs/heads/main", commit_id).unwrap();

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

    #[tokio::test]
    async fn diff_refs_shows_only_what_the_head_adds_over_the_merge_base() {
        let test = TestStore::new("diff-refs");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");

        // `main`: base commit, then a commit the feature branch never sees.
        let base = commit_files(&repo_dir, None, &[("README.md", b"# Demo\n")]);
        commit_files(
            &repo_dir,
            Some(base),
            &[("README.md", b"# Demo\n\nUpstream moved on.\n")],
        );

        // `feature`: branches from `base`, adds one file.
        {
            let repo = gix::open(&repo_dir).unwrap();
            let parent_tree_id = repo.find_commit(base).unwrap().tree_id().unwrap().detach();
            let mut editor = repo.edit_tree(parent_tree_id).unwrap();
            let blob = repo.write_blob(b"a feature\n").unwrap().detach();
            editor
                .upsert("feature.txt", gix_object::tree::EntryKind::Blob, blob)
                .unwrap();
            let tree_id = editor.write().unwrap().detach();
            let sig = gix_actor::Signature {
                name: "Test Author".into(),
                email: "author@example.com".into(),
                time: gix::date::Time::new(1_700_000_100, 0),
            };
            let commit = gix_object::Commit {
                tree: tree_id,
                parents: [base].into_iter().collect(),
                author: sig.clone(),
                committer: sig,
                encoding: None,
                message: "add feature".into(),
                extra_headers: Vec::new(),
            };
            let id = repo.write_object(commit).unwrap().detach();
            crate::force_set_ref(&repo, "refs/heads/feature", id).unwrap();
        }

        let diffs = diff_refs(
            &test.store,
            "alice/demo",
            "refs/heads/main",
            "refs/heads/feature",
        )
        .unwrap();
        // Only the feature's own addition — not the divergent README edit
        // `main` made after the branch point (three-dot semantics).
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].new_path.as_deref(), Some("feature.txt"));
        assert_eq!(diffs[0].old_path, None);
    }

    /// A file with two changes far enough apart that a 3-line context
    /// window can't bridge them must come back as *two* hunks, each with a
    /// correct `@@` header — the whole point of moving off the old
    /// single-hunk `diff_lines`.
    #[tokio::test]
    async fn a_modification_with_two_distant_edits_yields_two_windowed_hunks() {
        let test = TestStore::new("multi-hunk");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");

        let numbered = |a: &str, b: &str| -> Vec<u8> {
            let mut lines: Vec<String> = (1..=40).map(|n| format!("line {n}")).collect();
            lines[1] = a.to_string();
            lines[37] = b.to_string();
            (lines.join("\n") + "\n").into_bytes()
        };

        let root = commit_files(
            &repo_dir,
            None,
            &[("f.txt", &numbered("line 2", "line 38"))],
        );
        let second = commit_files(
            &repo_dir,
            Some(root),
            &[("f.txt", &numbered("line 2 CHANGED", "line 38 CHANGED"))],
        );

        let diffs = commit_diff(&test.store, "alice/demo", &second.to_string()).unwrap();
        let file = diffs
            .iter()
            .find(|d| d.new_path.as_deref() == Some("f.txt"))
            .expect("f.txt diff present");
        assert!(!file.is_binary && !file.is_too_large && !file.is_rename);
        assert_eq!(file.hunks.len(), 2, "two separated edits → two hunks");

        // First hunk brackets line 2, second brackets line 38 — the `@@`
        // offsets place each window where the change is.
        assert!(
            file.hunks[0].old_start <= 2 && file.hunks[0].old_start + file.hunks[0].old_lines > 2
        );
        assert!(
            file.hunks[1].old_start <= 38 && file.hunks[1].old_start + file.hunks[1].old_lines > 38
        );
        for hunk in &file.hunks {
            assert!(hunk
                .lines
                .iter()
                .any(|l| matches!(l, DiffLine::Removed(s) if s.starts_with("line "))));
            assert!(hunk
                .lines
                .iter()
                .any(|l| matches!(l, DiffLine::Added(s) if s.ends_with("CHANGED"))));
        }
    }

    /// Moving a file to a new path (with a small content tweak) is one
    /// `FileDiff` with `is_rename` set and both paths populated — not an
    /// unrelated delete + add.
    #[tokio::test]
    async fn a_renamed_file_is_reported_as_a_single_rename_change() {
        let test = TestStore::new("rename");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");

        let body: Vec<u8> = (1..=30)
            .map(|n| format!("shared content line {n}\n"))
            .collect::<String>()
            .into_bytes();
        let mut changed = body.clone();
        changed.extend_from_slice(b"one extra line\n");

        let root = commit_files(&repo_dir, None, &[("src/old_name.rs", &body)]);

        // Second commit: delete the old path, add the near-identical new one.
        let repo = gix::open(&repo_dir).unwrap();
        let parent_tree_id = repo.find_commit(root).unwrap().tree_id().unwrap().detach();
        let mut editor = repo.edit_tree(parent_tree_id).unwrap();
        editor.remove("src/old_name.rs").unwrap();
        let blob = repo.write_blob(&changed).unwrap().detach();
        editor
            .upsert("src/new_name.rs", gix_object::tree::EntryKind::Blob, blob)
            .unwrap();
        let tree_id = editor.write().unwrap().detach();
        let sig = gix_actor::Signature {
            name: "Test Author".into(),
            email: "author@example.com".into(),
            time: gix::date::Time::new(1_700_000_200, 0),
        };
        let commit = gix_object::Commit {
            tree: tree_id,
            parents: [root].into_iter().collect(),
            author: sig.clone(),
            committer: sig,
            encoding: None,
            message: "rename".into(),
            extra_headers: Vec::new(),
        };
        let second = repo.write_object(commit).unwrap().detach();
        crate::force_set_ref(&repo, "refs/heads/main", second).unwrap();

        let diffs = commit_diff(&test.store, "alice/demo", &second.to_string()).unwrap();
        assert_eq!(diffs.len(), 1, "one change, not a delete + an add");
        let file = &diffs[0];
        assert!(file.is_rename);
        assert_eq!(file.old_path.as_deref(), Some("src/old_name.rs"));
        assert_eq!(file.new_path.as_deref(), Some("src/new_name.rs"));
        assert!(file
            .hunks
            .iter()
            .flat_map(|h| &h.lines)
            .any(|l| matches!(l, DiffLine::Added(s) if s == "one extra line")));
    }

    /// A modified file past the byte budget comes back flagged, with no
    /// hunks — the caller renders "diff too large" rather than the file.
    #[tokio::test]
    async fn an_oversized_modification_is_flagged_and_carries_no_hunks() {
        let test = TestStore::new("too-large");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");

        let big = |tag: u8| -> Vec<u8> {
            let mut v = vec![b'x'; super::MAX_DIFF_BYTES + 1024];
            v[0] = tag;
            v
        };
        let root = commit_files(&repo_dir, None, &[("generated.bin", &big(b'a'))]);
        let second = commit_files(&repo_dir, Some(root), &[("generated.bin", &big(b'b'))]);

        let diffs = commit_diff(&test.store, "alice/demo", &second.to_string()).unwrap();
        let file = diffs
            .iter()
            .find(|d| d.new_path.as_deref() == Some("generated.bin"))
            .expect("generated.bin diff present");
        assert!(file.is_too_large);
        assert!(file.hunks.is_empty());
    }
}

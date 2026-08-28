//! `git blame` for one file at a revision — which commit last touched each
//! run of consecutive lines. A thin wrapper over `gix`'s
//! `Repository::blame_file` (`gix-blame`), the same engine `gitoxide`
//! ships; this crate never shells out to `git`.

use gix::bstr::ByteSlice;

use crate::store::RepoStore;
use crate::{open_repo_dir, record_git_op, GitError};

/// One run of consecutive lines in the blamed file, all attributed to a
/// single commit.
#[derive(Debug, Clone, PartialEq)]
pub struct BlameHunk {
    /// 1-based first line of the run in the file being blamed.
    pub start_line: u32,
    /// Number of lines the run spans.
    pub line_count: u32,
    pub commit_id: String,
    /// The attributing commit's subject line.
    pub summary: String,
    pub author_name: String,
    pub author_unix_seconds: i64,
}

/// The blame of a file: per-line commit attribution (`hunks`, in file
/// order) plus the file's own `lines`, so a caller can render the
/// annotated file without a second fetch. `lines.len()` is the blamed line
/// count; `hunks` partition `1..=lines.len()` with no gaps or overlap.
#[derive(Debug, Clone, PartialEq)]
pub struct Blame {
    pub hunks: Vec<BlameHunk>,
    pub lines: Vec<String>,
}

/// Blame `path` as of `rev` (a branch name, tag, or any commit-ish
/// `rev_parse` accepts). Errors if the revision doesn't resolve, the path
/// isn't a file there, or the content is binary/empty (an empty blame).
pub fn blame(store: &dyn RepoStore, name: &str, rev: &str, path: &str) -> Result<Blame, GitError> {
    let repo = open_repo_dir(store, name)?;

    let span = tracing::info_span!("git.blame", repo.name = %name, rev = %rev, path = %path);
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let suspect = repo
            .rev_parse_single(rev)
            .map_err(|err| GitError::Git(err.to_string()))?
            .object()
            .map_err(|err| GitError::Git(err.to_string()))?
            .peel_to_commit()
            .map_err(|err| GitError::Git(err.to_string()))?
            .id;

        let outcome = repo
            .blame_file(
                path.as_bytes().as_bstr(),
                suspect,
                gix::repository::blame_file::Options::default(),
            )
            .map_err(|err| GitError::Git(err.to_string()))?;

        // `outcome.blob` is the file's bytes; split on `\n` and drop the
        // single empty element a trailing newline leaves, so `lines.len()`
        // equals the blamed line count.
        let mut lines: Vec<String> = outcome
            .blob
            .split(|&byte| byte == b'\n')
            .map(|line| String::from_utf8_lossy(line).into_owned())
            .collect();
        if matches!(lines.last(), Some(last) if last.is_empty()) && lines.len() > 1 {
            lines.pop();
        }

        let mut hunks = Vec::with_capacity(outcome.entries.len());
        for entry in &outcome.entries {
            let commit = repo
                .find_commit(entry.commit_id)
                .map_err(|err| GitError::Git(err.to_string()))?;
            let summary = commit
                .message()
                .ok()
                .map(|message| message.summary().to_string())
                .unwrap_or_default();
            let author = commit.author().ok();
            let author_name = author
                .as_ref()
                .map(|author| author.name.to_string())
                .unwrap_or_default();
            let author_unix_seconds = author
                .and_then(|author| author.time().ok())
                .map(|time| time.seconds)
                .unwrap_or(0);
            hunks.push(BlameHunk {
                start_line: entry.start_in_blamed_file + 1,
                line_count: entry.len.get(),
                commit_id: entry.commit_id.to_string(),
                summary,
                author_name,
                author_unix_seconds,
            });
        }
        Ok(Blame { hunks, lines })
    })();
    record_git_op("git.blame", start, &result);
    result
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
                "edda-git-blame-test-{unique}-{}",
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

    fn commit_files(
        repo_dir: &std::path::Path,
        parent: Option<gix::ObjectId>,
        files: &[(&str, &[u8])],
        when: i64,
    ) -> gix::ObjectId {
        let repo = gix::open(repo_dir).unwrap();
        let parent_tree_id = match parent {
            Some(id) => repo.find_commit(id).unwrap().tree_id().unwrap().detach(),
            None => repo.empty_tree().id().detach(),
        };
        let mut editor = repo.edit_tree(parent_tree_id).unwrap();
        for (path, content) in files {
            let blob_id = repo.write_blob(*content).unwrap().detach();
            editor
                .upsert(*path, gix_object::tree::EntryKind::Blob, blob_id)
                .unwrap();
        }
        let tree_id = editor.write().unwrap().detach();
        let signature = gix_actor::Signature {
            name: "Blame Tester".into(),
            email: "blame@example.com".into(),
            time: gix::date::Time::new(when, 0),
        };
        let commit = gix_object::Commit {
            tree: tree_id,
            parents: parent.into_iter().collect(),
            author: signature.clone(),
            committer: signature,
            encoding: None,
            message: format!("commit at {when}").into(),
            extra_headers: Vec::new(),
        };
        let commit_id = repo.write_object(commit).unwrap().detach();
        crate::force_set_ref(&repo, "refs/heads/main", commit_id).unwrap();
        commit_id
    }

    #[tokio::test]
    async fn blame_attributes_each_line_run_to_the_commit_that_introduced_it() {
        let test = TestStore::new("basic");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");

        let first = commit_files(
            &repo_dir,
            None,
            &[("f.txt", b"alpha\nbeta\ngamma\n")],
            1_700_000_000,
        );
        // Change the middle line only.
        let second = commit_files(
            &repo_dir,
            Some(first),
            &[("f.txt", b"alpha\nBETA\ngamma\n")],
            1_700_000_100,
        );

        let blame = blame(&test.store, "alice/demo", "main", "f.txt").unwrap();
        assert_eq!(blame.lines, vec!["alpha", "BETA", "gamma"]);

        // Line 2 belongs to `second`; lines 1 and 3 still belong to `first`.
        let commit_of_line = |n: u32| {
            blame
                .hunks
                .iter()
                .find(|h| n >= h.start_line && n < h.start_line + h.line_count)
                .map(|h| h.commit_id.clone())
                .unwrap()
        };
        assert_eq!(commit_of_line(1), first.to_string());
        assert_eq!(commit_of_line(2), second.to_string());
        assert_eq!(commit_of_line(3), first.to_string());
        assert!(blame
            .hunks
            .iter()
            .all(|h| h.author_name == "Blame Tester" && h.author_unix_seconds > 0));
    }

    #[tokio::test]
    async fn blame_rejects_a_path_that_does_not_exist_at_the_revision() {
        let test = TestStore::new("missing");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        let repo_dir = test.store.repo_dir("alice/demo");
        commit_files(&repo_dir, None, &[("present.txt", b"hi\n")], 1_700_000_000);

        assert!(blame(&test.store, "alice/demo", "main", "absent.txt").is_err());
    }
}

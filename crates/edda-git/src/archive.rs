//! `git archive` — a `tar.gz` or `zip` snapshot of a tree at a revision.
//! Built with `gix`'s `worktree-stream` + `worktree-archive` (`gix-archive`),
//! the same path `gitoxide` uses; this crate never shells out to `git`.
//!
//! The archive is assembled into a single `Vec<u8>` on the caller's
//! blocking thread rather than streamed frame-by-frame to the client:
//! `gix-archive`'s writer needs `Seek` (the `zip` central directory) and a
//! self-hosted instance's trees are human-scale. A truly streamed archive
//! (temp file or a seek-free `tar` writer) is a later refinement — same
//! "correct and simple first" stance the upload-pack builder takes.

use std::io::Cursor;
use std::sync::atomic::AtomicBool;

use crate::store::RepoStore;
use crate::{open_repo_dir, record_git_op, GitError};

/// The container formats the archive endpoint offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    /// gzip-compressed tar.
    TarGz,
    /// zip.
    Zip,
}

impl ArchiveFormat {
    /// The `Content-Type` a transport should send this archive with.
    #[must_use]
    pub fn content_type(self) -> &'static str {
        match self {
            ArchiveFormat::TarGz => "application/gzip",
            ArchiveFormat::Zip => "application/zip",
        }
    }

    /// The filename extension (no leading dot).
    #[must_use]
    pub fn extension(self) -> &'static str {
        match self {
            ArchiveFormat::TarGz => "tar.gz",
            ArchiveFormat::Zip => "zip",
        }
    }
}

/// A `format` archive of the tree at `rev` (a branch name, tag, or any
/// commit-ish `rev_parse` accepts) in `name`'s repository. Every path in
/// the archive is prefixed with `{repo}/` (the repo's own path segment),
/// matching what `git archive --prefix` and the common hosting convention
/// produce.
pub fn archive(
    store: &dyn RepoStore,
    name: &str,
    rev: &str,
    format: ArchiveFormat,
) -> Result<Vec<u8>, GitError> {
    let repo = open_repo_dir(store, name)?;

    let span = tracing::info_span!(
        "git.archive",
        repo.name = %name,
        rev = %rev,
        format = format.extension()
    );
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let commit = repo
            .rev_parse_single(rev)
            .map_err(|err| GitError::Git(err.to_string()))?
            .object()
            .map_err(|err| GitError::Git(err.to_string()))?
            .peel_to_commit()
            .map_err(|err| GitError::Git(err.to_string()))?;
        let tree_id = commit
            .tree_id()
            .map_err(|err| GitError::Git(err.to_string()))?
            .detach();
        let modification_time = commit.time().map(|time| time.seconds).unwrap_or(0);

        let (stream, _index) = repo
            .worktree_stream(tree_id)
            .map_err(|err| GitError::Git(err.to_string()))?;

        let prefix = name.rsplit('/').next().unwrap_or(name);
        let options = gix_archive::Options {
            format: match format {
                ArchiveFormat::TarGz => gix_archive::Format::TarGz {
                    compression_level: None,
                },
                ArchiveFormat::Zip => gix_archive::Format::Zip {
                    compression_level: None,
                },
            },
            tree_prefix: Some(format!("{prefix}/").into()),
            modification_time,
        };

        let mut out = Cursor::new(Vec::new());
        let no_interrupt = AtomicBool::new(false);
        repo.worktree_archive(
            stream,
            &mut out,
            gix::progress::Discard,
            &no_interrupt,
            options,
        )
        .map_err(|err| GitError::Git(err.to_string()))?;
        Ok(out.into_inner())
    })();
    record_git_op("git.archive", start, &result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LocalFsStore;
    use crate::{create_repo, LockRegistry};
    use std::io::Read;
    use std::path::PathBuf;

    struct TestStore {
        store: LocalFsStore,
        root: PathBuf,
    }

    impl TestStore {
        fn new(unique: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "edda-git-archive-test-{unique}-{}",
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

    fn commit_files(repo_dir: &std::path::Path, files: &[(&str, &[u8])]) -> gix::ObjectId {
        let repo = gix::open(repo_dir).unwrap();
        let mut editor = repo.edit_tree(repo.empty_tree().id().detach()).unwrap();
        for (path, content) in files {
            let blob_id = repo.write_blob(*content).unwrap().detach();
            editor
                .upsert(*path, gix_object::tree::EntryKind::Blob, blob_id)
                .unwrap();
        }
        let tree_id = editor.write().unwrap().detach();
        let signature = gix_actor::Signature {
            name: "Archive Tester".into(),
            email: "archive@example.com".into(),
            time: gix::date::Time::new(1_700_000_000, 0),
        };
        let commit = gix_object::Commit {
            tree: tree_id,
            parents: Vec::new().into(),
            author: signature.clone(),
            committer: signature,
            encoding: None,
            message: "seed".into(),
            extra_headers: Vec::new(),
        };
        let commit_id = repo.write_object(commit).unwrap().detach();
        crate::force_set_ref(&repo, "refs/heads/main", commit_id).unwrap();
        commit_id
    }

    #[tokio::test]
    async fn tar_gz_archive_is_a_valid_gzip_stream_containing_the_prefixed_tree() {
        let test = TestStore::new("targz");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        commit_files(
            &test.store.repo_dir("alice/demo"),
            &[("README.md", b"# hi\n"), ("src/main.rs", b"fn main() {}\n")],
        );

        let bytes = archive(&test.store, "alice/demo", "main", ArchiveFormat::TarGz).unwrap();
        // gzip magic.
        assert_eq!(&bytes[..2], &[0x1f, 0x8b]);

        // Inflate; the tar stores each path as plaintext in its 512-byte
        // entry headers, so a substring search over the raw tar is enough
        // to prove the entries are present and `demo/`-prefixed without a
        // tar-parsing dev-dependency.
        let mut tar_bytes = Vec::new();
        flate2::read::GzDecoder::new(&bytes[..])
            .read_to_end(&mut tar_bytes)
            .unwrap();
        let contains = |needle: &[u8]| tar_bytes.windows(needle.len()).any(|w| w == needle);
        assert!(
            contains(b"demo/README.md"),
            "README entry present + prefixed"
        );
        assert!(
            contains(b"demo/src/main.rs"),
            "nested entry present + prefixed"
        );
        assert!(
            !contains(b"\0README.md\0"),
            "no unprefixed entry path in the tar headers"
        );
    }

    #[tokio::test]
    async fn zip_archive_has_the_zip_local_file_header_magic() {
        let test = TestStore::new("zip");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        commit_files(&test.store.repo_dir("alice/demo"), &[("f.txt", b"body\n")]);

        let bytes = archive(&test.store, "alice/demo", "main", ArchiveFormat::Zip).unwrap();
        assert_eq!(&bytes[..2], b"PK", "zip local-file-header magic");
        assert!(bytes.len() > 100);
    }

    #[tokio::test]
    async fn archive_rejects_an_unknown_revision() {
        let test = TestStore::new("badrev");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        commit_files(&test.store.repo_dir("alice/demo"), &[("f.txt", b"x\n")]);

        assert!(archive(
            &test.store,
            "alice/demo",
            "no-such-branch",
            ArchiveFormat::Zip
        )
        .is_err());
    }
}

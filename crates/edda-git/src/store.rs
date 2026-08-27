use std::path::PathBuf;

/// Resolves where a repo's git data lives. Kept separate from the git
/// operations in `mod.rs` so a future non-filesystem backend (repos synced
/// to S3/Garage/MinIO instead of the local disk) can be added later without
/// touching how repos are read or written — a store only has to answer
/// "where are this repo's bytes."
pub trait RepoStore: Send + Sync {
    /// Local, git-operable directory for a repo. For a remote-backed store
    /// this would be a local cache path kept in sync with the remote.
    ///
    /// `name` is a full `{owner}/{repo}` identity (validated against
    /// `edda_domain::validation::is_valid_repository_identity`) — every
    /// caller in this crate validates it first, so implementations can
    /// assume that shape rather than re-checking it.
    fn repo_dir(&self, name: &str) -> PathBuf;

    /// Full `{owner}/{repo}` identities of every repo currently in the store.
    fn list_repo_names(&self) -> std::io::Result<Vec<String>>;

    /// Where one Git LFS object's bytes live on disk, nested under the
    /// repo's own directory (`{repo_dir}/lfs/objects/{oid[0:2]}/{oid[2:4]}/
    /// {oid}`, mirroring `git-lfs`'s own local storage layout) rather than
    /// a separate top-level tree — a repo fork (a directory copy, see
    /// `fork_repo`) then naturally carries its LFS objects along with it,
    /// with no separate copy step. The default implementation is correct
    /// for any store built on `repo_dir`; only overridden by an
    /// implementation with a genuinely different physical layout.
    fn lfs_object_path(&self, name: &str, oid: &str) -> PathBuf {
        let base = self.repo_dir(name).join("lfs").join("objects");
        if oid.len() >= 4 {
            base.join(&oid[0..2]).join(&oid[2..4]).join(oid)
        } else {
            base.join(oid)
        }
    }

    /// Where one release asset's bytes live on disk, nested under the
    /// repo's own directory the same way `lfs_object_path` is — a fork
    /// (a directory copy) then naturally carries release assets along
    /// with it too, with no separate copy step. `storage_key` is
    /// `{release_id}/{filename}` (already-validated, non-path-traversing
    /// components — see `edda_http`'s upload handler); this default
    /// implementation only ever joins it under `releases/`, never
    /// interprets it further.
    fn release_asset_path(&self, name: &str, storage_key: &str) -> PathBuf {
        self.repo_dir(name).join("releases").join(storage_key)
    }
}

pub struct LocalFsStore {
    root: PathBuf,
}

impl LocalFsStore {
    /// Rooted at an explicit directory. The composition root passes
    /// `{data_dir}/repos` (resolved once by `edda_http::config`); tests
    /// pass a temp dir. This crate never reads the environment itself.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

impl RepoStore for LocalFsStore {
    /// `{root}/{owner}/{repo}.git` — one directory per owner, holding that
    /// owner's bare repos. Falls back to treating the whole string as a
    /// single path component if it somehow has no `/` (defensive only:
    /// every real call site validates `name` as `{owner}/{repo}` first, via
    /// `git::validate_name`, before it ever reaches here).
    fn repo_dir(&self, name: &str) -> PathBuf {
        match name.split_once('/') {
            Some((owner, repo)) => self.root.join(owner).join(format!("{repo}.git")),
            None => self.root.join(format!("{name}.git")),
        }
    }

    fn list_repo_names(&self) -> std::io::Result<Vec<String>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for owner_entry in std::fs::read_dir(&self.root)? {
            let owner_entry = owner_entry?;
            if !owner_entry.file_type()?.is_dir() {
                continue;
            }
            let Some(owner) = owner_entry.file_name().to_str().map(str::to_string) else {
                continue;
            };

            for repo_entry in std::fs::read_dir(owner_entry.path())? {
                let repo_entry = repo_entry?;
                if !repo_entry.file_type()?.is_dir() {
                    continue;
                }
                if let Some(repo) = repo_entry
                    .file_name()
                    .to_str()
                    .and_then(|s| s.strip_suffix(".git"))
                {
                    names.push(format!("{owner}/{repo}"));
                }
            }
        }
        names.sort();
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `LocalFsStore` rooted at a fresh directory under the OS temp dir,
    /// removed again when the test's `TestStore` is dropped — keeps
    /// filesystem tests isolated from both each other and from the real
    /// data directory (this crate never reads `EDDA_DATA_DIR` — the
    /// composition root passes an explicit root to `LocalFsStore::new`).
    struct TestStore {
        store: LocalFsStore,
        root: PathBuf,
    }

    impl TestStore {
        fn new(unique: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("edda-store-test-{unique}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            Self {
                store: LocalFsStore { root: root.clone() },
                root,
            }
        }
    }

    impl Drop for TestStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn repo_dir_nests_under_owner() {
        let test = TestStore::new("repo-dir");
        let dir = test.store.repo_dir("alice/my-repo");
        assert_eq!(dir, test.root.join("alice").join("my-repo.git"));
    }

    #[test]
    fn list_repo_names_is_empty_for_a_missing_root() {
        let test = TestStore::new("empty-root");
        assert_eq!(test.store.list_repo_names().unwrap(), Vec::<String>::new());
    }

    #[test]
    fn list_repo_names_returns_owner_repo_identities() {
        let test = TestStore::new("list-names");
        std::fs::create_dir_all(test.root.join("alice").join("repo-one.git")).unwrap();
        std::fs::create_dir_all(test.root.join("alice").join("repo-two.git")).unwrap();
        std::fs::create_dir_all(test.root.join("bob").join("repo-one.git")).unwrap();
        // A non-`.git`-suffixed directory (and a stray file) under an owner
        // shouldn't be reported as a repo.
        std::fs::create_dir_all(test.root.join("alice").join("not-a-repo")).unwrap();
        std::fs::write(test.root.join("alice").join("stray-file"), b"").unwrap();

        let mut names = test.store.list_repo_names().unwrap();
        names.sort();
        assert_eq!(
            names,
            vec![
                "alice/repo-one".to_string(),
                "alice/repo-two".to_string(),
                "bob/repo-one".to_string()
            ]
        );
    }
}

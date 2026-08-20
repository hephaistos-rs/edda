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
    /// `name` is a full `{owner}/{repo}` identity (see `git::validate_name`)
    /// — every caller in `git::mod` validates it first, so implementations
    /// can assume that shape rather than re-checking it.
    fn repo_dir(&self, name: &str) -> PathBuf;

    /// Full `{owner}/{repo}` identities of every repo currently in the store.
    fn list_repo_names(&self) -> std::io::Result<Vec<String>>;
}

pub struct LocalFsStore {
    root: PathBuf,
}

impl LocalFsStore {
    pub fn from_env() -> Self {
        let data_dir = std::env::var("EDDA_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data"));
        Self { root: data_dir.join("repos") }
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
            let Some(owner) = owner_entry.file_name().to_str().map(str::to_string) else { continue };

            for repo_entry in std::fs::read_dir(owner_entry.path())? {
                let repo_entry = repo_entry?;
                if !repo_entry.file_type()?.is_dir() {
                    continue;
                }
                if let Some(repo) = repo_entry.file_name().to_str().and_then(|s| s.strip_suffix(".git")) {
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
    /// `EDDA_DATA_DIR` (never touched here; see `LocalFsStore::from_env`).
    struct TestStore {
        store: LocalFsStore,
        root: PathBuf,
    }

    impl TestStore {
        fn new(unique: &str) -> Self {
            let root = std::env::temp_dir().join(format!("edda-store-test-{unique}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            Self { store: LocalFsStore { root: root.clone() }, root }
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
        assert_eq!(names, vec!["alice/repo-one".to_string(), "alice/repo-two".to_string(), "bob/repo-one".to_string()]);
    }
}

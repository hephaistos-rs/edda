use std::path::PathBuf;

/// Resolves where a repo's git data lives. Kept separate from the git
/// operations in `mod.rs` so a future non-filesystem backend (repos synced
/// to S3/Garage/MinIO instead of the local disk) can be added later without
/// touching how repos are read or written — a store only has to answer
/// "where are this repo's bytes."
pub trait RepoStore: Send + Sync {
    /// Local, git-operable directory for a repo. For a remote-backed store
    /// this would be a local cache path kept in sync with the remote.
    fn repo_dir(&self, name: &str) -> PathBuf;

    /// Names of every repo currently in the store.
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
    fn repo_dir(&self, name: &str) -> PathBuf {
        self.root.join(format!("{name}.git"))
    }

    fn list_repo_names(&self) -> std::io::Result<Vec<String>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            if let Some(name) = entry.file_name().to_str().and_then(|s| s.strip_suffix(".git")) {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }
}

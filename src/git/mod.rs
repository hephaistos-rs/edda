pub mod store;

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::Mutex as AsyncMutex;

use store::RepoStore;

/// Per-repo-name lock so two writes to the *same* repo serialize instead of
/// racing — not just Edda's own create/update/delete against each other, but
/// also against a `git push` landing at the same time (the git-http bridge in
/// `api` holds this for the duration of a `receive-pack`, since that's a
/// write too, e.g. someone deleting a repo mid-push). Writes to different
/// repos never contend.
///
/// `tokio::sync::Mutex` rather than `std`'s: the git-http bridge holds this
/// across an `.await` (a subprocess call), which a std `MutexGuard` can't
/// safely do (it isn't `Send`).
///
/// Entries are never removed, including for deleted repos: one `Arc<Mutex<()>>`
/// per distinct name ever touched is a few dozen bytes, and this is a
/// self-hosted tool with a human-scale repo count, not something worth adding
/// reference-counted eviction for.
pub(crate) fn repo_lock(name: &str) -> Arc<AsyncMutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>> = OnceLock::new();
    let registry = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    registry.entry(name.to_string()).or_insert_with(|| Arc::new(AsyncMutex::new(()))).clone()
}

#[derive(Debug)]
pub enum GitError {
    InvalidName(String),
    AlreadyExists(String),
    NotFound(String),
    Io(std::io::Error),
    Git(String),
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GitError::InvalidName(name) => write!(f, "\"{name}\" isn't a valid repository name"),
            GitError::AlreadyExists(name) => write!(f, "a repository named \"{name}\" already exists"),
            GitError::NotFound(name) => write!(f, "no repository named \"{name}\""),
            GitError::Io(err) => write!(f, "{err}"),
            GitError::Git(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for GitError {}

impl From<std::io::Error> for GitError {
    fn from(err: std::io::Error) -> Self {
        GitError::Io(err)
    }
}

pub struct RepoSummary {
    pub name: String,
    pub description: Option<String>,
    pub default_branch: Option<String>,
    pub branch_count: usize,
    pub is_empty: bool,
    pub last_commit: Option<CommitSummary>,
}

pub struct CommitSummary {
    pub summary: String,
    pub author_name: String,
    pub unix_seconds: i64,
}

/// Repo names become directory names under the store's root, so this is a
/// security boundary, not just validation: reject anything that could
/// escape the root (`.`, `..`, path separators) or collide with the `.git`
/// suffix the store appends.
fn validate_name(name: &str) -> Result<(), GitError> {
    let valid = !name.is_empty()
        && name.len() <= 100
        && name != "."
        && name != ".."
        && !name.starts_with('.')
        && !name.ends_with(".git")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if valid {
        Ok(())
    } else {
        Err(GitError::InvalidName(name.to_string()))
    }
}

/// Validates `name`, then resolves it to its on-disk directory. Used
/// anywhere a name needs to become a path — including the git-http bridge in
/// `api` — so validation always happens before a name meets the filesystem.
pub(crate) fn validated_repo_dir(store: &dyn RepoStore, name: &str) -> Result<PathBuf, GitError> {
    validate_name(name)?;
    Ok(store.repo_dir(name))
}

pub async fn create_repo(store: &dyn RepoStore, name: &str, description: Option<&str>) -> Result<(), GitError> {
    validate_name(name)?;
    let lock = repo_lock(name);
    let _guard = lock.lock().await;
    let dir = store.repo_dir(name);
    if dir.exists() {
        return Err(GitError::AlreadyExists(name.to_string()));
    }
    // gix::init_bare only mkdir's the target itself, not its parents.
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    gix::init_bare(&dir).map_err(|err| GitError::Git(err.to_string()))?;
    // `git http-backend` refuses pushes unless a repo opts in — a repo being
    // readable doesn't imply it should accept writes. There's no auth yet to
    // gate this further, so every repo opts in at creation time; once there's
    // real access control this is where per-repo write permission would live.
    let config = std::process::Command::new("git")
        .args(["config", "http.receivepack", "true"])
        .current_dir(&dir)
        .output()?;
    if !config.status.success() {
        return Err(GitError::Git(format!(
            "created the repo but couldn't enable http push: {}",
            String::from_utf8_lossy(&config.stderr)
        )));
    }
    if let Some(description) = description {
        let description = description.trim();
        if !description.is_empty() {
            std::fs::write(dir.join("description"), description)?;
        }
    }
    Ok(())
}

/// Updates the repo's description (the only editable field until `db`
/// exists). `None`/empty clears it, matching `read_description`'s notion of
/// "no description" rather than writing an empty file.
pub async fn update_repo(store: &dyn RepoStore, name: &str, description: Option<&str>) -> Result<(), GitError> {
    validate_name(name)?;
    let lock = repo_lock(name);
    let _guard = lock.lock().await;
    let dir = store.repo_dir(name);
    if !dir.exists() {
        return Err(GitError::NotFound(name.to_string()));
    }
    let path = dir.join("description");
    match description.map(str::trim) {
        Some(description) if !description.is_empty() => std::fs::write(path, description)?,
        _ => {
            if path.exists() {
                std::fs::remove_file(path)?;
            }
        }
    }
    Ok(())
}

pub async fn delete_repo(store: &dyn RepoStore, name: &str) -> Result<(), GitError> {
    validate_name(name)?;
    let lock = repo_lock(name);
    let _guard = lock.lock().await;
    let dir = store.repo_dir(name);
    if !dir.exists() {
        return Err(GitError::NotFound(name.to_string()));
    }
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

pub fn list_repos(store: &dyn RepoStore) -> Result<Vec<RepoSummary>, GitError> {
    let names = store.list_repo_names()?;
    names.iter().map(|name| repo_summary(store, name)).collect()
}

pub fn repo_summary(store: &dyn RepoStore, name: &str) -> Result<RepoSummary, GitError> {
    validate_name(name)?;
    let dir = store.repo_dir(name);
    if !dir.exists() {
        return Err(GitError::NotFound(name.to_string()));
    }

    let description = read_description(&dir);

    let repo = gix::open(&dir).map_err(|err| GitError::Git(err.to_string()))?;

    let mut branch_names: Vec<String> = match repo.references() {
        Ok(refs) => match refs.local_branches() {
            Ok(branches) => branches.filter_map(Result::ok).map(|r| r.name().shorten().to_string()).collect(),
            Err(_) => Vec::new(),
        },
        Err(_) => Vec::new(),
    };
    branch_names.sort();
    let branch_count = branch_names.len();

    let head = repo.head().map_err(|err| GitError::Git(err.to_string()))?;
    let mut default_branch = head.referent_name().map(|name| name.shorten().to_string());
    let mut is_empty = head.is_unborn();

    // `gix::init_bare` points HEAD at a fixed default (e.g. "master") that a
    // push can easily never create (e.g. it pushes "main" instead), which
    // would otherwise report a repo with real history as empty. Fall back to
    // a branch that actually exists. (The git-http bridge separately fixes
    // this for real on disk right after a push — see `fix_unborn_head` — this
    // is a display-only fallback for repos it hasn't run against yet.)
    if is_empty {
        if let Some(branch) = pick_default_branch(&branch_names) {
            default_branch = Some(branch.to_string());
            is_empty = false;
        }
    }

    let last_commit = if is_empty {
        None
    } else {
        let commit = if head.is_unborn() {
            default_branch
                .as_deref()
                .and_then(|branch| repo.find_reference(&format!("refs/heads/{branch}")).ok())
                .and_then(|mut reference| reference.peel_to_commit().ok())
        } else {
            repo.head_commit().ok()
        };
        commit.and_then(|commit| {
            let summary = commit.message().ok()?.summary().to_string();
            let author = commit.author().ok()?;
            let author_name = author.name.to_string();
            let unix_seconds = author.time().ok()?.seconds;
            Some(CommitSummary { summary, author_name, unix_seconds })
        })
    };

    Ok(RepoSummary {
        name: name.to_string(),
        description,
        default_branch,
        branch_count,
        is_empty,
        last_commit,
    })
}

/// Bare repos conventionally carry a `description` file (used by gitweb/cgit)
/// — reused here instead of a database column, since git already gives us
/// somewhere to put it and there's no `db` yet.
fn read_description(dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(dir.join("description")).ok()?;
    let text = text.trim();
    if text.is_empty() || text.starts_with("Unnamed repository") {
        None
    } else {
        Some(text.to_string())
    }
}

/// Prefers "main", then "master", then whatever's first — the same
/// preference order used both for display (`repo_summary`) and for actually
/// repairing HEAD on disk (`fix_unborn_head`).
fn pick_default_branch(names: &[String]) -> Option<&str> {
    names
        .iter()
        .find(|n| n.as_str() == "main")
        .or_else(|| names.iter().find(|n| n.as_str() == "master"))
        .or_else(|| names.first())
        .map(String::as_str)
}

/// `gix::init_bare` points a fresh repo's HEAD at a fixed default (e.g.
/// "master"). If the first push creates a differently-named branch (e.g.
/// "main"), HEAD is left pointing at a ref that was never created — harmless
/// for Edda's own reads (`repo_summary` already falls back), but it breaks a
/// real `git clone`: the client asks the server what HEAD is, gets a
/// nonexistent ref back, and can't check anything out. Called by the
/// git-http bridge right after a successful push to repair HEAD for real.
pub(crate) fn fix_unborn_head(dir: &Path) -> Result<(), GitError> {
    let repo = gix::open(dir).map_err(|err| GitError::Git(err.to_string()))?;
    let head = repo.head().map_err(|err| GitError::Git(err.to_string()))?;
    if !head.is_unborn() {
        return Ok(());
    }

    let mut branch_names: Vec<String> = match repo.references() {
        Ok(refs) => match refs.local_branches() {
            Ok(branches) => branches.filter_map(Result::ok).map(|r| r.name().shorten().to_string()).collect(),
            Err(_) => Vec::new(),
        },
        Err(_) => Vec::new(),
    };
    branch_names.sort();

    let Some(branch) = pick_default_branch(&branch_names) else {
        return Ok(()); // genuinely still empty — nothing to point HEAD at
    };

    let output = std::process::Command::new("git")
        .args(["symbolic-ref", "HEAD", &format!("refs/heads/{branch}")])
        .current_dir(dir)
        .output()?;
    if !output.status.success() {
        return Err(GitError::Git(format!("couldn't update HEAD: {}", String::from_utf8_lossy(&output.stderr))));
    }
    Ok(())
}

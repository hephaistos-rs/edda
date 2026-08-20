pub mod pack;
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

/// Records one git operation's outcome as the `edda.git.operation.duration`
/// metric (`operation`/`status` attributes only — never a repo name, see
/// `telemetry::metrics`). Kept as a one-line call at each instrumented git
/// boundary so a span's name and its matching metric label can't drift apart.
fn record_git_op<T>(operation: &'static str, start: std::time::Instant, result: &Result<T, GitError>) {
    let status = if result.is_ok() { "success" } else { "error" };
    crate::telemetry::metrics::record_git_operation(operation, status, start.elapsed());
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
    pub is_private: bool,
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

pub async fn create_repo(store: &dyn RepoStore, name: &str, description: Option<&str>, private: bool) -> Result<(), GitError> {
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
    {
        let span = tracing::info_span!("git.initialize", repo.name = %name);
        let _guard = span.enter();
        let start = std::time::Instant::now();
        let result = gix::init_bare(&dir).map_err(|err| GitError::Git(err.to_string())).map(|_| ());
        record_git_op("git.initialize", start, &result);
        result?;
    }
    if let Some(description) = description {
        let description = description.trim();
        if !description.is_empty() {
            std::fs::write(dir.join("description"), description)?;
        }
    }
    if private {
        std::fs::write(dir.join("private"), b"")?;
    }
    Ok(())
}

/// Updates the repo's description. `None`/empty clears it, matching
/// `read_description`'s notion of "no description" rather than writing an
/// empty file.
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

/// Flips a repo between public and private. Kept separate from
/// `update_repo` since it's gated differently — owner-only, not any
/// collaborator with write access (see `require_owner` in `server/mod.rs`).
pub async fn set_visibility(store: &dyn RepoStore, name: &str, private: bool) -> Result<(), GitError> {
    validate_name(name)?;
    let lock = repo_lock(name);
    let _guard = lock.lock().await;
    let dir = store.repo_dir(name);
    if !dir.exists() {
        return Err(GitError::NotFound(name.to_string()));
    }
    let path = dir.join("private");
    if private {
        std::fs::write(path, b"")?;
    } else if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Cheap visibility check that doesn't require opening the repo with `gix`
/// — used on every read path (file browsing, clone/fetch) to decide whether
/// an access check is even needed, without paying `repo_summary`'s cost of
/// walking branches and peeling the last commit.
pub fn is_repo_private(store: &dyn RepoStore, name: &str) -> Result<bool, GitError> {
    validate_name(name)?;
    let dir = store.repo_dir(name);
    if !dir.exists() {
        return Err(GitError::NotFound(name.to_string()));
    }
    Ok(read_private_flag(&dir))
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
    let is_private = read_private_flag(&dir);

    let repo = gix::open(&dir).map_err(|err| GitError::Git(err.to_string()))?;

    let branch_names = list_branch_names(&repo);
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
        is_private,
        last_commit,
    })
}

pub struct TreeEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: Option<u64>,
}

pub struct BlobContent {
    pub name: String,
    pub size: u64,
    pub is_binary: bool,
    /// `None` for binary content or anything past `MAX_INLINE_BLOB_BYTES` —
    /// the browser has no reason to render either, and there's no reason to
    /// pay to serialize/transfer bytes nothing will show.
    pub content: Option<String>,
}

pub struct CommitLogEntry {
    pub id: String,
    pub summary: String,
    pub author_name: String,
    pub unix_seconds: i64,
}

const MAX_INLINE_BLOB_BYTES: usize = 1_000_000;

/// Sorted local branch names — shared by `repo_summary` (for `branch_count`),
/// `open_and_resolve`'s unborn-HEAD fallback, and `list_branches` (for the
/// UI's branch switcher), so there's exactly one place that defines what
/// "the repo's branches" means.
fn list_branch_names(repo: &gix::Repository) -> Vec<String> {
    let mut names: Vec<String> = match repo.references() {
        Ok(refs) => match refs.local_branches() {
            Ok(branches) => branches.filter_map(Result::ok).map(|r| r.name().shorten().to_string()).collect(),
            Err(_) => Vec::new(),
        },
        Err(_) => Vec::new(),
    };
    names.sort();
    names
}

pub fn list_branches(store: &dyn RepoStore, name: &str) -> Result<Vec<String>, GitError> {
    validate_name(name)?;
    let dir = store.repo_dir(name);
    if !dir.exists() {
        return Err(GitError::NotFound(name.to_string()));
    }
    let repo = gix::open(&dir).map_err(|err| GitError::Git(err.to_string()))?;
    Ok(list_branch_names(&repo))
}

/// Opens `name`'s repo and resolves which commit to browse: `branch` if
/// given, else the same "real HEAD, falling back to a sensible default
/// branch" logic used everywhere else a repo needs one commit to point at
/// (see `pick_default_branch`).
#[tracing::instrument(name = "git.resolve_revision", skip_all, err, fields(branch = branch.unwrap_or("HEAD")))]
fn open_and_resolve<'repo>(
    repo: &'repo gix::Repository,
    branch: Option<&str>,
) -> Result<gix::Commit<'repo>, GitError> {
    let start = std::time::Instant::now();
    let result = (|| {
        if let Some(branch) = branch {
            let mut reference =
                repo.find_reference(&format!("refs/heads/{branch}")).map_err(|err| GitError::Git(err.to_string()))?;
            return reference.peel_to_commit().map_err(|err| GitError::Git(err.to_string()));
        }

        if let Ok(commit) = repo.head_commit() {
            return Ok(commit);
        }

        let branch_names = list_branch_names(repo);
        let branch = pick_default_branch(&branch_names).ok_or_else(|| GitError::Git("repository has no commits yet".to_string()))?;
        let mut reference =
            repo.find_reference(&format!("refs/heads/{branch}")).map_err(|err| GitError::Git(err.to_string()))?;
        reference.peel_to_commit().map_err(|err| GitError::Git(err.to_string()))
    })();
    record_git_op("git.resolve_revision", start, &result);
    result
}

#[tracing::instrument(name = "git.open", skip_all, err, fields(repo.name = %name))]
fn open_repo_dir(store: &dyn RepoStore, name: &str) -> Result<gix::Repository, GitError> {
    let start = std::time::Instant::now();
    let result = (|| {
        validate_name(name)?;
        let dir = store.repo_dir(name);
        if !dir.exists() {
            return Err(GitError::NotFound(name.to_string()));
        }
        gix::open(&dir).map_err(|err| GitError::Git(err.to_string()))
    })();
    record_git_op("git.open", start, &result);
    result
}

/// Lists the entries of the directory at `path` (root if empty) as it
/// existed at `branch`'s tip (or the default branch if `None`). Directories
/// sort before files, then alphabetically within each group.
pub fn browse_tree(store: &dyn RepoStore, name: &str, branch: Option<&str>, path: &str) -> Result<Vec<TreeEntry>, GitError> {
    let repo = open_repo_dir(store, name)?;
    let commit = open_and_resolve(&repo, branch)?;

    let span = tracing::info_span!("git.read_tree", repo.name = %name, path = %path);
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let mut tree = commit.tree().map_err(|err| GitError::Git(err.to_string()))?;

        if !path.is_empty() {
            let entry = tree
                .peel_to_entry_by_path(path)
                .map_err(|err| GitError::Git(err.to_string()))?
                .ok_or_else(|| GitError::NotFound(format!("{path} in {name}")))?;
            if entry.mode().kind() != gix_object::tree::EntryKind::Tree {
                return Err(GitError::Git(format!("\"{path}\" is not a directory")));
            }
            // `peel_to_entry_by_path` already left `tree` pointing at the
            // resolved directory's tree when the entry is one — nothing further
            // to do here.
        }

        let mut entries: Vec<TreeEntry> = tree
            .iter()
            .filter_map(Result::ok)
            .map(|entry| {
                let is_dir = entry.mode().kind() == gix_object::tree::EntryKind::Tree;
                // `.header()` reads just the object's size/type from its
                // (small) header — `.object()` would decompress the entire
                // blob just to throw the content away, which is a real cost
                // for anything but tiny files and pointless for a listing.
                let size = if is_dir { None } else { entry.id().header().ok().map(|header| header.size()) };
                TreeEntry { name: entry.filename().to_string(), is_dir, size }
            })
            .collect();
        entries.sort_by_key(|entry| (!entry.is_dir, entry.name.clone()));
        Ok(entries)
    })();
    record_git_op("git.read_tree", start, &result);
    result
}

/// Reads one file's content as it existed at `branch`'s tip (or the default
/// branch if `None`). Binary detection is the same coarse heuristic git
/// itself uses: a NUL byte anywhere in the first few KB means "binary."
pub fn read_blob(store: &dyn RepoStore, name: &str, branch: Option<&str>, path: &str) -> Result<BlobContent, GitError> {
    let repo = open_repo_dir(store, name)?;
    let commit = open_and_resolve(&repo, branch)?;

    let span = tracing::info_span!("git.read_blob", repo.name = %name, path = %path);
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let tree = commit.tree().map_err(|err| GitError::Git(err.to_string()))?;

        let entry = tree
            .lookup_entry_by_path(path)
            .map_err(|err| GitError::Git(err.to_string()))?
            .ok_or_else(|| GitError::NotFound(format!("{path} in {name}")))?;
        if entry.mode().kind() == gix_object::tree::EntryKind::Tree {
            return Err(GitError::Git(format!("\"{path}\" is a directory")));
        }

        let mut object = entry.object().map_err(|err| GitError::Git(err.to_string()))?;
        let data = std::mem::take(&mut object.data);
        let size = data.len() as u64;
        let is_binary = data.iter().take(8000).any(|&byte| byte == 0);

        let content =
            if is_binary || data.len() > MAX_INLINE_BLOB_BYTES { None } else { Some(String::from_utf8_lossy(&data).into_owned()) };

        let file_name = path.rsplit('/').next().unwrap_or(path).to_string();
        Ok(BlobContent { name: file_name, size, is_binary, content })
    })();
    record_git_op("git.read_blob", start, &result);
    result
}

/// The most recent `limit` commits reachable from `branch`'s tip (or the
/// default branch if `None`), newest first.
pub fn commit_log(store: &dyn RepoStore, name: &str, branch: Option<&str>, limit: usize) -> Result<Vec<CommitLogEntry>, GitError> {
    let repo = open_repo_dir(store, name)?;
    let commit = open_and_resolve(&repo, branch)?;

    // One span for the whole walk, not one per commit — up to `limit`
    // (currently 50) child spans would be noise, not signal (see the
    // "don't over-instrument" guidance this instrumentation follows
    // throughout). `commit_count` on the span after the fact answers "how
    // much work did this do" without per-commit spans.
    let span = tracing::info_span!("git.read_commit_log", repo.name = %name, commit_count = tracing::field::Empty);
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let walk = repo.rev_walk([commit.id()]).all().map_err(|err| GitError::Git(err.to_string()))?;

        let mut entries = Vec::new();
        for info in walk.take(limit) {
            let info = info.map_err(|err| GitError::Git(err.to_string()))?;
            let commit = repo.find_commit(info.id).map_err(|err| GitError::Git(err.to_string()))?;
            let summary = commit.message().ok().map(|message| message.summary().to_string()).unwrap_or_default();
            let author = commit.author().ok();
            let author_name = author.as_ref().map(|author| author.name.to_string()).unwrap_or_default();
            let unix_seconds = author.and_then(|author| author.time().ok()).map(|time| time.seconds).unwrap_or(0);
            entries.push(CommitLogEntry { id: info.id.to_string(), summary, author_name, unix_seconds });
        }
        Ok(entries)
    })();
    if let Ok(entries) = &result {
        span.record("commit_count", entries.len());
    }
    record_git_op("git.read_commit_log", start, &result);
    result
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

/// Not a git convention like `description` — Edda's own marker. Presence
/// (not content) is what matters, matching how the rest of this repo's
/// metadata is stored: cheap files next to the bare repo rather than a `db`
/// row, since there's still no `repos` table.
fn read_private_flag(dir: &Path) -> bool {
    dir.join("private").exists()
}

/// The all-zeros object id git's protocols use to mean "no such object" —
/// a ref-update command's old-id when creating a ref, or its new-id when
/// deleting one.
pub const ZERO_ID: &str = "0000000000000000000000000000000000000000";

/// Applies one ref-update command with the same compare-and-swap semantics
/// real git uses: the update only happens if `expected_old` matches the
/// ref's *actual* current value. This is the entire non-fast-forward
/// rejection mechanism — a stale push's `expected_old` won't match what's
/// really there once someone else has pushed, so it fails here rather than
/// silently overwriting history.
pub(crate) fn apply_ref_update(git_dir: &Path, ref_name: &str, expected_old: &str, new_id: &str) -> Result<(), String> {
    let ref_path = git_dir.join(ref_name);
    let current = std::fs::read_to_string(&ref_path).ok().map(|s| s.trim().to_string()).unwrap_or_else(|| ZERO_ID.to_string());

    if current != expected_old {
        return Err(format!("expected {expected_old}, found {current}"));
    }

    if new_id == ZERO_ID {
        if ref_path.exists() {
            std::fs::remove_file(&ref_path).map_err(|err| err.to_string())?;
        }
    } else {
        if let Some(parent) = ref_path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        std::fs::write(&ref_path, format!("{new_id}\n")).map_err(|err| err.to_string())?;
    }
    Ok(())
}

/// Prefers "main", then "master", then whatever's first — the same
/// preference order used both for display (`repo_summary`), for repairing
/// HEAD on disk (`fix_unborn_head`), and for the git-http bridge's ref
/// advertisement in `api` (a client cloning needs *some* answer for HEAD
/// even when the on-disk repo hasn't been repaired yet).
pub(crate) fn pick_default_branch(names: &[String]) -> Option<&str> {
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

    // HEAD's on-disk format for a symbolic ref is just this one line — the
    // same thing `git symbolic-ref` itself would write, and how
    // `gix::init_bare` sets it initially.
    std::fs::write(dir.join("HEAD"), format!("ref: refs/heads/{branch}\n"))?;
    Ok(())
}

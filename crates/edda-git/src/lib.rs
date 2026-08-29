pub mod archive;
pub mod blame;
pub mod changelog;
pub mod diff;
pub mod history;
pub mod hooks;
pub mod merge;
pub mod pack;
pub mod pktline;
pub mod protocol;
pub mod quarantine;
pub mod refs;
pub mod search;
pub mod sideband;
pub mod store;
pub mod tags;
pub mod transfer;

pub use archive::{archive, ArchiveFormat};
pub use blame::{blame, Blame, BlameHunk};
pub use changelog::{changelog_entries, changelog_markdown, ChangelogEntry};
pub use diff::{commit_diff, diff_refs, DiffHunk, DiffLine, FileDiff};
pub use hooks::{AppliedRef, ReceiveChecks, ReceiveOutcome};
pub use merge::{
    fast_forward_branch_to_ref, merge_branches, merge_pull_request, merge_ref_into_branch,
    rebase_ref_onto_branch, squash_ref_into_branch, MergeOutcome,
};
pub use refs::{force_set_ref, point_head_at, update_refs, RefUpdate, ZERO_ID};
pub use search::{search_tree, SearchMatch};
pub use store::repo_storage_bytes;
pub use tags::{create_annotated_tag, create_tag, list_tags, resolve_tag};
pub use transfer::import_branch_tip;

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::sync::Mutex as AsyncMutex;

use store::RepoStore;

/// Per-repo-name lock registry so two writes to the *same* repo serialize
/// instead of racing — not just Edda's own create/update/delete against
/// each other, but also against a `git push` landing at the same time (the
/// git-http bridge holds this for the duration of a `receive-pack`, since
/// that's a write too, e.g. someone deleting a repo mid-push). Writes to
/// different repos never contend.
///
/// `tokio::sync::Mutex` rather than `std`'s: a caller may hold this across
/// an `.await` (e.g. a `spawn_blocking` join), which a std `MutexGuard`
/// can't safely do (it isn't `Send`).
///
/// Entries are never removed, including for deleted repos: one
/// `Arc<Mutex<()>>` per distinct name ever touched is a few dozen bytes,
/// and this is a self-hosted tool with a human-scale repo count, not
/// something worth adding reference-counted eviction for.
///
/// An explicit, constructed value (one instance shared via the
/// composition root, `edda-web`, across both `edda-app` and `edda-ssh`)
/// rather than a process-global `static`: a `static` registry is
/// invisible plumbing that two independent test server instances in the
/// same process would silently share, which is exactly the hazard an
/// integration-test suite runs into.
#[derive(Default)]
pub struct LockRegistry {
    locks: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
}

impl LockRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lock_for(&self, name: &str) -> Arc<AsyncMutex<()>> {
        let mut registry = self
            .locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }
}

/// Records one git operation's outcome as the `edda.git.operation.duration`
/// metric (`operation`/`status` attributes only — never a repo name, see
/// `edda_telemetry::metrics`). Kept as a one-line call at each instrumented
/// git boundary so a span's name and its matching metric label can't drift
/// apart.
pub(crate) fn record_git_op<T>(
    operation: &'static str,
    start: std::time::Instant,
    result: &Result<T, GitError>,
) {
    let status = if result.is_ok() { "success" } else { "error" };
    edda_telemetry::metrics::record_git_operation(operation, status, start.elapsed());
}

#[derive(Debug)]
pub enum GitError {
    InvalidName(String),
    AlreadyExists(String),
    NotFound(String),
    Io(std::io::Error),
    Git(String),
    /// A merge (`merge::merge_branches`) left this many unresolved
    /// conflicts — the merge was not completed, no objects it wrote are
    /// reachable from any ref, and the target branch was not moved.
    Conflict(usize),
    /// A fast-forward-only merge was requested but the target branch
    /// cannot reach the source by fast-forward (its history has diverged).
    /// Nothing was written and no branch was moved.
    NotFastForward,
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GitError::InvalidName(name) => write!(f, "\"{name}\" isn't a valid repository name"),
            GitError::AlreadyExists(name) => {
                write!(f, "a repository named \"{name}\" already exists")
            }
            GitError::NotFound(name) => write!(f, "no repository named \"{name}\""),
            GitError::Io(err) => write!(f, "{err}"),
            GitError::Git(err) => write!(f, "{err}"),
            GitError::Conflict(count) => {
                write!(f, "the merge has {count} unresolved conflict(s)")
            }
            GitError::NotFastForward => {
                write!(f, "the target branch cannot fast-forward to the source")
            }
        }
    }
}

impl std::error::Error for GitError {}

impl From<std::io::Error> for GitError {
    fn from(err: std::io::Error) -> Self {
        GitError::Io(err)
    }
}

/// What only `gix` can answer about a repository. Deliberately excludes
/// `description`/visibility, which are `edda-domain`/`edda-db` concerns
/// (the `Repository` entity) — this crate has no business knowing about
/// them.
pub struct RepoSummary {
    pub name: String,
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

/// Validates a full repository identity, `{owner}/{repo}`, using
/// `edda_domain::validation`'s rules — the single source of truth for both
/// the username charset (`owner`) and the repo-segment charset (`repo`),
/// shared with account signup so a repo's URL segment always resolves to
/// an account that could actually exist.
fn validate_name(name: &str) -> Result<(), GitError> {
    if edda_domain::validation::is_valid_repository_identity(name) {
        Ok(())
    } else {
        Err(GitError::InvalidName(name.to_string()))
    }
}

/// Validates `name`, then resolves it to its on-disk directory. Used
/// anywhere a name needs to become a path — including the git-http
/// bridge — so validation always happens before a name meets the
/// filesystem.
pub fn validated_repo_dir(store: &dyn RepoStore, name: &str) -> Result<PathBuf, GitError> {
    validate_name(name)?;
    Ok(store.repo_dir(name))
}

/// Initializes a bare repository on disk. Description and visibility are
/// not this crate's concern (see `RepoSummary`'s doc comment) — a caller
/// creating a repository writes the `edda_domain::Repository` row via
/// `edda-db` in the same logical operation, in whichever order its own
/// transaction/lock discipline requires.
pub async fn create_repo(
    store: &dyn RepoStore,
    locks: &LockRegistry,
    name: &str,
) -> Result<(), GitError> {
    validate_name(name)?;
    let lock = locks.lock_for(name);
    let _guard = lock.lock().await;
    let dir = store.repo_dir(name);
    if dir.exists() {
        return Err(GitError::AlreadyExists(name.to_string()));
    }
    // gix::init_bare only mkdir's the target itself, not its parents.
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let span = tracing::info_span!("git.initialize", repo.name = %name);
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = gix::init_bare(&dir)
        .map_err(|err| GitError::Git(err.to_string()))
        .map(|_| ());
    record_git_op("git.initialize", start, &result);
    result
}

/// Forks `source_name` into a fresh `dest_name` by copying its whole bare
/// repository directory (including any LFS objects nested under it, see
/// `RepoStore::lfs_object_path`) — a naive, full-clone approach, not a
/// storage-efficient shared-object one. Explicitly accepted for now: a
/// storage-efficient fork (e.g. hardlinking or sharing the object store
/// between a repo and its forks) is real engineering work with its own
/// correctness hazards, and this naive approach is what every fork
/// produces independently correct results from with the least new
/// machinery.
///
/// Holds `source_name`'s lock for the duration of the copy, so a
/// concurrent push to the source can't interleave with reading its files
/// mid-copy — `dest_name` needs no lock of its own since nothing else can
/// know about it until this function creates it (the existence check
/// below is what actually prevents a name collision).
pub async fn fork_repo(
    store: &dyn RepoStore,
    locks: &LockRegistry,
    source_name: &str,
    dest_name: &str,
) -> Result<(), GitError> {
    validate_name(source_name)?;
    validate_name(dest_name)?;
    let source_dir = store.repo_dir(source_name);
    if !source_dir.exists() {
        return Err(GitError::NotFound(source_name.to_string()));
    }
    let dest_dir = store.repo_dir(dest_name);
    if dest_dir.exists() {
        return Err(GitError::AlreadyExists(dest_name.to_string()));
    }

    let lock = locks.lock_for(source_name);
    let _guard = lock.lock().await;

    if let Some(parent) = dest_dir.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let span = tracing::info_span!("git.fork", repo.source = %source_name, repo.dest = %dest_name);
    let _guard = span.enter();
    let current_span = tracing::Span::current();
    let start = std::time::Instant::now();
    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| copy_dir_recursive(&source_dir, &dest_dir))
    })
    .await
    .map_err(|_| GitError::Git("fork copy task panicked".to_string()))
    .and_then(|result| result.map_err(GitError::from));
    record_git_op("git.fork", start, &result);
    result
}

/// Real disk I/O, potentially a lot of it for a large repository — run on
/// the blocking pool by `fork_repo`, not called directly from async code.
/// Symlinks aren't followed or recreated: a bare git repository has no
/// legitimate reason to contain one, so silently skipping an unexpected
/// symlink entry is safer than either following it outside `src` or
/// failing the whole fork over it.
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &dst_path)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), &dst_path)?;
        }
    }
    Ok(())
}

pub async fn delete_repo(
    store: &dyn RepoStore,
    locks: &LockRegistry,
    name: &str,
) -> Result<(), GitError> {
    validate_name(name)?;
    let lock = locks.lock_for(name);
    let _guard = lock.lock().await;
    let dir = store.repo_dir(name);
    if !dir.exists() {
        return Err(GitError::NotFound(name.to_string()));
    }
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

pub fn repo_summary(store: &dyn RepoStore, name: &str) -> Result<RepoSummary, GitError> {
    validate_name(name)?;
    let dir = store.repo_dir(name);
    if !dir.exists() {
        return Err(GitError::NotFound(name.to_string()));
    }

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
            Some(CommitSummary {
                summary,
                author_name,
                unix_seconds,
            })
        })
    };

    Ok(RepoSummary {
        name: name.to_string(),
        default_branch,
        branch_count,
        is_empty,
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

/// The same coarse binary-detection heuristic git itself uses: a NUL byte
/// anywhere in the first few KB means "binary." Shared by `read_blob`
/// (`BlobContent::is_binary`), `diff::commit_diff` (`FileDiff::is_binary`),
/// and `search::search_tree` (skipping binary files entirely) — one
/// definition of "binary" for this crate, not three that could drift apart.
pub(crate) fn is_binary_data(data: &[u8]) -> bool {
    data.iter().take(8000).any(|&byte| byte == 0)
}

/// Sorted local branch names — shared by `repo_summary` (for `branch_count`),
/// `open_and_resolve`'s unborn-HEAD fallback, and `list_branches` (for the
/// UI's branch switcher), so there's exactly one place that defines what
/// "the repo's branches" means.
fn list_branch_names(repo: &gix::Repository) -> Vec<String> {
    let mut names: Vec<String> = match repo.references() {
        Ok(refs) => match refs.local_branches() {
            Ok(branches) => branches
                .filter_map(Result::ok)
                .map(|r| r.name().shorten().to_string())
                .collect(),
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
            let mut reference = repo
                .find_reference(&format!("refs/heads/{branch}"))
                .map_err(|err| GitError::Git(err.to_string()))?;
            return reference
                .peel_to_commit()
                .map_err(|err| GitError::Git(err.to_string()));
        }

        if let Ok(commit) = repo.head_commit() {
            return Ok(commit);
        }

        let branch_names = list_branch_names(repo);
        let branch = pick_default_branch(&branch_names)
            .ok_or_else(|| GitError::Git("repository has no commits yet".to_string()))?;
        let mut reference = repo
            .find_reference(&format!("refs/heads/{branch}"))
            .map_err(|err| GitError::Git(err.to_string()))?;
        reference
            .peel_to_commit()
            .map_err(|err| GitError::Git(err.to_string()))
    })();
    record_git_op("git.resolve_revision", start, &result);
    result
}

#[tracing::instrument(name = "git.open", skip_all, err, fields(repo.name = %name))]
pub(crate) fn open_repo_dir(
    store: &dyn RepoStore,
    name: &str,
) -> Result<gix::Repository, GitError> {
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

/// The hex commit id at the tip of `branch` in `name`'s repository — used
/// by the merge path to find a pull request's head commit for its
/// required-status-check gate. `NotFound` if the branch doesn't exist.
pub fn resolve_branch_commit(
    store: &dyn RepoStore,
    name: &str,
    branch: &str,
) -> Result<String, GitError> {
    let repo = open_repo_dir(store, name)?;
    let commit = open_and_resolve(&repo, Some(branch))?;
    Ok(commit.id().to_string())
}

/// Lists the entries of the directory at `path` (root if empty) as it
/// existed at `branch`'s tip (or the default branch if `None`). Directories
/// sort before files, then alphabetically within each group.
pub fn browse_tree(
    store: &dyn RepoStore,
    name: &str,
    branch: Option<&str>,
    path: &str,
) -> Result<Vec<TreeEntry>, GitError> {
    let repo = open_repo_dir(store, name)?;
    let commit = open_and_resolve(&repo, branch)?;

    let span = tracing::info_span!("git.read_tree", repo.name = %name, path = %path);
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let mut tree = commit
            .tree()
            .map_err(|err| GitError::Git(err.to_string()))?;

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
                let size = if is_dir {
                    None
                } else {
                    entry.id().header().ok().map(|header| header.size())
                };
                TreeEntry {
                    name: entry.filename().to_string(),
                    is_dir,
                    size,
                }
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
pub fn read_blob(
    store: &dyn RepoStore,
    name: &str,
    branch: Option<&str>,
    path: &str,
) -> Result<BlobContent, GitError> {
    let repo = open_repo_dir(store, name)?;
    let commit = open_and_resolve(&repo, branch)?;

    let span = tracing::info_span!("git.read_blob", repo.name = %name, path = %path);
    let _guard = span.enter();
    let start = std::time::Instant::now();
    let result = (|| {
        let tree = commit
            .tree()
            .map_err(|err| GitError::Git(err.to_string()))?;

        let entry = tree
            .lookup_entry_by_path(path)
            .map_err(|err| GitError::Git(err.to_string()))?
            .ok_or_else(|| GitError::NotFound(format!("{path} in {name}")))?;
        if entry.mode().kind() == gix_object::tree::EntryKind::Tree {
            return Err(GitError::Git(format!("\"{path}\" is a directory")));
        }

        let mut object = entry
            .object()
            .map_err(|err| GitError::Git(err.to_string()))?;
        let data = std::mem::take(&mut object.data);
        let size = data.len() as u64;
        let is_binary = is_binary_data(&data);

        let content = if is_binary || data.len() > MAX_INLINE_BLOB_BYTES {
            None
        } else {
            Some(String::from_utf8_lossy(&data).into_owned())
        };

        let file_name = path.rsplit('/').next().unwrap_or(path).to_string();
        Ok(BlobContent {
            name: file_name,
            size,
            is_binary,
            content,
        })
    })();
    record_git_op("git.read_blob", start, &result);
    result
}

/// The most recent `limit` commits reachable from `branch`'s tip (or the
/// default branch if `None`), newest first.
pub fn commit_log(
    store: &dyn RepoStore,
    name: &str,
    branch: Option<&str>,
    limit: usize,
) -> Result<Vec<CommitLogEntry>, GitError> {
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
        let walk = repo
            .rev_walk([commit.id()])
            .all()
            .map_err(|err| GitError::Git(err.to_string()))?;

        let mut entries = Vec::new();
        for info in walk.take(limit) {
            let info = info.map_err(|err| GitError::Git(err.to_string()))?;
            let commit = repo
                .find_commit(info.id)
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
            let unix_seconds = author
                .and_then(|author| author.time().ok())
                .map(|time| time.seconds)
                .unwrap_or(0);
            entries.push(CommitLogEntry {
                id: info.id.to_string(),
                summary,
                author_name,
                unix_seconds,
            });
        }
        Ok(entries)
    })();
    if let Ok(entries) = &result {
        span.record("commit_count", entries.len());
    }
    record_git_op("git.read_commit_log", start, &result);
    result
}

/// Prefers "main", then "master", then whatever's first — the same
/// preference order used both for display (`repo_summary`), for repairing
/// HEAD on disk (`fix_unborn_head`), and for the git-http bridge's ref
/// advertisement in `api` (a client cloning needs *some* answer for HEAD
/// even when the on-disk repo hasn't been repaired yet).
pub fn pick_default_branch(names: &[String]) -> Option<&str> {
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
pub fn fix_unborn_head(dir: &Path) -> Result<(), GitError> {
    let repo = gix::open(dir).map_err(|err| GitError::Git(err.to_string()))?;
    let head = repo.head().map_err(|err| GitError::Git(err.to_string()))?;
    if !head.is_unborn() {
        return Ok(());
    }

    let mut branch_names: Vec<String> = match repo.references() {
        Ok(refs) => match refs.local_branches() {
            Ok(branches) => branches
                .filter_map(Result::ok)
                .map(|r| r.name().shorten().to_string())
                .collect(),
            Err(_) => Vec::new(),
        },
        Err(_) => Vec::new(),
    };
    branch_names.sort();

    let Some(branch) = pick_default_branch(&branch_names) else {
        return Ok(()); // genuinely still empty — nothing to point HEAD at
    };

    // Repoint HEAD through `gix`'s symbolic-ref editing API rather than a
    // raw `HEAD` file write, so it takes the same locked, packed-refs-aware
    // path as every other ref update (see `refs::point_head_at`).
    refs::point_head_at(&repo, branch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LocalFsStore;

    struct TestStore {
        store: LocalFsStore,
        root: PathBuf,
    }

    impl TestStore {
        fn new(unique: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("edda-git-lib-test-{unique}-{}", std::process::id()));
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

    #[tokio::test]
    async fn fork_repo_copies_the_source_directory_including_nested_lfs_objects() {
        let test = TestStore::new("fork-ok");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();

        // A nested file mimicking where an LFS object would live (see
        // `RepoStore::lfs_object_path`) — the fork copy has no LFS-specific
        // logic of its own, so a plain nested file exercises the same
        // recursive-copy path a real LFS object would take.
        let lfs_dir = test.store.repo_dir("alice/demo").join("lfs/objects/ab/cd");
        std::fs::create_dir_all(&lfs_dir).unwrap();
        std::fs::write(lfs_dir.join("abcdef"), b"lfs content").unwrap();

        fork_repo(&test.store, &locks, "alice/demo", "bob/demo")
            .await
            .unwrap();

        assert!(test.store.repo_dir("bob/demo").join("HEAD").exists());
        let copied = test
            .store
            .repo_dir("bob/demo")
            .join("lfs/objects/ab/cd/abcdef");
        assert_eq!(std::fs::read(copied).unwrap(), b"lfs content");
    }

    #[tokio::test]
    async fn fork_repo_rejects_a_nonexistent_source() {
        let test = TestStore::new("fork-missing-source");
        let locks = LockRegistry::new();
        let err = fork_repo(&test.store, &locks, "alice/missing", "bob/demo")
            .await
            .unwrap_err();
        assert!(matches!(err, GitError::NotFound(_)));
    }

    #[tokio::test]
    async fn fork_repo_rejects_an_existing_destination() {
        let test = TestStore::new("fork-dest-exists");
        let locks = LockRegistry::new();
        create_repo(&test.store, &locks, "alice/demo")
            .await
            .unwrap();
        create_repo(&test.store, &locks, "bob/demo").await.unwrap();

        let err = fork_repo(&test.store, &locks, "alice/demo", "bob/demo")
            .await
            .unwrap_err();
        assert!(matches!(err, GitError::AlreadyExists(_)));
    }

    #[test]
    fn valid_owner_repo_identities() {
        assert!(validate_name("alice/my-repo").is_ok());
        assert!(validate_name("alice/my.repo_1").is_ok());
        assert!(validate_name("a/b").is_ok());
        assert!(validate_name(&format!("alice/{}", "a".repeat(100))).is_ok());
    }

    #[test]
    fn invalid_owner_repo_identities() {
        // no owner segment at all
        assert!(validate_name("my-repo").is_err());
        assert!(validate_name("").is_err());
        // empty owner or repo segment
        assert!(validate_name("/my-repo").is_err());
        assert!(validate_name("alice/").is_err());
        // more than one '/'
        assert!(validate_name("alice/sub/my-repo").is_err());
        // invalid owner segment (see `edda_domain::validation::is_valid_username`)
        assert!(validate_name("-alice/my-repo").is_err());
        assert!(validate_name("al ice/my-repo").is_err());
        assert!(validate_name(&format!("{}/repo", "a".repeat(40))).is_err());
        // invalid repo segment, same rules as before namespacing
        assert!(validate_name("alice/.").is_err());
        assert!(validate_name("alice/..").is_err());
        assert!(validate_name("alice/.hidden").is_err());
        assert!(validate_name("alice/repo.git").is_err());
        assert!(validate_name("alice/repo name").is_err());
        assert!(validate_name(&format!("alice/{}", "a".repeat(101))).is_err());
    }
}

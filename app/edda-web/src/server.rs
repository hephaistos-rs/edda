use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RepoDto {
    pub owner: String,
    pub name: String,
    pub description: Option<String>,
    pub default_branch: Option<String>,
    pub branch_count: usize,
    pub is_empty: bool,
    pub is_private: bool,
    pub is_owner: bool,
    pub last_commit: Option<CommitDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommitDto {
    pub summary: String,
    pub author_name: String,
    pub unix_seconds: i64,
}

/// Combines a DB-level `edda_domain::Repository` (identity, description,
/// visibility) with a git-level `edda_git::RepoSummary` (branch info, last
/// commit) — the two live in different crates (database identity in
/// `edda-db`, git-derived summary in `edda-git`), so building this DTO
/// is a join of both rather than a single `From`.
#[cfg(feature = "server")]
fn repo_dto(
    repository: &edda_domain::Repository,
    owner_username: &str,
    summary: edda_git::RepoSummary,
    is_owner: bool,
) -> RepoDto {
    RepoDto {
        owner: owner_username.to_string(),
        name: repository.name.clone(),
        description: repository.description.clone(),
        default_branch: summary.default_branch,
        branch_count: summary.branch_count,
        is_empty: summary.is_empty,
        is_private: repository.is_private(),
        is_owner,
        last_commit: summary.last_commit.map(|commit| CommitDto {
            summary: commit.summary,
            author_name: commit.author_name,
            unix_seconds: commit.unix_seconds,
        }),
    }
}

#[cfg(feature = "server")]
fn git_identity(owner_username: &str, name: &str) -> String {
    format!("{owner_username}/{name}")
}

#[get("/api/repos", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "repository.list", skip_all, err)]
pub async fn list_repos() -> Result<Vec<RepoDto>, ServerFnError> {
    let shared = crate::shared::get();

    let rows = edda_db::RepositoryRepo::list_all_with_owner_username(&shared.pool)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;

    let roles = match &auth.user {
        Some(session_user) => {
            edda_db::RepoAccessRepo::roles_for_user(&shared.pool, session_user.user.id)
                .await
                .map_err(|err| ServerFnError::new(err.to_string()))?
        }
        None => Vec::new(),
    };
    let roles: std::collections::HashMap<_, _> = roles.into_iter().collect();

    let mut visible = Vec::new();
    for (repository, owner_username) in rows {
        let role = roles.get(&repository.id).copied();
        if repository.is_private() && role.is_none() {
            continue;
        }
        let identity = git_identity(&owner_username, &repository.name);
        let summary = edda_git::repo_summary(shared.store.as_ref(), &identity)
            .map_err(|err| ServerFnError::new(err.to_string()))?;
        let is_owner = role == Some(edda_domain::RepoRole::Owner);
        visible.push(repo_dto(&repository, &owner_username, summary, is_owner));
    }
    Ok(visible)
}

#[get("/api/repos/:owner/:name", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "repository.get", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn get_repo(owner: String, name: String) -> Result<RepoDto, ServerFnError> {
    let shared = crate::shared::get();

    let repository = shared
        .authz
        .repository_by_name(&owner, &name)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;

    let actor = match &auth.user {
        Some(session_user) => edda_domain::ActorContext::User(session_user.user.id),
        None => edda_domain::ActorContext::Anonymous,
    };
    // Private repos 404 rather than 403 for anyone without a role — same
    // response as a repo that doesn't exist, so an outsider can't use this
    // to confirm a private repo's name is taken.
    shared
        .authz
        .check_read(&actor, &repository)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;

    let is_owner = shared
        .authz
        .check_danger_zone(&actor, &repository)
        .await
        .is_ok();
    let identity = git_identity(&owner, &name);
    let summary = edda_git::repo_summary(shared.store.as_ref(), &identity)
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(repo_dto(&repository, &owner, summary, is_owner))
}

/// `name` is just the repo-name segment — the owner half of the
/// `{owner}/{repo}` identity is never taken from the caller, only derived
/// from whoever is authenticated, so there's no way to create a repo under
/// someone else's namespace.
#[post("/api/repos", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "repository.create", skip_all, err, fields(repo.name = %name))]
pub async fn create_repo(
    name: String,
    description: Option<String>,
    private: bool,
) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();

    let Some(session_user) = auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let user = session_user.user;
    let identity = git_identity(&user.username, &name);

    let repository = edda_domain::Repository {
        id: edda_domain::RepositoryId::new(),
        owner: edda_domain::RepositoryOwner::User(user.id),
        name: name.clone(),
        description: description.filter(|d| !d.trim().is_empty()),
        visibility: if private {
            edda_domain::Visibility::Private
        } else {
            edda_domain::Visibility::Public
        },
        forked_from: None,
    };

    // Git-directory creation and the database row are two systems with no
    // shared transaction — create the git side first (cheap to leave
    // behind an empty bare repo if the DB insert then fails; the reverse,
    // a DB row pointing at a repo that was never created, is worse).
    edda_git::create_repo(shared.store.as_ref(), &shared.locks, &identity)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;

    // Inserting the row and granting its creator ownership happen inside
    // one transaction (`insert_with_owner`) rather than two separate
    // statements, which would mask an atomicity gap SQLite's
    // single-writer serialization happens to hide but PostgreSQL's real
    // concurrency would not.
    edda_db::RepositoryRepo::insert_with_owner(&shared.pool, &repository, user.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

/// Owner-only, unlike `update_repo`/`delete_repo` (owner *or* collaborator
/// with write access) — flipping a repo private/public is a stronger
/// action than editing its description.
#[post("/api/repos/:owner/:name/visibility", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "repository.set_visibility", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn set_repo_visibility(
    owner: String,
    name: String,
    private: bool,
) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();

    let Some(session_user) = auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let actor = edda_domain::ActorContext::User(session_user.user.id);

    let repository = shared
        .authz
        .repository_by_name(&owner, &name)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    shared
        .authz
        .check_danger_zone(&actor, &repository)
        .await
        .map_err(|_| ServerFnError::new("only the repo owner can change its visibility"))?;

    let visibility = if private {
        edda_domain::Visibility::Private
    } else {
        edda_domain::Visibility::Public
    };
    edda_db::RepositoryRepo::update_visibility(&shared.pool, repository.id, visibility)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))
}

#[post("/api/repos/:owner/:name/update", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "repository.update", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn update_repo(
    owner: String,
    name: String,
    description: Option<String>,
) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();

    let Some(session_user) = auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let actor = edda_domain::ActorContext::User(session_user.user.id);

    let repository = shared
        .authz
        .repository_by_name(&owner, &name)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    shared
        .authz
        .check_write(&actor, &repository)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;

    let description = description.filter(|d| !d.trim().is_empty());
    edda_db::RepositoryRepo::update_description(&shared.pool, repository.id, description.as_deref())
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))
}

#[post("/api/repos/:owner/:name/delete", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "repository.delete", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn delete_repo(owner: String, name: String) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();

    let Some(session_user) = auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let actor = edda_domain::ActorContext::User(session_user.user.id);

    let repository = shared
        .authz
        .repository_by_name(&owner, &name)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    // Deletion is now owner-only (`check_danger_zone`), not "any
    // collaborator" the way the pre-restructuring `require_write_access`
    // allowed — a deliberate tightening the four-tier role model exists
    // to make possible; see the Phase 1 completion report.
    shared
        .authz
        .check_danger_zone(&actor, &repository)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;

    let identity = git_identity(&owner, &name);
    edda_git::delete_repo(shared.store.as_ref(), &shared.locks, &identity)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    // No explicit "revoke all access grants" step: `repo_access` has an
    // `ON DELETE CASCADE` foreign key to `repositories`, so this is
    // structurally impossible to forget.
    edda_db::RepositoryRepo::delete(&shared.pool, repository.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

/// Forks `owner/name` into a repository of the same name under the
/// caller's own namespace. `name` is always kept as-is (no rename-on-fork
/// UI yet) — a caller that already owns a same-named repository gets the
/// same "already exists" error `create_repo` would give, which is the
/// right outcome (this function is not a rename tool).
#[post("/api/repos/:owner/:name/fork", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "repository.fork", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn fork_repo(owner: String, name: String) -> Result<(String, String), ServerFnError> {
    let shared = crate::shared::get();

    let Some(session_user) = auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let user = session_user.user;
    let actor = edda_domain::ActorContext::User(user.id);

    let source = shared
        .authz
        .repository_by_name(&owner, &name)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    shared
        .authz
        .check_read(&actor, &source)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;

    let source_identity = git_identity(&owner, &name);
    let dest_identity = git_identity(&user.username, &name);
    if source_identity == dest_identity {
        return Err(ServerFnError::new("you already own this repository"));
    }

    // Git-directory copy and the database row follow the same
    // "git side first" ordering `create_repo` uses, for the same reason:
    // an orphaned bare repo with no matching row is harmless and cheap to
    // clean up, while a row pointing at a repo that was never created is
    // worse.
    edda_git::fork_repo(
        shared.store.as_ref(),
        &shared.locks,
        &source_identity,
        &dest_identity,
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?;

    let fork = edda_domain::Repository {
        id: edda_domain::RepositoryId::new(),
        owner: edda_domain::RepositoryOwner::User(user.id),
        name: name.clone(),
        description: source.description.clone(),
        visibility: source.visibility,
        forked_from: Some(source.id),
    };
    edda_db::RepositoryRepo::insert_with_owner(&shared.pool, &fork, user.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;

    Ok((user.username, name))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TreeEntryDto {
    pub name: String,
    pub is_dir: bool,
    pub size: Option<u64>,
}

#[cfg(feature = "server")]
impl From<edda_git::TreeEntry> for TreeEntryDto {
    fn from(entry: edda_git::TreeEntry) -> Self {
        Self {
            name: entry.name,
            is_dir: entry.is_dir,
            size: entry.size,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlobDto {
    pub name: String,
    pub size: u64,
    pub is_binary: bool,
    pub content: Option<String>,
    /// Server-rendered HTML for `content`, already sanitized where that
    /// matters: a README (see `is_readme_filename`) gets `edda_render::
    /// markdown::render`'s GFM-to-sanitized-HTML output; any other
    /// non-binary text file gets `edda_render::syntax::highlight`'s
    /// syntax-highlighted markup instead. `None` for binary content and
    /// for anything with no inline `content` at all (oversized files) —
    /// the client falls back to plain-text `content` display whenever
    /// this is `None`.
    pub rendered_html: Option<String>,
}

/// `README`/`README.md`/`README.markdown`, case-insensitively — the same
/// three spellings GitHub/Forgejo treat as a repo's rendered landing
/// document. An exact-name match, not a substring/prefix one, so e.g.
/// `readme-notes.md` is treated as a plain text file (syntax-highlighted,
/// not markdown-rendered).
#[cfg(feature = "server")]
fn is_readme_filename(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "readme.md" | "readme.markdown" | "readme"
    )
}

#[cfg(feature = "server")]
fn blob_dto(blob: edda_git::BlobContent) -> BlobDto {
    let rendered_html = match (&blob.content, blob.is_binary) {
        (Some(content), false) if is_readme_filename(&blob.name) => {
            Some(edda_render::markdown::render(content))
        }
        (Some(content), false) => Some(edda_render::syntax::highlight(content, &blob.name)),
        _ => None,
    };
    BlobDto {
        name: blob.name,
        size: blob.size,
        is_binary: blob.is_binary,
        content: blob.content,
        rendered_html,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommitLogEntryDto {
    pub id: String,
    pub summary: String,
    pub author_name: String,
    pub unix_seconds: i64,
}

#[cfg(feature = "server")]
impl From<edda_git::CommitLogEntry> for CommitLogEntryDto {
    fn from(entry: edda_git::CommitLogEntry) -> Self {
        Self {
            id: entry.id,
            summary: entry.summary,
            author_name: entry.author_name,
            unix_seconds: entry.unix_seconds,
        }
    }
}

/// Shared by `get_tree`/`get_blob`/`get_commit_log`: a public repo needs
/// no access check at all (the common case); a private one needs the
/// caller to hold a `repo_access` role, same requirement and same
/// 404-not-403 reasoning as `get_repo`. Returns the resolved `Repository`
/// so callers don't have to look it up twice.
#[cfg(feature = "server")]
async fn require_read_access(
    auth: &axum_login::AuthSession<edda_auth::Backend>,
    owner: &str,
    name: &str,
) -> Result<edda_domain::Repository, ServerFnError> {
    let shared = crate::shared::get();
    let repository = shared
        .authz
        .repository_by_name(owner, name)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    let actor = match &auth.user {
        Some(session_user) => edda_domain::ActorContext::User(session_user.user.id),
        None => edda_domain::ActorContext::Anonymous,
    };
    shared
        .authz
        .check_read(&actor, &repository)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(repository)
}

/// `path` is a `/`-joined relative path within the repo (e.g. `"src/main.rs"`),
/// not a URL path segment — passed as a query parameter rather than a route
/// wildcard, since it can contain slashes at arbitrary depth.
#[get("/api/repos/:owner/:name/tree?branch&path", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "repository.tree", skip_all, err, fields(repo.owner = %owner, repo.name = %name, branch = branch.as_deref().unwrap_or("HEAD")))]
pub async fn get_tree(
    owner: String,
    name: String,
    branch: Option<String>,
    path: Option<String>,
) -> Result<Vec<TreeEntryDto>, ServerFnError> {
    require_read_access(&auth, &owner, &name).await?;
    let shared = crate::shared::get();
    let identity = git_identity(&owner, &name);
    let path = path.unwrap_or_default();
    let entries = edda_git::browse_tree(shared.store.as_ref(), &identity, branch.as_deref(), &path)
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(entries.into_iter().map(TreeEntryDto::from).collect())
}

#[get("/api/repos/:owner/:name/blob?branch&path", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "repository.blob", skip_all, err, fields(repo.owner = %owner, repo.name = %name, branch = branch.as_deref().unwrap_or("HEAD")))]
pub async fn get_blob(
    owner: String,
    name: String,
    branch: Option<String>,
    path: String,
) -> Result<BlobDto, ServerFnError> {
    require_read_access(&auth, &owner, &name).await?;
    let shared = crate::shared::get();
    let identity = git_identity(&owner, &name);
    let blob = edda_git::read_blob(shared.store.as_ref(), &identity, branch.as_deref(), &path)
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(blob_dto(blob))
}

#[get("/api/repos/:owner/:name/branches", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "repository.branches", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn get_branches(owner: String, name: String) -> Result<Vec<String>, ServerFnError> {
    require_read_access(&auth, &owner, &name).await?;
    let shared = crate::shared::get();
    let identity = git_identity(&owner, &name);
    edda_git::list_branches(shared.store.as_ref(), &identity)
        .map_err(|err| ServerFnError::new(err.to_string()))
}

#[get("/api/repos/:owner/:name/commits?branch", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "repository.commits", skip_all, err, fields(repo.owner = %owner, repo.name = %name, branch = branch.as_deref().unwrap_or("HEAD")))]
pub async fn get_commit_log(
    owner: String,
    name: String,
    branch: Option<String>,
) -> Result<Vec<CommitLogEntryDto>, ServerFnError> {
    require_read_access(&auth, &owner, &name).await?;
    let shared = crate::shared::get();
    let identity = git_identity(&owner, &name);
    let entries = edda_git::commit_log(shared.store.as_ref(), &identity, branch.as_deref(), 50)
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(entries.into_iter().map(CommitLogEntryDto::from).collect())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiffLineKind {
    Context,
    Added,
    Removed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiffLineDto {
    pub kind: DiffLineKind,
    /// Syntax-highlighted markup for just this one line's text (see
    /// `highlighted_line_html`) — not a whole `<pre><code>` block, since
    /// the UI renders each line as its own row (added/removed/context
    /// styling per row, per `DESIGN.md`'s never-color-alone rule), not a
    /// single flowing code block.
    pub html: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiffHunkDto {
    pub old_start: u32,
    pub new_start: u32,
    pub lines: Vec<DiffLineDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileDiffDto {
    pub old_path: Option<String>,
    pub new_path: Option<String>,
    pub is_binary: bool,
    pub hunks: Vec<DiffHunkDto>,
}

/// `edda_render::syntax::highlight` always wraps its output in a shared
/// `<pre class="edda-highlight"><code>...</code></pre>` fragment (a whole
/// file's worth of highlighted lines, in the tree/blob view this was
/// originally built for). A commit diff instead wants one syntax-
/// highlighted fragment *per line*, each independently wrapped in its own
/// added/removed/context row — so this strips that shared wrapper back off
/// per call rather than adding a second public entry point to
/// `edda-render` for "highlight, no wrapper." Safe to do with a plain
/// string strip (not a general HTML-parsing concern) because the wrapper's
/// exact text is this same workspace's own fixed format, not third-party
/// markup whose shape this code would otherwise have to guess at.
///
/// A real limitation worth naming: highlighting one line at a time gives
/// `syntect` no parser state carried over from the previous line, so a
/// token that only makes sense in a multi-line context (an unterminated
/// block comment or string, for instance) can highlight less accurately
/// here than it would in `syntax::highlight`'s whole-file mode. Acceptable
/// for a diff view — the exit criterion is "diffs render, syntax-
/// highlighted, for a representative set of languages," not "every
/// multi-line-token edge case highlights identically to a full-file view."
#[cfg(feature = "server")]
fn highlighted_line_html(text: &str, filename_hint: &str) -> String {
    let wrapped = edda_render::syntax::highlight(text, filename_hint);
    wrapped
        .strip_prefix("<pre class=\"edda-highlight\"><code>")
        .and_then(|rest| rest.strip_suffix("</code></pre>"))
        .unwrap_or(wrapped.as_str())
        .to_string()
}

#[cfg(feature = "server")]
fn file_diff_dto(diff: edda_git::FileDiff) -> FileDiffDto {
    let filename_hint = diff
        .new_path
        .clone()
        .or_else(|| diff.old_path.clone())
        .unwrap_or_default();
    let hunks = diff
        .hunks
        .into_iter()
        .map(|hunk| DiffHunkDto {
            old_start: hunk.old_start,
            new_start: hunk.new_start,
            lines: hunk
                .lines
                .into_iter()
                .map(|line| {
                    let (kind, text) = match line {
                        edda_git::DiffLine::Context(text) => (DiffLineKind::Context, text),
                        edda_git::DiffLine::Added(text) => (DiffLineKind::Added, text),
                        edda_git::DiffLine::Removed(text) => (DiffLineKind::Removed, text),
                    };
                    DiffLineDto {
                        kind,
                        html: highlighted_line_html(&text, &filename_hint),
                    }
                })
                .collect(),
        })
        .collect();
    FileDiffDto {
        old_path: diff.old_path,
        new_path: diff.new_path,
        is_binary: diff.is_binary,
        hunks,
    }
}

/// `path` isn't part of this route: `commit_id` alone (plus the repo
/// identity) is enough to compute a full commit's diff — see
/// `edda_git::diff::commit_diff`'s comparison-point rule (first parent, or
/// the empty tree for a root commit).
#[get("/api/repos/:owner/:name/commits/:commit_id/diff", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "repository.commit_diff", skip_all, err, fields(repo.owner = %owner, repo.name = %name, commit.id = %commit_id))]
pub async fn get_commit_diff(
    owner: String,
    name: String,
    commit_id: String,
) -> Result<Vec<FileDiffDto>, ServerFnError> {
    require_read_access(&auth, &owner, &name).await?;
    let shared = crate::shared::get();
    let identity = git_identity(&owner, &name);
    let diffs = edda_git::commit_diff(shared.store.as_ref(), &identity, &commit_id)
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(diffs.into_iter().map(file_diff_dto).collect())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SearchMatchDto {
    pub path: String,
    pub line_number: u32,
    pub line: String,
}

#[cfg(feature = "server")]
impl From<edda_git::SearchMatch> for SearchMatchDto {
    fn from(search_match: edda_git::SearchMatch) -> Self {
        Self {
            path: search_match.path,
            line_number: search_match.line_number,
            line: search_match.line,
        }
    }
}

#[get("/api/repos/:owner/:name/search?branch&query", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "repository.search", skip_all, err, fields(repo.owner = %owner, repo.name = %name, branch = branch.as_deref().unwrap_or("HEAD")))]
pub async fn search_code(
    owner: String,
    name: String,
    branch: Option<String>,
    query: String,
) -> Result<Vec<SearchMatchDto>, ServerFnError> {
    require_read_access(&auth, &owner, &name).await?;
    // An empty (or whitespace-only) query matches every line of every file
    // via plain substring search — a full tree walk for a result nobody
    // wants. Short-circuit before paying for it.
    if query.trim().is_empty() {
        return Ok(Vec::new());
    }
    let shared = crate::shared::get();
    let identity = git_identity(&owner, &name);
    let matches =
        edda_git::search_tree(shared.store.as_ref(), &identity, branch.as_deref(), &query)
            .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(matches.into_iter().map(SearchMatchDto::from).collect())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CurrentUser {
    pub id: String,
    pub username: String,
    pub email: String,
    pub is_admin: bool,
}

#[cfg(feature = "server")]
impl From<edda_domain::User> for CurrentUser {
    fn from(user: edda_domain::User) -> Self {
        Self {
            id: user.id.to_string(),
            username: user.username,
            email: user.email,
            is_admin: user.is_admin,
        }
    }
}

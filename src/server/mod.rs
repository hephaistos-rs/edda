use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RepoDto {
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

#[cfg(feature = "server")]
impl From<crate::git::RepoSummary> for RepoDto {
    fn from(summary: crate::git::RepoSummary) -> Self {
        Self {
            name: summary.name,
            description: summary.description,
            default_branch: summary.default_branch,
            branch_count: summary.branch_count,
            is_empty: summary.is_empty,
            is_private: summary.is_private,
            is_owner: false,
            last_commit: summary.last_commit.map(|commit| CommitDto {
                summary: commit.summary,
                author_name: commit.author_name,
                unix_seconds: commit.unix_seconds,
            }),
        }
    }
}

// Spans on these server functions carry `repo.name` as a field, never a
// metric label (see `telemetry::metrics`'s doc comment): Edda has no
// internal repository id to prefer instead — audited `migrations/*.sql` and
// confirmed there is no `repos` table at all, repos are identified solely by
// their filesystem-derived name. Name is bounded/human-scale (rejected past
// 100 chars, restricted charset — see `git::validate_name`), which is why
// it's acceptable as a span field despite being user-chosen.
/// `repo_access` role, keyed by repo name, for whichever user is calling —
/// used by `list_repos`/`get_repo` to decide both visibility (private repos
/// need at least a row here) and `RepoDto::is_owner` in one query rather
/// than N.
#[cfg(feature = "server")]
async fn access_roles(pool: &sqlx::SqlitePool, user_id: &str) -> Result<std::collections::HashMap<String, String>, ServerFnError> {
    let rows = sqlx::query!("SELECT repo_name, role FROM repo_access WHERE user_id = ?", user_id)
        .fetch_all(pool)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(rows.into_iter().map(|row| (row.repo_name, row.role)).collect())
}

#[get("/api/repos", auth: axum_login::AuthSession<crate::auth::Backend>)]
#[tracing::instrument(name = "repository.list", skip_all, err)]
pub async fn list_repos() -> Result<Vec<RepoDto>, ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    let summaries = git::list_repos(&store).map_err(|err| ServerFnError::new(err.to_string()))?;

    let roles = match &auth.user {
        Some(user) => access_roles(&auth.backend.pool, &user.id).await?,
        None => Default::default(),
    };

    let visible = summaries
        .into_iter()
        .filter(|summary| !summary.is_private || roles.contains_key(&summary.name))
        .map(|summary| {
            let is_owner = roles.get(&summary.name).is_some_and(|role| role == "owner");
            RepoDto { is_owner, ..RepoDto::from(summary) }
        })
        .collect();
    Ok(visible)
}

#[get("/api/repos/:name", auth: axum_login::AuthSession<crate::auth::Backend>)]
#[tracing::instrument(name = "repository.get", skip_all, err, fields(repo.name = %name))]
pub async fn get_repo(name: String) -> Result<RepoDto, ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    let summary = git::repo_summary(&store, &name).map_err(|err| ServerFnError::new(err.to_string()))?;

    let role = match &auth.user {
        Some(user) => {
            sqlx::query!("SELECT role FROM repo_access WHERE repo_name = ? AND user_id = ?", name, user.id)
                .fetch_optional(&auth.backend.pool)
                .await
                .map_err(|err| ServerFnError::new(err.to_string()))?
                .map(|row| row.role)
        }
        None => None,
    };
    // Private repos 404 rather than 403 for anyone without a role — same
    // response as a repo that doesn't exist, so an outsider can't use this
    // to confirm a private repo's name is taken.
    if summary.is_private && role.is_none() {
        return Err(ServerFnError::new(git::GitError::NotFound(name).to_string()));
    }

    let is_owner = role.as_deref() == Some("owner");
    Ok(RepoDto { is_owner, ..RepoDto::from(summary) })
}

#[post("/api/repos", auth: axum_login::AuthSession<crate::auth::Backend>)]
#[tracing::instrument(name = "repository.create", skip_all, err, fields(repo.name = %name))]
pub async fn create_repo(name: String, description: Option<String>, private: bool) -> Result<(), ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let Some(user) = auth.user else {
        return Err(ServerFnError::new("login required"));
    };

    let store = LocalFsStore::from_env();
    git::create_repo(&store, &name, description.as_deref(), private).await.map_err(|err| ServerFnError::new(err.to_string()))?;

    let pool = crate::db::pool().await.map_err(|err| ServerFnError::new(err.to_string()))?;
    crate::access::grant_owner(&pool, &name, &user.id).await.map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

/// Owner-only, unlike `update_repo`/`delete_repo` (owner *or* collaborator)
/// — flipping a repo private/public is a stronger action than editing its
/// description, closer to the collaborator-management routes in
/// `access::routes`, which use the same restriction.
#[post("/api/repos/:name/visibility", auth: axum_login::AuthSession<crate::auth::Backend>)]
#[tracing::instrument(name = "repository.set_visibility", skip_all, err, fields(repo.name = %name))]
pub async fn set_repo_visibility(name: String, private: bool) -> Result<(), ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let Some(user) = &auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let is_owner = crate::access::is_owner(&auth.backend.pool, &name, &user.id).await.map_err(|err| ServerFnError::new(err.to_string()))?;
    if !is_owner {
        return Err(ServerFnError::new("only the repo owner can change its visibility"));
    }

    let store = LocalFsStore::from_env();
    git::set_visibility(&store, &name, private).await.map_err(|err| ServerFnError::new(err.to_string()))
}

/// Shared by `update_repo`/`delete_repo`: both require the caller to be
/// logged in *and* to hold write access (owner or collaborator) to this
/// specific repo — `create_repo` is the only one of the three that doesn't
/// need this, since ownership is granted rather than checked there.
#[cfg(feature = "server")]
async fn require_write_access(auth: &axum_login::AuthSession<crate::auth::Backend>, name: &str) -> Result<(), ServerFnError> {
    let Some(user) = &auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let allowed =
        crate::access::has_write_access(&auth.backend.pool, name, &user.id).await.map_err(|err| ServerFnError::new(err.to_string()))?;
    if !allowed {
        return Err(ServerFnError::new("you don't have write access to this repo"));
    }
    Ok(())
}

/// Shared by `get_tree`/`get_blob`/`get_commit_log`: a public repo needs no
/// check at all (the common case, so this returns fast without touching the
/// db); a private one needs the caller to hold a `repo_access` row, same
/// requirement and same 404-not-403 reasoning as `get_repo`.
#[cfg(feature = "server")]
async fn require_read_access(
    auth: &axum_login::AuthSession<crate::auth::Backend>,
    store: &crate::git::store::LocalFsStore,
    name: &str,
) -> Result<(), ServerFnError> {
    use crate::git;

    let is_private = git::is_repo_private(store, name).map_err(|err| ServerFnError::new(err.to_string()))?;
    if !is_private {
        return Ok(());
    }
    let not_found = || ServerFnError::new(git::GitError::NotFound(name.to_string()).to_string());

    let Some(user) = &auth.user else { return Err(not_found()) };
    let allowed = crate::access::has_write_access(&auth.backend.pool, name, &user.id).await.map_err(|err| ServerFnError::new(err.to_string()))?;
    if !allowed {
        return Err(not_found());
    }
    Ok(())
}

#[post("/api/repos/:name/update", auth: axum_login::AuthSession<crate::auth::Backend>)]
#[tracing::instrument(name = "repository.update", skip_all, err, fields(repo.name = %name))]
pub async fn update_repo(name: String, description: Option<String>) -> Result<(), ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    require_write_access(&auth, &name).await?;

    let store = LocalFsStore::from_env();
    git::update_repo(&store, &name, description.as_deref()).await.map_err(|err| ServerFnError::new(err.to_string()))
}

#[post("/api/repos/:name/delete", auth: axum_login::AuthSession<crate::auth::Backend>)]
#[tracing::instrument(name = "repository.delete", skip_all, err, fields(repo.name = %name))]
pub async fn delete_repo(name: String) -> Result<(), ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    require_write_access(&auth, &name).await?;

    let store = LocalFsStore::from_env();
    git::delete_repo(&store, &name).await.map_err(|err| ServerFnError::new(err.to_string()))?;
    crate::access::revoke_all(&auth.backend.pool, &name).await.map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TreeEntryDto {
    pub name: String,
    pub is_dir: bool,
    pub size: Option<u64>,
}

#[cfg(feature = "server")]
impl From<crate::git::TreeEntry> for TreeEntryDto {
    fn from(entry: crate::git::TreeEntry) -> Self {
        Self { name: entry.name, is_dir: entry.is_dir, size: entry.size }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlobDto {
    pub name: String,
    pub size: u64,
    pub is_binary: bool,
    pub content: Option<String>,
}

#[cfg(feature = "server")]
impl From<crate::git::BlobContent> for BlobDto {
    fn from(blob: crate::git::BlobContent) -> Self {
        Self { name: blob.name, size: blob.size, is_binary: blob.is_binary, content: blob.content }
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
impl From<crate::git::CommitLogEntry> for CommitLogEntryDto {
    fn from(entry: crate::git::CommitLogEntry) -> Self {
        Self { id: entry.id, summary: entry.summary, author_name: entry.author_name, unix_seconds: entry.unix_seconds }
    }
}

/// `path` is a `/`-joined relative path within the repo (e.g. `"src/main.rs"`),
/// not a URL path segment — passed as a query parameter rather than a route
/// wildcard, since it can contain slashes at arbitrary depth. Extra `#[get]`
/// arguments are only routed through the query string when named explicitly
/// in the route literal (`?branch&path`) — left implicit, they'd silently
/// become JSON-body fields instead, which a plain `GET` never populates.
#[get("/api/repos/:name/tree?branch&path", auth: axum_login::AuthSession<crate::auth::Backend>)]
#[tracing::instrument(name = "repository.tree", skip_all, err, fields(repo.name = %name, branch = branch.as_deref().unwrap_or("HEAD")))]
pub async fn get_tree(name: String, branch: Option<String>, path: Option<String>) -> Result<Vec<TreeEntryDto>, ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    require_read_access(&auth, &store, &name).await?;
    let path = path.unwrap_or_default();
    let entries = git::browse_tree(&store, &name, branch.as_deref(), &path).map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(entries.into_iter().map(TreeEntryDto::from).collect())
}

#[get("/api/repos/:name/blob?branch&path", auth: axum_login::AuthSession<crate::auth::Backend>)]
#[tracing::instrument(name = "repository.blob", skip_all, err, fields(repo.name = %name, branch = branch.as_deref().unwrap_or("HEAD")))]
pub async fn get_blob(name: String, branch: Option<String>, path: String) -> Result<BlobDto, ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    require_read_access(&auth, &store, &name).await?;
    let blob = git::read_blob(&store, &name, branch.as_deref(), &path).map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(BlobDto::from(blob))
}

#[get("/api/repos/:name/commits?branch", auth: axum_login::AuthSession<crate::auth::Backend>)]
#[tracing::instrument(name = "repository.commits", skip_all, err, fields(repo.name = %name, branch = branch.as_deref().unwrap_or("HEAD")))]
pub async fn get_commit_log(name: String, branch: Option<String>) -> Result<Vec<CommitLogEntryDto>, ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    require_read_access(&auth, &store, &name).await?;
    let entries =
        git::commit_log(&store, &name, branch.as_deref(), 50).map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(entries.into_iter().map(CommitLogEntryDto::from).collect())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CurrentUser {
    pub id: String,
    pub email: String,
}

#[cfg(feature = "server")]
impl From<crate::auth::User> for CurrentUser {
    fn from(user: crate::auth::User) -> Self {
        Self { id: user.id, email: user.email }
    }
}

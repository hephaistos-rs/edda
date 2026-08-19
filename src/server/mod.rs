use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RepoDto {
    pub name: String,
    pub description: Option<String>,
    pub default_branch: Option<String>,
    pub branch_count: usize,
    pub is_empty: bool,
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
#[get("/api/repos")]
#[tracing::instrument(name = "repository.list", skip_all, err)]
pub async fn list_repos() -> Result<Vec<RepoDto>, ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    let summaries = git::list_repos(&store).map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(summaries.into_iter().map(RepoDto::from).collect())
}

#[get("/api/repos/:name")]
#[tracing::instrument(name = "repository.get", skip_all, err, fields(repo.name = %name))]
pub async fn get_repo(name: String) -> Result<RepoDto, ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    let summary = git::repo_summary(&store, &name).map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(RepoDto::from(summary))
}

#[post("/api/repos")]
#[tracing::instrument(name = "repository.create", skip_all, err, fields(repo.name = %name))]
pub async fn create_repo(name: String, description: Option<String>) -> Result<(), ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    git::create_repo(&store, &name, description.as_deref()).await.map_err(|err| ServerFnError::new(err.to_string()))
}

#[post("/api/repos/:name/update")]
#[tracing::instrument(name = "repository.update", skip_all, err, fields(repo.name = %name))]
pub async fn update_repo(name: String, description: Option<String>) -> Result<(), ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    git::update_repo(&store, &name, description.as_deref()).await.map_err(|err| ServerFnError::new(err.to_string()))
}

#[post("/api/repos/:name/delete")]
#[tracing::instrument(name = "repository.delete", skip_all, err, fields(repo.name = %name))]
pub async fn delete_repo(name: String) -> Result<(), ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    git::delete_repo(&store, &name).await.map_err(|err| ServerFnError::new(err.to_string()))
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
#[get("/api/repos/:name/tree?branch&path")]
#[tracing::instrument(name = "repository.tree", skip_all, err, fields(repo.name = %name, branch = branch.as_deref().unwrap_or("HEAD")))]
pub async fn get_tree(name: String, branch: Option<String>, path: Option<String>) -> Result<Vec<TreeEntryDto>, ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    let path = path.unwrap_or_default();
    let entries = git::browse_tree(&store, &name, branch.as_deref(), &path).map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(entries.into_iter().map(TreeEntryDto::from).collect())
}

#[get("/api/repos/:name/blob?branch&path")]
#[tracing::instrument(name = "repository.blob", skip_all, err, fields(repo.name = %name, branch = branch.as_deref().unwrap_or("HEAD")))]
pub async fn get_blob(name: String, branch: Option<String>, path: String) -> Result<BlobDto, ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    let blob = git::read_blob(&store, &name, branch.as_deref(), &path).map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(BlobDto::from(blob))
}

#[get("/api/repos/:name/commits?branch")]
#[tracing::instrument(name = "repository.commits", skip_all, err, fields(repo.name = %name, branch = branch.as_deref().unwrap_or("HEAD")))]
pub async fn get_commit_log(name: String, branch: Option<String>) -> Result<Vec<CommitLogEntryDto>, ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
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

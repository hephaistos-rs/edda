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

#[get("/api/repos")]
pub async fn list_repos() -> Result<Vec<RepoDto>, ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    let summaries = git::list_repos(&store).map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(summaries.into_iter().map(RepoDto::from).collect())
}

#[get("/api/repos/:name")]
pub async fn get_repo(name: String) -> Result<RepoDto, ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    let summary = git::repo_summary(&store, &name).map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(RepoDto::from(summary))
}

#[post("/api/repos")]
pub async fn create_repo(name: String, description: Option<String>) -> Result<(), ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    git::create_repo(&store, &name, description.as_deref()).await.map_err(|err| ServerFnError::new(err.to_string()))
}

#[post("/api/repos/:name/update")]
pub async fn update_repo(name: String, description: Option<String>) -> Result<(), ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    git::update_repo(&store, &name, description.as_deref()).await.map_err(|err| ServerFnError::new(err.to_string()))
}

#[post("/api/repos/:name/delete")]
pub async fn delete_repo(name: String) -> Result<(), ServerFnError> {
    use crate::git::{self, store::LocalFsStore};

    let store = LocalFsStore::from_env();
    git::delete_repo(&store, &name).await.map_err(|err| ServerFnError::new(err.to_string()))
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

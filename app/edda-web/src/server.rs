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
/// commit) — the two now live in different crates (plan.local.md §5.1),
/// so building this DTO is a join of both rather than a single `From`.
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
    };

    // Git-directory creation and the database row are two systems with no
    // shared transaction — create the git side first (cheap to leave
    // behind an empty bare repo if the DB insert then fails; the reverse,
    // a DB row pointing at a repo that was never created, is worse) per
    // plan.local.md §5.7/§9.2's ordering rule.
    edda_git::create_repo(shared.store.as_ref(), &shared.locks, &identity)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;

    // Inserting the row and granting its creator ownership happen inside
    // one transaction (`insert_with_owner`, added in plan.local.md §17
    // Phase 3) — previously two separate statements, which masked an
    // atomicity gap SQLite's single-writer serialization happened to hide
    // but PostgreSQL's real concurrency would not.
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
    // `ON DELETE CASCADE` foreign key to `repositories` now (plan.local.md
    // §5.5), so this is structurally impossible to forget — unlike the
    // pre-restructuring code, which had to remember to call
    // `access::revoke_all` here as a separate step.
    edda_db::RepositoryRepo::delete(&shared.pool, repository.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
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
}

#[cfg(feature = "server")]
impl From<edda_git::BlobContent> for BlobDto {
    fn from(blob: edda_git::BlobContent) -> Self {
        Self {
            name: blob.name,
            size: blob.size,
            is_binary: blob.is_binary,
            content: blob.content,
        }
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
    Ok(BlobDto::from(blob))
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CurrentUser {
    pub id: String,
    pub username: String,
    pub email: String,
}

#[cfg(feature = "server")]
impl From<edda_domain::User> for CurrentUser {
    fn from(user: edda_domain::User) -> Self {
        Self {
            id: user.id.to_string(),
            username: user.username,
            email: user.email,
        }
    }
}

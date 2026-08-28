//! `/api/v1/repos` — repository list + CRUD. Tree/blob/commits/diff/search
//! browsing lives in [`super::repo_browse`].

use axum::extract::{Path, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};

use edda_api_types::{CommitDto, CreateRepoRequest, ForkedRepoDto, RepoDto, UpdateRepoRequest};
use edda_domain::{ActorContext, RepoRole, Repository};

use super::{read_repo, Actor};
use crate::services::repository::NewRepository;
use crate::services::{git_identity, RepositoryService, ServiceError};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/repos", get(list).post(create))
        .route(
            "/api/v1/repos/{owner}/{repo}",
            get(get_one).patch(update).delete(delete),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/visibility",
            put(set_visibility),
        )
        .route("/api/v1/repos/{owner}/{repo}/fork", post(fork))
}

/// Joins a DB-level `Repository` (identity, description, visibility) with
/// its git-level `RepoSummary` (branch info, last commit) — the two live
/// in different crates, so this is a join, not a `From`.
fn repo_dto(
    repository: &Repository,
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

async fn list(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<RepoDto>>, ServiceError> {
    let rows = edda_db::RepositoryRepo::list_all_with_owner_username(&state.pool).await?;

    let roles = match actor.context().user_id() {
        Some(user_id) => edda_db::RepoAccessRepo::roles_for_user(&state.pool, user_id).await?,
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
        let summary = edda_git::repo_summary(state.store.as_ref(), &identity)?;
        let is_owner = role == Some(RepoRole::Owner);
        visible.push(repo_dto(&repository, &owner_username, summary, is_owner));
    }
    Ok(Json(visible))
}

async fn get_one(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<RepoDto>, ServiceError> {
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    let is_owner = state
        .authz
        .check_danger_zone(actor.context(), &repository)
        .await
        .is_ok();
    let identity = git_identity(&owner, &repo);
    let summary = edda_git::repo_summary(state.store.as_ref(), &identity)?;
    Ok(Json(repo_dto(&repository, &owner, summary, is_owner)))
}

async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Json(body): Json<CreateRepoRequest>,
) -> Result<Json<ForkedRepoDto>, ServiceError> {
    actor.require_user()?;
    let (owner, name) = RepositoryService::from_state(&state)
        .create(
            actor.context(),
            NewRepository {
                name: body.name,
                description: body.description,
                private: body.private,
                owner: body.owner,
            },
        )
        .await?;
    Ok(Json(ForkedRepoDto { owner, name }))
}

async fn update(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<UpdateRepoRequest>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    RepositoryService::from_state(&state)
        .update_description(actor.context(), &owner, &repo, body.description)
        .await?;
    Ok(Json(()))
}

async fn set_visibility(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<edda_api_types::SetVisibilityRequest>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    RepositoryService::from_state(&state)
        .set_visibility(actor.context(), &owner, &repo, body.private)
        .await?;
    Ok(Json(()))
}

async fn delete(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    RepositoryService::from_state(&state)
        .delete(actor.context(), &owner, &repo)
        .await?;
    Ok(Json(()))
}

async fn fork(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<ForkedRepoDto>, ServiceError> {
    actor.require_user()?;
    let (owner, name) = RepositoryService::from_state(&state)
        .fork(actor.context(), &owner, &repo)
        .await?;
    Ok(Json(ForkedRepoDto { owner, name }))
}

/// Resolve `{owner}/{repo}` for a read and hand back the identity string
/// browsing handlers pass to `edda-git` — the shared front half of every
/// [`super::repo_browse`] handler.
pub(crate) async fn read_repo_identity(
    state: &AppState,
    actor: &ActorContext,
    owner: &str,
    repo: &str,
) -> Result<String, ServiceError> {
    read_repo(state, actor, owner, repo).await?;
    Ok(git_identity(owner, repo))
}

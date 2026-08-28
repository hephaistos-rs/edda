//! `/api/v1/repos` — repository CRUD. Read-only browsing (tree/blob/
//! commits/diff/search) is still served by the Dioxus server functions
//! until the UI is cut over; this module is the write surface plus the
//! single-repo GET.

use axum::extract::{Path, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use edda_domain::Repository;

use super::{read_repo, Actor};
use crate::services::repository::NewRepository;
use crate::services::{RepositoryService, ServiceError};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/repos", post(create))
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

#[derive(Serialize)]
pub struct RepositoryDto {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub description: Option<String>,
    pub private: bool,
}

impl RepositoryDto {
    fn new(owner: &str, repository: &Repository) -> Self {
        Self {
            id: repository.id.to_string(),
            owner: owner.to_string(),
            name: repository.name.clone(),
            description: repository.description.clone(),
            private: repository.is_private(),
        }
    }
}

async fn get_one(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<RepositoryDto>, ServiceError> {
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    Ok(Json(RepositoryDto::new(&owner, &repository)))
}

#[derive(Deserialize)]
pub struct CreateRepoBody {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub private: bool,
    /// Organization namespace to create under; omitted → the caller's own.
    #[serde(default)]
    pub owner: Option<String>,
}

#[derive(Serialize)]
pub struct CreatedRepoDto {
    pub owner: String,
    pub name: String,
}

async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Json(body): Json<CreateRepoBody>,
) -> Result<Json<CreatedRepoDto>, ServiceError> {
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
    Ok(Json(CreatedRepoDto { owner, name }))
}

#[derive(Deserialize)]
pub struct UpdateRepoBody {
    #[serde(default)]
    pub description: Option<String>,
}

async fn update(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<UpdateRepoBody>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    RepositoryService::from_state(&state)
        .update_description(actor.context(), &owner, &repo, body.description)
        .await?;
    Ok(Json(()))
}

#[derive(Deserialize)]
pub struct SetVisibilityBody {
    pub private: bool,
}

async fn set_visibility(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<SetVisibilityBody>,
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
) -> Result<Json<CreatedRepoDto>, ServiceError> {
    actor.require_user()?;
    let (owner, name) = RepositoryService::from_state(&state)
        .fork(actor.context(), &owner, &repo)
        .await?;
    Ok(Json(CreatedRepoDto { owner, name }))
}

//! `/api/v1/repos/{owner}/{repo}/collaborators` — the versioned mirror of
//! `access_routes` (which the current UI still uses).

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use edda_domain::UserId;

use super::Actor;
use crate::services::{CollaboratorService, ServiceError};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/repos/{owner}/{repo}/collaborators",
            get(list).post(add),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/collaborators/{user_id}",
            axum::routing::delete(remove),
        )
}

#[derive(Serialize)]
pub struct CollaboratorDto {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub added_at: i64,
}

async fn list(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<CollaboratorDto>>, ServiceError> {
    actor.require_user()?;
    let rows = CollaboratorService::from_state(&state)
        .list(actor.context(), &owner, &repo)
        .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| CollaboratorDto {
                user_id: row.user.id.to_string(),
                email: row.user.email,
                role: row.role.as_db_str().to_string(),
                added_at: row.added_at,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct AddCollaboratorBody {
    pub email: String,
}

async fn add(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<AddCollaboratorBody>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    CollaboratorService::from_state(&state)
        .add(actor.context(), &owner, &repo, &body.email)
        .await?;
    Ok(Json(()))
}

async fn remove(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, user_id)): Path<(String, String, String)>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    let target: UserId = user_id.parse().map_err(|_| ServiceError::NotFound)?;
    CollaboratorService::from_state(&state)
        .remove(actor.context(), &owner, &repo, target)
        .await?;
    Ok(Json(()))
}

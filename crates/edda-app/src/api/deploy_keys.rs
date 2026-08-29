//! `/api/v1/repos/{owner}/{repo}/deploy-keys` — per-repository SSH deploy
//! keys. Managing them needs repository admin; see `DeployKeyService`.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};

use edda_api_types::{CreateDeployKeyRequest, DeployKeyDto};
use edda_domain::{DeployKey, DeployKeyId};

use super::Actor;
use crate::services::{DeployKeyService, ServiceError};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/repos/{owner}/{repo}/deploy-keys",
            get(list).post(add),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/deploy-keys/{id}",
            axum::routing::delete(remove),
        )
}

fn dto(key: DeployKey) -> DeployKeyDto {
    DeployKeyDto {
        id: key.id.to_string(),
        fingerprint: key.fingerprint,
        public_key: key.public_key,
        title: key.title,
        read_only: key.read_only,
        created_at: key.created_at,
        last_used_at: key.last_used_at,
    }
}

async fn list(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<DeployKeyDto>>, ServiceError> {
    actor.require_user()?;
    let keys = DeployKeyService::from_state(&state)
        .list(actor.context(), &owner, &repo)
        .await?;
    Ok(Json(keys.into_iter().map(dto).collect()))
}

async fn add(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<CreateDeployKeyRequest>,
) -> Result<Json<DeployKeyDto>, ServiceError> {
    actor.require_user()?;
    let key = DeployKeyService::from_state(&state)
        .add(
            actor.context(),
            &owner,
            &repo,
            &body.title,
            &body.public_key,
            body.read_only,
        )
        .await?;
    Ok(Json(dto(key)))
}

async fn remove(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, id)): Path<(String, String, String)>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    let key_id: DeployKeyId = id.parse().map_err(|_| ServiceError::NotFound)?;
    DeployKeyService::from_state(&state)
        .remove(actor.context(), &owner, &repo, key_id)
        .await?;
    Ok(Json(()))
}

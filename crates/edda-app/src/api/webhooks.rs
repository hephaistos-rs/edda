//! `/api/v1/repos/{owner}/{repo}/webhooks` — webhook create / delete.

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use edda_domain::WebhookId;

use super::Actor;
use crate::services::{ServiceError, WebhookService};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/repos/{owner}/{repo}/webhooks", post(create))
        .route(
            "/api/v1/repos/{owner}/{repo}/webhooks/{id}",
            axum::routing::delete(delete),
        )
}

#[derive(Deserialize)]
pub struct CreateWebhookBody {
    pub target_url: String,
    /// Wire event names, e.g. `pull_request.merged`.
    pub events: Vec<String>,
}

#[derive(Serialize)]
pub struct CreatedWebhookDto {
    pub id: String,
    /// Shown once — copy it now.
    pub secret: String,
}

async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<CreateWebhookBody>,
) -> Result<Json<CreatedWebhookDto>, ServiceError> {
    actor.require_user()?;
    let created = WebhookService::from_state(&state)
        .create(
            actor.context(),
            &owner,
            &repo,
            &body.target_url,
            &body.events,
        )
        .await?;
    Ok(Json(CreatedWebhookDto {
        id: created.id.to_string(),
        secret: created.secret,
    }))
}

async fn delete(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, id)): Path<(String, String, String)>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    let webhook_id: WebhookId = id.parse().map_err(|_| ServiceError::NotFound)?;
    WebhookService::from_state(&state)
        .delete(actor.context(), &owner, &repo, webhook_id)
        .await?;
    Ok(Json(()))
}

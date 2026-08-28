//! `/api/v1/repos/{owner}/{repo}/webhooks` — list / create / delete, plus
//! per-webhook delivery history. Owner/Admin only: a webhook governs what
//! repository data leaves the instance for every future event.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};

use edda_api_types::{CreateWebhookRequest, CreatedWebhookDto, WebhookDeliveryDto, WebhookDto};
use edda_domain::{ActorContext, Repository, WebhookId};

use super::Actor;
use crate::services::{ServiceError, WebhookService};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/repos/{owner}/{repo}/webhooks",
            get(list).post(create),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/webhooks/{id}",
            axum::routing::delete(delete),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/webhooks/{id}/deliveries",
            get(deliveries),
        )
}

async fn require_administer(
    state: &AppState,
    actor: &ActorContext,
    owner: &str,
    repo: &str,
) -> Result<Repository, ServiceError> {
    let repository = state.authz.repository_by_name(owner, repo).await?;
    state.authz.check_administer(actor, &repository).await?;
    Ok(repository)
}

fn webhook_dto(webhook: &edda_domain::Webhook) -> WebhookDto {
    WebhookDto {
        id: webhook.id.to_string(),
        target_url: webhook.target_url.clone(),
        events: webhook
            .events
            .iter()
            .map(|event| event.as_wire_str().to_string())
            .collect(),
        active: webhook.active,
        created_at: webhook.created_at,
    }
}

async fn list(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<WebhookDto>>, ServiceError> {
    actor.require_user()?;
    let repository = require_administer(&state, actor.context(), &owner, &repo).await?;
    let webhooks = edda_db::WebhookRepo::list_for_repository(&state.pool, repository.id).await?;
    Ok(Json(webhooks.iter().map(webhook_dto).collect()))
}

async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<CreateWebhookRequest>,
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

async fn deliveries(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, id)): Path<(String, String, String)>,
) -> Result<Json<Vec<WebhookDeliveryDto>>, ServiceError> {
    actor.require_user()?;
    require_administer(&state, actor.context(), &owner, &repo).await?;
    let webhook_id: WebhookId = id.parse().map_err(|_| ServiceError::NotFound)?;
    let rows = edda_db::WebhookDeliveryRepo::list_for_webhook(&state.pool, webhook_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|d| WebhookDeliveryDto {
                event: d.event.as_wire_str().to_string(),
                response_status: d.response_status,
                attempt_count: d.attempt_count,
                delivered: d.delivered_at.is_some(),
                created_at: d.created_at,
            })
            .collect(),
    ))
}

//! Webhook management — Dioxus server functions (repo *settings* content,
//! the same rationale branch-protection rules in `pr_server` already
//! use), not raw `edda-http` routes; delivery itself is a background job
//! (`job_handlers::deliver_webhook`), never inline here.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebhookDto {
    pub id: String,
    pub target_url: String,
    pub events: Vec<String>,
    pub active: bool,
    pub created_at: i64,
}

#[cfg(feature = "server")]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebhookDeliveryDto {
    pub event: String,
    pub response_status: Option<i32>,
    pub attempt_count: i32,
    pub delivered: bool,
    pub created_at: i64,
}

#[cfg(feature = "server")]
async fn require_administer(
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
    let Some(session_user) = &auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let actor = edda_domain::ActorContext::User(session_user.user.id);
    // Webhooks constrain what repository data leaves the instance for
    // every future event, regardless of who triggers it — the same
    // Owner/Admin tier branch-protection rules require, not plain write
    // access.
    shared
        .authz
        .check_administer(&actor, &repository)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(repository)
}

#[get("/api/repos/:owner/:name/webhooks", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "webhook.list", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn list_webhooks(owner: String, name: String) -> Result<Vec<WebhookDto>, ServerFnError> {
    let repository = require_administer(&auth, &owner, &name).await?;
    let shared = crate::shared::get();
    let webhooks = edda_db::WebhookRepo::list_for_repository(&shared.pool, repository.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(webhooks.iter().map(webhook_dto).collect())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CreatedWebhookDto {
    pub id: String,
    /// Shown once — the caller must copy it now, the same discipline
    /// already applied to a freshly created PAT.
    pub secret: String,
}

#[post("/api/repos/:owner/:name/webhooks", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "webhook.create", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn create_webhook(
    owner: String,
    name: String,
    target_url: String,
    events: Vec<String>,
) -> Result<CreatedWebhookDto, ServerFnError> {
    let repository = require_administer(&auth, &owner, &name).await?;
    let shared = crate::shared::get();

    let target_url = target_url.trim().to_string();
    if target_url.is_empty() {
        return Err(ServerFnError::new("a target URL is required"));
    }
    if events.is_empty() {
        return Err(ServerFnError::new("select at least one event"));
    }
    let parsed_events: Vec<edda_domain::WebhookEvent> = events
        .iter()
        .map(|event| {
            edda_domain::WebhookEvent::from_wire_str(event)
                .ok_or_else(|| ServerFnError::new(format!("unrecognized event {event:?}")))
        })
        .collect::<Result<_, _>>()?;

    // Creation-time SSRF check — delivery re-checks independently;
    // see `crate::ssrf`'s own doc comment for why both calls matter.
    crate::ssrf::resolve_and_check(&target_url)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;

    let raw_secret = edda_auth::webhook_signing::generate_secret();
    let ciphertext = edda_auth::secret_box::encrypt(raw_secret.as_bytes());

    let id = edda_domain::WebhookId::new();
    edda_db::WebhookRepo::insert(
        &shared.pool,
        id,
        repository.id,
        &target_url,
        &ciphertext,
        &parsed_events,
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?;

    Ok(CreatedWebhookDto {
        id: id.to_string(),
        secret: raw_secret,
    })
}

#[post("/api/repos/:owner/:name/webhooks/:id/delete", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "webhook.delete", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn delete_webhook(owner: String, name: String, id: String) -> Result<(), ServerFnError> {
    let repository = require_administer(&auth, &owner, &name).await?;
    let shared = crate::shared::get();
    let webhook_id = id
        .parse()
        .map_err(|_| ServerFnError::new("no such webhook"))?;
    edda_db::WebhookRepo::delete(&shared.pool, repository.id, webhook_id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

#[get("/api/repos/:owner/:name/webhooks/:id/deliveries", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "webhook.deliveries", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn list_webhook_deliveries(
    owner: String,
    name: String,
    id: String,
) -> Result<Vec<WebhookDeliveryDto>, ServerFnError> {
    require_administer(&auth, &owner, &name).await?;
    let shared = crate::shared::get();
    let webhook_id = id
        .parse()
        .map_err(|_| ServerFnError::new("no such webhook"))?;
    let deliveries = edda_db::WebhookDeliveryRepo::list_for_webhook(&shared.pool, webhook_id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(deliveries
        .into_iter()
        .map(|delivery| WebhookDeliveryDto {
            event: delivery.event.as_wire_str().to_string(),
            response_status: delivery.response_status,
            attempt_count: delivery.attempt_count,
            delivered: delivery.delivered_at.is_some(),
            created_at: delivery.created_at,
        })
        .collect())
}

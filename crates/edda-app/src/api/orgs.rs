//! `/api/v1/orgs` — organization creation.

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;

use super::Actor;
use crate::services::{OrganizationService, ServiceError};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/v1/orgs", post(create))
}

#[derive(Deserialize)]
pub struct CreateOrgBody {
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Json(body): Json<CreateOrgBody>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    OrganizationService::from_state(&state)
        .create(actor.context(), &body.name, body.display_name.as_deref())
        .await?;
    Ok(Json(()))
}

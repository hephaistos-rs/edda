//! `/api/v1/repos/{owner}/{repo}/branch-protection` — set / delete rules.

use axum::extract::{Path, State};
use axum::routing::put;
use axum::{Json, Router};
use serde::Deserialize;

use edda_domain::BranchProtectionRuleId;

use super::Actor;
use crate::services::{BranchProtectionService, ServiceError};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/repos/{owner}/{repo}/branch-protection", put(set))
        .route(
            "/api/v1/repos/{owner}/{repo}/branch-protection/{id}",
            axum::routing::delete(delete),
        )
}

#[derive(Deserialize)]
pub struct SetRuleBody {
    pub branch: String,
    #[serde(default)]
    pub required_approvals: i64,
}

async fn set(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<SetRuleBody>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    BranchProtectionService::from_state(&state)
        .set(
            actor.context(),
            &owner,
            &repo,
            &body.branch,
            body.required_approvals,
        )
        .await?;
    Ok(Json(()))
}

async fn delete(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, id)): Path<(String, String, String)>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    let rule_id: BranchProtectionRuleId = id.parse().map_err(|_| ServiceError::NotFound)?;
    BranchProtectionService::from_state(&state)
        .delete(actor.context(), &owner, &repo, rule_id)
        .await?;
    Ok(Json(()))
}

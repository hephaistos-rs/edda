//! `/api/v1/repos/{owner}/{repo}/branch-protection` — list / set / delete
//! rules.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};

use edda_api_types::{BranchProtectionDto, CreateBranchProtectionRequest};
use edda_domain::BranchProtectionRuleId;

use super::{read_repo, Actor};
use crate::services::{BranchProtectionService, ServiceError};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/repos/{owner}/{repo}/branch-protection",
            get(list).put(set),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/branch-protection/{id}",
            axum::routing::delete(delete),
        )
}

async fn list(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<BranchProtectionDto>>, ServiceError> {
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    let rules =
        edda_db::BranchProtectionRepo::list_for_repository(&state.pool, repository.id).await?;
    Ok(Json(
        rules
            .into_iter()
            .map(|rule| BranchProtectionDto {
                id: rule.id.to_string(),
                branch: rule.branch,
                required_approvals: rule.required_approvals,
            })
            .collect(),
    ))
}

async fn set(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<CreateBranchProtectionRequest>,
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

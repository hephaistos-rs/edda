//! `/api/v1/repos/{owner}/{repo}/branch-protection` — list / set / delete
//! rules.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};

use edda_api_types::{BranchProtectionDto, CreateBranchProtectionRequest};
use edda_db::BranchProtectionSettings;
use edda_domain::BranchProtectionRuleId;

use super::Actor;
use crate::services::{BranchProtectionService, ServiceError, SetBranchProtectionInput};
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
    let views = BranchProtectionService::from_state(&state)
        .list(actor.context(), &owner, &repo)
        .await?;
    Ok(Json(
        views
            .into_iter()
            .map(|view| BranchProtectionDto {
                id: view.rule.id.to_string(),
                branch: view.rule.pattern,
                required_approvals: view.rule.required_approvals,
                require_linear_history: view.rule.require_linear_history,
                require_signed_commits: view.rule.require_signed_commits,
                dismiss_stale_reviews: view.rule.dismiss_stale_reviews,
                require_up_to_date: view.rule.require_up_to_date,
                required_status_checks: view.rule.required_status_checks,
                push_allowlist_usernames: view.push_allowlist_usernames,
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
            SetBranchProtectionInput {
                pattern: body.branch,
                settings: BranchProtectionSettings {
                    required_approvals: body.required_approvals,
                    require_linear_history: body.require_linear_history,
                    require_signed_commits: body.require_signed_commits,
                    dismiss_stale_reviews: body.dismiss_stale_reviews,
                    require_up_to_date: body.require_up_to_date,
                    required_status_checks: body.required_status_checks,
                },
                push_allowlist_usernames: body.push_allowlist_usernames,
            },
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

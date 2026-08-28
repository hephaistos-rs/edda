//! `/api/v1/orgs/{org}/teams` — team CRUD + membership, and
//! `/api/v1/repos/{owner}/{repo}/teams` for attaching a team to a repo.

use axum::extract::{Path, State};
use axum::routing::{post, put};
use axum::{Json, Router};
use serde::Deserialize;

use super::Actor;
use crate::services::{ServiceError, TeamService};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/orgs/{org}/teams", post(create))
        .route(
            "/api/v1/orgs/{org}/teams/{team}/code-permission",
            put(set_code_permission),
        )
        .route("/api/v1/orgs/{org}/teams/{team}/members", post(add_member))
        .route(
            "/api/v1/orgs/{org}/teams/{team}/members/{username}",
            axum::routing::delete(remove_member),
        )
        .route("/api/v1/repos/{owner}/{repo}/teams", post(attach_to_repo))
}

#[derive(Deserialize)]
pub struct CreateTeamBody {
    pub name: String,
    /// A `TeamPermission` db string, e.g. `read` / `write` / `admin`.
    pub permission: String,
}

async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Path(org): Path<String>,
    Json(body): Json<CreateTeamBody>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    TeamService::from_state(&state)
        .create(actor.context(), &org, &body.name, &body.permission)
        .await?;
    Ok(Json(()))
}

#[derive(Deserialize)]
pub struct PermissionBody {
    pub permission: String,
}

async fn set_code_permission(
    State(state): State<AppState>,
    actor: Actor,
    Path((org, team)): Path<(String, String)>,
    Json(body): Json<PermissionBody>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    TeamService::from_state(&state)
        .set_code_permission(actor.context(), &org, &team, &body.permission)
        .await?;
    Ok(Json(()))
}

#[derive(Deserialize)]
pub struct MemberBody {
    pub username: String,
}

async fn add_member(
    State(state): State<AppState>,
    actor: Actor,
    Path((org, team)): Path<(String, String)>,
    Json(body): Json<MemberBody>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    TeamService::from_state(&state)
        .add_member(actor.context(), &org, &team, &body.username)
        .await?;
    Ok(Json(()))
}

async fn remove_member(
    State(state): State<AppState>,
    actor: Actor,
    Path((org, team, username)): Path<(String, String, String)>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    TeamService::from_state(&state)
        .remove_member(actor.context(), &org, &team, &username)
        .await?;
    Ok(Json(()))
}

#[derive(Deserialize)]
pub struct AttachTeamBody {
    pub team_org: String,
    pub team_name: String,
}

async fn attach_to_repo(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<AttachTeamBody>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    TeamService::from_state(&state)
        .attach_to_repo(
            actor.context(),
            &owner,
            &repo,
            &body.team_org,
            &body.team_name,
        )
        .await?;
    Ok(Json(()))
}

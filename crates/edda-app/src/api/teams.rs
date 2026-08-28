//! `/api/v1/orgs/{org}/teams` — team list / detail / CRUD + membership,
//! and `/api/v1/repos/{owner}/{repo}/teams` for the repo↔team grants.

use axum::extract::{Path, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};

use edda_api_types::{
    AttachTeamRequest, CreateTeamRequest, MemberRequest, PermissionRequest, TeamDto, TeamGrantDto,
    TeamSummaryDto,
};
use edda_domain::{ActorContext, Organization, Team, TeamUnit};

use super::Actor;
use crate::services::{ServiceError, TeamService};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/orgs/{org}/teams", get(list).post(create))
        .route("/api/v1/orgs/{org}/teams/{team}", get(get_one))
        .route(
            "/api/v1/orgs/{org}/teams/{team}/code-permission",
            put(set_code_permission),
        )
        .route("/api/v1/orgs/{org}/teams/{team}/members", post(add_member))
        .route(
            "/api/v1/orgs/{org}/teams/{team}/members/{username}",
            axum::routing::delete(remove_member),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/teams",
            get(list_repo_grants).post(attach_to_repo),
        )
}

async fn require_org_admin(
    state: &AppState,
    actor: &ActorContext,
    org: &str,
) -> Result<Organization, ServiceError> {
    let organization = state.authz.organization_by_name(org).await?;
    state
        .authz
        .check_administer_organization(actor, organization.id)
        .await?;
    Ok(organization)
}

async fn find_team(state: &AppState, org: &str, team: &str) -> Result<Team, ServiceError> {
    let organization = state.authz.organization_by_name(org).await?;
    edda_db::TeamRepo::find_by_org_and_name(&state.pool, organization.id, team)
        .await?
        .ok_or(ServiceError::NotFound)
}

async fn list(
    State(state): State<AppState>,
    actor: Actor,
    Path(org): Path<String>,
) -> Result<Json<Vec<TeamSummaryDto>>, ServiceError> {
    let organization = require_org_admin(&state, actor.context(), &org).await?;
    let teams = edda_db::TeamRepo::list_for_organization(&state.pool, organization.id).await?;
    Ok(Json(
        teams
            .into_iter()
            .map(|team| TeamSummaryDto {
                name: team.name,
                permission: team.permission.as_db_str().to_string(),
            })
            .collect(),
    ))
}

async fn get_one(
    State(state): State<AppState>,
    actor: Actor,
    Path((org, team_name)): Path<(String, String)>,
) -> Result<Json<TeamDto>, ServiceError> {
    require_org_admin(&state, actor.context(), &org).await?;
    let team = find_team(&state, &org, &team_name).await?;
    let code_override =
        edda_db::TeamRepo::find_unit_permission(&state.pool, team.id, TeamUnit::Code).await?;
    let members = edda_db::TeamMemberRepo::list_members(&state.pool, team.id).await?;
    Ok(Json(TeamDto {
        name: team.name,
        permission: team.permission.as_db_str().to_string(),
        code_permission_override: code_override.map(|p| p.as_db_str().to_string()),
        members: members.into_iter().map(|user| user.username).collect(),
    }))
}

async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Path(org): Path<String>,
    Json(body): Json<CreateTeamRequest>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    TeamService::from_state(&state)
        .create(actor.context(), &org, &body.name, &body.permission)
        .await?;
    Ok(Json(()))
}

async fn set_code_permission(
    State(state): State<AppState>,
    actor: Actor,
    Path((org, team)): Path<(String, String)>,
    Json(body): Json<PermissionRequest>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    TeamService::from_state(&state)
        .set_code_permission(actor.context(), &org, &team, &body.permission)
        .await?;
    Ok(Json(()))
}

async fn add_member(
    State(state): State<AppState>,
    actor: Actor,
    Path((org, team)): Path<(String, String)>,
    Json(body): Json<MemberRequest>,
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

async fn list_repo_grants(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<TeamGrantDto>>, ServiceError> {
    actor.require_user()?;
    let repository = state.authz.repository_by_name(&owner, &repo).await?;
    state
        .authz
        .check_danger_zone(actor.context(), &repository)
        .await?;
    let grants = edda_db::RepoAccessRepo::list_team_grants(&state.pool, repository.id).await?;
    Ok(Json(
        grants
            .into_iter()
            .map(|grant| TeamGrantDto {
                team_name: grant.team_name,
                role: grant.role.as_db_str().to_string(),
            })
            .collect(),
    ))
}

async fn attach_to_repo(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<AttachTeamRequest>,
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

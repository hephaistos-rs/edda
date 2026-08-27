//! Team management, and attaching a team to a repository — Dioxus server
//! functions. Team creation/membership/unit-permission changes are gated
//! on `AuthorizationService::check_administer_organization` (member of the
//! organization's Owners team); attaching a team to a *repository* is
//! gated on that repository's own `check_danger_zone`, the same tier
//! `access_routes`'s collaborator management already requires — the
//! repository owner decides who it trusts, not the team's own org.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TeamDto {
    pub name: String,
    pub permission: String,
    pub code_permission_override: Option<String>,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TeamSummaryDto {
    pub name: String,
    pub permission: String,
}

#[cfg(feature = "server")]
fn parse_permission(value: &str) -> Result<edda_domain::TeamPermission, ServerFnError> {
    edda_domain::TeamPermission::from_db_str(value)
        .ok_or_else(|| ServerFnError::new(format!("unrecognized permission {value:?}")))
}

#[cfg(feature = "server")]
async fn require_org_admin(
    auth: &axum_login::AuthSession<edda_auth::Backend>,
    org_name: &str,
) -> Result<edda_domain::Organization, ServerFnError> {
    let shared = crate::shared::get();
    let organization = shared
        .authz
        .organization_by_name(org_name)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    let Some(session_user) = &auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let actor = edda_domain::ActorContext::User(session_user.user.id);
    shared
        .authz
        .check_administer_organization(&actor, organization.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(organization)
}

#[cfg(feature = "server")]
async fn find_team(org_name: &str, team_name: &str) -> Result<edda_domain::Team, ServerFnError> {
    let shared = crate::shared::get();
    let organization = shared
        .authz
        .organization_by_name(org_name)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    edda_db::TeamRepo::find_by_org_and_name(&shared.pool, organization.id, team_name)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?
        .ok_or_else(|| ServerFnError::new("no such team"))
}

#[post("/api/orgs/:org_name/teams", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "team.create", skip_all, err, fields(org.name = %org_name, team.name = %team_name))]
pub async fn create_team(
    org_name: String,
    team_name: String,
    permission: String,
) -> Result<(), ServerFnError> {
    let organization = require_org_admin(&auth, &org_name).await?;
    let permission = parse_permission(&permission)?;
    let shared = crate::shared::get();
    edda_db::TeamRepo::insert(
        &shared.pool,
        edda_domain::TeamId::new(),
        organization.id,
        &team_name,
        permission,
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

#[get("/api/orgs/:org_name/teams", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "team.list", skip_all, err, fields(org.name = %org_name))]
pub async fn list_teams(org_name: String) -> Result<Vec<TeamSummaryDto>, ServerFnError> {
    let organization = require_org_admin(&auth, &org_name).await?;
    let shared = crate::shared::get();
    let teams = edda_db::TeamRepo::list_for_organization(&shared.pool, organization.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(teams
        .into_iter()
        .map(|team| TeamSummaryDto {
            name: team.name,
            permission: team.permission.as_db_str().to_string(),
        })
        .collect())
}

#[get("/api/orgs/:org_name/teams/:team_name", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "team.get", skip_all, err, fields(org.name = %org_name, team.name = %team_name))]
pub async fn get_team(org_name: String, team_name: String) -> Result<TeamDto, ServerFnError> {
    require_org_admin(&auth, &org_name).await?;
    let team = find_team(&org_name, &team_name).await?;
    let shared = crate::shared::get();
    let code_override =
        edda_db::TeamRepo::find_unit_permission(&shared.pool, team.id, edda_domain::TeamUnit::Code)
            .await
            .map_err(|err| ServerFnError::new(err.to_string()))?;
    let members = edda_db::TeamMemberRepo::list_members(&shared.pool, team.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(TeamDto {
        name: team.name,
        permission: team.permission.as_db_str().to_string(),
        code_permission_override: code_override.map(|p| p.as_db_str().to_string()),
        members: members.into_iter().map(|user| user.username).collect(),
    })
}

#[post("/api/orgs/:org_name/teams/:team_name/code-permission", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "team.set_code_permission", skip_all, err, fields(org.name = %org_name, team.name = %team_name))]
pub async fn set_team_code_permission(
    org_name: String,
    team_name: String,
    permission: String,
) -> Result<(), ServerFnError> {
    require_org_admin(&auth, &org_name).await?;
    let team = find_team(&org_name, &team_name).await?;
    let permission = parse_permission(&permission)?;
    let shared = crate::shared::get();
    edda_db::TeamRepo::set_unit_permission(
        &shared.pool,
        team.id,
        edda_domain::TeamUnit::Code,
        permission,
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

#[post("/api/orgs/:org_name/teams/:team_name/members", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "team.add_member", skip_all, err, fields(org.name = %org_name, team.name = %team_name))]
pub async fn add_team_member(
    org_name: String,
    team_name: String,
    username: String,
) -> Result<(), ServerFnError> {
    require_org_admin(&auth, &org_name).await?;
    let team = find_team(&org_name, &team_name).await?;
    let shared = crate::shared::get();
    let user = edda_db::UserRepo::find_by_username(&shared.pool, &username)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?
        .ok_or_else(|| ServerFnError::new("no such user"))?;
    edda_db::TeamMemberRepo::add(&shared.pool, team.id, user.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

#[post("/api/orgs/:org_name/teams/:team_name/members/:username/remove", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "team.remove_member", skip_all, err, fields(org.name = %org_name, team.name = %team_name))]
pub async fn remove_team_member(
    org_name: String,
    team_name: String,
    username: String,
) -> Result<(), ServerFnError> {
    require_org_admin(&auth, &org_name).await?;
    let team = find_team(&org_name, &team_name).await?;
    let shared = crate::shared::get();
    let user = edda_db::UserRepo::find_by_username(&shared.pool, &username)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?
        .ok_or_else(|| ServerFnError::new("no such user"))?;
    edda_db::TeamMemberRepo::remove(&shared.pool, team.id, user.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

/// Grants `team_name` (of `team_org`) push-level access to
/// `{repo_owner}/{repo_name}`, at the role its current `Code`-unit
/// permission resolves to (`Team::code_role`) — a snapshot taken at
/// attachment time, not re-evaluated later; see that method's own doc
/// comment for why.
#[post("/api/repos/:repo_owner/:repo_name/teams", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "team.attach_to_repo", skip_all, err, fields(repo.owner = %repo_owner, repo.name = %repo_name))]
pub async fn attach_team_to_repo(
    repo_owner: String,
    repo_name: String,
    team_org: String,
    team_name: String,
) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();
    let repository = shared
        .authz
        .repository_by_name(&repo_owner, &repo_name)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    let Some(session_user) = &auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let actor = edda_domain::ActorContext::User(session_user.user.id);
    shared
        .authz
        .check_danger_zone(&actor, &repository)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;

    let team = find_team(&team_org, &team_name).await?;
    let code_override =
        edda_db::TeamRepo::find_unit_permission(&shared.pool, team.id, edda_domain::TeamUnit::Code)
            .await
            .map_err(|err| ServerFnError::new(err.to_string()))?;
    let Some(role) = team.code_role(code_override) else {
        return Err(ServerFnError::new(
            "this team has no Code-unit access configured — set a permission before attaching it",
        ));
    };
    edda_db::RepoAccessRepo::grant(
        &shared.pool,
        repository.id,
        edda_domain::AccessSubject::Team(team.id),
        role,
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

// Constructed only in this module's `#[get]` handler body, which the
// server-fn macro strips from the client build — where the type then
// survives solely in the endpoint's return signature.
#[cfg_attr(not(feature = "server"), allow(dead_code))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TeamGrantDto {
    pub team_name: String,
    pub role: String,
}

#[get("/api/repos/:repo_owner/:repo_name/teams", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "team.list_repo_grants", skip_all, err, fields(repo.owner = %repo_owner, repo.name = %repo_name))]
pub async fn list_repo_team_grants(
    repo_owner: String,
    repo_name: String,
) -> Result<Vec<TeamGrantDto>, ServerFnError> {
    let shared = crate::shared::get();
    let repository = shared
        .authz
        .repository_by_name(&repo_owner, &repo_name)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    let Some(session_user) = &auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let actor = edda_domain::ActorContext::User(session_user.user.id);
    shared
        .authz
        .check_danger_zone(&actor, &repository)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    let grants = edda_db::RepoAccessRepo::list_team_grants(&shared.pool, repository.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(grants
        .into_iter()
        .map(|grant| TeamGrantDto {
            team_name: grant.team_name,
            role: grant.role.as_db_str().to_string(),
        })
        .collect())
}

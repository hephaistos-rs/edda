//! `TeamService` — team CRUD + membership within an organization, and
//! attaching a team to a repository.
//!
//! Team-level changes are gated on `check_administer_organization` (member
//! of the org's Owners team). Attaching a team to a *repository* is gated
//! on that repository's own `check_danger_zone` — the repo owner decides
//! who it trusts, not the team's org.

use edda_auth::AuthorizationService;
use edda_db::{DbPool, RepoAccessRepo, TeamMemberRepo, TeamRepo, UserRepo};
use edda_domain::{
    AccessSubject, ActorContext, Organization, Team, TeamId, TeamPermission, TeamUnit,
};

use super::ServiceError;
use crate::AppState;

#[derive(Clone)]
pub struct TeamService {
    pool: DbPool,
    authz: AuthorizationService,
}

impl TeamService {
    pub fn new(pool: DbPool, authz: AuthorizationService) -> Self {
        Self { pool, authz }
    }

    #[must_use]
    pub fn from_state(state: &AppState) -> Self {
        Self::new(state.pool.clone(), state.authz.clone())
    }

    pub async fn create(
        &self,
        actor: &ActorContext,
        org_name: &str,
        team_name: &str,
        permission: &str,
    ) -> Result<(), ServiceError> {
        let organization = self.org_admin_checked(actor, org_name).await?;
        let permission = parse_permission(permission)?;
        TeamRepo::insert(
            &self.pool,
            TeamId::new(),
            organization.id,
            team_name,
            permission,
        )
        .await?;
        Ok(())
    }

    pub async fn set_code_permission(
        &self,
        actor: &ActorContext,
        org_name: &str,
        team_name: &str,
        permission: &str,
    ) -> Result<(), ServiceError> {
        self.org_admin_checked(actor, org_name).await?;
        let team = self.find_team(org_name, team_name).await?;
        let permission = parse_permission(permission)?;
        TeamRepo::set_unit_permission(&self.pool, team.id, TeamUnit::Code, permission).await?;
        Ok(())
    }

    pub async fn add_member(
        &self,
        actor: &ActorContext,
        org_name: &str,
        team_name: &str,
        username: &str,
    ) -> Result<(), ServiceError> {
        self.org_admin_checked(actor, org_name).await?;
        let team = self.find_team(org_name, team_name).await?;
        let user = UserRepo::find_by_username(&self.pool, username)
            .await?
            .ok_or(ServiceError::NotFound)?;
        TeamMemberRepo::add(&self.pool, team.id, user.id).await?;
        Ok(())
    }

    pub async fn remove_member(
        &self,
        actor: &ActorContext,
        org_name: &str,
        team_name: &str,
        username: &str,
    ) -> Result<(), ServiceError> {
        self.org_admin_checked(actor, org_name).await?;
        let team = self.find_team(org_name, team_name).await?;
        let user = UserRepo::find_by_username(&self.pool, username)
            .await?
            .ok_or(ServiceError::NotFound)?;
        if !TeamMemberRepo::remove(&self.pool, team.id, user.id).await? {
            return Err(ServiceError::NotFound);
        }
        Ok(())
    }

    /// Grant a team push-level access to a repository, at the role its
    /// current `Code`-unit permission resolves to (a snapshot taken now).
    pub async fn attach_to_repo(
        &self,
        actor: &ActorContext,
        repo_owner: &str,
        repo_name: &str,
        team_org: &str,
        team_name: &str,
    ) -> Result<(), ServiceError> {
        let repository = self.authz.repository_by_name(repo_owner, repo_name).await?;
        self.authz.check_danger_zone(actor, &repository).await?;
        let team = self.find_team(team_org, team_name).await?;
        let code_override =
            TeamRepo::find_unit_permission(&self.pool, team.id, TeamUnit::Code).await?;
        let role = team.code_role(code_override).ok_or_else(|| {
            ServiceError::Conflict(
                "this team has no Code-unit access configured — set a permission before attaching \
                 it"
                .to_string(),
            )
        })?;
        RepoAccessRepo::grant(
            &self.pool,
            repository.id,
            AccessSubject::Team(team.id),
            role,
        )
        .await?;
        Ok(())
    }

    async fn org_admin_checked(
        &self,
        actor: &ActorContext,
        org_name: &str,
    ) -> Result<Organization, ServiceError> {
        let organization = self.authz.organization_by_name(org_name).await?;
        self.authz
            .check_administer_organization(actor, organization.id)
            .await?;
        Ok(organization)
    }

    async fn find_team(&self, org_name: &str, team_name: &str) -> Result<Team, ServiceError> {
        let organization = self.authz.organization_by_name(org_name).await?;
        TeamRepo::find_by_org_and_name(&self.pool, organization.id, team_name)
            .await?
            .ok_or(ServiceError::NotFound)
    }
}

fn parse_permission(value: &str) -> Result<TeamPermission, ServiceError> {
    TeamPermission::from_db_str(value)
        .ok_or_else(|| ServiceError::Validation(format!("unrecognized permission {value:?}")))
}

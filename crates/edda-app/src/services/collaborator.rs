//! `CollaboratorService` — add / remove / list repository collaborators.
//! Owner-only (`check_danger_zone`), matching the existing `access_routes`
//! surface this service now backs.

use edda_auth::AuthorizationService;
use edda_db::{CollaboratorRow, DbPool, RepoAccessRepo, UserRepo};
use edda_domain::{AccessSubject, ActorContext, RepoRole, Repository, UserId};

use super::ServiceError;
use crate::AppState;

#[derive(Clone)]
pub struct CollaboratorService {
    pool: DbPool,
    authz: AuthorizationService,
}

impl CollaboratorService {
    pub fn new(pool: DbPool, authz: AuthorizationService) -> Self {
        Self { pool, authz }
    }

    #[must_use]
    pub fn from_state(state: &AppState) -> Self {
        Self::new(state.pool.clone(), state.authz.clone())
    }

    /// Grant write access to the user with this email address.
    pub async fn add(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        email: &str,
    ) -> Result<(), ServiceError> {
        let repository = self.danger_zone_checked(actor, owner, name).await?;
        let user = UserRepo::find_by_email(&self.pool, email)
            .await?
            .ok_or(ServiceError::NotFound)?
            .user;
        RepoAccessRepo::grant(
            &self.pool,
            repository.id,
            AccessSubject::User(user.id),
            RepoRole::Write,
        )
        .await?;
        Ok(())
    }

    pub async fn remove(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        target: UserId,
    ) -> Result<(), ServiceError> {
        let repository = self.danger_zone_checked(actor, owner, name).await?;
        if !RepoAccessRepo::remove_grant(&self.pool, repository.id, AccessSubject::User(target))
            .await?
        {
            return Err(ServiceError::NotFound);
        }
        Ok(())
    }

    /// List collaborators — any signed-in user who can see the repo.
    pub async fn list(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
    ) -> Result<Vec<CollaboratorRow>, ServiceError> {
        let repository = self.authz.repository_by_name(owner, name).await?;
        self.authz.check_read(actor, &repository).await?;
        Ok(RepoAccessRepo::list_collaborators(&self.pool, repository.id).await?)
    }

    async fn danger_zone_checked(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
    ) -> Result<Repository, ServiceError> {
        let repository = self.authz.repository_by_name(owner, name).await?;
        self.authz.check_danger_zone(actor, &repository).await?;
        Ok(repository)
    }
}

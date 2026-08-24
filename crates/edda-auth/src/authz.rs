//! The authorization *service*: fetches whatever `edda-domain`'s pure
//! authorization functions need (via `edda-db`) and calls them. See
//! plan.local.md §7.2 — this module must never decide an outcome itself,
//! only assemble the inputs a decision in `edda_domain::access` needs.

use edda_db::{DbPool, RepoAccessRepo, RepositoryRepo};
use edda_domain::{
    can_administer_repository, can_manage_repository_danger_zone, can_read_repository,
    can_write_repository, ActorContext, AuthzError, Repository,
};

#[derive(Clone)]
pub struct AuthorizationService {
    pool: DbPool,
}

impl AuthorizationService {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Resolves the `{owner_username}/{repo_name}` form used in URLs and
    /// clone paths. Returns `NotFound` for both "the string is malformed"
    /// and "the repository genuinely doesn't exist" — this function makes
    /// no visibility/access decision of its own, so it's safe for a
    /// caller to call this before ever checking `can_read`/`can_write`.
    pub async fn repository_by_name(
        &self,
        owner_username: &str,
        name: &str,
    ) -> Result<Repository, AuthzError> {
        RepositoryRepo::find_by_owner_username_and_name(&self.pool, owner_username, name)
            .await
            .map_err(|_| AuthzError::NotFound)?
            .ok_or(AuthzError::NotFound)
    }

    async fn access_for(
        &self,
        actor: &ActorContext,
        repository: &Repository,
    ) -> Result<Option<edda_domain::RepoAccess>, AuthzError> {
        match actor.user_id() {
            Some(user_id) => RepoAccessRepo::find(&self.pool, repository.id, user_id)
                .await
                .map_err(|_| AuthzError::NotFound),
            None => Ok(None),
        }
    }

    pub async fn check_read(
        &self,
        actor: &ActorContext,
        repository: &Repository,
    ) -> Result<(), AuthzError> {
        let access = self.access_for(actor, repository).await?;
        can_read_repository(actor, repository, access.as_ref())
    }

    pub async fn check_write(
        &self,
        actor: &ActorContext,
        repository: &Repository,
    ) -> Result<(), AuthzError> {
        let access = self.access_for(actor, repository).await?;
        can_write_repository(actor, repository, access.as_ref())
    }

    pub async fn check_administer(
        &self,
        actor: &ActorContext,
        repository: &Repository,
    ) -> Result<(), AuthzError> {
        let access = self.access_for(actor, repository).await?;
        can_administer_repository(actor, repository, access.as_ref())
    }

    pub async fn check_danger_zone(
        &self,
        actor: &ActorContext,
        repository: &Repository,
    ) -> Result<(), AuthzError> {
        let access = self.access_for(actor, repository).await?;
        can_manage_repository_danger_zone(actor, repository, access.as_ref())
    }
}

//! `RepositoryService` — create / fork / update / set-visibility / delete.
//! Git-directory side effects and the DB row are two systems with no
//! shared transaction; the service keeps the "git side first" ordering the
//! pre-service handlers used (an orphan bare repo is cheap to clean up; a
//! row pointing at a repo that was never created is not).

use std::sync::Arc;

use edda_auth::AuthorizationService;
use edda_db::{DbPool, RepositoryRepo, TeamRepo};
use edda_domain::{ActorContext, Repository, RepositoryId, RepositoryOwner, Visibility};
use edda_git::store::RepoStore;
use edda_git::LockRegistry;

use super::{acting_user, audit, git_identity, ServiceError};
use crate::AppState;

/// What a caller supplies to open a repository.
pub struct NewRepository {
    pub name: String,
    pub description: Option<String>,
    pub private: bool,
    /// `None` → under the caller's own namespace; `Some(org)` → under an
    /// organization the caller administers.
    pub owner: Option<String>,
}

#[derive(Clone)]
pub struct RepositoryService {
    pool: DbPool,
    store: Arc<dyn RepoStore>,
    locks: Arc<LockRegistry>,
    authz: AuthorizationService,
    /// Phase 9: consulted by `create` so an account whose email is still
    /// unverified can't create repositories when the instance requires
    /// verification.
    registration: edda_domain::RegistrationPolicy,
}

impl RepositoryService {
    pub fn new(
        pool: DbPool,
        store: Arc<dyn RepoStore>,
        locks: Arc<LockRegistry>,
        authz: AuthorizationService,
        registration: edda_domain::RegistrationPolicy,
    ) -> Self {
        Self {
            pool,
            store,
            locks,
            authz,
            registration,
        }
    }

    #[must_use]
    pub fn from_state(state: &AppState) -> Self {
        Self::new(
            state.pool.clone(),
            state.store.clone(),
            state.locks.clone(),
            state.authz.clone(),
            state.config.registration.clone(),
        )
    }

    /// Create a repository under the caller's namespace, or under an
    /// organization's (the caller must be on its Owners team). Returns the
    /// `{owner}/{name}` the repo now lives at.
    pub async fn create(
        &self,
        actor: &ActorContext,
        spec: NewRepository,
    ) -> Result<(String, String), ServiceError> {
        let user = acting_user(&self.pool, actor).await?;
        if spec.name.trim().is_empty() {
            return Err(ServiceError::Validation(
                "a repository needs a name".to_string(),
            ));
        }
        // Phase 9: block an unverified account from creating repositories
        // when the instance's registration policy requires verification.
        if let Some(status) = edda_db::UserRepo::account_status(&self.pool, user.id).await? {
            if edda_auth::require_verified_for_write(&status, &self.registration).is_err() {
                return Err(ServiceError::Forbidden);
            }
        }

        let (owner_username, repo_owner, owner_team_id) = match &spec.owner {
            Some(org_name) => {
                let organization = self.authz.organization_by_name(org_name).await?;
                self.authz
                    .check_administer_organization(actor, organization.id)
                    .await?;
                let owners_team =
                    TeamRepo::find_by_org_and_name(&self.pool, organization.id, "Owners")
                        .await?
                        .ok_or_else(|| {
                            ServiceError::Conflict("organization has no Owners team".to_string())
                        })?;
                (
                    organization.name,
                    RepositoryOwner::Organization(organization.id),
                    Some(owners_team.id),
                )
            }
            None => (user.username.clone(), RepositoryOwner::User(user.id), None),
        };
        let identity = git_identity(&owner_username, spec.name.trim());

        let repository = Repository {
            id: RepositoryId::new(),
            owner: repo_owner,
            name: spec.name.trim().to_string(),
            description: spec.description.filter(|d| !d.trim().is_empty()),
            visibility: visibility_of(spec.private),
            forked_from: None,
        };

        edda_git::create_repo(self.store.as_ref(), &self.locks, &identity).await?;

        match owner_team_id {
            Some(team_id) => {
                RepositoryRepo::insert_with_owner_team(&self.pool, &repository, team_id).await
            }
            None => RepositoryRepo::insert_with_owner(&self.pool, &repository, user.id).await,
        }?;

        audit::record(
            &self.pool,
            audit::AuditEntry::new("repository.create", &user.id.to_string())
                .target("repository", &repository.id.to_string())
                .detail(serde_json::json!({ "identity": identity, "private": spec.private })),
        )
        .await;
        Ok((owner_username, repository.name))
    }

    /// Fork `owner/name` into the caller's own namespace, keeping the name.
    pub async fn fork(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
    ) -> Result<(String, String), ServiceError> {
        let user = acting_user(&self.pool, actor).await?;
        let source = self.authz.repository_by_name(owner, name).await?;
        self.authz.check_read(actor, &source).await?;

        let source_identity = git_identity(owner, name);
        let dest_identity = git_identity(&user.username, name);
        if source_identity == dest_identity {
            return Err(ServiceError::Conflict(
                "you already own this repository".to_string(),
            ));
        }

        edda_git::fork_repo(
            self.store.as_ref(),
            &self.locks,
            &source_identity,
            &dest_identity,
        )
        .await?;

        let fork = Repository {
            id: RepositoryId::new(),
            owner: RepositoryOwner::User(user.id),
            name: name.to_string(),
            description: source.description.clone(),
            visibility: source.visibility,
            forked_from: Some(source.id),
        };
        RepositoryRepo::insert_with_owner(&self.pool, &fork, user.id)
            .await
            .map_err(|err| match err {
                edda_db::repository_repo::InsertRepositoryError::AlreadyExists(_) => {
                    ServiceError::Conflict(
                        "you already have a repository with that name".to_string(),
                    )
                }
                edda_db::repository_repo::InsertRepositoryError::Db(err) => ServiceError::Db(err),
            })?;

        audit::record(
            &self.pool,
            audit::AuditEntry::new("repository.fork", &user.id.to_string())
                .target("repository", &fork.id.to_string())
                .detail(serde_json::json!({ "source": source_identity, "fork": dest_identity })),
        )
        .await;
        Ok((user.username, name.to_string()))
    }

    /// Edit the description — write access (owner or a write collaborator).
    pub async fn update_description(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        description: Option<String>,
    ) -> Result<(), ServiceError> {
        let repository = self.write_checked(actor, owner, name).await?;
        let description = description.filter(|d| !d.trim().is_empty());
        RepositoryRepo::update_description(&self.pool, repository.id, description.as_deref())
            .await?;
        Ok(())
    }

    /// Flip public/private — owner-only (`check_danger_zone`), a stronger
    /// action than editing the description.
    pub async fn set_visibility(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        private: bool,
    ) -> Result<(), ServiceError> {
        let repository = self.authz.repository_by_name(owner, name).await?;
        self.authz.check_danger_zone(actor, &repository).await?;
        RepositoryRepo::update_visibility(&self.pool, repository.id, visibility_of(private))
            .await?;
        if let Some(actor_id) = actor.user_id() {
            audit::record(
                &self.pool,
                audit::AuditEntry::new("repository.set_visibility", &actor_id.to_string())
                    .target("repository", &repository.id.to_string())
                    .detail(serde_json::json!({ "identity": git_identity(owner, name), "private": private })),
            )
            .await;
        }
        Ok(())
    }

    /// Delete the repository and its git directory — owner-only. Access
    /// grants fall away via `repo_access`'s `ON DELETE CASCADE`.
    pub async fn delete(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
    ) -> Result<(), ServiceError> {
        let repository = self.authz.repository_by_name(owner, name).await?;
        self.authz.check_danger_zone(actor, &repository).await?;
        let identity = git_identity(owner, name);
        edda_git::delete_repo(self.store.as_ref(), &self.locks, &identity).await?;
        RepositoryRepo::delete(&self.pool, repository.id).await?;
        if let Some(actor_id) = actor.user_id() {
            audit::record(
                &self.pool,
                audit::AuditEntry::new("repository.delete", &actor_id.to_string())
                    .target("repository", &repository.id.to_string())
                    .detail(serde_json::json!({ "identity": identity })),
            )
            .await;
        }
        Ok(())
    }

    async fn write_checked(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
    ) -> Result<Repository, ServiceError> {
        let repository = self.authz.repository_by_name(owner, name).await?;
        self.authz.check_write(actor, &repository).await?;
        Ok(repository)
    }
}

fn visibility_of(private: bool) -> Visibility {
    if private {
        Visibility::Private
    } else {
        Visibility::Public
    }
}

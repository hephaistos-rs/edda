//! `ReleaseService` — create a release (resolving or creating its tag in
//! the repository's git data first). Write access.

use std::sync::Arc;

use edda_auth::AuthorizationService;
use edda_db::{DbPool, EventRepo, NewRelease, ReleaseRepo};
use edda_domain::{ActorContext, DomainEvent, EventId, ReleaseId, Repository};
use edda_git::store::RepoStore;

use super::{git_identity, ServiceError};
use crate::AppState;

/// What a caller supplies to publish a release.
pub struct NewReleaseInput {
    pub tag_name: String,
    /// A branch name or commit id the tag should point at, when it doesn't
    /// already exist.
    pub target: String,
    pub title: String,
    pub body: Option<String>,
    pub draft: bool,
    pub prerelease: bool,
}

#[derive(Clone)]
pub struct ReleaseService {
    pool: DbPool,
    store: Arc<dyn RepoStore>,
    authz: AuthorizationService,
}

impl ReleaseService {
    pub fn new(pool: DbPool, store: Arc<dyn RepoStore>, authz: AuthorizationService) -> Self {
        Self { pool, store, authz }
    }

    #[must_use]
    pub fn from_state(state: &AppState) -> Self {
        Self::new(state.pool.clone(), state.store.clone(), state.authz.clone())
    }

    /// Create a release. Returns the tag name it was published against.
    pub async fn create(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        input: NewReleaseInput,
    ) -> Result<String, ServiceError> {
        let (repository, author_id) = self.write_checked(actor, owner, name).await?;
        let tag_name = input.tag_name.trim().to_string();
        let title = input.title.trim().to_string();
        if tag_name.is_empty() {
            return Err(ServiceError::Validation(
                "a tag name is required".to_string(),
            ));
        }
        if title.is_empty() {
            return Err(ServiceError::Validation(
                "a release title is required".to_string(),
            ));
        }

        let identity = git_identity(owner, name);
        let target_commit = match edda_git::resolve_tag(self.store.as_ref(), &identity, &tag_name) {
            Ok(commit) => commit,
            Err(_) => {
                edda_git::create_tag(self.store.as_ref(), &identity, &tag_name, &input.target)?
            }
        };

        let release_id = ReleaseId::new();
        let mut tx = self.pool.begin().await?;
        ReleaseRepo::insert(
            &mut tx,
            release_id,
            repository.id,
            NewRelease {
                tag_name: &tag_name,
                target_commit: &target_commit,
                name: &title,
                body: input.body.as_deref().filter(|b| !b.trim().is_empty()),
                draft: input.draft,
                prerelease: input.prerelease,
                author_id,
            },
        )
        .await?;
        // A draft release is collaborator-only and fires nothing; a
        // published one fans out `ReleasePublished`.
        if !input.draft {
            EventRepo::append(
                &mut tx,
                EventId::new(),
                &DomainEvent::ReleasePublished {
                    release_id,
                    repository_id: repository.id,
                    published_by_id: author_id,
                },
            )
            .await?;
        }
        tx.commit().await?;

        Ok(tag_name)
    }

    async fn write_checked(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
    ) -> Result<(Repository, edda_domain::UserId), ServiceError> {
        let user_id = actor.user_id().ok_or(ServiceError::Unauthorized)?;
        let repository = self.authz.repository_by_name(owner, name).await?;
        self.authz.check_write(actor, &repository).await?;
        Ok((repository, user_id))
    }
}

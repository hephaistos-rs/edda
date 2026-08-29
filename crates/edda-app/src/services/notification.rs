//! `NotificationService` — mark a notification read, the per-user
//! email-notification preference, and a repository watch/ignore
//! subscription. Read/write-your-own-data operations: the only check is
//! "is this a real user," done by the caller resolving `Actor`.

use edda_auth::AuthorizationService;
use edda_db::{DbPool, NotificationRepo, UserRepo, WatchRepo};
use edda_domain::{ActorContext, NotificationId, WatchId, WatchLevel, WatchSubject};

use super::ServiceError;
use crate::AppState;

#[derive(Clone)]
pub struct NotificationService {
    pool: DbPool,
    authz: AuthorizationService,
}

impl NotificationService {
    pub fn new(pool: DbPool, authz: AuthorizationService) -> Self {
        Self { pool, authz }
    }

    #[must_use]
    pub fn from_state(state: &AppState) -> Self {
        Self::new(state.pool.clone(), state.authz.clone())
    }

    /// The caller's watch level for a repository (`None` = the default:
    /// notified only for direct involvement). Read access.
    pub async fn repo_watch_level(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
    ) -> Result<Option<WatchLevel>, ServiceError> {
        let user_id = actor.user_id().ok_or(ServiceError::Unauthorized)?;
        let repository = self.authz.repository_by_name(owner, name).await?;
        self.authz.check_read(actor, &repository).await?;
        Ok(WatchRepo::get(&self.pool, user_id, WatchSubject::Repository(repository.id)).await?)
    }

    /// Set the caller's watch level for a repository (`watching` or
    /// `ignoring`). Read access — you can watch any repo you can see.
    pub async fn set_repo_watch(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        level: WatchLevel,
    ) -> Result<(), ServiceError> {
        let user_id = actor.user_id().ok_or(ServiceError::Unauthorized)?;
        let repository = self.authz.repository_by_name(owner, name).await?;
        self.authz.check_read(actor, &repository).await?;
        WatchRepo::set(
            &self.pool,
            WatchId::new(),
            user_id,
            WatchSubject::Repository(repository.id),
            level,
        )
        .await?;
        Ok(())
    }

    /// Clear the caller's watch row for a repository (back to the default).
    pub async fn clear_repo_watch(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
    ) -> Result<(), ServiceError> {
        let user_id = actor.user_id().ok_or(ServiceError::Unauthorized)?;
        let repository = self.authz.repository_by_name(owner, name).await?;
        WatchRepo::clear(&self.pool, user_id, WatchSubject::Repository(repository.id)).await?;
        Ok(())
    }

    pub async fn mark_read(
        &self,
        actor: &ActorContext,
        id: NotificationId,
    ) -> Result<(), ServiceError> {
        let user_id = actor.user_id().ok_or(ServiceError::Unauthorized)?;
        if !NotificationRepo::mark_read(&self.pool, user_id, id).await? {
            return Err(ServiceError::NotFound);
        }
        Ok(())
    }

    pub async fn set_email_notifications(
        &self,
        actor: &ActorContext,
        enabled: bool,
    ) -> Result<(), ServiceError> {
        let user_id = actor.user_id().ok_or(ServiceError::Unauthorized)?;
        UserRepo::set_email_notifications_enabled(&self.pool, user_id, enabled).await?;
        Ok(())
    }
}

//! `NotificationService` — mark a notification read, and the per-user
//! email-notification preference. Read-your-own-data operations: the only
//! check is "is this a real user," done by the caller resolving `Actor`.

use edda_db::{DbPool, NotificationRepo, UserRepo};
use edda_domain::{ActorContext, NotificationId};

use super::ServiceError;
use crate::AppState;

#[derive(Clone)]
pub struct NotificationService {
    pool: DbPool,
}

impl NotificationService {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub fn from_state(state: &AppState) -> Self {
        Self::new(state.pool.clone())
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

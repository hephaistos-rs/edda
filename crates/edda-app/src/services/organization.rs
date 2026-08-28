//! `OrganizationService` — create an organization (and its Owners team,
//! via `edda_auth::create_organization`). Any signed-in user may create
//! one.

use edda_db::DbPool;
use edda_domain::ActorContext;

use super::ServiceError;
use crate::AppState;

#[derive(Clone)]
pub struct OrganizationService {
    pool: DbPool,
}

impl OrganizationService {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub fn from_state(state: &AppState) -> Self {
        Self::new(state.pool.clone())
    }

    pub async fn create(
        &self,
        actor: &ActorContext,
        name: &str,
        display_name: Option<&str>,
    ) -> Result<(), ServiceError> {
        let user_id = actor.user_id().ok_or(ServiceError::Unauthorized)?;
        let display_name = display_name.filter(|d| !d.trim().is_empty());
        edda_auth::create_organization(&self.pool, name, display_name, user_id).await?;
        Ok(())
    }
}

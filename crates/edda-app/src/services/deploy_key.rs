//! `DeployKeyService` — list / add / remove a repository's SSH deploy
//! keys. Managing them needs repository **admin** (`check_administer`),
//! matching how mainstream hosts gate the deploy-key surface.

use edda_auth::AuthorizationService;
use edda_db::DbPool;
use edda_domain::{ActorContext, DeployKey, DeployKeyId, Repository};

use super::{audit, ServiceError};
use crate::AppState;

impl From<edda_auth::deploy_keys::AddDeployKeyError> for ServiceError {
    fn from(err: edda_auth::deploy_keys::AddDeployKeyError) -> Self {
        use edda_auth::deploy_keys::AddDeployKeyError as E;
        match err {
            E::Empty | E::InvalidKey => ServiceError::Validation(err.to_string()),
            E::FingerprintTaken => ServiceError::Conflict(err.to_string()),
            E::Db(err) => ServiceError::Db(err),
        }
    }
}

#[derive(Clone)]
pub struct DeployKeyService {
    pool: DbPool,
    authz: AuthorizationService,
}

impl DeployKeyService {
    pub fn new(pool: DbPool, authz: AuthorizationService) -> Self {
        Self { pool, authz }
    }

    #[must_use]
    pub fn from_state(state: &AppState) -> Self {
        Self::new(state.pool.clone(), state.authz.clone())
    }

    pub async fn list(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
    ) -> Result<Vec<DeployKey>, ServiceError> {
        let repository = self.admin_checked(actor, owner, name).await?;
        Ok(edda_auth::deploy_keys::list(&self.pool, repository.id).await?)
    }

    pub async fn add(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        title: &str,
        public_key: &str,
        read_only: bool,
    ) -> Result<DeployKey, ServiceError> {
        let repository = self.admin_checked(actor, owner, name).await?;
        let key =
            edda_auth::deploy_keys::add(&self.pool, repository.id, title, public_key, read_only)
                .await?;
        if let Some(actor_id) = actor.user_id() {
            audit::record(
                &self.pool,
                audit::AuditEntry::new("deploy_key.add", &actor_id.to_string())
                    .target("repository", &repository.id.to_string())
                    .detail(serde_json::json!({
                        "title": key.title,
                        "fingerprint": key.fingerprint,
                        "read_only": key.read_only,
                    })),
            )
            .await;
        }
        Ok(key)
    }

    pub async fn remove(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        key_id: DeployKeyId,
    ) -> Result<(), ServiceError> {
        let repository = self.admin_checked(actor, owner, name).await?;
        if !edda_auth::deploy_keys::revoke(&self.pool, repository.id, key_id).await? {
            return Err(ServiceError::NotFound);
        }
        if let Some(actor_id) = actor.user_id() {
            audit::record(
                &self.pool,
                audit::AuditEntry::new("deploy_key.remove", &actor_id.to_string())
                    .target("repository", &repository.id.to_string())
                    .detail(serde_json::json!({ "deploy_key_id": key_id.to_string() })),
            )
            .await;
        }
        Ok(())
    }

    async fn admin_checked(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
    ) -> Result<Repository, ServiceError> {
        let repository = self.authz.repository_by_name(owner, name).await?;
        self.authz.check_administer(actor, &repository).await?;
        Ok(repository)
    }
}

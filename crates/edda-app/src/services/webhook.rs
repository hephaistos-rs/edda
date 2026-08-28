//! `WebhookService` — create / delete repository webhooks. Owner/Admin
//! tier (`check_administer`): a webhook governs what repository data
//! leaves the instance for every future event, regardless of who triggers
//! it. Delivery itself is an outbox-driven background job.

use edda_auth::AuthorizationService;
use edda_db::{DbPool, WebhookRepo};
use edda_domain::{ActorContext, Repository, WebhookEvent, WebhookId};

use super::ServiceError;
use crate::security::ssrf;
use crate::AppState;

#[derive(Clone)]
pub struct WebhookService {
    pool: DbPool,
    authz: AuthorizationService,
}

/// A freshly created webhook's id and its signing secret — the secret is
/// shown once, never retrievable again.
pub struct CreatedWebhook {
    pub id: WebhookId,
    pub secret: String,
}

impl WebhookService {
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
        owner: &str,
        name: &str,
        target_url: &str,
        events: &[String],
    ) -> Result<CreatedWebhook, ServiceError> {
        let repository = self.administer_checked(actor, owner, name).await?;
        let target_url = target_url.trim();
        if target_url.is_empty() {
            return Err(ServiceError::Validation(
                "a target URL is required".to_string(),
            ));
        }
        if events.is_empty() {
            return Err(ServiceError::Validation(
                "select at least one event".to_string(),
            ));
        }
        let parsed: Vec<WebhookEvent> = events
            .iter()
            .map(|event| {
                WebhookEvent::from_wire_str(event).ok_or_else(|| {
                    ServiceError::Validation(format!("unrecognized event {event:?}"))
                })
            })
            .collect::<Result<_, _>>()?;

        // Creation-time SSRF check; delivery re-checks independently.
        ssrf::resolve_and_check(target_url)
            .await
            .map_err(|err| ServiceError::Validation(err.to_string()))?;

        let raw_secret = edda_auth::webhook_signing::generate_secret();
        let ciphertext = edda_auth::secret_box::encrypt(raw_secret.as_bytes())
            .map_err(|err| ServiceError::Conflict(err.to_string()))?;

        let id = WebhookId::new();
        WebhookRepo::insert(
            &self.pool,
            id,
            repository.id,
            target_url,
            &ciphertext,
            &parsed,
        )
        .await?;

        Ok(CreatedWebhook {
            id,
            secret: raw_secret,
        })
    }

    pub async fn delete(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        webhook_id: WebhookId,
    ) -> Result<(), ServiceError> {
        let repository = self.administer_checked(actor, owner, name).await?;
        if !WebhookRepo::delete(&self.pool, repository.id, webhook_id).await? {
            return Err(ServiceError::NotFound);
        }
        Ok(())
    }

    async fn administer_checked(
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

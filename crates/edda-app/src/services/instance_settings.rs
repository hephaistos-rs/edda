//! `InstanceSettingsService` — reads and writes the admin-editable
//! instance settings (Phase 12) and keeps the shared runtime cache
//! (`RuntimeConfig::instance_settings`, an `ArcSwap`) current.
//!
//! The request path never calls this service: it reads
//! `state.config.instance_settings.load()` directly (wait-free). This
//! service is only for the admin "view / save settings" endpoints and the
//! one-time startup load.

use std::sync::Arc;

use arc_swap::ArcSwap;
use edda_db::{DbPool, InstanceSettingsRepo};
use edda_domain::{InstanceSettings, InstanceSettingsDefaults};

use super::{audit, ServiceError};
use crate::AppState;

#[derive(Clone)]
pub struct InstanceSettingsService {
    pool: DbPool,
    defaults: InstanceSettingsDefaults,
    cache: Arc<ArcSwap<InstanceSettings>>,
}

impl InstanceSettingsService {
    #[must_use]
    pub fn from_state(state: &AppState) -> Self {
        Self {
            pool: state.pool.clone(),
            defaults: state.config.instance_settings_defaults.clone(),
            cache: state.config.instance_settings.clone(),
        }
    }

    /// Builds the shared cache handle from the environment baseline plus
    /// whatever override rows are already in the database — what the
    /// composition root calls once, before the first request, to seed
    /// `RuntimeConfig::instance_settings`. A database read failure here is
    /// logged and the environment defaults stand (startup is never
    /// blocked on this).
    pub async fn bootstrap(
        pool: &DbPool,
        defaults: InstanceSettingsDefaults,
    ) -> Arc<ArcSwap<InstanceSettings>> {
        let resolved = match InstanceSettingsRepo::list(pool).await {
            Ok(rows) => InstanceSettings::resolve(&defaults, &rows),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "could not read instance_settings overrides at startup; \
                     using the environment defaults"
                );
                InstanceSettings::resolve(&defaults, &[])
            }
        };
        Arc::new(ArcSwap::from_pointee(resolved))
    }

    /// The effective settings right now.
    #[must_use]
    pub fn current(&self) -> Arc<InstanceSettings> {
        self.cache.load_full()
    }

    /// Re-reads the override rows and swaps a fresh snapshot into the
    /// shared cache. Returns the new effective settings.
    pub async fn reload(&self) -> Result<Arc<InstanceSettings>, ServiceError> {
        let rows = InstanceSettingsRepo::list(&self.pool).await?;
        let resolved = Arc::new(InstanceSettings::resolve(&self.defaults, &rows));
        self.cache.store(resolved.clone());
        Ok(resolved)
    }

    /// Persists `settings` as the complete override set (one row per
    /// field), then refreshes the cache so the next request sees it. The
    /// write is one transaction; `admin_id` is recorded on each row and
    /// in the audit log.
    pub async fn save(
        &self,
        settings: &InstanceSettings,
        admin_id: &str,
    ) -> Result<Arc<InstanceSettings>, ServiceError> {
        settings.validate().map_err(ServiceError::Validation)?;

        let mut tx = self.pool.begin().await?;
        for (key, value) in settings.to_rows() {
            InstanceSettingsRepo::upsert(&mut tx, &key, &value, Some(admin_id)).await?;
        }
        tx.commit().await?;

        audit::record(
            &self.pool,
            audit::AuditEntry::new("admin.instance_settings.update", admin_id),
        )
        .await;

        self.reload().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edda_domain::RegistrationMode;

    async fn service() -> InstanceSettingsService {
        let pool = edda_db::test_pool().await;
        let defaults = InstanceSettingsDefaults::default();
        let cache = InstanceSettingsService::bootstrap(&pool, defaults.clone()).await;
        InstanceSettingsService {
            pool,
            defaults,
            cache,
        }
    }

    #[tokio::test]
    async fn save_persists_overrides_and_refreshes_the_cache() {
        let svc = service().await;
        assert_eq!(svc.current().registration_mode, RegistrationMode::Open);

        let next = InstanceSettings {
            registration_mode: RegistrationMode::Closed,
            default_repo_visibility: edda_domain::Visibility::Public,
            welcome_message: Some("hello".to_string()),
            require_signin_to_view: true,
        };
        svc.save(&next, "admin-1").await.unwrap();

        // The in-memory cache reflects the change immediately.
        assert_eq!(svc.current().registration_mode, RegistrationMode::Closed);
        assert!(svc.current().require_signin_to_view);

        // A fresh service over the same pool reads the same persisted state.
        let reopened = InstanceSettingsService {
            pool: svc.pool.clone(),
            defaults: svc.defaults.clone(),
            cache: InstanceSettingsService::bootstrap(&svc.pool, svc.defaults.clone()).await,
        };
        assert_eq!(reopened.current().welcome_message.as_deref(), Some("hello"));
        assert_eq!(
            reopened.current().default_repo_visibility,
            edda_domain::Visibility::Public
        );
    }

    #[tokio::test]
    async fn save_rejects_an_over_long_welcome_message() {
        let svc = service().await;
        let bad = InstanceSettings {
            welcome_message: Some(
                "x".repeat(edda_domain::instance_settings::MAX_WELCOME_MESSAGE_LEN + 1),
            ),
            ..InstanceSettings::default()
        };
        assert!(matches!(
            svc.save(&bad, "admin-1").await,
            Err(ServiceError::Validation(_))
        ));
    }
}

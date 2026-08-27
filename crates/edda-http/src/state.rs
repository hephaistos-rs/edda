use std::sync::Arc;

use edda_auth::{AuthorizationService, Backend};
use edda_db::DbPool;
use edda_git::store::RepoStore;
use edda_git::LockRegistry;

use crate::config::RateLimitConfig;

/// Everything an `edda-http` handler needs, constructed once by the
/// composition root (`edda-web`) and shared via axum's `State` extractor
/// — so a handler never reads the environment or derives its own
/// `LockRegistry` independently.
#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub store: Arc<dyn RepoStore>,
    pub locks: Arc<LockRegistry>,
    pub authz: AuthorizationService,
    pub backend: Backend,
    /// Validated deployment configuration the request path needs. Built
    /// from `edda_http::config::Settings`; `Default` (feature configs
    /// `None`, generous rate limits) is fine for tests that don't
    /// exercise WebAuthn/OIDC/rate-limit tuning.
    pub config: RuntimeConfig,
}

/// The slice of [`crate::config::Settings`] the HTTP request path reads at
/// runtime (as opposed to the wiring-time slices the composition root
/// consumes directly).
#[derive(Clone, Default)]
pub struct RuntimeConfig {
    /// `None` unless `EDDA_WEBAUTHN_RP_ID`/`_ORIGIN` are configured.
    pub webauthn: Option<edda_auth::webauthn::Config>,
    /// `None` unless the `EDDA_OAUTH_*` set is configured.
    pub oidc: Option<edda_auth::oauth::Config>,
    /// `EDDA_EXTERNAL_URL` (or a derived `http://ip:port`). Anchors
    /// redirect/origin defaults in later phases; empty in `Default`.
    pub external_url: String,
    pub rate_limit: RateLimitConfig,
}

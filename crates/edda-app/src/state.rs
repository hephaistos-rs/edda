use std::sync::Arc;

use edda_auth::{AuthorizationService, Backend};
use edda_db::DbPool;
use edda_git::store::RepoStore;
use edda_git::LockRegistry;

use crate::config::{GitLimits, RateLimitConfig, SessionConfig};

/// Everything an `edda-app` handler needs, constructed once by the
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
    /// from `edda_app::config::Settings`; `Default` (feature configs
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
    /// The configured OIDC providers; empty (the `Default`) when OIDC
    /// login isn't offered.
    pub oidc: edda_auth::oauth::Providers,
    /// `EDDA_EXTERNAL_URL` (or a derived `http://ip:port`). Anchors
    /// redirect/origin defaults; empty in `Default`.
    pub external_url: String,
    /// Extra web origins (`scheme://host[:port]`) a browser may send a
    /// credentialed, state-changing request from, beyond same-origin and
    /// `external_url` — `EDDA_TRUSTED_ORIGINS`, for a split
    /// frontend/backend deployment. Empty by default (same-origin only).
    /// Consumed by `security::origin`.
    pub trusted_origins: Vec<String>,
    pub rate_limit: RateLimitConfig,
    /// Instance registration policy (Phase 9, H2/S3) — signup mode, email
    /// domain allowlist, and whether a new account needs email
    /// verification before it may push / create. `Default` is wide open.
    ///
    /// This is the *environment* baseline; the effective policy also folds
    /// in any runtime `instance_settings` override of the signup mode —
    /// use [`RuntimeConfig::effective_registration_policy`] on the request
    /// path, not this field directly.
    pub registration: edda_domain::RegistrationPolicy,
    /// `EDDA_REQUIRE_SIGNIN_VIEW` — the *environment* default for instance
    /// privacy. The effective value is
    /// `instance_settings.load().require_signin_to_view`, which an admin
    /// can toggle at runtime; read that on the request path.
    pub require_signin_to_view: bool,
    /// The environment-derived baseline the `instance_settings` cache
    /// resolves overrides against — held so the cache can be recomputed
    /// after an admin edit without re-reading the environment.
    pub instance_settings_defaults: edda_domain::InstanceSettingsDefaults,
    /// The live, admin-editable instance settings (Phase 12). Seeded from
    /// the database at startup and swapped wholesale by the admin
    /// "save settings" path — a wait-free `.load()` on the request path,
    /// no restart. `Default` is the built-in behaviour.
    pub instance_settings: std::sync::Arc<arc_swap::ArcSwap<edda_domain::InstanceSettings>>,
    /// Streamed-body size ceilings for the git/LFS transfer paths
    /// (`EDDA_GIT_MAX_PACK_BYTES` / `EDDA_LFS_MAX_OBJECT_BYTES`). `Default`
    /// is 2 GiB / 4 GiB — a real cap even in tests that don't tune it.
    pub git_limits: GitLimits,
    /// Session lifetimes (S10). The request path reads
    /// `session.absolute_ttl_secs` to expire a too-old session in the
    /// actor-resolution path; the rolling TTL is applied at wiring time by
    /// the composition root's `Expiry`.
    pub session: SessionConfig,
}

impl RuntimeConfig {
    /// The registration policy in force right now: the env-configured
    /// email-domain allowlist and email-verification requirement, plus the
    /// signup `mode` from `instance_settings` (an admin can change the
    /// mode at runtime; the other two are deployment-fixed).
    #[must_use]
    pub fn effective_registration_policy(&self) -> edda_domain::RegistrationPolicy {
        edda_domain::RegistrationPolicy {
            mode: self.instance_settings.load().registration_mode,
            ..self.registration.clone()
        }
    }

    /// Whether an anonymous request is refused everywhere but the
    /// login/health surface — the effective, admin-toggleable value.
    #[must_use]
    pub fn require_signin_to_view(&self) -> bool {
        self.instance_settings.load().require_signin_to_view
    }
}

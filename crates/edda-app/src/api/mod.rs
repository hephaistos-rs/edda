//! `/api/v1/*` — the versioned, documented REST surface: thin axum
//! handlers that resolve an [`Actor`], call a `crate::services` method,
//! and serialize its result. The single primary API (plan.local.md §14.3);
//! the Dioxus UI consumes exactly this.
//!
//! The [`Actor`] extractor resolves an identity from **either** the
//! session cookie (how the web UI authenticates) **or** an
//! `Authorization: Bearer <PAT>` header (how API clients do). A request
//! with neither, or an unusable one, yields [`ActorContext::Anonymous`];
//! write handlers turn that into `ServiceError::Unauthorized`.
//!
//! Cookie-authenticated, state-changing requests additionally pass the
//! CSRF/Origin check in [`crate::security::origin`] (wired in
//! [`crate::router`]) — an `Origin`/`Sec-Fetch-Site` allowlist on top of
//! the `SameSite=Lax` session cookie. Bearer-token requests carry no
//! ambient credential and are exempt.
//!
//! Versioning: `/api/v1` is additive-only; a breaking change means
//! `/api/v2`, never an in-place change here.

mod error;
mod git_read;

pub mod branch_protection;
pub mod collaborators;
pub mod deploy_keys;
pub mod issues;
pub mod metrics;
pub mod notifications;
pub mod orgs;
pub mod pulls;
pub mod releases;
pub mod repo_browse;
pub mod repos;
pub mod statuses;
pub mod teams;
pub mod webhooks;

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::Router;
use axum_login::AuthSession;

use edda_auth::Backend;
use edda_domain::{ActorContext, Repository, TokenScope, UserId};

use crate::services::ServiceError;
use crate::AppState;

pub(crate) use git_read::git_read;

/// The `/api/v1` actor, resolved once per request from the session cookie
/// or a bearer token.
pub struct Actor(pub ActorContext);

impl Actor {
    /// The resolved identity — hand this to `crate::services` methods.
    #[must_use]
    pub fn context(&self) -> &ActorContext {
        &self.0
    }

    /// The acting user's id, or `Unauthorized` if the request carried no
    /// usable identity — the first line of every write handler.
    pub fn require_user(&self) -> Result<UserId, ServiceError> {
        self.0.user_id().ok_or(ServiceError::Unauthorized)
    }

    /// Asserts the actor's PAT operation scope permits `required`
    /// (`RepoRead` on a GET, `RepoWrite` on a mutation). A session-cookie
    /// user is not PAT-scoped and always passes; a token with a narrower
    /// scope gets `Forbidden`. Anonymous is unaffected here — `require_user`
    /// upstream already turns it into `Unauthorized`.
    pub fn require_scope(&self, required: TokenScope) -> Result<(), ServiceError> {
        if self.0.permits_token_scope(required) {
            Ok(())
        } else {
            Err(ServiceError::Forbidden)
        }
    }
}

impl FromRequestParts<AppState> for Actor {
    // Rejects only one case: a scoped PAT used on a method it isn't
    // allowed for (a `repo:read` token doing a write). Everything else —
    // no credential, a bad token — resolves to `Anonymous` and is handled
    // by the handler's own `require_user`.
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Session cookie first — the web UI's path. `AuthSession` reads
        // the identity the `AuthManagerLayer` (applied by the composition
        // root, outside this router) already resolved; a request without
        // that layer, or without a valid session, simply carries no user
        // here and falls through to the bearer check.
        if let Ok(auth) = AuthSession::<Backend>::from_request_parts(parts, state).await {
            if let Some(session_user) = &auth.user {
                let user_id = session_user.user.id;
                // Absolute session TTL (S10): a session established longer
                // ago than `EDDA_SESSION_ABSOLUTE_TTL_SECONDS` is treated
                // as signed-out regardless of recent activity.
                let login_at = auth
                    .session
                    .get::<i64>(crate::auth_routes::SESSION_LOGIN_AT)
                    .await
                    .ok()
                    .flatten();
                if crate::auth_routes::session_login_expired(
                    login_at,
                    state.config.session.absolute_ttl_secs,
                ) {
                    let _ = auth.session.flush().await;
                } else {
                    return Ok(Actor(ActorContext::User(user_id)));
                }
            }
        }

        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        let context = match token {
            Some(token) => match edda_auth::tokens::authenticate(&state.pool, token).await {
                Some((user, scope, token_scope)) => ActorContext::Token {
                    user_id: user.id,
                    scope,
                    token_scope,
                },
                None => ActorContext::Anonymous,
            },
            None => ActorContext::Anonymous,
        };

        // A read-only PAT may issue safe (GET/HEAD/OPTIONS) requests only;
        // anything else needs `RepoWrite` (or `All`). One check here covers
        // every `/api/v1` mutation route without threading a scope
        // assertion through ~30 handlers. Per-resource authorization
        // (`check_write` etc.) still runs in the service layer.
        let required = if parts.method.is_safe() {
            TokenScope::RepoRead
        } else {
            TokenScope::RepoWrite
        };
        if !context.permits_token_scope(required) {
            return Err(ServiceError::Forbidden.into_response());
        }

        // Instance-private mode (Phase 9, `EDDA_REQUIRE_SIGNIN_VIEW`): an
        // anonymous caller may not touch `/api/v1` at all. Auth-adjacent
        // endpoints (`/api/auth/*`, OAuth, WebAuthn) live on a different
        // sub-router and never resolve an `Actor`, so login still works.
        if state.config.require_signin_to_view() && matches!(context, ActorContext::Anonymous) {
            return Err(ServiceError::Unauthorized.into_response());
        }

        Ok(Actor(context))
    }
}

/// Resolve `{owner}/{repo}` and assert `actor` may read it — the shared
/// front half of every `/api/v1` repo-scoped GET. `NotFound` masks both
/// "no such repo" and "private, and you may not know it exists".
pub(crate) async fn read_repo(
    state: &AppState,
    actor: &ActorContext,
    owner: &str,
    repo: &str,
) -> Result<Repository, ServiceError> {
    let repository = state.authz.repository_by_name(owner, repo).await?;
    state.authz.check_read(actor, &repository).await?;
    Ok(repository)
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(repos::routes())
        .merge(repo_browse::routes())
        .merge(pulls::routes())
        .merge(issues::routes())
        .merge(releases::routes())
        .merge(webhooks::routes())
        .merge(branch_protection::routes())
        .merge(statuses::routes())
        .merge(collaborators::routes())
        .merge(deploy_keys::routes())
        .merge(orgs::routes())
        .merge(teams::routes())
        .merge(notifications::routes())
}

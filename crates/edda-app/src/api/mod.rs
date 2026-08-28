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

pub mod branch_protection;
pub mod collaborators;
pub mod issues;
pub mod notifications;
pub mod orgs;
pub mod pulls;
pub mod releases;
pub mod repo_browse;
pub mod repos;
pub mod teams;
pub mod webhooks;

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::Router;
use axum_login::AuthSession;

use edda_auth::Backend;
use edda_domain::{ActorContext, Repository, UserId};

use crate::services::ServiceError;
use crate::AppState;

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
}

impl FromRequestParts<AppState> for Actor {
    type Rejection = std::convert::Infallible;

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
            if let Some(session_user) = auth.user {
                return Ok(Actor(ActorContext::User(session_user.user.id)));
            }
        }

        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        let context = match token {
            Some(token) => match edda_auth::tokens::authenticate(&state.pool, token).await {
                Some((user, scope)) => ActorContext::Token {
                    user_id: user.id,
                    scope,
                },
                None => ActorContext::Anonymous,
            },
            None => ActorContext::Anonymous,
        };
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
        .merge(collaborators::routes())
        .merge(orgs::routes())
        .merge(teams::routes())
        .merge(notifications::routes())
}

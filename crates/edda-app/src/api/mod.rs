//! `/api/v1/*` — the versioned, documented REST surface: thin axum
//! handlers that resolve an [`Actor`], call a `crate::services` method,
//! and serialize its result. The single primary API (plan.local.md §14.3);
//! the Dioxus UI is being cut over to consume exactly this.
//!
//! Authentication here is `Authorization: Bearer <PAT>` only — never a
//! session cookie, so CSRF is structurally N/A on this surface. A missing
//! or unresolvable token yields [`ActorContext::Anonymous`]; write
//! handlers turn that into `ServiceError::Unauthorized`.
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
pub mod repos;
pub mod teams;
pub mod webhooks;

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::Router;

use edda_domain::{ActorContext, Repository, UserId};

use crate::services::ServiceError;
use crate::AppState;

/// The `/api/v1` actor, resolved once per request from the bearer token.
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

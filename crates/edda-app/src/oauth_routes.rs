//! HTTP surface for OAuth2/OIDC consumer login — the routes that drive
//! `edda_auth::oauth`'s `start`/`complete`/`link` through an actual
//! browser redirect round-trip. Nothing here decides *policy* (account
//! linking, email matching, per-provider provisioning); that is all
//! `edda_auth::oauth`'s job — this module only shuttles the browser to
//! and from the chosen identity provider and stashes the CSRF/nonce/PKCE
//! values in between.
//!
//! Since Phase 9 the instance may configure **several** providers
//! (`EDDA_OIDC_PROVIDERS`). The `{provider}`-parameterized routes name
//! one explicitly; the bare routes work only when exactly one provider
//! is configured. The chosen provider's name is recorded in the pending
//! session blob, so the callback resolves it from there, not the URL.
//!
//! The three values `start` returns (csrf token, nonce, PKCE verifier)
//! have to survive the redirect to the provider and back, so they're
//! stashed in the pre-login session via `tower_sessions::Session` — the
//! same session machinery `axum_login` itself rides on, just used here
//! before a login exists rather than after.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use axum_login::{AuthSession, AuthnBackend};
use serde::Deserialize;
use tower_sessions::Session;

use edda_auth::oauth::{self, ProviderConfig};
use edda_auth::Backend;

use crate::state::AppState;

const SESSION_KEY: &str = "oauth_pending";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PendingOAuth {
    /// Which configured provider this flow is against — the callback
    /// resolves the `ProviderConfig` from this, never from the URL.
    provider_name: String,
    csrf_token: String,
    nonce: String,
    pkce_verifier: String,
    /// `Some` only when this flow was started via `/link` from an
    /// already-authenticated context — see `oauth::link`'s doc comment on
    /// why linking is never inferred from an email match alone.
    link_user_id: Option<String>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/auth/oauth/enabled", get(enabled))
        .route("/api/auth/oauth/providers", get(list_providers))
        .route("/api/auth/oauth/login", get(start_login))
        .route("/api/auth/oauth/link", get(start_link))
        .route("/api/auth/oauth/callback", get(callback))
        .route("/api/auth/oauth/{provider}/login", get(start_login_named))
        .route("/api/auth/oauth/{provider}/link", get(start_link_named))
        .route("/api/auth/oauth/{provider}/callback", get(callback))
}

/// Lets the UI decide whether to render a "sign in with SSO" affordance
/// at all — this instance's OIDC configuration is server-side.
async fn enabled(State(state): State<AppState>) -> Response {
    axum::Json(!state.config.oidc.is_empty()).into_response()
}

#[derive(serde::Serialize)]
struct ProviderDto {
    name: String,
    display_name: String,
}

/// The configured providers, for a UI that offers a choice.
async fn list_providers(State(state): State<AppState>) -> Response {
    let list: Vec<ProviderDto> = state
        .config
        .oidc
        .iter()
        .map(|p| ProviderDto {
            name: p.name.clone(),
            display_name: p.display_name.clone(),
        })
        .collect();
    axum::Json(list).into_response()
}

/// Resolves the provider for a request: an explicit name, or — when
/// `name` is `None` — the sole configured provider. `Err` is a
/// ready-to-return response (404 when OIDC is off, 400 when a name is
/// needed or unknown).
#[allow(clippy::result_large_err)]
fn resolve_provider<'a>(
    state: &'a AppState,
    name: Option<&str>,
) -> Result<&'a ProviderConfig, Response> {
    if state.config.oidc.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            "OAuth login is not configured for this instance",
        )
            .into_response());
    }
    match name {
        Some(name) => state
            .config
            .oidc
            .by_name(name)
            .ok_or_else(|| (StatusCode::NOT_FOUND, "no such OIDC provider").into_response()),
        None => state.config.oidc.only().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "several OIDC providers are configured — use /api/auth/oauth/{provider}/login",
            )
                .into_response()
        }),
    }
}

/// Begins a fresh login attempt against the sole configured provider.
async fn start_login(State(state): State<AppState>, session: Session) -> Response {
    begin(&state, session, None, None).await
}

/// Begins a fresh login against a named provider.
async fn start_login_named(
    State(state): State<AppState>,
    session: Session,
    Path(provider): Path<String>,
) -> Response {
    begin(&state, session, Some(&provider), None).await
}

/// Begins a *link* attempt from an already-authenticated session — the
/// only path that may attach a new OAuth identity to an account whose
/// email already matches an existing password account (see
/// `oauth::link`'s doc comment). Refuses outright if the caller isn't
/// logged in.
async fn start_link(
    State(state): State<AppState>,
    session: Session,
    auth: AuthSession<Backend>,
) -> Response {
    match require_login(&auth) {
        Ok(user_id) => begin(&state, session, None, Some(user_id)).await,
        Err(resp) => resp,
    }
}

async fn start_link_named(
    State(state): State<AppState>,
    session: Session,
    auth: AuthSession<Backend>,
    Path(provider): Path<String>,
) -> Response {
    match require_login(&auth) {
        Ok(user_id) => begin(&state, session, Some(&provider), Some(user_id)).await,
        Err(resp) => resp,
    }
}

#[allow(clippy::result_large_err)]
fn require_login(auth: &AuthSession<Backend>) -> Result<String, Response> {
    auth.user
        .as_ref()
        .map(|u| u.user.id.to_string())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "log in before linking an external account",
            )
                .into_response()
        })
}

async fn begin(
    state: &AppState,
    session: Session,
    provider_name: Option<&str>,
    link_user_id: Option<String>,
) -> Response {
    let provider = match resolve_provider(state, provider_name) {
        Ok(provider) => provider,
        Err(response) => return response,
    };
    let request = match oauth::start(provider).await {
        Ok(request) => request,
        Err(err) => return (StatusCode::BAD_GATEWAY, err.to_string()).into_response(),
    };
    let pending = PendingOAuth {
        provider_name: provider.name.clone(),
        csrf_token: request.csrf_token,
        nonce: request.nonce,
        pkce_verifier: request.pkce_verifier,
        link_user_id,
    };
    if let Err(err) = session.insert(SESSION_KEY, pending).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }
    Redirect::to(&request.url).into_response()
}

#[derive(Deserialize)]
struct CallbackParams {
    code: String,
    state: String,
}

/// Best-effort OAuth audit logging, via the one audit path
/// (`crate::services::audit`, S11).
async fn record(pool: &edda_db::DbPool, event_type: &str, actor_id: &str) {
    crate::services::audit::record(
        pool,
        crate::services::audit::AuditEntry::new(event_type, actor_id),
    )
    .await;
}

/// Handles the provider's redirect back to Edda: verifies the CSRF state
/// matches what `begin` stashed, resolves the provider from the pending
/// blob, then hands the authorization code to `oauth::complete` (a
/// login) or `oauth::link` (an account link).
#[tracing::instrument(name = "authentication.oauth.callback", skip_all)]
async fn callback(
    State(state): State<AppState>,
    session: Session,
    mut auth: AuthSession<Backend>,
    Query(params): Query<CallbackParams>,
) -> Response {
    let pending: Option<PendingOAuth> = match session.get(SESSION_KEY).await {
        Ok(pending) => pending,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    let Some(pending) = pending else {
        return (
            StatusCode::BAD_REQUEST,
            "no OAuth login is pending for this session",
        )
            .into_response();
    };
    // Consumed on first use regardless of outcome below — a pending flow
    // is single-shot, and the callback endpoint must never be replayable.
    let _ = session.remove::<PendingOAuth>(SESSION_KEY).await;

    let provider = match resolve_provider(&state, Some(&pending.provider_name)) {
        Ok(provider) => provider.clone(),
        Err(response) => return response,
    };

    if params.state != pending.csrf_token {
        return (
            StatusCode::BAD_REQUEST,
            "OAuth state parameter did not match",
        )
            .into_response();
    }

    if let Some(link_user_id) = pending.link_user_id {
        let Ok(user_id) = link_user_id.parse::<edda_domain::UserId>() else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "corrupt pending link").into_response();
        };
        return match oauth::link(
            &state.pool,
            &provider,
            user_id,
            &params.code,
            pending.pkce_verifier,
            &pending.nonce,
        )
        .await
        {
            Ok(()) => {
                record(&state.pool, "auth.oauth.link", &user_id.to_string()).await;
                Redirect::to("/settings").into_response()
            }
            Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
        };
    }

    let outcome = match oauth::complete(
        &state.pool,
        &provider,
        &params.code,
        pending.pkce_verifier,
        &pending.nonce,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(err) => return (StatusCode::BAD_GATEWAY, err.to_string()).into_response(),
    };

    let user = match outcome {
        oauth::LoginOutcome::LoggedIn(user) | oauth::LoginOutcome::NewAccountCreated(user) => user,
        oauth::LoginOutcome::NewAccountPendingApproval(_) => {
            return (
                StatusCode::ACCEPTED,
                "your account was created and is awaiting administrator approval",
            )
                .into_response();
        }
        oauth::LoginOutcome::EmailBelongsToExistingAccount => {
            return (
                StatusCode::CONFLICT,
                "an account with that email already exists — log in with your password, then \
                 link this provider from settings",
            )
                .into_response();
        }
        oauth::LoginOutcome::ProvisioningNotAllowed => {
            return (
                StatusCode::FORBIDDEN,
                "this provider does not create new accounts — ask an administrator for one, then \
                 link the provider from settings",
            )
                .into_response();
        }
        oauth::LoginOutcome::EmailDomainNotAllowed => {
            return (
                StatusCode::FORBIDDEN,
                "your email domain is not permitted for this sign-in provider",
            )
                .into_response();
        }
    };

    if edda_auth::require_enabled(&user).is_err() {
        return (StatusCode::UNAUTHORIZED, "this account has been disabled").into_response();
    }

    let Ok(Some(session_user)) = state.backend.get_user(&user.id.to_string()).await else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not resolve the session identity",
        )
            .into_response();
    };
    if let Err(err) = auth.login(&session_user).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }
    crate::auth_routes::stamp_session_login(&auth).await;
    record(&state.pool, "auth.login.success", &user.id.to_string()).await;
    Redirect::to("/").into_response()
}

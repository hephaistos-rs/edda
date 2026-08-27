//! HTTP surface for OAuth2/OIDC consumer login — the routes that drive
//! `edda_auth::oauth`'s `start`/`complete`/`link` through an actual
//! browser redirect round-trip. Nothing here decides *policy* (account
//! linking, email matching); that is all `edda_auth::oauth`'s job — this
//! module only shuttles the browser to and from the configured identity
//! provider and stashes the CSRF/nonce/PKCE values in between.
//!
//! The three values `start` returns (csrf token, nonce, PKCE verifier)
//! have to survive the redirect to the provider and back, so they're
//! stashed in the pre-login session via `tower_sessions::Session` — the
//! same session machinery `axum_login` itself rides on, just used here
//! before a login exists rather than after.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use axum_login::{AuthSession, AuthnBackend};
use serde::Deserialize;
use tower_sessions::Session;

use edda_auth::{oauth, Backend};

use crate::state::AppState;

const SESSION_KEY: &str = "oauth_pending";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PendingOAuth {
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
        .route("/api/auth/oauth/login", get(start_login))
        .route("/api/auth/oauth/link", get(start_link))
        .route("/api/auth/oauth/callback", get(callback))
}

/// Lets the UI decide whether to render an "sign in with SSO"/"link
/// external account" affordance at all — this instance's OIDC
/// configuration is server-side, so the client has no other way to know
/// whether `/api/auth/oauth/login` would even work.
async fn enabled(State(state): State<AppState>) -> Response {
    axum::Json(state.config.oidc.is_some()).into_response()
}

/// This instance's OIDC config, or a 404 when it isn't configured (the
/// `EDDA_OAUTH_*` set unset). Resolved once at startup by
/// `edda_http::config` and carried in `AppState`.
// `Err` is a ready-to-return axum `Response` (the "value or a 404" helper
// pattern) — intentionally, not an error to bubble up a deep call stack.
#[allow(clippy::result_large_err)]
fn config_or_404(state: &AppState) -> Result<oauth::Config, Response> {
    state.config.oidc.clone().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "OAuth login is not configured for this instance",
        )
            .into_response()
    })
}

/// Begins a fresh login attempt: redirects the browser to the configured
/// provider's consent screen.
async fn start_login(State(state): State<AppState>, session: Session) -> Response {
    begin(&state, session, None).await
}

/// Begins a *link* attempt from an already-authenticated session — the
/// only path that may attach a new OAuth identity to an account whose
/// email already matches an existing password account (see
/// `oauth::link`'s doc comment). Refuses outright if the caller isn't
/// logged in; there is nothing useful to link a floating identity to.
async fn start_link(
    State(state): State<AppState>,
    session: Session,
    auth: AuthSession<Backend>,
) -> Response {
    let Some(session_user) = auth.user else {
        return (
            StatusCode::UNAUTHORIZED,
            "log in before linking an external account",
        )
            .into_response();
    };
    begin(&state, session, Some(session_user.user.id.to_string())).await
}

async fn begin(state: &AppState, session: Session, link_user_id: Option<String>) -> Response {
    let config = match config_or_404(state) {
        Ok(config) => config,
        Err(response) => return response,
    };
    let request = match oauth::start(&config).await {
        Ok(request) => request,
        Err(err) => return (StatusCode::BAD_GATEWAY, err.to_string()).into_response(),
    };
    let pending = PendingOAuth {
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

/// Best-effort audit logging — see `admin_routes::record`'s identical
/// reasoning for why a logging failure must never fail the action it
/// describes.
async fn record(pool: &edda_db::DbPool, event_type: &str, actor_id: &str) {
    let _ = edda_db::AuditEventRepo::insert(
        pool,
        edda_domain::AuditEventId::new(),
        event_type,
        Some(actor_id),
        None,
        None,
        None,
    )
    .await;
}

/// Handles the provider's redirect back to Edda: verifies the CSRF state
/// matches what `begin` stashed, then hands the authorization code to
/// `oauth::complete` (a login) or `oauth::link` (an account link),
/// depending on which one `begin` recorded as pending.
#[tracing::instrument(name = "authentication.oauth.callback", skip_all)]
async fn callback(
    State(state): State<AppState>,
    session: Session,
    mut auth: AuthSession<Backend>,
    Query(params): Query<CallbackParams>,
) -> Response {
    let config = match config_or_404(&state) {
        Ok(config) => config,
        Err(response) => return response,
    };

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
            &config,
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
        &config,
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
        oauth::LoginOutcome::LoggedIn(user) => user,
        oauth::LoginOutcome::NewAccountCreated(user) => user,
        oauth::LoginOutcome::EmailBelongsToExistingAccount => {
            return (
                StatusCode::CONFLICT,
                "an account with that email already exists — log in with your password, then \
                 link this provider from settings",
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
    record(&state.pool, "auth.login.success", &user.id.to_string()).await;
    Redirect::to("/").into_response()
}

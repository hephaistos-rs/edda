//! HTTP surface for WebAuthn/passkey registration and authentication —
//! the browser-facing routes that drive `edda_auth::webauthn`'s
//! `begin_registration`/`finish_registration`/`begin_authentication`/
//! `finish_authentication` through an actual `navigator.credentials`
//! round trip. Nothing here decides ceremony *policy* (challenge/origin/
//! signature verification); that is all `edda_auth::webauthn`'s job —
//! this module only shuttles JSON between the client and that module and
//! completes the session on a successful authentication, the same split
//! `oauth_routes` has with `edda_auth::oauth`.
//!
//! Registration is only ever offered to an already-authenticated caller
//! (an account adds its own passkey from settings). Authentication is
//! only ever offered as an *alternative second factor* to TOTP, gated
//! behind the same `pending_login` token `login_totp` uses — this
//! instance never does discoverable/usernameless WebAuthn login, so
//! `login_options`/`login_verify` both require a password-verified
//! identity already established via `/api/auth/login`.

use axum::extract::{Json, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_login::{AuthSession, AuthnBackend};
use serde::{Deserialize, Serialize};

use edda_auth::webauthn::{
    self, AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, PublicKeyCredential,
    WebauthnError,
};
use edda_auth::Backend;

use crate::auth_routes::{record, CurrentUserDto};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/auth/webauthn/enabled", get(enabled))
        .route(
            "/api/auth/webauthn/register/options",
            post(register_options),
        )
        .route("/api/auth/webauthn/register/verify", post(register_verify))
        .route("/api/auth/webauthn/login/options", post(login_options))
        .route("/api/auth/webauthn/login/verify", post(login_verify))
        .route("/api/auth/webauthn/credentials", get(list_credentials))
        .route(
            "/api/auth/webauthn/credentials/{id}/revoke",
            post(revoke_credential),
        )
}

async fn enabled() -> Response {
    axum::Json(webauthn::Config::from_env().is_some()).into_response()
}

async fn config_or_404() -> Result<webauthn::Config, Response> {
    webauthn::Config::from_env().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "WebAuthn is not configured for this instance",
        )
            .into_response()
    })
}

fn webauthn_error_response(err: WebauthnError) -> Response {
    let status = match err {
        WebauthnError::CeremonyExpired => StatusCode::UNAUTHORIZED,
        WebauthnError::NoCredentials => StatusCode::NOT_FOUND,
        WebauthnError::InvalidResponse => StatusCode::BAD_REQUEST,
        WebauthnError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, err.to_string()).into_response()
}

#[derive(Serialize)]
struct CeremonyOptionsDto<T: Serialize> {
    options: T,
    state_token: String,
}

/// Starts registering a new passkey for the caller's own, already-
/// authenticated account.
async fn register_options(State(state): State<AppState>, auth: AuthSession<Backend>) -> Response {
    let Some(session_user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let config = match config_or_404().await {
        Ok(config) => config,
        Err(response) => return response,
    };
    match webauthn::begin_registration(
        &state.pool,
        &config,
        session_user.user.id,
        &session_user.user.username,
        &session_user.user.username,
    )
    .await
    {
        Ok((options, state_token)) => Json(CeremonyOptionsDto {
            options,
            state_token,
        })
        .into_response(),
        Err(err) => webauthn_error_response(err),
    }
}

#[derive(Deserialize)]
struct RegisterVerifyBody {
    state_token: String,
    label: String,
    credential: PublicKeyCredential<AuthenticatorAttestationResponse>,
}

async fn register_verify(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Json(body): Json<RegisterVerifyBody>,
) -> Response {
    let Some(session_user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let config = match config_or_404().await {
        Ok(config) => config,
        Err(response) => return response,
    };
    match webauthn::finish_registration(
        &state.pool,
        &config,
        &body.state_token,
        session_user.user.id,
        &body.label,
        body.credential,
    )
    .await
    {
        Ok(()) => {
            record(
                &state.pool,
                "auth.webauthn.register",
                &session_user.user.id.to_string(),
            )
            .await;
            StatusCode::OK.into_response()
        }
        Err(err) => webauthn_error_response(err),
    }
}

#[derive(Deserialize)]
struct LoginOptionsBody {
    pending_login_token: String,
}

/// Offers a passkey as an alternative to a TOTP code for the second step
/// of a login already in progress (see `auth_routes::login`). Returns 404
/// if the account has no registered passkey — same "no error, just
/// nothing to offer" shape as `begin_authentication` itself — so the
/// client can silently fall back to the TOTP-only form.
async fn login_options(
    State(state): State<AppState>,
    Json(body): Json<LoginOptionsBody>,
) -> Response {
    let Some(user_id) = edda_auth::pending_login::verify(&body.pending_login_token)
        .and_then(|id| id.parse::<edda_domain::UserId>().ok())
    else {
        return (StatusCode::UNAUTHORIZED, "that login attempt has expired").into_response();
    };
    let config = match config_or_404().await {
        Ok(config) => config,
        Err(response) => return response,
    };
    match webauthn::begin_authentication(&state.pool, &config, user_id).await {
        Ok(Some((options, state_token))) => Json(CeremonyOptionsDto {
            options,
            state_token,
        })
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            "no passkey is registered for this account",
        )
            .into_response(),
        Err(err) => webauthn_error_response(err),
    }
}

#[derive(Deserialize)]
struct LoginVerifyBody {
    pending_login_token: String,
    state_token: String,
    credential: PublicKeyCredential<AuthenticatorAssertionResponse>,
}

/// Completes a login with a passkey in place of a TOTP code — the
/// WebAuthn-specific twin of `auth_routes::login_totp`. Both the
/// `pending_login_token` (password already verified) and the WebAuthn
/// `state_token` (this specific challenge was issued to this specific
/// user for an authentication ceremony) must agree on the same account;
/// disagreement is treated identically to either one alone being invalid.
#[tracing::instrument(name = "authentication.webauthn.login", skip_all)]
async fn login_verify(
    State(state): State<AppState>,
    mut auth: AuthSession<Backend>,
    Json(body): Json<LoginVerifyBody>,
) -> Response {
    let Some(user_id) = edda_auth::pending_login::verify(&body.pending_login_token)
        .and_then(|id| id.parse::<edda_domain::UserId>().ok())
    else {
        return (StatusCode::UNAUTHORIZED, "that login attempt has expired").into_response();
    };

    let Some(row) = (match edda_db::UserRepo::find_by_id(&state.pool, user_id).await {
        Ok(row) => row,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }) else {
        return (StatusCode::UNAUTHORIZED, "that login attempt has expired").into_response();
    };
    if edda_auth::require_enabled(&row.user).is_err() {
        return (StatusCode::UNAUTHORIZED, "that login attempt has expired").into_response();
    }

    let config = match config_or_404().await {
        Ok(config) => config,
        Err(response) => return response,
    };
    if let Err(err) = webauthn::finish_authentication(
        &state.pool,
        &config,
        &body.state_token,
        user_id,
        body.credential,
    )
    .await
    {
        return webauthn_error_response(err);
    }

    let Ok(Some(session_user)) = state.backend.get_user(&user_id.to_string()).await else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not resolve the session identity",
        )
            .into_response();
    };
    if let Err(err) = auth.login(&session_user).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }
    record(&state.pool, "auth.login.success", &user_id.to_string()).await;
    Json(CurrentUserDto::from(row.user)).into_response()
}

#[derive(Serialize)]
struct WebauthnCredentialDto {
    id: String,
    label: String,
    created_at: i64,
    last_used_at: Option<i64>,
}

impl From<edda_db::webauthn_repo::WebauthnCredentialRow> for WebauthnCredentialDto {
    fn from(row: edda_db::webauthn_repo::WebauthnCredentialRow) -> Self {
        Self {
            id: row.id.to_string(),
            label: row.label,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
        }
    }
}

async fn list_credentials(State(state): State<AppState>, auth: AuthSession<Backend>) -> Response {
    let Some(session_user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match webauthn::list(&state.pool, session_user.user.id).await {
        Ok(creds) => Json(
            creds
                .into_iter()
                .map(WebauthnCredentialDto::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

async fn revoke_credential(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path(id): Path<String>,
) -> Response {
    let Some(session_user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(credential_id) = id.parse() else {
        return (StatusCode::NOT_FOUND, "no such passkey").into_response();
    };
    match webauthn::revoke(&state.pool, session_user.user.id, credential_id).await {
        Ok(true) => {
            record(
                &state.pool,
                "auth.webauthn.revoke",
                &session_user.user.id.to_string(),
            )
            .await;
            StatusCode::OK.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "no such passkey").into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

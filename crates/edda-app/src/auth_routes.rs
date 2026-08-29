//! Raw axum routes for signup/login/logout/whoami/tokens — not Dioxus
//! server functions. `axum_login::AuthSession` is a real axum
//! `FromRequestParts` extractor, but Dioxus's `#[server]`/`#[post]`
//! macros only special-case a fixed allowlist of extractor types; anything
//! outside that list gets treated as a regular JSON body argument instead,
//! which fails since `AuthSession` isn't `Deserialize`. Plain axum has no
//! such restriction, so these routes live here.

use axum::extract::{Json, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_login::{AuthSession, AuthnBackend};
use serde::{Deserialize, Serialize};

use edda_auth::{Backend, Credentials as AuthCredentials};

use crate::state::AppState;

/// Best-effort audit logging — now a thin shim over the one audit path
/// (`crate::services::audit`, S11). `pub(crate)`: `webauthn_routes` /
/// `oauth_routes` complete a login the same way `login`/`login_totp` here
/// do, and share this rather than duplicating it.
pub(crate) async fn record(pool: &edda_db::DbPool, event_type: &str, actor_id: &str) {
    crate::services::audit::record(
        pool,
        crate::services::audit::AuditEntry::new(event_type, actor_id),
    )
    .await;
}

/// The session key holding the unix time the current session was
/// established — read in the actor-resolution path to enforce the absolute
/// session TTL (S10).
pub(crate) const SESSION_LOGIN_AT: &str = "login_at";

/// Records "this session started now" — call right after every successful
/// `auth.login(...)`.
pub(crate) async fn stamp_session_login(auth: &AuthSession<Backend>) {
    let _ = auth
        .session
        .insert(SESSION_LOGIN_AT, crate::services::now_unix())
        .await;
}

/// Whether a session established at `login_at` has passed the absolute TTL
/// (`EDDA_SESSION_ABSOLUTE_TTL_SECONDS`). A session with no stamp predates
/// the feature and is treated as fresh, so a deploy doesn't kick everyone.
pub(crate) fn session_login_expired(login_at: Option<i64>, absolute_ttl_secs: i64) -> bool {
    match login_at {
        Some(at) => crate::services::now_unix().saturating_sub(at) > absolute_ttl_secs,
        None => false,
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/auth/signup", post(signup))
        .route("/api/auth/login", post(login))
        .route("/api/auth/login/totp", post(login_totp))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/me", get(me))
        .route("/api/auth/tokens", post(create_token).get(list_tokens))
        .route("/api/auth/tokens/{id}/revoke", post(revoke_token))
        .route("/api/auth/totp/enroll", post(totp_enroll))
        .route("/api/auth/totp/activate", post(totp_activate))
        .route("/api/auth/totp/disable", post(totp_disable))
        .route(
            "/api/auth/password-reset/request",
            post(request_password_reset),
        )
        .route(
            "/api/auth/password-reset/consume",
            post(consume_password_reset),
        )
}

/// Same `X-Forwarded-Proto`/`Host`-based reconstruction `edda_app::lfs`'s
/// own `base_url` uses — kept as a separate small copy here rather than a
/// shared helper: each call site's needs are trivial enough that a shared
/// abstraction would cost more (an extra module boundary to look through)
/// than it saves.
fn base_url(headers: &HeaderMap) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("http");
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost");
    format!("{scheme}://{host}")
}

#[derive(Deserialize)]
struct RequestPasswordResetBody {
    email: String,
}

/// Always responds `200` regardless of whether `email` matched a real
/// account — the same information-hiding discipline this workspace
/// already applies to private-repo existence (`AuthzError::NotFound`).
/// An email is only actually enqueued when a real, enabled account
/// matched.
#[tracing::instrument(name = "authentication.password_reset.request", skip_all)]
async fn request_password_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RequestPasswordResetBody>,
) -> Response {
    let outcome = edda_auth::password_reset::request(&state.pool, &body.email).await;
    match outcome {
        Ok(Some((user, raw_token))) => {
            let reset_link = format!("{}/reset-password?token={raw_token}", base_url(&headers));
            let subject = "Reset your Edda password".to_string();
            let body_text = format!(
                "Someone (hopefully you) requested a password reset for your Edda account.\n\n\
                 Reset your password: {reset_link}\n\n\
                 This link expires in one hour. If you didn't request this, you can ignore this email."
            );
            let _ = edda_jobs::enqueue(
                &state.pool,
                edda_domain::JobPayload::SendEmail {
                    to_email: user.email,
                    subject,
                    body_text,
                },
            )
            .await;
        }
        Ok(None) => {}
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
    StatusCode::OK.into_response()
}

#[derive(Deserialize)]
struct ConsumePasswordResetBody {
    token: String,
    new_password: String,
}

#[tracing::instrument(name = "authentication.password_reset.consume", skip_all)]
async fn consume_password_reset(
    State(state): State<AppState>,
    Json(body): Json<ConsumePasswordResetBody>,
) -> Response {
    match edda_auth::password_reset::consume(&state.pool, &body.token, &body.new_password).await {
        Ok(user_id) => {
            record(
                &state.pool,
                "auth.password_reset.consume",
                &user_id.to_string(),
            )
            .await;
            StatusCode::OK.into_response()
        }
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

/// The over-the-wire shape of a logged-in identity. Deliberately its own
/// type, not a re-export of `edda_domain::User` — `edda-app` is a
/// server-only crate, so anything it exposes has to be independently
/// mirrored by `edda-web`'s wasm-compiled client code anyway; keeping a
/// dedicated DTO at the crate boundary (not just the public HTTP API)
/// avoids leaking domain types into the wasm build.
/// `pub(crate)`: `webauthn_routes::login_verify` returns the same shape
/// after completing a login via a passkey instead of a password+TOTP
/// pair — see `record`'s identical reasoning for sharing rather than
/// duplicating.
#[derive(Debug, Serialize)]
pub(crate) struct CurrentUserDto {
    id: String,
    username: String,
    email: String,
    is_admin: bool,
}

impl From<edda_domain::User> for CurrentUserDto {
    fn from(user: edda_domain::User) -> Self {
        Self {
            id: user.id.to_string(),
            username: user.username,
            email: user.email,
            is_admin: user.is_admin,
        }
    }
}

#[derive(Deserialize)]
struct LoginBody {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct SignupBody {
    username: String,
    email: String,
    password: String,
}

async fn signup(
    State(state): State<AppState>,
    mut auth: AuthSession<Backend>,
    Json(body): Json<SignupBody>,
) -> Response {
    let user =
        match edda_auth::signup(&state.pool, &body.username, &body.email, &body.password).await {
            Ok(user) => user,
            Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
        };

    // Newly created — the account has no repositories yet, so there is no
    // owner grant to seed here.
    let session_user = match state.backend.get_user(&user.id.to_string()).await {
        Ok(Some(session_user)) => session_user,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "account created but could not start a session",
            )
                .into_response()
        }
    };
    if let Err(err) = auth.login(&session_user).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }
    crate::auth_routes::stamp_session_login(&auth).await;

    Json(CurrentUserDto::from(user)).into_response()
}

/// Either a completed login or a "you still need a second factor"
/// challenge — the client tells the two apart by which field is present.
#[derive(Serialize)]
#[serde(untagged)]
enum LoginResponse {
    LoggedIn(CurrentUserDto),
    NeedsTotp { pending_login_token: String },
}

// `skip_all`: `creds` carries a raw password — never a span field.
#[tracing::instrument(name = "authentication.login", skip_all)]
async fn login(
    State(state): State<AppState>,
    mut auth: AuthSession<Backend>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> Response {
    let email = body.email.clone();
    let client_ip = crate::rate_limit::client_ip(&headers)
        .map(|ip| ip.to_string())
        .unwrap_or_default();

    // Brute-force throttle (S4): a locked (account, IP) or a locked
    // account-wide counter refuses the attempt before the password is even
    // checked.
    match edda_auth::login_throttle::check(&state.pool, &email, &client_ip).await {
        Ok(()) => {}
        Err(edda_auth::login_throttle::ThrottleError::LockedOut {
            retry_after_seconds,
        }) => {
            record(&state.pool, "auth.login.throttled", &email).await;
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(
                    axum::http::header::RETRY_AFTER,
                    retry_after_seconds.to_string(),
                )],
                "too many failed sign-in attempts — try again later",
            )
                .into_response();
        }
        Err(err) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
        }
    }

    let creds = AuthCredentials {
        email: body.email,
        password: body.password,
    };

    // `Backend::authenticate` already refuses a disabled account here
    // (returns `Ok(None)`, indistinguishable from a wrong password) — see
    // that function's own doc comment. Nothing extra is needed for that
    // case at this layer.
    let session_user = match auth.authenticate(creds).await {
        Ok(Some(session_user)) => session_user,
        Ok(None) => {
            let _ =
                edda_auth::login_throttle::record_failure(&state.pool, &email, &client_ip).await;
            return (
                StatusCode::UNAUTHORIZED,
                "that email or password isn't right",
            )
                .into_response();
        }
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

    // The password was correct — clear the throttle now, even if a second
    // factor is still pending (2FA guessing is bounded by TOTP's own
    // window and the auth-endpoint rate limiter, not this counter).
    let _ = edda_auth::login_throttle::record_success(&state.pool, &email, &client_ip).await;

    let user = session_user.user.clone();

    // Password verified — but if this account has an *activated* TOTP
    // credential, or at least one registered WebAuthn credential, the
    // session isn't established yet. A pending-login token (short-lived,
    // HMAC-signed, scoped to this one user) stands in for "password
    // already verified" until a second request presents a valid TOTP/
    // recovery code to `/api/auth/login/totp` or a valid passkey
    // assertion to `/api/auth/webauthn/login/verify`. See
    // `edda_auth::totp`'s and `edda_auth::pending_login`'s own doc
    // comments for the full reasoning — `axum_login::AuthnBackend::
    // authenticate` has no room for this intermediate state, so it has to
    // live at this route level instead of inside `authenticate` itself.
    // Checking WebAuthn here (not just TOTP) matters: without it, an
    // account with *only* a passkey registered — no TOTP — would skip a
    // second factor entirely, since `authenticate` already established
    // the password was correct and nothing downstream would ever ask for
    // more.
    let auth_backend = auth.backend.clone();
    let pool = auth_backend.pool();
    let has_totp = edda_auth::totp::is_activated(pool, user.id)
        .await
        .unwrap_or(false);
    let has_webauthn = !edda_auth::webauthn::list(pool, user.id)
        .await
        .unwrap_or_default()
        .is_empty();
    if has_totp || has_webauthn {
        let pending_login_token = edda_auth::pending_login::issue(&user.id.to_string());
        return Json(LoginResponse::NeedsTotp {
            pending_login_token,
        })
        .into_response();
    }

    if let Err(err) = auth.login(&session_user).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }
    crate::auth_routes::stamp_session_login(&auth).await;
    record(pool, "auth.login.success", &user.id.to_string()).await;

    Json(LoginResponse::LoggedIn(CurrentUserDto::from(user))).into_response()
}

#[derive(Deserialize)]
struct LoginTotpBody {
    pending_login_token: String,
    code: String,
}

/// Completes a login that `login` deferred for a second factor: verifies
/// the pending-login token plus a TOTP/recovery code, then — only on
/// success — actually establishes the session.
#[tracing::instrument(name = "authentication.login.totp", skip_all)]
async fn login_totp(
    State(state): State<AppState>,
    mut auth: AuthSession<Backend>,
    Json(body): Json<LoginTotpBody>,
) -> Response {
    let Some(user_id_str) = edda_auth::pending_login::verify(&body.pending_login_token) else {
        return (StatusCode::UNAUTHORIZED, "that login attempt has expired").into_response();
    };
    let Ok(user_id) = user_id_str.parse::<edda_domain::UserId>() else {
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

    match edda_auth::totp::verify(&state.pool, user_id, &row.user.email, &body.code).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::UNAUTHORIZED, "that code was incorrect").into_response(),
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
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
    crate::auth_routes::stamp_session_login(&auth).await;
    record(&state.pool, "auth.login.success", &user_id.to_string()).await;
    Json(CurrentUserDto::from(row.user)).into_response()
}

async fn logout(mut auth: AuthSession<Backend>) -> Response {
    match auth.logout().await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

async fn me(auth: AuthSession<Backend>) -> Response {
    Json(
        auth.user
            .map(|session_user| CurrentUserDto::from(session_user.user)),
    )
    .into_response()
}

#[derive(Deserialize)]
struct CreateTokenBody {
    name: String,
    /// `"read"` → a `repo:read` token (clone/fetch + GET `/api/v1`),
    /// `"write"` → also push + mutating `/api/v1`. Omitted → a fully
    /// unscoped token (every operation), the historical default.
    #[serde(default)]
    scope: Option<String>,
}

fn parse_token_scope(raw: Option<&str>) -> Result<edda_domain::TokenScope, &'static str> {
    match raw.map(str::trim).unwrap_or("") {
        "" | "all" => Ok(edda_domain::TokenScope::All),
        "read" => Ok(edda_domain::TokenScope::RepoRead),
        "write" => Ok(edda_domain::TokenScope::RepoWrite),
        _ => Err("scope must be one of: read, write, all"),
    }
}

fn token_scope_label(scope: edda_domain::TokenScope) -> &'static str {
    match scope {
        edda_domain::TokenScope::All => "all",
        edda_domain::TokenScope::RepoRead => "read",
        edda_domain::TokenScope::RepoWrite => "write",
    }
}

#[derive(Serialize)]
struct CreatedTokenDto {
    id: String,
    name: String,
    token: String,
    scope: &'static str,
    created_at: i64,
}

#[derive(Serialize)]
struct TokenInfoDto {
    id: String,
    name: String,
    scope: &'static str,
    created_at: i64,
    last_used_at: Option<i64>,
}

impl From<edda_domain::AccessToken> for TokenInfoDto {
    fn from(token: edda_domain::AccessToken) -> Self {
        Self {
            id: token.id.to_string(),
            name: token.name,
            scope: token_scope_label(token.token_scope),
            created_at: token.created_at,
            last_used_at: token.last_used_at,
        }
    }
}

// `body.name` is a user-chosen label for the token (like a device name),
// not the token secret itself — the generated token value is never
// captured anywhere in telemetry.
#[tracing::instrument(name = "authentication.token.create", skip_all, fields(token.name = %body.name))]
async fn create_token(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Json(body): Json<CreateTokenBody>,
) -> Response {
    let Some(session_user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let scope = match parse_token_scope(body.scope.as_deref()) {
        Ok(scope) => scope,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    match edda_auth::tokens::create_scoped(&state.pool, session_user.user.id, &body.name, scope)
        .await
    {
        Ok((raw, token)) => {
            record(
                &state.pool,
                "auth.token.create",
                &session_user.user.id.to_string(),
            )
            .await;
            Json(CreatedTokenDto {
                id: token.id.to_string(),
                name: token.name,
                token: raw,
                scope: token_scope_label(token.token_scope),
                created_at: token.created_at,
            })
            .into_response()
        }
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn list_tokens(State(state): State<AppState>, auth: AuthSession<Backend>) -> Response {
    let Some(session_user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match edda_auth::tokens::list(&state.pool, session_user.user.id).await {
        Ok(tokens) => Json(
            tokens
                .into_iter()
                .map(TokenInfoDto::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

async fn revoke_token(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path(id): Path<String>,
) -> Response {
    let Some(session_user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(token_id) = id.parse() else {
        return (StatusCode::NOT_FOUND, "no such token").into_response();
    };
    match edda_auth::tokens::revoke(&state.pool, session_user.user.id, token_id).await {
        Ok(true) => {
            record(
                &state.pool,
                "auth.token.revoke",
                &session_user.user.id.to_string(),
            )
            .await;
            StatusCode::OK.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "no such token").into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

#[derive(Serialize)]
struct TotpEnrollDto {
    secret_base32: String,
    otpauth_uri: String,
}

/// Starts (or restarts) 2FA enrollment for the caller's own account. Does
/// not gate login until `totp_activate` succeeds with a real code.
async fn totp_enroll(State(state): State<AppState>, auth: AuthSession<Backend>) -> Response {
    let Some(session_user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match edda_auth::totp::enroll(&state.pool, session_user.user.id, &session_user.user.email).await
    {
        Ok((secret_base32, otpauth_uri)) => Json(TotpEnrollDto {
            secret_base32,
            otpauth_uri,
        })
        .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct TotpActivateBody {
    code: String,
}

/// Recovery codes are returned here, once — see `edda_auth::totp::
/// activate`'s own "shown once" doc comment for why nothing about this
/// response is retrievable again afterward.
#[derive(Serialize)]
struct TotpActivateDto {
    recovery_codes: Vec<String>,
}

#[tracing::instrument(name = "authentication.totp.activate", skip_all)]
async fn totp_activate(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Json(body): Json<TotpActivateBody>,
) -> Response {
    let Some(session_user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match edda_auth::totp::activate(
        &state.pool,
        session_user.user.id,
        &session_user.user.email,
        &body.code,
    )
    .await
    {
        Ok(recovery_codes) => Json(TotpActivateDto { recovery_codes }).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

#[tracing::instrument(name = "authentication.totp.disable", skip_all)]
async fn totp_disable(State(state): State<AppState>, auth: AuthSession<Backend>) -> Response {
    let Some(session_user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match edda_auth::totp::disable(&state.pool, session_user.user.id).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

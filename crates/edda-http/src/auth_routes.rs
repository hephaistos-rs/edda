//! Raw axum routes for signup/login/logout/whoami/tokens — not Dioxus
//! server functions. `axum_login::AuthSession` is a real axum
//! `FromRequestParts` extractor, but Dioxus's `#[server]`/`#[post]`
//! macros only special-case a fixed allowlist of extractor types; anything
//! outside that list gets treated as a regular JSON body argument instead,
//! which fails since `AuthSession` isn't `Deserialize`. Plain axum has no
//! such restriction, so these routes live here.

use axum::extract::{Json, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_login::{AuthSession, AuthnBackend};
use serde::{Deserialize, Serialize};

use edda_auth::{Backend, Credentials as AuthCredentials};

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/auth/signup", post(signup))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/me", get(me))
        .route("/api/auth/tokens", post(create_token).get(list_tokens))
        .route("/api/auth/tokens/{id}/revoke", post(revoke_token))
}

/// The over-the-wire shape of a logged-in identity. Deliberately its own
/// type, not a re-export of `edda_domain::User` — `edda-http` is a
/// server-only crate, so anything it exposes has to be independently
/// mirrored by `edda-web`'s wasm-compiled client code anyway (see
/// plan.local.md §10.2's DTO-boundary discussion, applied here at the
/// crate boundary rather than only at the public-API boundary).
#[derive(Debug, Serialize)]
struct CurrentUserDto {
    id: String,
    username: String,
    email: String,
}

impl From<edda_domain::User> for CurrentUserDto {
    fn from(user: edda_domain::User) -> Self {
        Self {
            id: user.id.to_string(),
            username: user.username,
            email: user.email,
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
    // owner grant to seed here (unlike the pre-restructuring flow, which
    // conflated "create an account" with "grant repo ownership" only at
    // repo-creation time too; this call site never needed one).
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

    Json(CurrentUserDto::from(user)).into_response()
}

// `skip_all`: `creds` carries a raw password — never a span field.
#[tracing::instrument(name = "authentication.login", skip_all)]
async fn login(mut auth: AuthSession<Backend>, Json(creds): Json<LoginBody>) -> Response {
    let creds = AuthCredentials {
        email: creds.email,
        password: creds.password,
    };

    let session_user = match auth.authenticate(creds).await {
        Ok(Some(session_user)) => session_user,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                "that email or password isn't right",
            )
                .into_response()
        }
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

    let user = session_user.user.clone();
    if let Err(err) = auth.login(&session_user).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }

    Json(CurrentUserDto::from(user)).into_response()
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
}

#[derive(Serialize)]
struct CreatedTokenDto {
    id: String,
    name: String,
    token: String,
    created_at: i64,
}

#[derive(Serialize)]
struct TokenInfoDto {
    id: String,
    name: String,
    created_at: i64,
    last_used_at: Option<i64>,
}

impl From<edda_domain::AccessToken> for TokenInfoDto {
    fn from(token: edda_domain::AccessToken) -> Self {
        Self {
            id: token.id.to_string(),
            name: token.name,
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
    match edda_auth::tokens::create(&state.pool, session_user.user.id, &body.name).await {
        Ok((raw, token)) => Json(CreatedTokenDto {
            id: token.id.to_string(),
            name: token.name,
            token: raw,
            created_at: token.created_at,
        })
        .into_response(),
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
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such token").into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

//! Raw axum routes for signup/login/logout/whoami — not Dioxus server
//! functions. `axum_login::AuthSession` is a real axum `FromRequestParts`
//! extractor, but Dioxus's `#[server]`/`#[post]` macros only special-case a
//! fixed allowlist of extractor types (headers, cookies); anything outside
//! that list gets treated as a regular JSON body argument instead, which
//! fails since `AuthSession` isn't `Deserialize`. Plain axum has no such
//! restriction, so login/signup/logout/whoami live here instead.

use axum::extract::{Json, Path};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_login::AuthSession;
use serde::Deserialize;

use crate::auth::{tokens, Backend};
use crate::server::CurrentUser;

pub fn routes() -> Router {
    Router::new()
        .route("/api/auth/signup", post(signup))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/me", get(me))
        .route("/api/auth/tokens", post(create_token).get(list_tokens))
        .route("/api/auth/tokens/{id}/revoke", post(revoke_token))
}

#[derive(Deserialize)]
struct Credentials {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct SignupBody {
    username: String,
    email: String,
    password: String,
}

async fn signup(mut auth: AuthSession<Backend>, Json(body): Json<SignupBody>) -> Response {
    let pool = match crate::db::pool().await {
        Ok(pool) => pool,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

    let user = match crate::auth::signup(&pool, &body.username, &body.email, &body.password).await {
        Ok(user) => user,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };

    if let Err(err) = auth.login(&user).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }

    Json(CurrentUser::from(user)).into_response()
}

// `skip_all`: `creds` carries a raw password — never a span field.
#[tracing::instrument(name = "authentication.login", skip_all)]
async fn login(mut auth: AuthSession<Backend>, Json(creds): Json<Credentials>) -> Response {
    let creds = crate::auth::Credentials { email: creds.email, password: creds.password };

    let user = match auth.authenticate(creds).await {
        Ok(Some(user)) => user,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "that email or password isn't right").into_response(),
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

    if let Err(err) = auth.login(&user).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }

    Json(CurrentUser::from(user)).into_response()
}

async fn logout(mut auth: AuthSession<Backend>) -> Response {
    match auth.logout().await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

async fn me(auth: AuthSession<Backend>) -> Response {
    Json(auth.user.map(CurrentUser::from)).into_response()
}

#[derive(Deserialize)]
struct CreateTokenBody {
    name: String,
}

#[derive(serde::Serialize)]
struct CreatedToken {
    id: String,
    name: String,
    token: String,
    created_at: i64,
}

// `body.name` is a user-chosen label for the token (like a device name), not
// the token secret itself — the generated token value is never captured
// anywhere in telemetry.
#[tracing::instrument(name = "authentication.token.create", skip_all, fields(token.name = %body.name))]
async fn create_token(auth: AuthSession<Backend>, Json(body): Json<CreateTokenBody>) -> Response {
    let Some(user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match tokens::create(&auth.backend.pool, &user.id, &body.name).await {
        Ok((raw, info)) => {
            Json(CreatedToken { id: info.id, name: info.name, token: raw, created_at: info.created_at }).into_response()
        }
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn list_tokens(auth: AuthSession<Backend>) -> Response {
    let Some(user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match tokens::list(&auth.backend.pool, &user.id).await {
        Ok(tokens) => Json(tokens).into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

async fn revoke_token(auth: AuthSession<Backend>, Path(id): Path<String>) -> Response {
    let Some(user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match tokens::revoke(&auth.backend.pool, &user.id, &id).await {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such token").into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

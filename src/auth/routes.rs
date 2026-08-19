//! Raw axum routes for signup/login/logout/whoami — not Dioxus server
//! functions. `axum_login::AuthSession` is a real axum `FromRequestParts`
//! extractor, but Dioxus's `#[server]`/`#[post]` macros only special-case a
//! fixed allowlist of extractor types (headers, cookies); anything outside
//! that list gets treated as a regular JSON body argument instead, which
//! fails since `AuthSession` isn't `Deserialize`. Plain axum has no such
//! restriction, so login/signup/logout/whoami live here instead.

use axum::extract::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_login::AuthSession;
use serde::Deserialize;

use crate::auth::Backend;
use crate::server::CurrentUser;

pub fn routes() -> Router {
    Router::new()
        .route("/api/auth/signup", post(signup))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/me", get(me))
}

#[derive(Deserialize)]
struct Credentials {
    email: String,
    password: String,
}

async fn signup(mut auth: AuthSession<Backend>, Json(creds): Json<Credentials>) -> Response {
    let pool = match crate::db::pool().await {
        Ok(pool) => pool,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

    let user = match crate::auth::signup(&pool, &creds.email, &creds.password).await {
        Ok(user) => user,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };

    if let Err(err) = auth.login(&user).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }

    Json(CurrentUser::from(user)).into_response()
}

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

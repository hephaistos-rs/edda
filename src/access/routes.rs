//! Raw axum routes, not Dioxus server functions — for the same reason as
//! `auth::routes`: these need `AuthSession` for identity, which the
//! `#[get]`/`#[post]` macros only support via their `server_args` extractor
//! syntax when the caller already knows the exact type up front. That works
//! fine for the repo CRUD functions in `server/mod.rs` (this codebase now
//! uses it there too), but these routes are new enough, and specific enough
//! to access control, that keeping them alongside the rest of the raw
//! axum surface (`auth::routes`, `api::routes`) is the more consistent home.

use axum::extract::{Json, Path};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post};
use axum::Router;
use axum_login::AuthSession;
use serde::Deserialize;

use crate::access::{self, AccessError};
use crate::auth::Backend;

pub fn routes() -> Router {
    Router::new()
        .route("/api/repos/{name}/collaborators", post(add_collaborator).get(list_collaborators))
        .route("/api/repos/{name}/collaborators/{user_id}", delete(remove_collaborator))
}

impl IntoResponse for AccessError {
    fn into_response(self) -> Response {
        let status = match self {
            AccessError::NotOwner => StatusCode::FORBIDDEN,
            AccessError::UserNotFound => StatusCode::NOT_FOUND,
            AccessError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.to_string()).into_response()
    }
}

#[derive(Deserialize)]
struct AddCollaboratorBody {
    email: String,
}

#[tracing::instrument(name = "access.collaborator.add", skip_all, fields(repo.name = %name))]
async fn add_collaborator(auth: AuthSession<Backend>, Path(name): Path<String>, Json(body): Json<AddCollaboratorBody>) -> Response {
    let Some(user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match access::add_collaborator(&auth.backend.pool, &name, &user.id, &body.email).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(err) => err.into_response(),
    }
}

#[tracing::instrument(name = "access.collaborator.list", skip_all, fields(repo.name = %name))]
async fn list_collaborators(auth: AuthSession<Backend>, Path(name): Path<String>) -> Response {
    if auth.user.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match access::list_collaborators(&auth.backend.pool, &name).await {
        Ok(collaborators) => Json(collaborators).into_response(),
        Err(err) => err.into_response(),
    }
}

#[tracing::instrument(name = "access.collaborator.remove", skip_all, fields(repo.name = %name))]
async fn remove_collaborator(auth: AuthSession<Backend>, Path((name, target_user_id)): Path<(String, String)>) -> Response {
    let Some(user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match access::remove_collaborator(&auth.backend.pool, &name, &user.id, &target_user_id).await {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such collaborator").into_response(),
        Err(err) => err.into_response(),
    }
}

//! SSH key management — raw axum routes for the same reason as
//! `auth_routes`: these need `AuthSession` for identity. Every operation
//! here is scoped to the caller's *own* keys — a user can never list,
//! add for, or revoke another user's key through this surface (there is
//! no "target user" parameter to abuse; the acting user is always taken
//! from the session, never from client input).

use axum::extract::{Json, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use axum_login::AuthSession;
use serde::{Deserialize, Serialize};

use edda_auth::Backend;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/ssh-keys", post(add_key).get(list_keys))
        .route("/api/ssh-keys/{id}/revoke", post(revoke_key))
}

#[derive(Serialize)]
struct SshKeyDto {
    id: String,
    title: String,
    fingerprint: String,
    created_at: i64,
    last_used_at: Option<i64>,
}

impl From<edda_domain::SshKey> for SshKeyDto {
    fn from(key: edda_domain::SshKey) -> Self {
        Self {
            id: key.id.to_string(),
            title: key.title,
            fingerprint: key.fingerprint,
            created_at: key.created_at,
            last_used_at: key.last_used_at,
        }
    }
}

#[derive(Deserialize)]
struct AddSshKeyBody {
    title: String,
    public_key: String,
}

#[tracing::instrument(name = "authentication.ssh_key.add", skip_all, fields(key.title = %body.title))]
async fn add_key(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Json(body): Json<AddSshKeyBody>,
) -> Response {
    let Some(session_user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match edda_auth::ssh::add(
        &state.pool,
        session_user.user.id,
        &body.title,
        &body.public_key,
    )
    .await
    {
        Ok(key) => Json(SshKeyDto::from(key)).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn list_keys(State(state): State<AppState>, auth: AuthSession<Backend>) -> Response {
    let Some(session_user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match edda_auth::ssh::list(&state.pool, session_user.user.id).await {
        Ok(keys) => Json(keys.into_iter().map(SshKeyDto::from).collect::<Vec<_>>()).into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

async fn revoke_key(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path(id): Path<String>,
) -> Response {
    let Some(session_user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(key_id) = id.parse() else {
        return (StatusCode::NOT_FOUND, "no such key").into_response();
    };
    match edda_auth::ssh::revoke(&state.pool, session_user.user.id, key_id).await {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such key").into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

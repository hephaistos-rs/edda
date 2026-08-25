//! Collaborator management — raw axum routes for the same reason as
//! `auth_routes`: these need `AuthSession` for identity.

use axum::extract::{Json, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post};
use axum::Router;
use axum_login::AuthSession;
use serde::{Deserialize, Serialize};

use edda_auth::Backend;
use edda_db::{RepoAccessRepo, UserRepo};
use edda_domain::AuthzError;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/repos/{owner}/{name}/collaborators",
            post(add_collaborator).get(list_collaborators),
        )
        .route(
            "/api/repos/{owner}/{name}/collaborators/{user_id}",
            delete(remove_collaborator),
        )
}

fn authz_error_response(err: AuthzError) -> Response {
    match err {
        AuthzError::NotFound => (StatusCode::NOT_FOUND, "no such repository").into_response(),
        AuthzError::Forbidden => {
            (StatusCode::FORBIDDEN, "only the repo owner can do that").into_response()
        }
    }
}

#[derive(Deserialize)]
struct AddCollaboratorBody {
    email: String,
}

#[derive(Serialize)]
struct CollaboratorDto {
    user_id: String,
    email: String,
    role: String,
    added_at: i64,
}

// Collaborator management stays Owner-only (`check_danger_zone`) even
// though the four-tier role model's own target capability matrix would
// allow Admin+ here — nothing currently grants Admin to anyone but the
// owner (Owner already satisfies an Admin+ check), so this is a
// deliberately conservative choice, not yet the final target.
#[tracing::instrument(name = "access.collaborator.add", skip_all, fields(repo.owner = %owner, repo.name = %name))]
async fn add_collaborator(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path((owner, name)): Path<(String, String)>,
    Json(body): Json<AddCollaboratorBody>,
) -> Response {
    let Some(session_user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let actor = edda_domain::ActorContext::User(session_user.user.id);

    let repository = match state.authz.repository_by_name(&owner, &name).await {
        Ok(repository) => repository,
        Err(err) => return authz_error_response(err),
    };
    if let Err(err) = state.authz.check_danger_zone(&actor, &repository).await {
        return authz_error_response(err);
    }

    // `UserRepo` only exposes a credential-carrying row from `find_by_email`
    // (it's the same lookup `edda-auth`'s login path uses) — only `.user`
    // is needed here, the password hash is simply discarded.
    match UserRepo::find_by_email(&state.pool, &body.email).await {
        Ok(Some(row)) => {
            if let Err(err) = RepoAccessRepo::grant(
                &state.pool,
                repository.id,
                row.user.id,
                edda_domain::RepoRole::Write,
            )
            .await
            {
                return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
            }
            StatusCode::OK.into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "no user with that email").into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

#[tracing::instrument(name = "access.collaborator.list", skip_all, fields(repo.owner = %owner, repo.name = %name))]
async fn list_collaborators(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path((owner, name)): Path<(String, String)>,
) -> Response {
    if auth.user.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let repository = match state.authz.repository_by_name(&owner, &name).await {
        Ok(repository) => repository,
        Err(err) => return authz_error_response(err),
    };
    match RepoAccessRepo::list_collaborators(&state.pool, repository.id).await {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|row| CollaboratorDto {
                    user_id: row.user.id.to_string(),
                    email: row.user.email,
                    role: row.role.as_db_str().to_string(),
                    added_at: row.added_at,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

#[tracing::instrument(name = "access.collaborator.remove", skip_all, fields(repo.owner = %owner, repo.name = %name))]
async fn remove_collaborator(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path((owner, name, target_user_id)): Path<(String, String, String)>,
) -> Response {
    let Some(session_user) = auth.user else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let actor = edda_domain::ActorContext::User(session_user.user.id);

    let repository = match state.authz.repository_by_name(&owner, &name).await {
        Ok(repository) => repository,
        Err(err) => return authz_error_response(err),
    };
    if let Err(err) = state.authz.check_danger_zone(&actor, &repository).await {
        return authz_error_response(err);
    }
    let Ok(target_user_id) = target_user_id.parse() else {
        return (StatusCode::NOT_FOUND, "no such collaborator").into_response();
    };
    match RepoAccessRepo::remove_collaborator(&state.pool, repository.id, target_user_id).await {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such collaborator").into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

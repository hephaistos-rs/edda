//! Instance administration over HTTP — the web-UI-facing counterpart to
//! `edda-cli`. Every handler resolves the caller the same way every other
//! authenticated route in this crate does (`AuthSession` -> `auth.user`),
//! then gates on `edda_domain::require_instance_admin` — the single
//! centralized instance-admin check, never an ad hoc `if user.is_admin`.
//! An admin-gated route existing isn't a secret worth a 404 the way a
//! private repo is, so a logged-in non-admin gets a plain 403, not a
//! fake "not found."

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_login::AuthSession;
use serde::Serialize;

use edda_auth::Backend;
use edda_domain::require_instance_admin;

use crate::state::AppState;

/// Best-effort admin audit logging, via the one audit path
/// (`crate::services::audit`, S11).
async fn record(pool: &edda_db::DbPool, event_type: &str, actor_id: &str, target_id: &str) {
    crate::services::audit::record(
        pool,
        crate::services::audit::AuditEntry::new(event_type, actor_id).target("user", target_id),
    )
    .await;
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/admin/users", get(list_users))
        .route("/api/admin/users/{id}/admin", post(set_admin))
        .route("/api/admin/users/{id}/disable", post(disable_user))
        .route("/api/admin/users/{id}/enable", post(enable_user))
        .route("/api/admin/users/{id}", axum::routing::delete(delete_user))
        .route("/api/admin/audit-events", get(list_audit_events))
}

fn require_admin(
    auth: &AuthSession<Backend>,
) -> Result<edda_domain::User, (StatusCode, &'static str)> {
    let Some(session_user) = &auth.user else {
        return Err((StatusCode::UNAUTHORIZED, "login required"));
    };
    require_instance_admin(session_user.user.is_admin)
        .map_err(|_| (StatusCode::FORBIDDEN, "admin access required"))?;
    Ok(session_user.user.clone())
}

#[derive(Serialize)]
struct AdminUserDto {
    id: String,
    username: String,
    email: String,
    is_admin: bool,
    disabled: bool,
}

impl From<edda_domain::User> for AdminUserDto {
    fn from(user: edda_domain::User) -> Self {
        Self {
            id: user.id.to_string(),
            username: user.username,
            email: user.email,
            is_admin: user.is_admin,
            disabled: user.disabled_at.is_some(),
        }
    }
}

#[tracing::instrument(name = "admin.users.list", skip_all)]
async fn list_users(State(state): State<AppState>, auth: AuthSession<Backend>) -> Response {
    if let Err(err) = require_admin(&auth) {
        return err.into_response();
    }
    match edda_db::UserRepo::list_all(&state.pool).await {
        Ok(users) => Json(
            users
                .into_iter()
                .map(AdminUserDto::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

fn parse_user_id(id: &str) -> Result<edda_domain::UserId, (StatusCode, &'static str)> {
    id.parse()
        .map_err(|_| (StatusCode::NOT_FOUND, "no such user"))
}

#[derive(serde::Deserialize)]
struct SetAdminBody {
    is_admin: bool,
}

#[tracing::instrument(name = "admin.users.set_admin", skip_all, fields(target.user_id = %id))]
async fn set_admin(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path(id): Path<String>,
    Json(body): Json<SetAdminBody>,
) -> Response {
    let admin = match require_admin(&auth) {
        Ok(admin) => admin,
        Err(err) => return err.into_response(),
    };
    let user_id = match parse_user_id(&id) {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };
    match edda_db::UserRepo::set_admin(&state.pool, user_id, body.is_admin).await {
        Ok(true) => {
            let event_type = if body.is_admin {
                "admin.user.grant_admin"
            } else {
                "admin.user.revoke_admin"
            };
            record(&state.pool, event_type, &admin.id.to_string(), &id).await;
            StatusCode::OK.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "no such user").into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

#[tracing::instrument(name = "admin.users.disable", skip_all, fields(target.user_id = %id))]
async fn disable_user(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path(id): Path<String>,
) -> Response {
    set_disabled(state, auth, id, true).await
}

#[tracing::instrument(name = "admin.users.enable", skip_all, fields(target.user_id = %id))]
async fn enable_user(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path(id): Path<String>,
) -> Response {
    set_disabled(state, auth, id, false).await
}

async fn set_disabled(
    state: AppState,
    auth: AuthSession<Backend>,
    id: String,
    disabled: bool,
) -> Response {
    let admin = match require_admin(&auth) {
        Ok(admin) => admin,
        Err(err) => return err.into_response(),
    };
    let user_id = match parse_user_id(&id) {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };
    match edda_db::UserRepo::set_disabled(&state.pool, user_id, disabled).await {
        Ok(true) => {
            let event_type = if disabled {
                "admin.user.disable"
            } else {
                "admin.user.enable"
            };
            record(&state.pool, event_type, &admin.id.to_string(), &id).await;
            StatusCode::OK.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "no such user").into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

#[tracing::instrument(name = "admin.users.delete", skip_all, fields(target.user_id = %id))]
async fn delete_user(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path(id): Path<String>,
) -> Response {
    let admin = match require_admin(&auth) {
        Ok(admin) => admin,
        Err(err) => return err.into_response(),
    };
    let user_id = match parse_user_id(&id) {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };
    match edda_db::UserRepo::delete(&state.pool, user_id).await {
        Ok(true) => {
            record(&state.pool, "admin.user.delete", &admin.id.to_string(), &id).await;
            StatusCode::OK.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "no such user").into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

#[derive(Serialize)]
struct AuditEventDto {
    id: String,
    occurred_at: i64,
    event_type: String,
    actor_id: Option<String>,
    target_type: Option<String>,
    target_id: Option<String>,
    detail_json: Option<String>,
}

impl From<edda_db::AuditEvent> for AuditEventDto {
    fn from(event: edda_db::AuditEvent) -> Self {
        Self {
            id: event.id.to_string(),
            occurred_at: event.occurred_at,
            event_type: event.event_type,
            actor_id: event.actor_id,
            target_type: event.target_type,
            target_id: event.target_id,
            detail_json: event.detail_json,
        }
    }
}

async fn list_audit_events(State(state): State<AppState>, auth: AuthSession<Backend>) -> Response {
    if let Err(err) = require_admin(&auth) {
        return err.into_response();
    }
    match edda_db::AuditEventRepo::list_recent(&state.pool, 200).await {
        Ok(events) => Json(
            events
                .into_iter()
                .map(AuditEventDto::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

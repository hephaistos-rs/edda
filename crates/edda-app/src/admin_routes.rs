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
use serde::{Deserialize, Serialize};

use edda_auth::Backend;
use edda_domain::{require_instance_admin, InstanceSettings, RegistrationMode, Visibility};

use crate::services::InstanceSettingsService;
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
        .route("/api/admin/users/pending", get(list_pending_users))
        .route("/api/admin/users/{id}/admin", post(set_admin))
        .route("/api/admin/users/{id}/approve", post(approve_user))
        .route("/api/admin/users/{id}/disable", post(disable_user))
        .route("/api/admin/users/{id}/enable", post(enable_user))
        .route("/api/admin/users/{id}", axum::routing::delete(delete_user))
        .route("/api/admin/audit-events", get(list_audit_events))
        .route(
            "/api/admin/settings",
            get(get_instance_settings).put(put_instance_settings),
        )
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

/// The admin approval queue (Phase 9, `Approval` registration mode):
/// accounts created but not yet activated.
#[tracing::instrument(name = "admin.users.list_pending", skip_all)]
async fn list_pending_users(State(state): State<AppState>, auth: AuthSession<Backend>) -> Response {
    if let Err(err) = require_admin(&auth) {
        return err.into_response();
    }
    match edda_db::UserRepo::list_pending_approval(&state.pool).await {
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

/// Activates a pending account (`Approval` registration mode). Once
/// approved the account can sign in normally.
#[tracing::instrument(name = "admin.users.approve", skip_all, fields(target.user_id = %id))]
async fn approve_user(
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
    match edda_db::UserRepo::approve(&state.pool, user_id).await {
        Ok(true) => {
            record(
                &state.pool,
                "admin.user.approve",
                &admin.id.to_string(),
                &id,
            )
            .await;
            StatusCode::OK.into_response()
        }
        // Unknown id, or already approved — nothing changed.
        Ok(false) => (StatusCode::NOT_FOUND, "no such pending user").into_response(),
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
        // The account still owns repositories — a precondition failure the
        // caller can act on (transfer/delete those first), not a server
        // error.
        Err(err @ edda_db::DeleteUserError::OwnsRepositories { .. }) => {
            (StatusCode::CONFLICT, err.to_string()).into_response()
        }
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

/// The admin-editable instance settings (Phase 12). `registration_mode`
/// and `default_repo_visibility` are the same lowercase strings the
/// corresponding `EDDA_*` variables and the database use.
#[derive(Serialize, Deserialize)]
struct InstanceSettingsDto {
    registration_mode: String,
    default_repo_visibility: String,
    welcome_message: Option<String>,
    require_signin_to_view: bool,
}

impl From<&InstanceSettings> for InstanceSettingsDto {
    fn from(settings: &InstanceSettings) -> Self {
        Self {
            registration_mode: settings.registration_mode.as_db_str().to_string(),
            default_repo_visibility: settings.default_repo_visibility.as_db_str().to_string(),
            welcome_message: settings.welcome_message.clone(),
            require_signin_to_view: settings.require_signin_to_view,
        }
    }
}

impl InstanceSettingsDto {
    fn into_domain(self) -> Result<InstanceSettings, (StatusCode, String)> {
        let registration_mode = RegistrationMode::parse(&self.registration_mode).ok_or((
            StatusCode::BAD_REQUEST,
            format!(
                "registration_mode must be one of open, approval, closed (got {:?})",
                self.registration_mode
            ),
        ))?;
        let default_repo_visibility = Visibility::from_db_str(self.default_repo_visibility.trim())
            .ok_or((
                StatusCode::BAD_REQUEST,
                format!(
                    "default_repo_visibility must be one of public, private (got {:?})",
                    self.default_repo_visibility
                ),
            ))?;
        let welcome_message = self
            .welcome_message
            .map(|text| text.trim().to_string())
            .filter(|text| !text.is_empty());
        Ok(InstanceSettings {
            registration_mode,
            default_repo_visibility,
            welcome_message,
            require_signin_to_view: self.require_signin_to_view,
        })
    }
}

#[tracing::instrument(name = "admin.settings.get", skip_all)]
async fn get_instance_settings(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
) -> Response {
    if let Err(err) = require_admin(&auth) {
        return err.into_response();
    }
    let current = state.config.instance_settings.load();
    Json(InstanceSettingsDto::from(&**current)).into_response()
}

#[tracing::instrument(name = "admin.settings.put", skip_all)]
async fn put_instance_settings(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Json(body): Json<InstanceSettingsDto>,
) -> Response {
    let admin = match require_admin(&auth) {
        Ok(admin) => admin,
        Err(err) => return err.into_response(),
    };
    let settings = match body.into_domain() {
        Ok(settings) => settings,
        Err((status, message)) => return (status, message).into_response(),
    };
    match InstanceSettingsService::from_state(&state)
        .save(&settings, &admin.id.to_string())
        .await
    {
        Ok(updated) => Json(InstanceSettingsDto::from(&*updated)).into_response(),
        Err(err) => (
            StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            err.client_message(),
        )
            .into_response(),
    }
}

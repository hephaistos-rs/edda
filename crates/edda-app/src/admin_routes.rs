//! Instance administration over HTTP — the web-UI-facing counterpart to
//! `edda-cli`. Every handler resolves the caller the same way every other
//! authenticated route in this crate does (`AuthSession` -> `auth.user`),
//! then gates on `edda_domain::require_instance_admin` — the single
//! centralized instance-admin check, never an ad hoc `if user.is_admin`.
//! An admin-gated route existing isn't a secret worth a 404 the way a
//! private repo is, so a logged-in non-admin gets a plain 403, not a
//! fake "not found."

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_login::AuthSession;
use serde::{Deserialize, Serialize};

use edda_auth::Backend;
use edda_domain::{
    require_instance_admin, InstanceSettings, JobId, JobStatus, RegistrationMode, RepositoryId,
    Visibility,
};

use crate::services::InstanceSettingsService;
use crate::state::AppState;

/// Best-effort admin audit logging, via the one audit path
/// (`crate::services::audit`, S11).
async fn record(pool: &edda_db::DbPool, event_type: &str, actor_id: &str, target_id: &str) {
    record_on(pool, event_type, actor_id, "user", target_id).await;
}

async fn record_on(
    pool: &edda_db::DbPool,
    event_type: &str,
    actor_id: &str,
    target_type: &str,
    target_id: &str,
) {
    crate::services::audit::record(
        pool,
        crate::services::audit::AuditEntry::new(event_type, actor_id)
            .target(target_type, target_id),
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
        .route("/api/admin/system", get(system_info))
        .route("/api/admin/repos", get(list_repos))
        .route(
            "/api/admin/repos/{id}/visibility",
            post(set_repo_visibility),
        )
        .route(
            "/api/admin/repos/{id}",
            axum::routing::delete(delete_repo_admin),
        )
        .route("/api/admin/orgs", get(list_orgs))
        .route("/api/admin/jobs", get(list_jobs))
        .route("/api/admin/jobs/{id}/retry", post(retry_job))
        .route("/api/admin/jobs/{id}/cancel", post(cancel_job))
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

#[derive(Deserialize)]
struct AuditQuery {
    /// Prefix filter on `event_type`, e.g. `admin.` or `repository.`.
    event_type: Option<String>,
}

async fn list_audit_events(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Query(query): Query<AuditQuery>,
) -> Response {
    if let Err(err) = require_admin(&auth) {
        return err.into_response();
    }
    match edda_db::AuditEventRepo::list_filtered(&state.pool, query.event_type.as_deref(), 200)
        .await
    {
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

// ───────────────────────── system info (Phase 12) ─────────────────────

#[derive(Serialize)]
struct SystemInfoDto {
    version: &'static str,
    database_backend: String,
    users: i64,
    repositories: i64,
    organizations: i64,
    open_pull_requests: i64,
    open_issues: i64,
    jobs_pending: i64,
    jobs_running: i64,
    jobs_dead: i64,
    tracked_git_bytes: i64,
    tracked_lfs_bytes: i64,
}

#[tracing::instrument(name = "admin.system", skip_all)]
async fn system_info(State(state): State<AppState>, auth: AuthSession<Backend>) -> Response {
    if let Err(err) = require_admin(&auth) {
        return err.into_response();
    }
    let stats = match edda_db::AdminStatsRepo::snapshot(&state.pool).await {
        Ok(stats) => stats,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    let (pending, running, dead) = match edda_db::JobRepo::queue_depths(&state.pool).await {
        Ok(depths) => depths,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    Json(SystemInfoDto {
        version: env!("CARGO_PKG_VERSION"),
        database_backend: format!("{:?}", state.pool.backend()).to_lowercase(),
        users: stats.users,
        repositories: stats.repositories,
        organizations: stats.organizations,
        open_pull_requests: stats.open_pull_requests,
        open_issues: stats.open_issues,
        jobs_pending: pending,
        jobs_running: running,
        jobs_dead: dead,
        tracked_git_bytes: stats.tracked_git_bytes,
        tracked_lfs_bytes: stats.tracked_lfs_bytes,
    })
    .into_response()
}

// ───────────────────────── repositories (Phase 12) ────────────────────

#[derive(Serialize)]
struct AdminRepoDto {
    id: String,
    owner: String,
    name: String,
    private: bool,
    is_fork: bool,
}

#[tracing::instrument(name = "admin.repos.list", skip_all)]
async fn list_repos(State(state): State<AppState>, auth: AuthSession<Backend>) -> Response {
    if let Err(err) = require_admin(&auth) {
        return err.into_response();
    }
    match edda_db::RepositoryRepo::list_all_with_owner_username(&state.pool).await {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|(repo, owner)| AdminRepoDto {
                    id: repo.id.to_string(),
                    private: repo.is_private(),
                    is_fork: repo.forked_from.is_some(),
                    owner,
                    name: repo.name,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

fn parse_repo_id(id: &str) -> Result<RepositoryId, (StatusCode, &'static str)> {
    id.parse()
        .map_err(|_| (StatusCode::NOT_FOUND, "no such repository"))
}

#[derive(Deserialize)]
struct SetVisibilityBody {
    /// `"public"` or `"private"`.
    visibility: String,
}

#[tracing::instrument(name = "admin.repos.set_visibility", skip_all, fields(repo.id = %id))]
async fn set_repo_visibility(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path(id): Path<String>,
    Json(body): Json<SetVisibilityBody>,
) -> Response {
    let admin = match require_admin(&auth) {
        Ok(admin) => admin,
        Err(err) => return err.into_response(),
    };
    let repo_id = match parse_repo_id(&id) {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };
    let Some(visibility) = Visibility::from_db_str(body.visibility.trim()) else {
        return (
            StatusCode::BAD_REQUEST,
            "visibility must be public or private",
        )
            .into_response();
    };
    match edda_db::RepositoryRepo::update_visibility(&state.pool, repo_id, visibility).await {
        Ok(()) => {
            record_on(
                &state.pool,
                "admin.repository.set_visibility",
                &admin.id.to_string(),
                "repository",
                &id,
            )
            .await;
            StatusCode::OK.into_response()
        }
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

#[tracing::instrument(name = "admin.repos.delete", skip_all, fields(repo.id = %id))]
async fn delete_repo_admin(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path(id): Path<String>,
) -> Response {
    let admin = match require_admin(&auth) {
        Ok(admin) => admin,
        Err(err) => return err.into_response(),
    };
    let repo_id = match parse_repo_id(&id) {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };
    let found = match edda_db::RepositoryRepo::find_by_id_with_owner_username(&state.pool, repo_id)
        .await
    {
        Ok(found) => found,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    let Some((repo, owner)) = found else {
        return (StatusCode::NOT_FOUND, "no such repository").into_response();
    };
    let identity = format!("{owner}/{}", repo.name);
    // Git directory first, then the row — an orphan bare repo is cheap to
    // sweep; a row pointing at a deleted tree is not (same ordering the
    // RepositoryService uses).
    if let Err(err) = edda_git::delete_repo(state.store.as_ref(), &state.locks, &identity).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }
    match edda_db::RepositoryRepo::delete(&state.pool, repo_id).await {
        Ok(()) => {
            record_on(
                &state.pool,
                "admin.repository.delete",
                &admin.id.to_string(),
                "repository",
                &id,
            )
            .await;
            StatusCode::OK.into_response()
        }
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

// ───────────────────────── organizations (Phase 12) ──────────────────

#[derive(Serialize)]
struct AdminOrgDto {
    id: String,
    name: String,
    display_name: Option<String>,
}

#[tracing::instrument(name = "admin.orgs.list", skip_all)]
async fn list_orgs(State(state): State<AppState>, auth: AuthSession<Backend>) -> Response {
    if let Err(err) = require_admin(&auth) {
        return err.into_response();
    }
    match edda_db::OrganizationRepo::list_all(&state.pool).await {
        Ok(orgs) => Json(
            orgs.into_iter()
                .map(|org| AdminOrgDto {
                    id: org.id.to_string(),
                    name: org.name,
                    display_name: org.display_name,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

// ───────────────────────── job queue (Phase 12) ──────────────────────

#[derive(Serialize)]
struct AdminJobDto {
    id: String,
    kind: String,
    status: String,
    attempts: u32,
    max_attempts: u32,
    run_at: i64,
    created_at: i64,
    last_error: Option<String>,
}

impl From<edda_domain::JobRecord> for AdminJobDto {
    fn from(job: edda_domain::JobRecord) -> Self {
        Self {
            id: job.id.to_string(),
            kind: job.payload.kind().as_metric_label().to_string(),
            status: job.status.as_db_str().to_string(),
            attempts: job.attempts,
            max_attempts: job.max_attempts,
            run_at: job.run_at,
            created_at: job.created_at,
            last_error: job.last_error,
        }
    }
}

#[derive(Deserialize)]
struct JobListQuery {
    /// `"failed"` for the dead-letter view; anything else (or absent) =
    /// recent activity across every status.
    status: Option<String>,
}

#[tracing::instrument(name = "admin.jobs.list", skip_all)]
async fn list_jobs(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Query(query): Query<JobListQuery>,
) -> Response {
    if let Err(err) = require_admin(&auth) {
        return err.into_response();
    }
    let result = match query.status.as_deref().and_then(JobStatus::from_db_str) {
        Some(status) => edda_db::JobRepo::list_by_status(&state.pool, status, 200).await,
        None => edda_db::JobRepo::list_recent(&state.pool, 200).await,
    };
    match result {
        Ok(jobs) => {
            Json(jobs.into_iter().map(AdminJobDto::from).collect::<Vec<_>>()).into_response()
        }
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

fn parse_job_id(id: &str) -> Result<JobId, (StatusCode, &'static str)> {
    id.parse()
        .map_err(|_| (StatusCode::NOT_FOUND, "no such job"))
}

#[tracing::instrument(name = "admin.jobs.retry", skip_all, fields(job.id = %id))]
async fn retry_job(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path(id): Path<String>,
) -> Response {
    let admin = match require_admin(&auth) {
        Ok(admin) => admin,
        Err(err) => return err.into_response(),
    };
    let job_id = match parse_job_id(&id) {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };
    match edda_db::JobRepo::requeue(&state.pool, job_id).await {
        Ok(true) => {
            record_on(
                &state.pool,
                "admin.job.retry",
                &admin.id.to_string(),
                "job",
                &id,
            )
            .await;
            StatusCode::OK.into_response()
        }
        Ok(false) => (
            StatusCode::CONFLICT,
            "only a dead-lettered job can be retried",
        )
            .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

#[tracing::instrument(name = "admin.jobs.cancel", skip_all, fields(job.id = %id))]
async fn cancel_job(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path(id): Path<String>,
) -> Response {
    let admin = match require_admin(&auth) {
        Ok(admin) => admin,
        Err(err) => return err.into_response(),
    };
    let job_id = match parse_job_id(&id) {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };
    match edda_db::JobRepo::delete(&state.pool, job_id).await {
        Ok(true) => {
            record_on(
                &state.pool,
                "admin.job.cancel",
                &admin.id.to_string(),
                "job",
                &id,
            )
            .await;
            StatusCode::OK.into_response()
        }
        Ok(false) => (StatusCode::CONFLICT, "a running job cannot be cancelled").into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

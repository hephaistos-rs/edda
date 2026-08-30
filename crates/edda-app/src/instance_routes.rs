//! `GET /api/instance` — the handful of instance settings a *signed-out*
//! visitor's UI needs (the sign-in page's welcome banner, whether signup
//! is offered, the default visibility to pre-select on the new-repo
//! form). Public by design: it sits outside the `/api/v1` `Actor` gate,
//! so it answers even when the instance is otherwise private
//! (`EDDA_REQUIRE_SIGNIN_VIEW`) — it exposes nothing an unauthenticated
//! login page shouldn't already show.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use edda_domain::RegistrationMode;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/instance", get(instance_info))
}

#[derive(Serialize)]
struct InstanceInfoDto {
    /// The admin-configured welcome banner, or `null` when unset.
    welcome_message: Option<String>,
    /// Whether self-service signup is offered at all (`false` in
    /// `closed` registration mode).
    signup_enabled: bool,
    /// `open` | `approval` | `closed`.
    registration_mode: String,
    /// `public` | `private` — what the new-repo form should default to.
    default_repo_visibility: String,
}

#[tracing::instrument(name = "instance.info", skip_all)]
async fn instance_info(State(state): State<AppState>) -> Json<InstanceInfoDto> {
    let settings = state.config.instance_settings.load();
    Json(InstanceInfoDto {
        welcome_message: settings.welcome_message.clone(),
        signup_enabled: settings.registration_mode != RegistrationMode::Closed,
        registration_mode: settings.registration_mode.as_db_str().to_string(),
        default_repo_visibility: settings.default_repo_visibility.as_db_str().to_string(),
    })
}

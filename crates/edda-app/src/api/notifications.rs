//! `/api/v1/notifications` + `/api/v1/user/email-notifications`.

use axum::extract::{Path, State};
use axum::routing::{post, put};
use axum::{Json, Router};
use serde::Deserialize;

use edda_domain::NotificationId;

use super::Actor;
use crate::services::{NotificationService, ServiceError};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/notifications/{id}/read", post(mark_read))
        .route(
            "/api/v1/user/email-notifications",
            put(set_email_notifications),
        )
}

async fn mark_read(
    State(state): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    let notification_id: NotificationId = id.parse().map_err(|_| ServiceError::NotFound)?;
    NotificationService::from_state(&state)
        .mark_read(actor.context(), notification_id)
        .await?;
    Ok(Json(()))
}

#[derive(Deserialize)]
pub struct EmailNotificationsBody {
    pub enabled: bool,
}

async fn set_email_notifications(
    State(state): State<AppState>,
    actor: Actor,
    Json(body): Json<EmailNotificationsBody>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    NotificationService::from_state(&state)
        .set_email_notifications(actor.context(), body.enabled)
        .await?;
    Ok(Json(()))
}

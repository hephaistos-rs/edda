//! `/api/v1/notifications` + `/api/v1/user/email-notifications` — a user's
//! own notifications and the email-notification preference toggle. These
//! are read-your-own-data endpoints, so "is someone signed in" is the only
//! access question.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};

use edda_api_types::{EmailNotificationsRequest, NotificationDto, SetWatchRequest, WatchStatusDto};
use edda_domain::{Notification, NotificationId, WatchLevel};

use super::Actor;
use crate::services::{NotificationService, ServiceError};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/notifications", get(list))
        .route("/api/v1/notifications/unread-count", get(unread_count))
        .route("/api/v1/notifications/{id}/read", post(mark_read))
        .route(
            "/api/v1/user/email-notifications",
            get(get_email_notifications).put(set_email_notifications),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/subscription",
            get(get_subscription)
                .put(set_subscription)
                .delete(clear_subscription),
        )
}

async fn get_subscription(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<WatchStatusDto>, ServiceError> {
    actor.require_user()?;
    let level = NotificationService::from_state(&state)
        .repo_watch_level(actor.context(), &owner, &repo)
        .await?;
    Ok(Json(WatchStatusDto {
        level: level.map(|l| l.as_db_str().to_string()),
    }))
}

async fn set_subscription(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<SetWatchRequest>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    let level = WatchLevel::from_db_str(&body.level)
        .ok_or_else(|| ServiceError::Validation(format!("unknown watch level {:?}", body.level)))?;
    NotificationService::from_state(&state)
        .set_repo_watch(actor.context(), &owner, &repo, level)
        .await?;
    Ok(Json(()))
}

async fn clear_subscription(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    NotificationService::from_state(&state)
        .clear_repo_watch(actor.context(), &owner, &repo)
        .await?;
    Ok(Json(()))
}

fn notification_dto(notification: &Notification) -> NotificationDto {
    NotificationDto {
        id: notification.id.to_string(),
        kind: notification.kind.as_db_str().to_string(),
        subject_type: notification.subject.subject_type_db_str().to_string(),
        subject_id: notification.subject.subject_id().to_string(),
        read: !notification.is_unread(),
        created_at: notification.created_at,
    }
}

async fn list(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<Vec<NotificationDto>>, ServiceError> {
    let user_id = actor.require_user()?;
    let notifications = edda_db::NotificationRepo::list_for_user(&state.pool, user_id).await?;
    Ok(Json(notifications.iter().map(notification_dto).collect()))
}

async fn unread_count(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<i64>, ServiceError> {
    // Anonymous has no notifications — `0`, not an error, so the navbar
    // badge need not special-case "not logged in".
    let Some(user_id) = actor.context().user_id() else {
        return Ok(Json(0));
    };
    Ok(Json(
        edda_db::NotificationRepo::unread_count(&state.pool, user_id).await?,
    ))
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

async fn get_email_notifications(
    State(state): State<AppState>,
    actor: Actor,
) -> Result<Json<bool>, ServiceError> {
    let user_id = actor.require_user()?;
    Ok(Json(
        edda_db::UserRepo::email_notifications_enabled(&state.pool, user_id).await?,
    ))
}

async fn set_email_notifications(
    State(state): State<AppState>,
    actor: Actor,
    Json(body): Json<EmailNotificationsRequest>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    NotificationService::from_state(&state)
        .set_email_notifications(actor.context(), body.enabled)
        .await?;
    Ok(Json(()))
}

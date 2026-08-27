//! In-app notifications + the email-notification preference toggle —
//! Dioxus server functions, read-your-own-data queries with no
//! cross-user access question, so no `AuthorizationService` call is
//! needed beyond "is someone logged in."

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotificationDto {
    pub id: String,
    pub kind: String,
    pub subject_type: String,
    pub subject_id: String,
    pub read: bool,
    pub created_at: i64,
}

#[cfg(feature = "server")]
fn notification_dto(notification: &edda_domain::Notification) -> NotificationDto {
    let (subject_type, subject_id) = match notification.subject {
        edda_domain::NotificationSubject::PullRequest(id) => ("pull_request", id.to_string()),
        edda_domain::NotificationSubject::Issue(id) => ("issue", id.to_string()),
    };
    NotificationDto {
        id: notification.id.to_string(),
        kind: notification.kind.as_db_str().to_string(),
        subject_type: subject_type.to_string(),
        subject_id,
        read: !notification.is_unread(),
        created_at: notification.created_at,
    }
}

#[get("/api/notifications", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "notification.list", skip_all, err)]
pub async fn list_notifications() -> Result<Vec<NotificationDto>, ServerFnError> {
    let Some(session_user) = &auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let shared = crate::shared::get();
    let notifications =
        edda_db::NotificationRepo::list_for_user(&shared.pool, session_user.user.id)
            .await
            .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(notifications.iter().map(notification_dto).collect())
}

#[get("/api/notifications/unread-count", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "notification.unread_count", skip_all, err)]
pub async fn unread_notification_count() -> Result<i64, ServerFnError> {
    let Some(session_user) = &auth.user else {
        // Anonymous has no notifications — `0`, not an error, so the
        // navbar badge doesn't need to special-case "not logged in."
        return Ok(0);
    };
    let shared = crate::shared::get();
    edda_db::NotificationRepo::unread_count(&shared.pool, session_user.user.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))
}

#[post("/api/notifications/:id/read", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "notification.mark_read", skip_all, err)]
pub async fn mark_notification_read(id: String) -> Result<(), ServerFnError> {
    let Some(session_user) = &auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let notification_id = id
        .parse()
        .map_err(|_| ServerFnError::new("no such notification"))?;
    let shared = crate::shared::get();
    edda_db::NotificationRepo::mark_read(&shared.pool, session_user.user.id, notification_id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

#[get("/api/settings/email-notifications", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "settings.email_notifications.get", skip_all, err)]
pub async fn get_email_notifications_enabled() -> Result<bool, ServerFnError> {
    let Some(session_user) = &auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let shared = crate::shared::get();
    edda_db::UserRepo::email_notifications_enabled(&shared.pool, session_user.user.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))
}

#[post("/api/settings/email-notifications", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "settings.email_notifications.set", skip_all, err)]
pub async fn set_email_notifications_enabled(enabled: bool) -> Result<(), ServerFnError> {
    let Some(session_user) = &auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let shared = crate::shared::get();
    edda_db::UserRepo::set_email_notifications_enabled(&shared.pool, session_user.user.id, enabled)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

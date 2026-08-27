//! `webhooks`/`webhook_deliveries` persistence. `secret_ciphertext` is
//! opaque bytes here — encryption/decryption is `edda_auth::secret_box`'s
//! job; this repo only ever stores or returns the ciphertext as-is, never
//! interprets it.

use edda_domain::{
    RepositoryId, Webhook, WebhookDelivery, WebhookDeliveryId, WebhookEvent, WebhookId,
};

use crate::{get_bool, get_bytes, get_i64, get_opt_i64, get_string, Backend, DbConn, DbError};

fn events_to_json(events: &[WebhookEvent]) -> String {
    serde_json::to_string(events).expect("WebhookEvent list always serializes")
}

fn events_from_json(json: &str) -> Vec<WebhookEvent> {
    serde_json::from_str(json).expect("stored webhook events are a valid JSON array")
}

fn row_to_webhook(
    id: String,
    repository_id: String,
    target_url: String,
    events: String,
    active: bool,
    created_at: i64,
) -> Webhook {
    Webhook {
        id: id.parse().expect("stored webhook id is a valid UUID"),
        repository_id: repository_id
            .parse()
            .expect("stored repository id is a valid UUID"),
        target_url,
        events: events_from_json(&events),
        active,
        created_at,
    }
}

pub struct WebhookRepo;

impl WebhookRepo {
    pub async fn insert<'c>(
        db: impl DbConn<'c>,
        id: WebhookId,
        repository_id: RepositoryId,
        target_url: &str,
        secret_ciphertext: &[u8],
        events: &[WebhookEvent],
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let events_json = events_to_json(events);
        let created_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO webhooks (id, repository_id, target_url, secret_ciphertext, events, active, created_at)
                 VALUES ($1, $2, $3, $4, $5, 1, $6)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO webhooks (id, repository_id, target_url, secret_ciphertext, events, active, created_at)
                 VALUES (?, ?, ?, ?, ?, 1, ?)"
            }
        };
        sqlx::query(sql)
            .bind(id.to_string())
            .bind(repository_id.to_string())
            .bind(target_url)
            .bind(secret_ciphertext)
            .bind(&events_json)
            .bind(created_at)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    pub async fn list_for_repository<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
    ) -> Result<Vec<Webhook>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, repository_id, target_url, events, active, created_at FROM webhooks WHERE repository_id = $1 ORDER BY created_at DESC"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, repository_id, target_url, events, active, created_at FROM webhooks WHERE repository_id = ? ORDER BY created_at DESC"
            }
        };
        let rows = sqlx::query(sql)
            .bind(repository_id.to_string())
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(row_to_webhook(
                    get_string(&row, "id")?,
                    get_string(&row, "repository_id")?,
                    get_string(&row, "target_url")?,
                    get_string(&row, "events")?,
                    get_bool(&row, "active")?,
                    get_i64(&row, "created_at")?,
                ))
            })
            .collect()
    }

    /// Every active webhook in `repository_id` subscribed to `event` — the
    /// fan-out set a `DomainEvent` dispatches jobs to. Filtering by
    /// subscription happens in Rust (`Webhook::is_subscribed_to`), not a
    /// SQL `WHERE events LIKE ...` on the JSON column — repository webhook
    /// counts are small, and a JSON substring match on `events` would be
    /// both slower to reason about and wrong at the edges (e.g. matching
    /// `"push"` inside `"pull_request.opened"` — sorry, doesn't actually
    /// collide, but the general class of JSON-as-string matching bugs is
    /// exactly why this filters in application code instead).
    pub async fn find_subscribed<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
        event: WebhookEvent,
    ) -> Result<Vec<Webhook>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let all = Self::list_for_repository(&mut h, repository_id).await?;
        Ok(all
            .into_iter()
            .filter(|webhook| webhook.is_subscribed_to(event))
            .collect())
    }

    pub async fn find_by_id<'c>(
        db: impl DbConn<'c>,
        id: WebhookId,
    ) -> Result<Option<Webhook>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, repository_id, target_url, events, active, created_at FROM webhooks WHERE id = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, repository_id, target_url, events, active, created_at FROM webhooks WHERE id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(id.to_string())
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(|row| {
            Ok(row_to_webhook(
                get_string(&row, "id")?,
                get_string(&row, "repository_id")?,
                get_string(&row, "target_url")?,
                get_string(&row, "events")?,
                get_bool(&row, "active")?,
                get_i64(&row, "created_at")?,
            ))
        })
        .transpose()
    }

    /// The decrypted-at-rest-but-still-ciphertext-here secret bytes for
    /// `id` — only ever called by the delivery job handler, right before
    /// it calls `edda_auth::secret_box::decrypt` and signs an outgoing
    /// payload. Never joined into any other query in this file, so a
    /// listing/display read has no path that accidentally pulls it along.
    pub async fn find_secret_ciphertext<'c>(
        db: impl DbConn<'c>,
        id: WebhookId,
    ) -> Result<Option<Vec<u8>>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => "SELECT secret_ciphertext FROM webhooks WHERE id = $1",
            Backend::Sqlite | Backend::MySql => {
                "SELECT secret_ciphertext FROM webhooks WHERE id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(id.to_string())
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(|row| get_bytes(&row, "secret_ciphertext").map_err(DbError::from))
            .transpose()
    }

    pub async fn delete<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
        id: WebhookId,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => "DELETE FROM webhooks WHERE id = $1 AND repository_id = $2",
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM webhooks WHERE id = ? AND repository_id = ?"
            }
        };
        let result = sqlx::query(sql)
            .bind(id.to_string())
            .bind(repository_id.to_string())
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[allow(clippy::too_many_arguments)]
fn row_to_delivery(
    id: String,
    webhook_id: String,
    event: String,
    payload: String,
    response_status: Option<i64>,
    attempt_count: i64,
    delivered_at: Option<i64>,
    created_at: i64,
) -> WebhookDelivery {
    WebhookDelivery {
        id: id.parse().expect("stored delivery id is a valid UUID"),
        webhook_id: webhook_id
            .parse()
            .expect("stored webhook id is a valid UUID"),
        event: WebhookEvent::from_wire_str(&event).expect("stored webhook event is a known value"),
        payload,
        response_status: response_status.map(|status| status as i32),
        attempt_count: attempt_count as i32,
        delivered_at,
        created_at,
    }
}

pub struct WebhookDeliveryRepo;

impl WebhookDeliveryRepo {
    pub async fn insert<'c>(
        db: impl DbConn<'c>,
        id: WebhookDeliveryId,
        webhook_id: WebhookId,
        event: WebhookEvent,
        payload: &str,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let created_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO webhook_deliveries (id, webhook_id, event, payload, attempt_count, created_at)
                 VALUES ($1, $2, $3, $4, 0, $5)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO webhook_deliveries (id, webhook_id, event, payload, attempt_count, created_at)
                 VALUES (?, ?, ?, ?, 0, ?)"
            }
        };
        sqlx::query(sql)
            .bind(id.to_string())
            .bind(webhook_id.to_string())
            .bind(event.as_wire_str())
            .bind(payload)
            .bind(created_at)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// Records one delivery attempt's outcome — `response_status: None`
    /// means the request itself failed (network error, blocked by the
    /// SSRF check) rather than the target responding with an error status.
    pub async fn record_attempt<'c>(
        db: impl DbConn<'c>,
        id: WebhookDeliveryId,
        attempt_count: i32,
        response_status: Option<i32>,
        delivered: bool,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let delivered_at = if delivered {
            Some(crate::now_unix())
        } else {
            None
        };
        let sql = match h.backend() {
            Backend::Postgres => {
                "UPDATE webhook_deliveries SET attempt_count = $1, response_status = $2, delivered_at = $3 WHERE id = $4"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE webhook_deliveries SET attempt_count = ?, response_status = ?, delivered_at = ? WHERE id = ?"
            }
        };
        sqlx::query(sql)
            .bind(attempt_count as i64)
            .bind(response_status.map(|status| status as i64))
            .bind(delivered_at)
            .bind(id.to_string())
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    pub async fn list_for_webhook<'c>(
        db: impl DbConn<'c>,
        webhook_id: WebhookId,
    ) -> Result<Vec<WebhookDelivery>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, webhook_id, event, payload, response_status, attempt_count, delivered_at, created_at
                 FROM webhook_deliveries WHERE webhook_id = $1 ORDER BY created_at DESC"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, webhook_id, event, payload, response_status, attempt_count, delivered_at, created_at
                 FROM webhook_deliveries WHERE webhook_id = ? ORDER BY created_at DESC"
            }
        };
        let rows = sqlx::query(sql)
            .bind(webhook_id.to_string())
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(row_to_delivery(
                    get_string(&row, "id")?,
                    get_string(&row, "webhook_id")?,
                    get_string(&row, "event")?,
                    get_string(&row, "payload")?,
                    get_opt_i64(&row, "response_status")?,
                    get_i64(&row, "attempt_count")?,
                    get_opt_i64(&row, "delivered_at")?,
                    get_i64(&row, "created_at")?,
                ))
            })
            .collect()
    }

    pub async fn find_by_id<'c>(
        db: impl DbConn<'c>,
        id: WebhookDeliveryId,
    ) -> Result<Option<WebhookDelivery>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, webhook_id, event, payload, response_status, attempt_count, delivered_at, created_at
                 FROM webhook_deliveries WHERE id = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, webhook_id, event, payload, response_status, attempt_count, delivered_at, created_at
                 FROM webhook_deliveries WHERE id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(id.to_string())
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(|row| {
            Ok(row_to_delivery(
                get_string(&row, "id")?,
                get_string(&row, "webhook_id")?,
                get_string(&row, "event")?,
                get_string(&row, "payload")?,
                get_opt_i64(&row, "response_status")?,
                get_i64(&row, "attempt_count")?,
                get_opt_i64(&row, "delivered_at")?,
                get_i64(&row, "created_at")?,
            ))
        })
        .transpose()
    }
}

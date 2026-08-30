//! The audit log's persistence boundary — a plain insert/list pair. The
//! *decision* of which events are security-relevant enough to record lives
//! in `edda_app::services::audit` (called by every mutating application
//! service and the raw auth/admin/OAuth routes); this repo just stores
//! whatever it's handed.

use edda_domain::AuditEventId;

use crate::{get_i64, get_opt_string, get_string, Backend, DbConn, DbError};

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub id: AuditEventId,
    pub occurred_at: i64,
    pub event_type: String,
    pub actor_id: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub detail_json: Option<String>,
}

pub struct AuditEventRepo;

impl AuditEventRepo {
    #[allow(clippy::too_many_arguments)]
    pub async fn insert<'c>(
        db: impl DbConn<'c>,
        id: AuditEventId,
        event_type: &str,
        actor_id: Option<&str>,
        target_type: Option<&str>,
        target_id: Option<&str>,
        detail_json: Option<&str>,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let occurred_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO audit_events (id, occurred_at, event_type, actor_id, target_type, target_id, detail_json)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO audit_events (id, occurred_at, event_type, actor_id, target_type, target_id, detail_json)
                 VALUES (?, ?, ?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(sql)
            .bind(&id_text)
            .bind(occurred_at)
            .bind(event_type)
            .bind(actor_id)
            .bind(target_type)
            .bind(target_id)
            .bind(detail_json)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// Most recent `limit` events, newest first — capped rather than
    /// paginated, matching this codebase's existing "no pagination yet,
    /// solo-developer scale" precedent (see `UserRepo::list_all`'s own
    /// comment on this).
    pub async fn list_recent<'c>(
        db: impl DbConn<'c>,
        limit: i64,
    ) -> Result<Vec<AuditEvent>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, occurred_at, event_type, actor_id, target_type, target_id, detail_json
                 FROM audit_events ORDER BY occurred_at DESC LIMIT $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, occurred_at, event_type, actor_id, target_type, target_id, detail_json
                 FROM audit_events ORDER BY occurred_at DESC LIMIT ?"
            }
        };
        let rows = sqlx::query(sql)
            .bind(limit)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter().map(row_to_event).collect()
    }

    /// Most recent `limit` events whose `event_type` starts with
    /// `prefix`, newest first — the admin audit view's one filter
    /// (e.g. `"admin."`, `"repository."`). An empty / `None` prefix is
    /// the same as [`Self::list_recent`].
    pub async fn list_filtered<'c>(
        db: impl DbConn<'c>,
        prefix: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AuditEvent>, DbError> {
        let Some(prefix) = prefix.filter(|p| !p.is_empty()) else {
            return Self::list_recent(db, limit).await;
        };
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, occurred_at, event_type, actor_id, target_type, target_id, detail_json
                 FROM audit_events WHERE event_type LIKE $1 ORDER BY occurred_at DESC LIMIT $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, occurred_at, event_type, actor_id, target_type, target_id, detail_json
                 FROM audit_events WHERE event_type LIKE ? ORDER BY occurred_at DESC LIMIT ?"
            }
        };
        // Our event types are fixed dotted identifiers — no `%`/`_` of
        // their own — so appending the wildcard here is safe.
        let rows = sqlx::query(sql)
            .bind(format!("{prefix}%"))
            .bind(limit)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter().map(row_to_event).collect()
    }
}

fn row_to_event(row: sqlx::any::AnyRow) -> Result<AuditEvent, DbError> {
    Ok(AuditEvent {
        id: get_string(&row, "id")?
            .parse()
            .expect("stored audit event id is a valid UUID"),
        occurred_at: get_i64(&row, "occurred_at")?,
        event_type: get_string(&row, "event_type")?,
        actor_id: get_opt_string(&row, "actor_id")?,
        target_type: get_opt_string(&row, "target_type")?,
        target_id: get_opt_string(&row, "target_id")?,
        detail_json: get_opt_string(&row, "detail_json")?,
    })
}

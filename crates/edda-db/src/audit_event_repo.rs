//! The audit log's persistence boundary — a plain insert/list pair. The
//! *decision* of which events are security-relevant enough to record
//! lives in `edda_telemetry::audit` (the `tracing_subscriber::Layer` that
//! captures them); this repo just stores whatever it's handed.

use edda_domain::AuditEventId;

use crate::{get_i64, get_opt_string, get_string, Backend, DbPool};

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
    pub async fn insert(
        pool: &DbPool,
        id: AuditEventId,
        event_type: &str,
        actor_id: Option<&str>,
        target_type: Option<&str>,
        target_id: Option<&str>,
        detail_json: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        let occurred_at = crate::now_unix();
        let sql = match pool.backend {
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
            .execute(&pool.any)
            .await?;
        Ok(())
    }

    /// Most recent `limit` events, newest first — capped rather than
    /// paginated, matching this codebase's existing "no pagination yet,
    /// solo-developer scale" precedent (see `UserRepo::list_all`'s own
    /// comment on this).
    pub async fn list_recent(pool: &DbPool, limit: i64) -> Result<Vec<AuditEvent>, sqlx::Error> {
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT id, occurred_at, event_type, actor_id, target_type, target_id, detail_json
                 FROM audit_events ORDER BY occurred_at DESC LIMIT $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, occurred_at, event_type, actor_id, target_type, target_id, detail_json
                 FROM audit_events ORDER BY occurred_at DESC LIMIT ?"
            }
        };
        let rows = sqlx::query(sql).bind(limit).fetch_all(&pool.any).await?;
        rows.into_iter()
            .map(|row| {
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
            })
            .collect()
    }
}

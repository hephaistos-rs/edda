//! `AuditLog` — the one path every application service (and the raw auth /
//! admin / OAuth routes) writes a security-relevant event through (S11).
//!
//! Best-effort: a failure to record an audit row is logged, never
//! propagated to fail the operation it describes — the same stance the
//! pre-Phase-8 ad-hoc `record()` helpers took, now unified here so
//! `detail_json` is populated consistently and there's a single place that
//! decides the row shape.

use edda_db::DbPool;
use edda_domain::AuditEventId;

/// One audit row's payload. `detail` is any JSON-serializable value with
/// the human-relevant specifics of the action (repo identity, target name,
/// role, direction) — **never** a credential, token, or secret.
pub struct AuditEntry<'a> {
    pub event_type: &'a str,
    pub actor_id: Option<&'a str>,
    pub target_type: Option<&'a str>,
    pub target_id: Option<&'a str>,
    pub detail: Option<serde_json::Value>,
}

impl<'a> AuditEntry<'a> {
    /// An entry for an action a user took on a named target.
    #[must_use]
    pub fn new(event_type: &'a str, actor_id: &'a str) -> Self {
        Self {
            event_type,
            actor_id: Some(actor_id),
            target_type: None,
            target_id: None,
            detail: None,
        }
    }

    #[must_use]
    pub fn target(mut self, target_type: &'a str, target_id: &'a str) -> Self {
        self.target_type = Some(target_type);
        self.target_id = Some(target_id);
        self
    }

    #[must_use]
    pub fn detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = Some(detail);
        self
    }
}

/// Writes `entry`. Never fails the caller.
pub async fn record(pool: &DbPool, entry: AuditEntry<'_>) {
    let detail_json = entry.detail.map(|value| value.to_string());
    if let Err(err) = edda_db::AuditEventRepo::insert(
        pool,
        AuditEventId::new(),
        entry.event_type,
        entry.actor_id,
        entry.target_type,
        entry.target_id,
        detail_json.as_deref(),
    )
    .await
    {
        tracing::warn!(
            error = %err,
            event_type = entry.event_type,
            "failed to write audit event"
        );
    }
}

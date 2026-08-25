-- The audit log, built directly from the `tracing::instrument`d spans
-- already present on every mutating operation (`edda_telemetry::audit`
-- is a `tracing_subscriber::Layer` that captures security-relevant
-- events into this table) rather than a bespoke logging call added
-- per-site — this reuses instrumentation that already exists everywhere
-- a mutation happens, instead of hand-adding a second logging call at
-- every one of those sites. `actor_id` is nullable (a failed-login
-- attempt against an unknown username has no
-- resolved actor yet) and `ON DELETE SET NULL` (a deleted user's past
-- audit trail is retained, not cascaded away). `detail_json` carries
-- event-specific fields (e.g. an SSH key's fingerprint, a token's name)
-- as a JSON object rather than a fixed column per event type, since the
-- field set genuinely varies by `event_type`.
CREATE TABLE audit_events (
    id          TEXT PRIMARY KEY NOT NULL,
    occurred_at INTEGER NOT NULL DEFAULT (unixepoch()),
    event_type  TEXT NOT NULL,
    actor_id    TEXT REFERENCES users(id) ON DELETE SET NULL,
    target_type TEXT,
    target_id   TEXT,
    detail_json TEXT
) STRICT;

CREATE INDEX idx_audit_events_occurred_at ON audit_events(occurred_at);
CREATE INDEX idx_audit_events_actor ON audit_events(actor_id);

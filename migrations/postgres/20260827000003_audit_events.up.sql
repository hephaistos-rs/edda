-- PostgreSQL counterpart of sqlite/20260827000003_audit_events.up.sql.
CREATE TABLE audit_events (
    id          TEXT PRIMARY KEY NOT NULL,
    occurred_at BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    event_type  TEXT NOT NULL,
    actor_id    TEXT REFERENCES users(id) ON DELETE SET NULL,
    target_type TEXT,
    target_id   TEXT,
    detail_json TEXT
);

CREATE INDEX idx_audit_events_occurred_at ON audit_events(occurred_at);
CREATE INDEX idx_audit_events_actor ON audit_events(actor_id);

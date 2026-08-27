-- PostgreSQL counterpart of sqlite/20260831000001_events.up.sql.
CREATE TABLE events (
    id             TEXT PRIMARY KEY NOT NULL,
    occurred_at    BIGINT NOT NULL,
    aggregate_type TEXT NOT NULL,
    aggregate_id   TEXT NOT NULL,
    kind           TEXT NOT NULL,
    payload_json   TEXT NOT NULL,
    processed_at   BIGINT
);

CREATE INDEX idx_events_unprocessed ON events(occurred_at) WHERE processed_at IS NULL;

CREATE INDEX idx_events_aggregate ON events(aggregate_type, aggregate_id);

-- MySQL/MariaDB counterpart of sqlite/20260831000001_events.up.sql.
-- `payload_json` is a bounded `VARCHAR`, not `TEXT` — the `Any`-decodes-
-- MySQL-`TEXT`-as-`BLOB` reason explained in the `repositories` migration;
-- 8192 matches the `jobs.payload` precedent. A serialized `DomainEvent` is
-- a handful of UUIDs and an enum tag, far inside that.
--
-- No partial index (`... WHERE processed_at IS NULL`) — MySQL/MariaDB have
-- none. A plain composite on `(processed_at, occurred_at)` still serves the
-- dispatcher's `WHERE processed_at IS NULL ORDER BY occurred_at` scan (the
-- leading equality column narrows to the NULL group, the second orders
-- within it), the same fallback the `repo_access` one-owner index uses.
CREATE TABLE events (
    id             VARCHAR(36) PRIMARY KEY NOT NULL,
    occurred_at    BIGINT NOT NULL,
    aggregate_type VARCHAR(64) NOT NULL,
    aggregate_id   VARCHAR(36) NOT NULL,
    kind           VARCHAR(64) NOT NULL,
    payload_json   VARCHAR(8192) NOT NULL,
    processed_at   BIGINT
);

CREATE INDEX idx_events_unprocessed ON events(processed_at, occurred_at);

CREATE INDEX idx_events_aggregate ON events(aggregate_type, aggregate_id);

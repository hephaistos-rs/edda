-- MySQL/MariaDB counterpart of sqlite/20260827000003_audit_events.up.sql.
-- `event_type`/`target_type`/`target_id` are `VARCHAR`, not `TEXT` (the
-- `Any`-decodes-MySQL-`TEXT`-as-`BLOB` reason explained in the
-- `repositories` migration); `detail_json` is generously bounded for the
-- same reason.
CREATE TABLE audit_events (
    id          VARCHAR(36) PRIMARY KEY NOT NULL,
    occurred_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    event_type  VARCHAR(128) NOT NULL,
    actor_id    VARCHAR(36),
    target_type VARCHAR(64),
    target_id   VARCHAR(255),
    detail_json VARCHAR(4096),
    CONSTRAINT fk_audit_events_actor FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_audit_events_occurred_at ON audit_events(occurred_at);
CREATE INDEX idx_audit_events_actor ON audit_events(actor_id);

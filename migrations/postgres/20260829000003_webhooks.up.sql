-- PostgreSQL counterpart of sqlite/20260829000003_webhooks.up.sql. `BLOB`
-- becomes `BYTEA`.
CREATE TABLE webhooks (
    id                TEXT PRIMARY KEY NOT NULL,
    repository_id     TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    target_url        TEXT NOT NULL,
    secret_ciphertext BYTEA NOT NULL,
    events            TEXT NOT NULL,
    active            INTEGER NOT NULL DEFAULT 1,
    created_at        BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE INDEX idx_webhooks_repository ON webhooks(repository_id);

CREATE TABLE webhook_deliveries (
    id              TEXT PRIMARY KEY NOT NULL,
    webhook_id      TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event           TEXT NOT NULL,
    payload         TEXT NOT NULL,
    response_status INTEGER,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    delivered_at    BIGINT,
    created_at      BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);

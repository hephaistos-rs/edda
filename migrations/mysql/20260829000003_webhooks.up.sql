-- MySQL/MariaDB counterpart of sqlite/20260829000003_webhooks.up.sql.
-- `target_url`/`events`/`payload` are bounded `VARCHAR`, not `TEXT` — the
-- `Any`-decodes-MySQL-`TEXT`-as-`BLOB` reason explained in the
-- `repositories` migration. `secret_ciphertext` stays `BLOB`, correct
-- because that column *is* decoded as raw bytes (same reasoning as
-- `totp_secrets.secret_ciphertext`).
CREATE TABLE webhooks (
    id                VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id     VARCHAR(36) NOT NULL,
    target_url        VARCHAR(2048) NOT NULL,
    secret_ciphertext BLOB NOT NULL,
    events            VARCHAR(2048) NOT NULL,
    active            INTEGER NOT NULL DEFAULT 1,
    created_at        BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_webhooks_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE INDEX idx_webhooks_repository ON webhooks(repository_id);

CREATE TABLE webhook_deliveries (
    id              VARCHAR(36) PRIMARY KEY NOT NULL,
    webhook_id      VARCHAR(36) NOT NULL,
    event           VARCHAR(64) NOT NULL,
    payload         VARCHAR(8192) NOT NULL,
    response_status INTEGER,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    delivered_at    BIGINT,
    created_at      BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_webhook_deliveries_webhook FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
);

CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);

-- `secret_ciphertext` is the HMAC signing secret, AES-256-GCM-encrypted at
-- rest under `EDDA_SECRET_KEY` (`edda_auth::secret_box` — the same
-- primitive `totp_secrets.secret_ciphertext` already uses, widened from
-- TOTP-only to any secret this workspace needs to recover in full rather
-- than merely verify). `events` is a JSON array of
-- `edda_domain::WebhookEvent` wire strings (e.g. `["pull_request.merged"]`)
-- — a set-valued, occasionally-extended enum, so JSON per this workspace's
-- own enum-representation rule, not a join table.
CREATE TABLE webhooks (
    id                TEXT PRIMARY KEY NOT NULL,
    repository_id     TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    target_url        TEXT NOT NULL,
    secret_ciphertext BLOB NOT NULL,
    events            TEXT NOT NULL,
    active            INTEGER NOT NULL DEFAULT 1,
    created_at        INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_webhooks_repository ON webhooks(repository_id);

-- One row per delivery attempt — this *is* the job-execution record,
-- also directly user-visible as a "recent deliveries" list and queried
-- independently of the `jobs` table's own bookkeeping.
CREATE TABLE webhook_deliveries (
    id              TEXT PRIMARY KEY NOT NULL,
    webhook_id      TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event           TEXT NOT NULL,
    payload         TEXT NOT NULL,
    response_status INTEGER,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    delivered_at    INTEGER,
    created_at      INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);

-- MySQL/MariaDB counterpart of sqlite/20260829000001_jobs.up.sql. `payload`/
-- `last_error` are bounded `VARCHAR`, not `TEXT` — the `Any`-decodes-MySQL-
-- `TEXT`-as-`BLOB` reason explained in the `repositories` migration; 8192
-- matches the `webauthn_credentials.passkey_json` precedent.
CREATE TABLE jobs (
    id           VARCHAR(36) PRIMARY KEY NOT NULL,
    payload      VARCHAR(8192) NOT NULL,
    status       VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    run_at       BIGINT NOT NULL,
    last_error   VARCHAR(2048),
    created_at   BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP())
);

CREATE INDEX idx_jobs_status_run_at ON jobs(status, run_at);

-- MySQL/MariaDB counterpart of sqlite/20260901000002_login_attempts.up.sql.
-- `attempt_key` is `lower(email)|ip` — an email is at most 254 chars and an
-- IP at most 45, so `VARCHAR(320)` covers it and can be a `PRIMARY KEY`
-- (`TEXT` cannot without a prefix length).
CREATE TABLE login_attempts (
    attempt_key     VARCHAR(320) PRIMARY KEY NOT NULL,
    failure_count   INTEGER NOT NULL DEFAULT 0,
    first_failed_at BIGINT NOT NULL,
    last_failed_at  BIGINT NOT NULL,
    locked_until    BIGINT
);

-- PostgreSQL counterpart of sqlite/20260901000002_login_attempts.up.sql.
CREATE TABLE login_attempts (
    attempt_key     TEXT PRIMARY KEY NOT NULL,
    failure_count   INTEGER NOT NULL DEFAULT 0,
    first_failed_at BIGINT NOT NULL,
    last_failed_at  BIGINT NOT NULL,
    locked_until    BIGINT
);

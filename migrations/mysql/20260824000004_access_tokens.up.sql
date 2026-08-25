-- MySQL/MariaDB counterpart of sqlite/20260824000004_access_tokens.up.sql
-- (plan.local.md §17 Phase 3, revised 2026-08-25). `token_hash` is a
-- hex-encoded SHA-256 digest (always 64 characters) — `VARCHAR(64)`, not
-- `TEXT`, so it can carry a plain `UNIQUE` constraint. `repository_scope`
-- is `VARCHAR`, not `TEXT`, for the same `Any`-decodes-MySQL-`TEXT`-as-
-- `BLOB` reason explained in the `repositories` migration.
CREATE TABLE access_tokens (
    id                VARCHAR(36) PRIMARY KEY NOT NULL,
    user_id           VARCHAR(36) NOT NULL,
    name              VARCHAR(255) NOT NULL,
    token_hash        VARCHAR(64) NOT NULL UNIQUE,
    repository_scope  VARCHAR(2048) NOT NULL,
    created_at        BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    last_used_at      BIGINT,
    CONSTRAINT fk_access_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_access_tokens_user_id ON access_tokens(user_id);

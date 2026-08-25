-- MySQL/MariaDB counterpart of sqlite/20260825000001_ssh_keys.up.sql
-- (plan.local.md §17 Phase 3, revised 2026-08-25). `fingerprint`
-- (`SHA256:<base64>`) is bounded well under 128 characters in practice —
-- `VARCHAR(128)` so it can carry a plain `UNIQUE` constraint.
-- `public_key` is `VARCHAR`, not `TEXT`, for the same `Any`-decodes-
-- MySQL-`TEXT`-as-`BLOB` reason explained in the `repositories`
-- migration — 4096 is generous for even an RSA-4096 OpenSSH public key
-- plus a long comment.
CREATE TABLE ssh_keys (
    id            VARCHAR(36) PRIMARY KEY NOT NULL,
    user_id       VARCHAR(36) NOT NULL,
    fingerprint   VARCHAR(128) NOT NULL UNIQUE,
    public_key    VARCHAR(4096) NOT NULL,
    title         VARCHAR(255) NOT NULL,
    created_at    BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    last_used_at  BIGINT,
    CONSTRAINT fk_ssh_keys_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_ssh_keys_user_id ON ssh_keys(user_id);

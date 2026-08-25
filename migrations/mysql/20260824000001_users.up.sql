-- MySQL/MariaDB counterpart of sqlite/20260824000001_users.up.sql
-- (plan.local.md §17 Phase 3, revised 2026-08-25). No `STRICT` (neither
-- MySQL nor MariaDB has an equivalent table-level keyword — InnoDB is
-- already strictly typed for these column types). IDs are UUIDv7-as-text,
-- fixed at 36 characters, so `VARCHAR(36)` rather than `TEXT` — MySQL/
-- MariaDB can't put a plain `UNIQUE`/primary-key index on `TEXT` without
-- an explicit prefix length, and a bounded `VARCHAR` is the honest type
-- here anyway.
--
-- Case-insensitive uniqueness: a direct functional index
-- (`CREATE UNIQUE INDEX ... ((LOWER(username)))`, MySQL 8.0.13+ syntax)
-- is rejected by MariaDB — tried and confirmed against a real
-- `mariadb:12.3.3` instance while writing this migration. The portable
-- fix, working on both MySQL and MariaDB, is the same STORED-generated-
-- column technique used for the one-owner-per-repository invariant in
-- `repo_access`: a lowercased shadow column, unique-indexed directly
-- (an ordinary column index, not a functional one).
CREATE TABLE users (
    id             VARCHAR(36) PRIMARY KEY NOT NULL,
    username       VARCHAR(255) NOT NULL,
    username_lower VARCHAR(255) AS (LOWER(username)) STORED,
    email          VARCHAR(255) NOT NULL,
    email_lower    VARCHAR(255) AS (LOWER(email)) STORED,
    password_hash  VARCHAR(255) NOT NULL,
    created_at     BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP())
);

CREATE UNIQUE INDEX idx_users_username_ci ON users (username_lower);
CREATE UNIQUE INDEX idx_users_email_ci ON users (email_lower);

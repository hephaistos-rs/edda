-- MySQL/MariaDB counterpart of sqlite/20260824000002_repositories.up.sql
-- (plan.local.md §17 Phase 3, revised 2026-08-25). `description` is
-- `VARCHAR`, not `TEXT`: confirmed directly against `sqlx-mysql`'s
-- source (`any.rs`) that MySQL's wire protocol reports `TEXT` using the
-- same column-type code as `BLOB`, which `sqlx`'s `Any` layer maps to
-- `AnyTypeInfoKind::Blob` — decoding it as a Rust `String` then fails at
-- runtime ("mismatched types... not compatible with SQL type `BLOB`",
-- hit running this crate's own tests against a real MariaDB instance).
-- `VARCHAR` doesn't have this ambiguity. Every other column-width choice
-- here is explained in the `users` migration.
CREATE TABLE repositories (
    id             VARCHAR(36) PRIMARY KEY NOT NULL,
    owner_type     VARCHAR(16) NOT NULL CHECK (owner_type IN ('user')),
    owner_id       VARCHAR(36) NOT NULL,
    name           VARCHAR(255) NOT NULL,
    description    VARCHAR(1024),
    visibility     VARCHAR(16) NOT NULL CHECK (visibility IN ('public', 'private')),
    created_at     BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP())
);

CREATE UNIQUE INDEX idx_repositories_owner_name ON repositories(owner_type, owner_id, name);
CREATE INDEX idx_repositories_owner ON repositories(owner_type, owner_id);

-- PostgreSQL counterpart of sqlite/20260827000001_admin_and_disable.up.sql.
-- Kept as INTEGER (not native BOOLEAN) to match the decode path used for
-- this flag on every other backend, rather than adding a bool-specific
-- branch to `AnyRow` handling.
ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN disabled_at BIGINT;

-- MySQL/MariaDB counterpart of sqlite/20260827000001_admin_and_disable.up.sql.
ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN disabled_at BIGINT;

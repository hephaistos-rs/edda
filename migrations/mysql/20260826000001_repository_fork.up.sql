-- MySQL/MariaDB counterpart of sqlite/20260826000001_repository_fork.up.sql.
-- `VARCHAR(36)`, not `TEXT`, matching every other id-shaped column in this
-- chain (UUIDv7-as-text is fixed at 36 characters).
ALTER TABLE repositories ADD COLUMN forked_from VARCHAR(36);

CREATE INDEX idx_repositories_forked_from ON repositories(forked_from);

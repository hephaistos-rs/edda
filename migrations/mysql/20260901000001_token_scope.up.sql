-- MySQL/MariaDB counterpart of sqlite/20260901000001_token_scope.up.sql.
-- `VARCHAR`, not `TEXT`, for the same `Any`-decodes-MySQL-`TEXT`-as-`BLOB`
-- reason as `repository_scope` in the `access_tokens` migration.
ALTER TABLE access_tokens ADD COLUMN token_scope VARCHAR(255) NOT NULL DEFAULT '"All"';

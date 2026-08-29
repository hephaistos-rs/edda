-- MySQL/MariaDB counterpart of sqlite/20260901000003_deploy_keys.up.sql.
-- `fingerprint` / `public_key` sizing matches the `ssh_keys` migration
-- (bounded `VARCHAR`, not `TEXT`, so `fingerprint` can be `UNIQUE`).
CREATE TABLE deploy_keys (
    id            VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id VARCHAR(36) NOT NULL,
    fingerprint   VARCHAR(128) NOT NULL UNIQUE,
    public_key    VARCHAR(4096) NOT NULL,
    title         VARCHAR(255) NOT NULL,
    read_only     INTEGER NOT NULL DEFAULT 1,
    created_at    BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    last_used_at  BIGINT,
    CONSTRAINT fk_deploy_keys_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE INDEX idx_deploy_keys_repository_id ON deploy_keys(repository_id);

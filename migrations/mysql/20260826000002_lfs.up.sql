-- MySQL/MariaDB counterpart of sqlite/20260826000002_lfs.up.sql.
-- `oid` is a hex-encoded SHA-256 digest (always 64 characters) —
-- `VARCHAR(64)`. `storage_key`/`path` are `VARCHAR`, not `TEXT`, for the
-- same `Any`-decodes-MySQL-`TEXT`-as-`BLOB` reason explained in the
-- `repositories` migration.
CREATE TABLE lfs_objects (
    repository_id VARCHAR(36) NOT NULL,
    oid           VARCHAR(64) NOT NULL,
    size_bytes    BIGINT NOT NULL,
    storage_key   VARCHAR(512) NOT NULL,
    created_at    BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    PRIMARY KEY (repository_id, oid),
    CONSTRAINT fk_lfs_objects_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE TABLE lfs_locks (
    id            VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id VARCHAR(36) NOT NULL,
    path          VARCHAR(1024) NOT NULL,
    owner_id      VARCHAR(36) NOT NULL,
    created_at    BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_lfs_locks_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
    CONSTRAINT fk_lfs_locks_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- MySQL/MariaDB can't put a plain unique index directly on a `VARCHAR(1024)`
-- column without an explicit prefix length (InnoDB's index key-length
-- limit) — indexing a 255-byte prefix is enough to enforce uniqueness for
-- any realistic file path while staying within that limit.
CREATE UNIQUE INDEX idx_lfs_locks_repository_path ON lfs_locks(repository_id, path(255));

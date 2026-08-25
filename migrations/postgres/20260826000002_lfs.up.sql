-- PostgreSQL counterpart of sqlite/20260826000002_lfs.up.sql. No STRICT
-- (Postgres is natively strictly typed); BIGINT for timestamps, matching
-- every other Postgres migration in this chain.
CREATE TABLE lfs_objects (
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    oid           TEXT NOT NULL,
    size_bytes    BIGINT NOT NULL,
    storage_key   TEXT NOT NULL,
    created_at    BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    PRIMARY KEY (repository_id, oid)
);

CREATE TABLE lfs_locks (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    path          TEXT NOT NULL,
    owner_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE UNIQUE INDEX idx_lfs_locks_repository_path ON lfs_locks(repository_id, path);

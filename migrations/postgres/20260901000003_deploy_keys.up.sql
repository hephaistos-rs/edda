-- PostgreSQL counterpart of sqlite/20260901000003_deploy_keys.up.sql.
CREATE TABLE deploy_keys (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint   TEXT NOT NULL UNIQUE,
    public_key    TEXT NOT NULL,
    title         TEXT NOT NULL,
    read_only     INTEGER NOT NULL DEFAULT 1,
    created_at    BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    last_used_at  BIGINT
);

CREATE INDEX idx_deploy_keys_repository_id ON deploy_keys(repository_id);

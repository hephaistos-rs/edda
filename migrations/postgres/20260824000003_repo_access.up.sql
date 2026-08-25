-- PostgreSQL counterpart of sqlite/20260824000003_repo_access.up.sql.
-- The one-owner-per-repository partial unique index is supported
-- natively by PostgreSQL (unlike MySQL/MariaDB, which needs the
-- generated-column workaround in the mysql migration) — kept unchanged.
CREATE TABLE repo_access (
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role          TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin', 'owner')),
    added_at      BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    PRIMARY KEY (repository_id, user_id)
);

CREATE INDEX idx_repo_access_repository_id ON repo_access(repository_id);

CREATE UNIQUE INDEX idx_repo_access_one_owner ON repo_access(repository_id) WHERE role = 'owner';

-- PostgreSQL counterpart of sqlite/20260824000002_repositories.up.sql
-- (plan.local.md §17 Phase 3). Identical shape to the SQLite version — no
-- portability hazards in this table (see that file's comments for the
-- polymorphic-owner reasoning, unchanged here).
CREATE TABLE repositories (
    id             TEXT PRIMARY KEY NOT NULL,
    owner_type     TEXT NOT NULL CHECK (owner_type IN ('user')),
    owner_id       TEXT NOT NULL,
    name           TEXT NOT NULL,
    description    TEXT,
    visibility     TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
    created_at     BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE UNIQUE INDEX idx_repositories_owner_name ON repositories(owner_type, owner_id, name);
CREATE INDEX idx_repositories_owner ON repositories(owner_type, owner_id);

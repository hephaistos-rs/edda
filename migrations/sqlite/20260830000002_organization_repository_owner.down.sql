-- Reverses the widening: any organization-owned repository is dropped
-- first (its `repo_access`/`pull_requests`/etc. rows cascade with it, same
-- as any other repository deletion) since the narrowed CHECK can no longer
-- store `owner_type = 'organization'` rows at all.
DELETE FROM repositories WHERE owner_type = 'organization';

CREATE TABLE repositories_old (
    id             TEXT PRIMARY KEY NOT NULL,
    owner_type     TEXT NOT NULL CHECK (owner_type IN ('user')),
    owner_id       TEXT NOT NULL,
    name           TEXT NOT NULL,
    description    TEXT,
    visibility     TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
    created_at     INTEGER NOT NULL DEFAULT (unixepoch()),
    forked_from    TEXT
) STRICT;

INSERT INTO repositories_old (id, owner_type, owner_id, name, description, visibility, created_at, forked_from)
SELECT id, owner_type, owner_id, name, description, visibility, created_at, forked_from FROM repositories;

DROP TABLE repositories;
ALTER TABLE repositories_old RENAME TO repositories;

CREATE UNIQUE INDEX idx_repositories_owner_name ON repositories(owner_type, owner_id, name);
CREATE INDEX idx_repositories_owner ON repositories(owner_type, owner_id);
CREATE INDEX idx_repositories_forked_from ON repositories(forked_from);

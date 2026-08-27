-- Widens `repositories.owner_type`'s CHECK to admit 'organization', now
-- that the `organizations` table exists. SQLite can't ALTER a CHECK
-- constraint in place, so this follows SQLite's own documented table-
-- rebuild procedure for schema changes ALTER TABLE doesn't support
-- directly (https://www.sqlite.org/lang_altertable.html, "Making Other
-- Kinds Of Table Schema Changes"): create the widened table under a new
-- name, copy every existing row across unchanged (they're all still
-- `owner_type = 'user'`), drop the old table, and rename the new one into
-- its place.
--
-- `repo_access`, `pull_requests`, `issues`, `releases`, `webhooks`, and
-- `branch_protection_rules` all reference `repositories(id)` by foreign
-- key. `DROP TABLE` of a table other rows still reference *does* fail
-- with `foreign_keys` enforcement on (confirmed directly, not assumed) —
-- `edda_db::run_migrations` dedicates one connection to the whole SQLite
-- migration run and disables `PRAGMA foreign_keys` on it before this file
-- runs specifically so this rebuild is possible, then re-enables it
-- afterward. Every referencing row's `repository_id` value is untouched
-- by this migration (only `repositories.id` values are copied across,
-- unchanged), so once the rename completes every foreign key resolves
-- exactly as it did before.
CREATE TABLE repositories_new (
    id             TEXT PRIMARY KEY NOT NULL,
    owner_type     TEXT NOT NULL CHECK (owner_type IN ('user', 'organization')),
    owner_id       TEXT NOT NULL,
    name           TEXT NOT NULL,
    description    TEXT,
    visibility     TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
    created_at     INTEGER NOT NULL DEFAULT (unixepoch()),
    forked_from    TEXT
) STRICT;

INSERT INTO repositories_new (id, owner_type, owner_id, name, description, visibility, created_at, forked_from)
SELECT id, owner_type, owner_id, name, description, visibility, created_at, forked_from FROM repositories;

DROP TABLE repositories;
ALTER TABLE repositories_new RENAME TO repositories;

CREATE UNIQUE INDEX idx_repositories_owner_name ON repositories(owner_type, owner_id, name);
CREATE INDEX idx_repositories_owner ON repositories(owner_type, owner_id);
CREATE INDEX idx_repositories_forked_from ON repositories(forked_from);

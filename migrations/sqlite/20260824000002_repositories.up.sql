-- A repository is a first-class row with a stable id — the `{owner}/{repo}`
-- string is how a repo is addressed in URLs and clone paths, but it's
-- derived (via a join to the owning account) and enforced unique below,
-- not treated as the primary key.
--
-- `owner_type`/`owner_id` are a polymorphic reference rather than a plain
-- `owner_id REFERENCES users(id)` foreign key: SQLite can't express a
-- foreign key that targets one of two different tables depending on a
-- sibling column, and organizations don't exist yet to be the second
-- target. Only `'user'` is accepted today; the
-- `CHECK` widens (and, ideally, a real foreign-key-shaped constraint is
-- reconsidered) in the migration that introduces organizations.
-- No `default_branch` (or any other column `gix` can answer): that data
-- lives only in the actual git repository, read live by `edda-git`, so it
-- can never drift from what a `git clone` of the same repo would show.
CREATE TABLE repositories (
    id             TEXT PRIMARY KEY NOT NULL,
    owner_type     TEXT NOT NULL CHECK (owner_type IN ('user')),
    owner_id       TEXT NOT NULL,
    name           TEXT NOT NULL,
    description    TEXT,
    visibility     TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
    created_at     INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

-- A given owner can't have two repositories with the same name — this is
-- the uniqueness the old filesystem-path identity model got for free from
-- the filesystem itself; it now has to be a real database constraint.
CREATE UNIQUE INDEX idx_repositories_owner_name ON repositories(owner_type, owner_id, name);
CREATE INDEX idx_repositories_owner ON repositories(owner_type, owner_id);

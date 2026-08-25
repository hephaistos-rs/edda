-- Four-tier role model (Read/Write/Admin/Owner). `user_id` is a direct
-- foreign key (not the polymorphic pattern `repositories.owner_id` uses)
-- because there is no team/subject-kind widening needed before
-- organizations exist; a `subject_type`-style widening belongs in the
-- migration that introduces organizations, not pre-added now for
-- convenience.
CREATE TABLE repo_access (
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role          TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin', 'owner')),
    added_at      INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (repository_id, user_id)
) STRICT;

CREATE INDEX idx_repo_access_repository_id ON repo_access(repository_id);

-- Exactly one Owner grant per repository at all times — the invariant
-- `edda-domain`'s authorization functions assume holds.
CREATE UNIQUE INDEX idx_repo_access_one_owner ON repo_access(repository_id) WHERE role = 'owner';

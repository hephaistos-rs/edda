CREATE TABLE repo_access (
    repo_name  TEXT NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- 'owner': granted once, automatically, to whoever created the repo.
    -- 'collaborator': granted later, only by an owner. Both roles currently
    -- get identical write access (push, edit description, delete) — no
    -- finer-grained permission split yet.
    role       TEXT NOT NULL CHECK (role IN ('owner', 'collaborator')),
    added_at   INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (repo_name, user_id)
) STRICT;

CREATE INDEX idx_repo_access_repo_name ON repo_access(repo_name);

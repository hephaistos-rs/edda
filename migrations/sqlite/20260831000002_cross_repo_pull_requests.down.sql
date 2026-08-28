-- Reverts H4: reinstates the same-repository `CHECK` on `pull_requests`.
-- Any cross-repository pull requests created while it was lifted are
-- dropped (they can't satisfy the reinstated constraint) — a down
-- migration reverting a capability necessarily discards data that only
-- existed because of it.
CREATE TABLE pull_requests_new (
    id                   TEXT PRIMARY KEY NOT NULL,
    repository_id        TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    number               INTEGER NOT NULL,
    title                TEXT NOT NULL,
    body                 TEXT,
    author_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    source_branch        TEXT NOT NULL,
    target_branch        TEXT NOT NULL,
    state                TEXT NOT NULL CHECK (state IN ('open', 'draft', 'merged', 'closed')),
    merged_at            INTEGER,
    merge_commit         TEXT,
    merge_strategy       TEXT CHECK (merge_strategy IN ('merge')),
    closed_at            INTEGER,
    close_reason         TEXT CHECK (close_reason IN ('completed', 'not_planned')),
    created_at           INTEGER NOT NULL DEFAULT (unixepoch()),
    CHECK (source_repository_id = repository_id)
) STRICT;

INSERT INTO pull_requests_new (id, repository_id, number, title, body, author_id,
    source_repository_id, source_branch, target_branch, state, merged_at, merge_commit,
    merge_strategy, closed_at, close_reason, created_at)
SELECT id, repository_id, number, title, body, author_id,
    source_repository_id, source_branch, target_branch, state, merged_at, merge_commit,
    merge_strategy, closed_at, close_reason, created_at
FROM pull_requests
WHERE source_repository_id = repository_id;

DROP TABLE pull_requests;
ALTER TABLE pull_requests_new RENAME TO pull_requests;

CREATE UNIQUE INDEX idx_pull_requests_repo_number ON pull_requests(repository_id, number);
CREATE INDEX idx_pull_requests_repo_state ON pull_requests(repository_id, state);

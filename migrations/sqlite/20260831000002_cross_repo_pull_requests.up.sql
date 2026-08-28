-- Lifts the same-repository restriction on pull requests (plan.local.md
-- H4 / Phase 5): drops the table-level `CHECK (source_repository_id =
-- repository_id)` so a fork-sourced pull request — whose source branch
-- lives in a *different* repository than the target — can be stored.
-- Authorization for the cross-repo case is
-- `edda_domain::can_open_cross_repo_pull_request` (write on the fork +
-- read on upstream); the merge still writes only into the target and
-- never touches the fork.
--
-- SQLite can't drop a table `CHECK` in place, so this is SQLite's own
-- documented table-rebuild procedure (see
-- `20260830000002_organization_repository_owner` for the same dance and
-- the note that `edda_db::run_migrations` disables `PRAGMA foreign_keys`
-- for the whole SQLite migration run so a `DROP TABLE` of a table other
-- rows reference by foreign key is possible). Every referencing row's
-- `pull_request_id` / `source_repository_id` value is copied across
-- unchanged, so once the rename completes every foreign key resolves
-- exactly as before.
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
    created_at           INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

INSERT INTO pull_requests_new (id, repository_id, number, title, body, author_id,
    source_repository_id, source_branch, target_branch, state, merged_at, merge_commit,
    merge_strategy, closed_at, close_reason, created_at)
SELECT id, repository_id, number, title, body, author_id,
    source_repository_id, source_branch, target_branch, state, merged_at, merge_commit,
    merge_strategy, closed_at, close_reason, created_at
FROM pull_requests;

DROP TABLE pull_requests;
ALTER TABLE pull_requests_new RENAME TO pull_requests;

CREATE UNIQUE INDEX idx_pull_requests_repo_number ON pull_requests(repository_id, number);
CREATE INDEX idx_pull_requests_repo_state ON pull_requests(repository_id, state);

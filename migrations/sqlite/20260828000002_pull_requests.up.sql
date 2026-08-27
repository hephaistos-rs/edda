-- Pull requests. `source_repository_id`/`source_branch` model a PR's
-- source as a repository/branch pair (`edda_domain::PrRef`) so a future
-- cross-repo (fork-sourced) PR is representable without widening this
-- table — but only same-repository PRs are created today,
-- enforced here by the `CHECK` tying `source_repository_id` back to
-- `repository_id`, not just in application code.
--
-- `state`/`merged_at`/`merge_commit`/`merge_strategy`/`closed_at`/
-- `close_reason` together encode `edda_domain::PrState`'s four variants —
-- only the columns valid for the current `state` are ever non-NULL; the
-- domain layer reconstructs the enum from this shape, never the other
-- way around.
CREATE TABLE pull_requests (
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

CREATE UNIQUE INDEX idx_pull_requests_repo_number ON pull_requests(repository_id, number);
CREATE INDEX idx_pull_requests_repo_state ON pull_requests(repository_id, state);

-- A reviewer's verdict on a pull request. Append-only — a new review
-- never deletes an earlier one from the same reviewer, so review history
-- is preserved; `edda_domain::latest_reviews` decides which one counts
-- toward a required-approval-count check.
CREATE TABLE pr_reviews (
    id              TEXT PRIMARY KEY NOT NULL,
    pull_request_id TEXT NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
    reviewer_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state           TEXT NOT NULL CHECK (state IN ('approved', 'changes_requested', 'commented')),
    body            TEXT,
    created_at      INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_pr_reviews_pull_request ON pr_reviews(pull_request_id);

-- A pull-request comment, optionally anchored to one diff line/range in
-- one commit (`anchor_*` columns, all-NULL together or all-set together
-- — enforced by the `CHECK` below, not just convention). One table for
-- both anchored and general comments — see `edda_domain::PrComment`'s
-- doc comment for why this isn't split into two tables.
CREATE TABLE pr_comments (
    id                 TEXT PRIMARY KEY NOT NULL,
    pull_request_id    TEXT NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
    author_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body               TEXT NOT NULL,
    anchor_file_path   TEXT,
    anchor_line_start  INTEGER,
    anchor_line_end    INTEGER,
    anchor_commit_sha  TEXT,
    created_at         INTEGER NOT NULL DEFAULT (unixepoch()),
    CHECK (
        (anchor_file_path IS NULL AND anchor_line_start IS NULL AND anchor_line_end IS NULL AND anchor_commit_sha IS NULL)
        OR
        (anchor_file_path IS NOT NULL AND anchor_line_start IS NOT NULL AND anchor_line_end IS NOT NULL AND anchor_commit_sha IS NOT NULL)
    )
) STRICT;

CREATE INDEX idx_pr_comments_pull_request ON pr_comments(pull_request_id);

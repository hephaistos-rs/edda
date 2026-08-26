-- PostgreSQL counterpart of sqlite/20260828000002_pull_requests.up.sql.
CREATE TABLE pull_requests (
    id                   TEXT PRIMARY KEY NOT NULL,
    repository_id        TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    number               BIGINT NOT NULL,
    title                TEXT NOT NULL,
    body                 TEXT,
    author_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    source_branch        TEXT NOT NULL,
    target_branch        TEXT NOT NULL,
    state                TEXT NOT NULL CHECK (state IN ('open', 'draft', 'merged', 'closed')),
    merged_at            BIGINT,
    merge_commit         TEXT,
    merge_strategy       TEXT CHECK (merge_strategy IN ('merge')),
    closed_at            BIGINT,
    close_reason         TEXT CHECK (close_reason IN ('completed', 'not_planned')),
    created_at           BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    CHECK (source_repository_id = repository_id)
);

CREATE UNIQUE INDEX idx_pull_requests_repo_number ON pull_requests(repository_id, number);
CREATE INDEX idx_pull_requests_repo_state ON pull_requests(repository_id, state);

CREATE TABLE pr_reviews (
    id              TEXT PRIMARY KEY NOT NULL,
    pull_request_id TEXT NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
    reviewer_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state           TEXT NOT NULL CHECK (state IN ('approved', 'changes_requested', 'commented')),
    body            TEXT,
    created_at      BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE INDEX idx_pr_reviews_pull_request ON pr_reviews(pull_request_id);

CREATE TABLE pr_comments (
    id                 TEXT PRIMARY KEY NOT NULL,
    pull_request_id    TEXT NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
    author_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body               TEXT NOT NULL,
    anchor_file_path   TEXT,
    anchor_line_start  INTEGER,
    anchor_line_end    INTEGER,
    anchor_commit_sha  TEXT,
    created_at         BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    CHECK (
        (anchor_file_path IS NULL AND anchor_line_start IS NULL AND anchor_line_end IS NULL AND anchor_commit_sha IS NULL)
        OR
        (anchor_file_path IS NOT NULL AND anchor_line_start IS NOT NULL AND anchor_line_end IS NOT NULL AND anchor_commit_sha IS NOT NULL)
    )
);

CREATE INDEX idx_pr_comments_pull_request ON pr_comments(pull_request_id);

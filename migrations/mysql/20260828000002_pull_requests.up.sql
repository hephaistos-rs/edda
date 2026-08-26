-- MySQL/MariaDB counterpart of sqlite/20260828000002_pull_requests.up.sql.
-- `body` is `VARCHAR`, not `TEXT` — same `Any`-decodes-MySQL-`TEXT`-as-
-- `BLOB` reason explained in the `repositories` migration; 8192 matches
-- the `webauthn_credentials.passkey_json` precedent for "comfortably a
-- few KB, stays a plain VARCHAR."
CREATE TABLE pull_requests (
    id                   VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id        VARCHAR(36) NOT NULL,
    number               BIGINT NOT NULL,
    title                VARCHAR(255) NOT NULL,
    body                 VARCHAR(8192),
    author_id            VARCHAR(36) NOT NULL,
    source_repository_id VARCHAR(36) NOT NULL,
    source_branch        VARCHAR(255) NOT NULL,
    target_branch        VARCHAR(255) NOT NULL,
    state                VARCHAR(16) NOT NULL CHECK (state IN ('open', 'draft', 'merged', 'closed')),
    merged_at            BIGINT,
    merge_commit         VARCHAR(64),
    merge_strategy       VARCHAR(16) CHECK (merge_strategy IN ('merge')),
    closed_at            BIGINT,
    close_reason         VARCHAR(16) CHECK (close_reason IN ('completed', 'not_planned')),
    created_at           BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_pull_requests_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
    CONSTRAINT fk_pull_requests_author FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_pull_requests_source_repository FOREIGN KEY (source_repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
    CHECK (source_repository_id = repository_id)
);

CREATE UNIQUE INDEX idx_pull_requests_repo_number ON pull_requests(repository_id, number);
CREATE INDEX idx_pull_requests_repo_state ON pull_requests(repository_id, state);

CREATE TABLE pr_reviews (
    id              VARCHAR(36) PRIMARY KEY NOT NULL,
    pull_request_id VARCHAR(36) NOT NULL,
    reviewer_id     VARCHAR(36) NOT NULL,
    state           VARCHAR(32) NOT NULL CHECK (state IN ('approved', 'changes_requested', 'commented')),
    body            VARCHAR(8192),
    created_at      BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_pr_reviews_pull_request FOREIGN KEY (pull_request_id) REFERENCES pull_requests(id) ON DELETE CASCADE,
    CONSTRAINT fk_pr_reviews_reviewer FOREIGN KEY (reviewer_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_pr_reviews_pull_request ON pr_reviews(pull_request_id);

CREATE TABLE pr_comments (
    id                 VARCHAR(36) PRIMARY KEY NOT NULL,
    pull_request_id    VARCHAR(36) NOT NULL,
    author_id          VARCHAR(36) NOT NULL,
    body               VARCHAR(8192) NOT NULL,
    anchor_file_path   VARCHAR(1024),
    anchor_line_start  INTEGER,
    anchor_line_end    INTEGER,
    anchor_commit_sha  VARCHAR(64),
    created_at         BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_pr_comments_pull_request FOREIGN KEY (pull_request_id) REFERENCES pull_requests(id) ON DELETE CASCADE,
    CONSTRAINT fk_pr_comments_author FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE,
    CHECK (
        (anchor_file_path IS NULL AND anchor_line_start IS NULL AND anchor_line_end IS NULL AND anchor_commit_sha IS NULL)
        OR
        (anchor_file_path IS NOT NULL AND anchor_line_start IS NOT NULL AND anchor_line_end IS NOT NULL AND anchor_commit_sha IS NOT NULL)
    )
);

CREATE INDEX idx_pr_comments_pull_request ON pr_comments(pull_request_id);

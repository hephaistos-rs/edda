-- PostgreSQL counterpart of sqlite/20260828000003_issues.up.sql.
CREATE TABLE milestones (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    title         TEXT NOT NULL,
    description   TEXT,
    due_on        BIGINT,
    state         TEXT NOT NULL CHECK (state IN ('open', 'closed'))
);

CREATE INDEX idx_milestones_repository ON milestones(repository_id);

CREATE TABLE issues (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    number        BIGINT NOT NULL,
    title         TEXT NOT NULL,
    body          TEXT,
    author_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state         TEXT NOT NULL CHECK (state IN ('open', 'closed')),
    closed_at     BIGINT,
    close_reason  TEXT CHECK (close_reason IN ('completed', 'not_planned')),
    milestone_id  TEXT REFERENCES milestones(id) ON DELETE SET NULL,
    created_at    BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE UNIQUE INDEX idx_issues_repo_number ON issues(repository_id, number);
CREATE INDEX idx_issues_repo_state ON issues(repository_id, state);
CREATE INDEX idx_issues_milestone ON issues(milestone_id);

CREATE TABLE issue_comments (
    id         TEXT PRIMARY KEY NOT NULL,
    issue_id   TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    author_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE INDEX idx_issue_comments_issue ON issue_comments(issue_id);

CREATE TABLE labels (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    color         TEXT NOT NULL,
    description   TEXT,
    archived_at   BIGINT
);

CREATE UNIQUE INDEX idx_labels_repo_name ON labels(repository_id, name);

CREATE TABLE issue_labels (
    issue_id TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    label_id TEXT NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
    PRIMARY KEY (issue_id, label_id)
);

CREATE INDEX idx_issue_labels_label ON issue_labels(label_id);

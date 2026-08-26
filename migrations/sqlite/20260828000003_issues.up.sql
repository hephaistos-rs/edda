CREATE TABLE milestones (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    title         TEXT NOT NULL,
    description   TEXT,
    due_on        INTEGER,
    state         TEXT NOT NULL CHECK (state IN ('open', 'closed'))
) STRICT;

CREATE INDEX idx_milestones_repository ON milestones(repository_id);

-- Shares its per-repository numbering sequence with `pull_requests` — see
-- `repo_number_counters`.
CREATE TABLE issues (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    number        INTEGER NOT NULL,
    title         TEXT NOT NULL,
    body          TEXT,
    author_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state         TEXT NOT NULL CHECK (state IN ('open', 'closed')),
    closed_at     INTEGER,
    close_reason  TEXT CHECK (close_reason IN ('completed', 'not_planned')),
    milestone_id  TEXT REFERENCES milestones(id) ON DELETE SET NULL,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE UNIQUE INDEX idx_issues_repo_number ON issues(repository_id, number);
CREATE INDEX idx_issues_repo_state ON issues(repository_id, state);
CREATE INDEX idx_issues_milestone ON issues(milestone_id);

CREATE TABLE issue_comments (
    id         TEXT PRIMARY KEY NOT NULL,
    issue_id   TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    author_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_issue_comments_issue ON issue_comments(issue_id);

-- Not yet organization-scoped — `repository_id` only, until organizations
-- exist in a later phase (see `edda_domain::Label`'s doc comment).
CREATE TABLE labels (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    color         TEXT NOT NULL,
    description   TEXT,
    archived_at   INTEGER
) STRICT;

CREATE UNIQUE INDEX idx_labels_repo_name ON labels(repository_id, name);

CREATE TABLE issue_labels (
    issue_id TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    label_id TEXT NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
    PRIMARY KEY (issue_id, label_id)
) STRICT;

CREATE INDEX idx_issue_labels_label ON issue_labels(label_id);

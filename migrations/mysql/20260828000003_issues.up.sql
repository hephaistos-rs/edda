-- MySQL/MariaDB counterpart of sqlite/20260828000003_issues.up.sql.
CREATE TABLE milestones (
    id            VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id VARCHAR(36) NOT NULL,
    title         VARCHAR(255) NOT NULL,
    description   VARCHAR(1024),
    due_on        BIGINT,
    state         VARCHAR(16) NOT NULL CHECK (state IN ('open', 'closed')),
    CONSTRAINT fk_milestones_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE INDEX idx_milestones_repository ON milestones(repository_id);

CREATE TABLE issues (
    id            VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id VARCHAR(36) NOT NULL,
    number        BIGINT NOT NULL,
    title         VARCHAR(255) NOT NULL,
    body          VARCHAR(8192),
    author_id     VARCHAR(36) NOT NULL,
    state         VARCHAR(16) NOT NULL CHECK (state IN ('open', 'closed')),
    closed_at     BIGINT,
    close_reason  VARCHAR(16) CHECK (close_reason IN ('completed', 'not_planned')),
    milestone_id  VARCHAR(36),
    created_at    BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_issues_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
    CONSTRAINT fk_issues_author FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_issues_milestone FOREIGN KEY (milestone_id) REFERENCES milestones(id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX idx_issues_repo_number ON issues(repository_id, number);
CREATE INDEX idx_issues_repo_state ON issues(repository_id, state);
CREATE INDEX idx_issues_milestone ON issues(milestone_id);

CREATE TABLE issue_comments (
    id         VARCHAR(36) PRIMARY KEY NOT NULL,
    issue_id   VARCHAR(36) NOT NULL,
    author_id  VARCHAR(36) NOT NULL,
    body       VARCHAR(8192) NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_issue_comments_issue FOREIGN KEY (issue_id) REFERENCES issues(id) ON DELETE CASCADE,
    CONSTRAINT fk_issue_comments_author FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_issue_comments_issue ON issue_comments(issue_id);

CREATE TABLE labels (
    id            VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id VARCHAR(36) NOT NULL,
    name          VARCHAR(255) NOT NULL,
    color         VARCHAR(32) NOT NULL,
    description   VARCHAR(1024),
    archived_at   BIGINT,
    CONSTRAINT fk_labels_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_labels_repo_name ON labels(repository_id, name);

CREATE TABLE issue_labels (
    issue_id VARCHAR(36) NOT NULL,
    label_id VARCHAR(36) NOT NULL,
    PRIMARY KEY (issue_id, label_id),
    CONSTRAINT fk_issue_labels_issue FOREIGN KEY (issue_id) REFERENCES issues(id) ON DELETE CASCADE,
    CONSTRAINT fk_issue_labels_label FOREIGN KEY (label_id) REFERENCES labels(id) ON DELETE CASCADE
);

CREATE INDEX idx_issue_labels_label ON issue_labels(label_id);

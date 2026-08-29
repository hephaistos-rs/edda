DROP TABLE IF EXISTS watches;
DROP TABLE IF EXISTS issue_assignees;

-- Restore the value-list CHECK on the rebuilt tables (mirror of the `.up`
-- rebuild, with the original narrow constraints).
CREATE TABLE pull_requests_old (
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
INSERT INTO pull_requests_old
SELECT id, repository_id, number, title, body, author_id, source_repository_id,
       source_branch, target_branch, state, merged_at, merge_commit, merge_strategy,
       closed_at, close_reason, created_at
FROM pull_requests;
DROP TABLE pull_requests;
ALTER TABLE pull_requests_old RENAME TO pull_requests;
CREATE UNIQUE INDEX idx_pull_requests_repo_number ON pull_requests(repository_id, number);
CREATE INDEX idx_pull_requests_repo_state ON pull_requests(repository_id, state);

CREATE TABLE notifications_old (
    id           TEXT PRIMARY KEY NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('mention', 'pr_review_requested', 'issue_assigned')),
    subject_type TEXT NOT NULL CHECK (subject_type IN ('pull_request', 'issue')),
    subject_id   TEXT NOT NULL,
    read_at      INTEGER,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;
INSERT INTO notifications_old
SELECT id, user_id, kind, subject_type, subject_id, read_at, created_at
FROM notifications;
DROP TABLE notifications;
ALTER TABLE notifications_old RENAME TO notifications;
CREATE INDEX idx_notifications_user_read ON notifications(user_id, read_at);
CREATE INDEX idx_notifications_dedupe_lookup ON notifications(user_id, kind, subject_type, subject_id);

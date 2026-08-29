-- Phase 11 (collaboration surface): issue assignees, watch/subscribe, and
-- the enum columns that every capability phase keeps growing lose their
-- value-list CHECK.

-- Multiple assignees per issue — the composite-PK junction shape
-- `issue_labels` already uses. `assigned_by_id` is nullable so deleting
-- the assigner's account leaves the assignment intact.
CREATE TABLE issue_assignees (
    issue_id       TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_by_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    assigned_at    INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (issue_id, user_id)
) STRICT;
CREATE INDEX idx_issue_assignees_user ON issue_assignees(user_id);

-- A user's standing interest in a repository / issue / pull request.
-- Polymorphic subject with no foreign key — the same low-integrity,
-- high-churn rationale `notifications` documents.
CREATE TABLE watches (
    id           TEXT PRIMARY KEY NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('repository', 'issue', 'pull_request')),
    subject_id   TEXT NOT NULL,
    level        TEXT NOT NULL CHECK (level IN ('watching', 'ignoring')),
    created_at   INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;
CREATE UNIQUE INDEX idx_watches_user_subject ON watches(user_id, subject_type, subject_id);
CREATE INDEX idx_watches_subject ON watches(subject_type, subject_id);

-- Drop the value-list CHECK on `pull_requests.merge_strategy` and on
-- `notifications.kind` / `notifications.subject_type`: these three enums
-- grow every capability phase (Phase 11 alone triples the merge-strategy
-- and notification-kind sets), and the domain `*_from_db_str` functions
-- are the validated gate. SQLite has no in-place CHECK drop, so each host
-- table is rebuilt — foreign-key enforcement is already disabled for the
-- whole migration run (see `edda_db::run_migrations`).
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
    merge_strategy       TEXT,
    closed_at            INTEGER,
    close_reason         TEXT CHECK (close_reason IN ('completed', 'not_planned')),
    created_at           INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;
INSERT INTO pull_requests_new
SELECT id, repository_id, number, title, body, author_id, source_repository_id,
       source_branch, target_branch, state, merged_at, merge_commit, merge_strategy,
       closed_at, close_reason, created_at
FROM pull_requests;
DROP TABLE pull_requests;
ALTER TABLE pull_requests_new RENAME TO pull_requests;
CREATE UNIQUE INDEX idx_pull_requests_repo_number ON pull_requests(repository_id, number);
CREATE INDEX idx_pull_requests_repo_state ON pull_requests(repository_id, state);

CREATE TABLE notifications_new (
    id           TEXT PRIMARY KEY NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id   TEXT NOT NULL,
    read_at      INTEGER,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;
INSERT INTO notifications_new
SELECT id, user_id, kind, subject_type, subject_id, read_at, created_at
FROM notifications;
DROP TABLE notifications;
ALTER TABLE notifications_new RENAME TO notifications;
CREATE INDEX idx_notifications_user_read ON notifications(user_id, read_at);
CREATE INDEX idx_notifications_dedupe_lookup ON notifications(user_id, kind, subject_type, subject_id);

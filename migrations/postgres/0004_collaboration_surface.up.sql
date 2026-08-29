-- Phase 11 (collaboration surface): issue assignees, watch/subscribe, and
-- dropping the value-list CHECK on three fast-growing enum columns
-- (`pull_requests.merge_strategy`, `notifications.kind` /
-- `notifications.subject_type`) — the domain `*_from_db_str` functions are
-- the validated gate, and these enums grow every capability phase.

CREATE TABLE issue_assignees (
    issue_id       TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_by_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    assigned_at    BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    PRIMARY KEY (issue_id, user_id)
);
CREATE INDEX idx_issue_assignees_user ON issue_assignees(user_id);

CREATE TABLE watches (
    id           TEXT PRIMARY KEY NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('repository', 'issue', 'pull_request')),
    subject_id   TEXT NOT NULL,
    level        TEXT NOT NULL CHECK (level IN ('watching', 'ignoring')),
    created_at   BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);
CREATE UNIQUE INDEX idx_watches_user_subject ON watches(user_id, subject_type, subject_id);
CREATE INDEX idx_watches_subject ON watches(subject_type, subject_id);

ALTER TABLE pull_requests DROP CONSTRAINT IF EXISTS pull_requests_merge_strategy_check;
ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_kind_check;
ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_subject_type_check;

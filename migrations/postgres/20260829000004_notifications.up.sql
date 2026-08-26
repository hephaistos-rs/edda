-- PostgreSQL counterpart of sqlite/20260829000004_notifications.up.sql.
CREATE TABLE notifications (
    id           TEXT PRIMARY KEY NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('mention', 'pr_review_requested', 'issue_assigned')),
    subject_type TEXT NOT NULL CHECK (subject_type IN ('pull_request', 'issue')),
    subject_id   TEXT NOT NULL,
    read_at      BIGINT,
    created_at   BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE INDEX idx_notifications_user_read ON notifications(user_id, read_at);
CREATE INDEX idx_notifications_dedupe_lookup ON notifications(user_id, kind, subject_type, subject_id);

ALTER TABLE users ADD COLUMN email_notifications_enabled INTEGER NOT NULL DEFAULT 1;

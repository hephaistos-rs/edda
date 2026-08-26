-- `subject_type`/`subject_id` is a polymorphic-subject pair
-- (`edda_domain::NotificationSubject`), the same pattern already used for
-- `repositories.owner_type`/`owner_id` — deliberately not two nullable FK
-- columns (one per possible subject kind), since the subject set grows
-- additively and a new kind would otherwise need a new nullable column
-- every time. `read_at` is nullable (NULL = unread); the
-- create-time duplicate check (`edda_db::NotificationRepo::insert_if_new`)
-- is an application-level check-then-insert, not a DB constraint — see
-- that function's own doc comment for why.
--
-- Also adds `users.email_notifications_enabled`: the per-user opt-out for
-- email delivery of a notification (in-app notifications are always
-- created; email is the part this flag gates) — defaults to enabled,
-- toggled from the settings page.
CREATE TABLE notifications (
    id           TEXT PRIMARY KEY NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('mention', 'pr_review_requested', 'issue_assigned')),
    subject_type TEXT NOT NULL CHECK (subject_type IN ('pull_request', 'issue')),
    subject_id   TEXT NOT NULL,
    read_at      INTEGER,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_notifications_user_read ON notifications(user_id, read_at);
CREATE INDEX idx_notifications_dedupe_lookup ON notifications(user_id, kind, subject_type, subject_id);

ALTER TABLE users ADD COLUMN email_notifications_enabled INTEGER NOT NULL DEFAULT 1;

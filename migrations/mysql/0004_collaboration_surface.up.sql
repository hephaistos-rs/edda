-- Phase 11 (collaboration surface): issue assignees, watch/subscribe, and
-- dropping the value-list CHECK on three fast-growing enum columns
-- (`pull_requests.merge_strategy`, `notifications.kind` /
-- `notifications.subject_type`) — the domain `*_from_db_str` functions are
-- the validated gate, and these enums grow every capability phase.
--
-- MariaDB names a column-level CHECK after its column, and cannot
-- `DROP CONSTRAINT` such a name (it collides with the column); `MODIFY`ing
-- the column to its bare definition drops the inline CHECK cleanly.

CREATE TABLE issue_assignees (
    issue_id       VARCHAR(36) NOT NULL,
    user_id        VARCHAR(36) NOT NULL,
    assigned_by_id VARCHAR(36),
    assigned_at    BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    PRIMARY KEY (issue_id, user_id),
    CONSTRAINT fk_issue_assignees_issue FOREIGN KEY (issue_id) REFERENCES issues(id) ON DELETE CASCADE,
    CONSTRAINT fk_issue_assignees_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_issue_assignees_assigner FOREIGN KEY (assigned_by_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX idx_issue_assignees_user ON issue_assignees(user_id);

CREATE TABLE watches (
    id           VARCHAR(36) PRIMARY KEY NOT NULL,
    user_id      VARCHAR(36) NOT NULL,
    subject_type VARCHAR(16) NOT NULL CHECK (subject_type IN ('repository', 'issue', 'pull_request')),
    subject_id   VARCHAR(36) NOT NULL,
    level        VARCHAR(16) NOT NULL CHECK (level IN ('watching', 'ignoring')),
    created_at   BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_watches_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_watches_user_subject ON watches(user_id, subject_type, subject_id);
CREATE INDEX idx_watches_subject ON watches(subject_type, subject_id);

ALTER TABLE pull_requests MODIFY merge_strategy VARCHAR(16);
ALTER TABLE notifications MODIFY kind VARCHAR(32) NOT NULL;
ALTER TABLE notifications MODIFY subject_type VARCHAR(32) NOT NULL;

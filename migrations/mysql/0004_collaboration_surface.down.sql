SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS watches;
DROP TABLE IF EXISTS issue_assignees;
SET FOREIGN_KEY_CHECKS = 1;

ALTER TABLE pull_requests MODIFY merge_strategy VARCHAR(16) CHECK (merge_strategy IN ('merge'));
ALTER TABLE notifications MODIFY kind VARCHAR(32) NOT NULL
    CHECK (kind IN ('mention', 'pr_review_requested', 'issue_assigned'));
ALTER TABLE notifications MODIFY subject_type VARCHAR(32) NOT NULL
    CHECK (subject_type IN ('pull_request', 'issue'));

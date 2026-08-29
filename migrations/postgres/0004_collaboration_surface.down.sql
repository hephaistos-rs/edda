DROP TABLE IF EXISTS watches;
DROP TABLE IF EXISTS issue_assignees;

ALTER TABLE pull_requests
    ADD CONSTRAINT pull_requests_merge_strategy_check CHECK (merge_strategy IN ('merge'));
ALTER TABLE notifications
    ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('mention', 'pr_review_requested', 'issue_assigned'));
ALTER TABLE notifications
    ADD CONSTRAINT notifications_subject_type_check
    CHECK (subject_type IN ('pull_request', 'issue'));

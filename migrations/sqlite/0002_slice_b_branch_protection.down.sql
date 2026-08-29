DROP TABLE IF EXISTS review_requests;
DROP TABLE IF EXISTS commit_statuses;
DROP TABLE IF EXISTS repo_sizes;
DROP TABLE IF EXISTS branch_protection_push_allowlist;

ALTER TABLE branch_protection_rules DROP COLUMN required_status_checks;
ALTER TABLE branch_protection_rules DROP COLUMN require_up_to_date;
ALTER TABLE branch_protection_rules DROP COLUMN dismiss_stale_reviews;
ALTER TABLE branch_protection_rules DROP COLUMN require_signed_commits;
ALTER TABLE branch_protection_rules DROP COLUMN require_linear_history;

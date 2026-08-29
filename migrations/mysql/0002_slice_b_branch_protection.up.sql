-- Phase 10 (vertical slice B): branch-protection depth, push quota,
-- external commit statuses, and CODEOWNERS-driven review requests. The
-- first incremental migration after the 0001 baseline.

-- Branch protection widens. The `branch` column is now matched as a glob
-- pattern (`release/*`, `v?.?`) — no schema change, an exact name like
-- `main` still matches only `main`. The new columns are the merge/push
-- policy flags plus the external-status-check requirement list (a JSON
-- array of check contexts).
ALTER TABLE branch_protection_rules ADD COLUMN require_linear_history INTEGER NOT NULL DEFAULT 0;
ALTER TABLE branch_protection_rules ADD COLUMN require_signed_commits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE branch_protection_rules ADD COLUMN dismiss_stale_reviews  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE branch_protection_rules ADD COLUMN require_up_to_date     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE branch_protection_rules ADD COLUMN required_status_checks VARCHAR(2048) NOT NULL DEFAULT '[]';

-- Subjects allowed to push directly to a rule's matched branches even
-- though the rule exists (an allowlist that only widens). Typed subject,
-- exactly one of the two set — mirrors `repo_access`.
CREATE TABLE branch_protection_push_allowlist (
    rule_id         VARCHAR(36) NOT NULL,
    subject_user_id VARCHAR(36),
    subject_team_id VARCHAR(36),
    added_at        BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_bp_allowlist_rule FOREIGN KEY (rule_id) REFERENCES branch_protection_rules(id) ON DELETE CASCADE,
    CONSTRAINT fk_bp_allowlist_subject_user FOREIGN KEY (subject_user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_bp_allowlist_subject_team FOREIGN KEY (subject_team_id) REFERENCES teams(id) ON DELETE CASCADE,
    CONSTRAINT chk_bp_allowlist_one_subject CHECK ((subject_user_id IS NOT NULL) + (subject_team_id IS NOT NULL) = 1)
);
CREATE UNIQUE INDEX idx_bp_allowlist_user ON branch_protection_push_allowlist(rule_id, subject_user_id);
CREATE UNIQUE INDEX idx_bp_allowlist_team ON branch_protection_push_allowlist(rule_id, subject_team_id);
CREATE INDEX idx_bp_allowlist_rule ON branch_protection_push_allowlist(rule_id);

-- Per-repository size accounting, refreshed by the `UpdateRepoSize` job
-- after every push and read by the pre-receive quota check.
CREATE TABLE repo_sizes (
    repository_id VARCHAR(36) PRIMARY KEY NOT NULL,
    git_bytes     BIGINT NOT NULL DEFAULT 0,
    lfs_bytes     BIGINT NOT NULL DEFAULT 0,
    computed_at   BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_repo_sizes_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

-- External CI status for a commit — reported through the status API,
-- consulted by `can_merge_pull_request` when the target branch requires
-- status checks. One row per (repo, commit, context); a repeat report for
-- the same context overwrites.
CREATE TABLE commit_statuses (
    id            VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id VARCHAR(36) NOT NULL,
    commit_sha    VARCHAR(64) NOT NULL,
    context       VARCHAR(255) NOT NULL,
    state         VARCHAR(16) NOT NULL CHECK (state IN ('pending', 'success', 'failure', 'error')),
    target_url    VARCHAR(2048),
    description   VARCHAR(1024),
    created_at    BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    updated_at    BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_commit_statuses_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_commit_statuses_key ON commit_statuses(repository_id, commit_sha, context);
CREATE INDEX idx_commit_statuses_commit ON commit_statuses(repository_id, commit_sha);

-- A pending request for one user to review a pull request — created from a
-- CODEOWNERS match on push (Phase 10) or manually (Phase 11).
CREATE TABLE review_requests (
    id              VARCHAR(36) PRIMARY KEY NOT NULL,
    pull_request_id VARCHAR(36) NOT NULL,
    reviewer_id     VARCHAR(36) NOT NULL,
    created_at      BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_review_requests_pull_request FOREIGN KEY (pull_request_id) REFERENCES pull_requests(id) ON DELETE CASCADE,
    CONSTRAINT fk_review_requests_reviewer FOREIGN KEY (reviewer_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_review_requests_pr_reviewer ON review_requests(pull_request_id, reviewer_id);
CREATE INDEX idx_review_requests_pr ON review_requests(pull_request_id);
CREATE INDEX idx_review_requests_reviewer ON review_requests(reviewer_id);

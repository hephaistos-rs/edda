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
ALTER TABLE branch_protection_rules ADD COLUMN required_status_checks TEXT NOT NULL DEFAULT '[]';

-- Subjects allowed to push directly to a rule's matched branches even
-- though the rule exists (an allowlist that only widens). Typed subject,
-- exactly one of the two set — mirrors `repo_access`.
CREATE TABLE branch_protection_push_allowlist (
    rule_id         TEXT NOT NULL REFERENCES branch_protection_rules(id) ON DELETE CASCADE,
    subject_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    subject_team_id TEXT REFERENCES teams(id) ON DELETE CASCADE,
    added_at        INTEGER NOT NULL DEFAULT (unixepoch()),
    CHECK ((subject_user_id IS NOT NULL) + (subject_team_id IS NOT NULL) = 1)
) STRICT;
CREATE UNIQUE INDEX idx_bp_allowlist_user ON branch_protection_push_allowlist(rule_id, subject_user_id);
CREATE UNIQUE INDEX idx_bp_allowlist_team ON branch_protection_push_allowlist(rule_id, subject_team_id);
CREATE INDEX idx_bp_allowlist_rule ON branch_protection_push_allowlist(rule_id);

-- Per-repository size accounting, refreshed by the `UpdateRepoSize` job
-- after every push and read by the pre-receive quota check.
CREATE TABLE repo_sizes (
    repository_id TEXT PRIMARY KEY NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    git_bytes     INTEGER NOT NULL DEFAULT 0,
    lfs_bytes     INTEGER NOT NULL DEFAULT 0,
    computed_at   INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

-- External CI status for a commit — reported through the status API,
-- consulted by `can_merge_pull_request` when the target branch requires
-- status checks. One row per (repo, commit, context); a repeat report for
-- the same context overwrites.
CREATE TABLE commit_statuses (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    commit_sha    TEXT NOT NULL,
    context       TEXT NOT NULL,
    state         TEXT NOT NULL CHECK (state IN ('pending', 'success', 'failure', 'error')),
    target_url    TEXT,
    description   TEXT,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at    INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;
CREATE UNIQUE INDEX idx_commit_statuses_key ON commit_statuses(repository_id, commit_sha, context);
CREATE INDEX idx_commit_statuses_commit ON commit_statuses(repository_id, commit_sha);

-- A pending request for one user to review a pull request — created from a
-- CODEOWNERS match on push (Phase 10) or manually (Phase 11).
CREATE TABLE review_requests (
    id              TEXT PRIMARY KEY NOT NULL,
    pull_request_id TEXT NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
    reviewer_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;
CREATE UNIQUE INDEX idx_review_requests_pr_reviewer ON review_requests(pull_request_id, reviewer_id);
CREATE INDEX idx_review_requests_pr ON review_requests(pull_request_id);
CREATE INDEX idx_review_requests_reviewer ON review_requests(reviewer_id);

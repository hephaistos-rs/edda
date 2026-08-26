-- A rule's mere existence for `branch` blocks direct pushes to it (for
-- anyone below `RepoRole::Admin`) and requires `required_approvals`
-- latest-review approvals to merge a pull request targeting it — see
-- `edda_domain::branch_protection`'s module doc comment. No glob
-- patterns: one row names one exact branch, this phase's deliberate
-- minimal slice.
CREATE TABLE branch_protection_rules (
    id                  TEXT PRIMARY KEY NOT NULL,
    repository_id       TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    branch              TEXT NOT NULL,
    required_approvals  INTEGER NOT NULL DEFAULT 1
) STRICT;

CREATE UNIQUE INDEX idx_branch_protection_repo_branch ON branch_protection_rules(repository_id, branch);

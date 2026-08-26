-- PostgreSQL counterpart of sqlite/20260828000004_branch_protection.up.sql.
CREATE TABLE branch_protection_rules (
    id                  TEXT PRIMARY KEY NOT NULL,
    repository_id       TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    branch              TEXT NOT NULL,
    required_approvals  INTEGER NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX idx_branch_protection_repo_branch ON branch_protection_rules(repository_id, branch);

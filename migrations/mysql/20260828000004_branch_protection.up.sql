-- MySQL/MariaDB counterpart of sqlite/20260828000004_branch_protection.up.sql.
CREATE TABLE branch_protection_rules (
    id                  VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id       VARCHAR(36) NOT NULL,
    branch              VARCHAR(255) NOT NULL,
    required_approvals  INTEGER NOT NULL DEFAULT 1,
    CONSTRAINT fk_branch_protection_rules_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_branch_protection_repo_branch ON branch_protection_rules(repository_id, branch);

-- MySQL/MariaDB counterpart of sqlite/20260828000001_repo_numbering.up.sql.
CREATE TABLE repo_number_counters (
    repository_id VARCHAR(36) PRIMARY KEY NOT NULL,
    next_number   BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT fk_repo_number_counters_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

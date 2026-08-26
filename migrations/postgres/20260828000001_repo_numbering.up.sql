-- PostgreSQL counterpart of sqlite/20260828000001_repo_numbering.up.sql.
CREATE TABLE repo_number_counters (
    repository_id TEXT PRIMARY KEY NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    next_number   BIGINT NOT NULL DEFAULT 1
);

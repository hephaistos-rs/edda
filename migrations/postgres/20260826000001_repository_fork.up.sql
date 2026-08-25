-- PostgreSQL counterpart of sqlite/20260826000001_repository_fork.up.sql.
ALTER TABLE repositories ADD COLUMN forked_from TEXT;

CREATE INDEX idx_repositories_forked_from ON repositories(forked_from);

DROP INDEX idx_repositories_forked_from ON repositories;
ALTER TABLE repositories DROP COLUMN forked_from;

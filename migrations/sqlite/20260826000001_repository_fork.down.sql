DROP INDEX idx_repositories_forked_from;
ALTER TABLE repositories DROP COLUMN forked_from;

-- Additive column: which repository (if any) this one was forked from.
-- No foreign key to `repositories(id)` — SQLite can't add a foreign key
-- via ALTER TABLE ADD COLUMN, and the source repository outliving its
-- forks isn't an invariant this needs to enforce at the database level
-- (a fork stays a fully independent repository even if its source is
-- later deleted).
ALTER TABLE repositories ADD COLUMN forked_from TEXT;

CREATE INDEX idx_repositories_forked_from ON repositories(forked_from);

-- PostgreSQL counterpart of
-- sqlite/20260831000002_cross_repo_pull_requests.up.sql.
--
-- Lifts the same-repository restriction on pull requests (H4 / Phase 5).
-- PostgreSQL names the single unnamed *table-level* CHECK on a table
-- `<table>_check` (column-level ones get `<table>_<column>_check`), so
-- the table constraint from the original migration is `pull_requests_check`.
ALTER TABLE pull_requests DROP CONSTRAINT IF EXISTS pull_requests_check;

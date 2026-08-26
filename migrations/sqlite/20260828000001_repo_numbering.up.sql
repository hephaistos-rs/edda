-- One row per repository that has ever needed a pull-request/issue
-- number, tracking the next number to hand out. Pull requests and issues
-- share this single counter (per repository) — matching how every
-- mainstream git host numbers the two interchangeably (`#5` may resolve
-- to either) — so it lives in its own table rather than as a column on
-- either `pull_requests` or `issues`. Allocation is a compare-and-swap
-- loop in `edda-db` (`UPDATE ... WHERE next_number = ?`), the same
-- optimistic-concurrency idiom `apply_ref_update` already uses for ref
-- updates — portable across all three backends without relying on
-- `SELECT ... FOR UPDATE` (SQLite has no such syntax) or `RETURNING` on
-- `UPDATE` (not reliably available on MySQL/MariaDB through `sqlx::Any`).
CREATE TABLE repo_number_counters (
    repository_id TEXT PRIMARY KEY NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    next_number   INTEGER NOT NULL DEFAULT 1
) STRICT;

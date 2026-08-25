-- Instance-level admin flag and account-disable timestamp. Both additive,
-- both boolean-shaped but stored as INTEGER (0/1) rather than a native
-- BOOLEAN type — SQLite has none, and this keeps the same `get_i64`-based
-- decode path already used everywhere else in this crate rather than
-- introducing a fourth per-backend bool-decode story through `AnyRow`.
-- `disabled_at` is nullable and holds *when* an admin disabled the
-- account (NULL = enabled), not a plain flag, so an audit trail question
-- ("since when has this account been disabled?") doesn't need a second
-- column later.
ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN disabled_at INTEGER;

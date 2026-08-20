-- Adds `users.username`, the identity that will namespace repositories
-- (`{owner}/{repo}`, owner == username). SQLite's `ALTER TABLE ... ADD
-- COLUMN` can't add a UNIQUE constraint to an existing table, so this uses
-- the standard SQLite rebuild pattern: new table, copy data across, drop
-- old, rename new.
--
-- `username` is left nullable here rather than `NOT NULL`: existing rows
-- have no username yet, and the value each one gets (derived from the
-- email local-part, deduplicated with a numeric suffix on collision) needs
-- real string processing that SQL is a poor, error-prone tool for compared
-- to a normal, unit-tested Rust function. `auth::backfill_usernames` fills
-- every `NULL` in right after migrations run (see `migrations::run`) —
-- application code (`auth::signup`) is what actually requires a username
-- for every *new* account from here on, the same way it already requires a
-- non-empty `email`/`password` beyond what this schema enforces at the DB
-- level.
CREATE TABLE users_new (
    id            TEXT PRIMARY KEY NOT NULL,
    username      TEXT UNIQUE COLLATE NOCASE,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

INSERT INTO users_new (id, username, email, password_hash, created_at)
SELECT id, NULL, email, password_hash, created_at FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

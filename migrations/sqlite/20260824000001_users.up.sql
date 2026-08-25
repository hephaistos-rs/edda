-- Authored as a single table (no separate `username` backfill migration)
-- since there is no existing deployment to preserve.
CREATE TABLE users (
    -- UUIDv7 (time-ordered), generated app-side and stored as text. Avoids
    -- leaking a guessable sequential id / user count, unlike AUTOINCREMENT.
    id            TEXT PRIMARY KEY NOT NULL,
    -- COLLATE NOCASE: without it, "Alice" and "alice" would be treated as
    -- different usernames/emails, allowing duplicate accounts that differ
    -- only by case.
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

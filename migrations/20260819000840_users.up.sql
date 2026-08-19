CREATE TABLE users (
    -- UUIDv7 (time-ordered), generated app-side and stored as text. Avoids
    -- leaking a guessable sequential id / user count, unlike AUTOINCREMENT.
    id            TEXT PRIMARY KEY NOT NULL,
    -- COLLATE NOCASE: without it, "Alice@example.com" and "alice@example.com"
    -- would be treated as different emails, allowing duplicate accounts that
    -- differ only by case.
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

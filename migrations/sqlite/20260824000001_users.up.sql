-- Phase 1 schema: authored fresh, not evolved from the pre-restructuring
-- history — there is no existing deployment to preserve (plan.local.md
-- §0/§19). This collapses what used to be two migrations (`users` plus a
-- later `users_username` backfill-and-widen) into one table, since there
-- are no existing rows that ever lacked a `username`.
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

-- PostgreSQL counterpart of sqlite/20260824000001_users.up.sql. No STRICT
-- (Postgres is natively strictly typed). Case-
-- insensitive uniqueness is index-based (LOWER(...)) rather than a
-- COLLATE NOCASE column, to avoid requiring the citext extension.
CREATE TABLE users (
    id            TEXT PRIMARY KEY NOT NULL,
    username      TEXT NOT NULL,
    email         TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE UNIQUE INDEX idx_users_username_ci ON users (LOWER(username));
CREATE UNIQUE INDEX idx_users_email_ci ON users (LOWER(email));

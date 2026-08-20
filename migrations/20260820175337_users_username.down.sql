CREATE TABLE users_old (
    id            TEXT PRIMARY KEY NOT NULL,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

INSERT INTO users_old (id, email, password_hash, created_at)
SELECT id, email, password_hash, created_at FROM users;

DROP TABLE users;
ALTER TABLE users_old RENAME TO users;

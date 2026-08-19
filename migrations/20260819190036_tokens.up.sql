CREATE TABLE tokens (
    id            TEXT PRIMARY KEY NOT NULL,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    -- SHA-256 of the raw token, not the raw token itself — same "never
    -- store the secret" principle as password hashing, but a fast hash is
    -- correct here (not argon2): a 32-byte random token already has 256
    -- bits of entropy, so slow hashing buys nothing against brute-force and
    -- would be needless cost on every git push.
    token_hash    TEXT NOT NULL UNIQUE,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
    last_used_at  INTEGER
) STRICT;

CREATE INDEX idx_tokens_user_id ON tokens(user_id);

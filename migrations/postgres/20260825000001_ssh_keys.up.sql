-- PostgreSQL counterpart of sqlite/20260825000001_ssh_keys.up.sql.
CREATE TABLE ssh_keys (
    id            TEXT PRIMARY KEY NOT NULL,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint   TEXT NOT NULL UNIQUE,
    public_key    TEXT NOT NULL,
    title         TEXT NOT NULL,
    created_at    BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    last_used_at  BIGINT
);

CREATE INDEX idx_ssh_keys_user_id ON ssh_keys(user_id);

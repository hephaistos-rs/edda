-- PostgreSQL counterpart of sqlite/20260824000004_access_tokens.up.sql.
-- RETURNING (relied on by AccessTokenRepo) is native to PostgreSQL — no
-- change needed there.
CREATE TABLE access_tokens (
    id                TEXT PRIMARY KEY NOT NULL,
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    token_hash        TEXT NOT NULL UNIQUE,
    repository_scope  TEXT NOT NULL DEFAULT '"All"',
    created_at        BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    last_used_at      BIGINT
);

CREATE INDEX idx_access_tokens_user_id ON access_tokens(user_id);

-- `token_hash` uses a fast hash, not a brute-force-resistant slow one: a
-- 32-byte random token already has 256 bits of entropy.
--
-- `repository_scope` is a JSON-encoded `edda_domain::RepositoryScope`
-- (`"All"` / `"PublicOnly"` / `{"Specific":["<repository-id>", ...]}`).
-- Every token created today is `"All"` — unscoped — so this column gives
-- a future token-creation UI somewhere to narrow a *new* token's reach
-- without a further schema change.
CREATE TABLE access_tokens (
    id                TEXT PRIMARY KEY NOT NULL,
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    token_hash        TEXT NOT NULL UNIQUE,
    repository_scope  TEXT NOT NULL DEFAULT '"All"',
    created_at        INTEGER NOT NULL DEFAULT (unixepoch()),
    last_used_at      INTEGER
) STRICT;

CREATE INDEX idx_access_tokens_user_id ON access_tokens(user_id);

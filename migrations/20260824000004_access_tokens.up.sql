-- Replaces the pre-restructuring `tokens` table. `token_hash` keeps the
-- same fast-hash reasoning as before (a 32-byte random token already has
-- 256 bits of entropy; no brute-force-resistant slow hash is needed).
--
-- `repository_scope` is new: a JSON-encoded `edda_domain::RepositoryScope`
-- (`"All"` / `"PublicOnly"` / `{"Specific":["<repository-id>", ...]}`).
-- Every token created today is `"All"` — unscoped, matching exactly what a
-- personal access token did before this column existed — so introducing
-- this column changes no existing token's behavior; it only gives a
-- future token-creation UI somewhere to narrow a *new* token's reach
-- without a further schema change. See plan.local.md §4.2.
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

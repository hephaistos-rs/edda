-- Per-repository SSH deploy keys: a public key that authenticates as the
-- *repository* (not a user), for CI / automation that clones or pushes
-- one repo. `read_only = 1` (the default) permits `git-upload-pack` only;
-- `read_only = 0` also permits `git-receive-pack`. Resolution lives in
-- `edda_auth::deploy_keys` and is consulted by `edda-ssh`'s
-- `auth_publickey` *after* a user-key lookup misses, so a key registered
-- as both a user key and a deploy key resolves to the user.
--
-- `fingerprint` is unique within this table (the same key can't be a
-- deploy key for two repositories) — same rationale as `ssh_keys`.
CREATE TABLE deploy_keys (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint   TEXT NOT NULL UNIQUE,
    public_key    TEXT NOT NULL,
    title         TEXT NOT NULL,
    read_only     INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
    last_used_at  INTEGER
) STRICT;

CREATE INDEX idx_deploy_keys_repository_id ON deploy_keys(repository_id);

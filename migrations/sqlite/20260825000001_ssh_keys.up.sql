-- Registered public keys for git-over-SSH authentication (`edda-ssh`).
--
-- `fingerprint` is globally unique (not scoped per-user): the same public
-- key registered to two different accounts would make SSH authentication
-- ambiguous about which identity to resolve to, so it's rejected as a
-- straightforward uniqueness violation rather than a case Edda has to
-- pick a tiebreak for.
CREATE TABLE ssh_keys (
    id            TEXT PRIMARY KEY NOT NULL,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint   TEXT NOT NULL UNIQUE,
    public_key    TEXT NOT NULL,
    title         TEXT NOT NULL,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
    last_used_at  INTEGER
) STRICT;

CREATE INDEX idx_ssh_keys_user_id ON ssh_keys(user_id);

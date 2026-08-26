-- Linked OAuth/OIDC identities. `(provider, subject_id)` is the pair a
-- returning login looks up by — `subject_id` is the provider's own
-- immutable `sub` claim, never the user's email (email can change at the
-- provider; `sub` is defined by OIDC to be stable for the account's
-- lifetime).
CREATE TABLE oauth_identities (
    id         TEXT PRIMARY KEY NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider   TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE UNIQUE INDEX idx_oauth_identities_provider_subject ON oauth_identities(provider, subject_id);
CREATE INDEX idx_oauth_identities_user ON oauth_identities(user_id);

-- One row per user. `secret_ciphertext` is the TOTP shared secret,
-- AES-256-GCM-encrypted at rest under the instance's `EDDA_SECRET_KEY`
-- (`edda_auth::secret_box`) — unlike a password or token hash, this value
-- must be recovered in full to compute a code on each verification, so it
-- can't be one-way hashed. `activated_at` is NULL until the user proves
-- control by submitting one valid code after enrollment; a row with
-- `activated_at IS NULL` does not yet gate login (see `edda_auth::totp`).
CREATE TABLE totp_secrets (
    user_id           TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_ciphertext BLOB NOT NULL,
    created_at        INTEGER NOT NULL DEFAULT (unixepoch()),
    activated_at      INTEGER
) STRICT;

-- Recovery codes: hashed the same way access tokens are (SHA-256 — high
-- entropy, generated server-side, no brute-force-resistant hash needed),
-- one-time use (`used_at` set on consumption, never deleted, so "this
-- code was already used" is distinguishable from "this code never
-- existed").
CREATE TABLE totp_recovery_codes (
    id         TEXT PRIMARY KEY NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_totp_recovery_codes_user ON totp_recovery_codes(user_id);
CREATE UNIQUE INDEX idx_totp_recovery_codes_hash ON totp_recovery_codes(code_hash);

-- WebAuthn credentials are public-key material by design — nothing here
-- needs encryption at rest (contrast `totp_secrets` above). `passkey_json`
-- is `edda_auth::webauthn`'s own serialized `StoredCredential` (credential
-- ID, SEC1 public key point, sign counter); `edda-db` never interprets it
-- directly, only round-trips it through `serde_json`.
CREATE TABLE webauthn_credentials (
    id           TEXT PRIMARY KEY NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label        TEXT NOT NULL,
    passkey_json TEXT NOT NULL,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
    last_used_at INTEGER
) STRICT;

CREATE INDEX idx_webauthn_credentials_user ON webauthn_credentials(user_id);

-- Schema only for now — the request/confirm/email-delivery flow that uses
-- this table is deferred to a later phase, since it depends on an
-- email-sending capability that doesn't exist yet. Single-use,
-- short-lived, hashed the same way access tokens are.
CREATE TABLE password_reset_tokens (
    id         TEXT PRIMARY KEY NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
) STRICT;

CREATE UNIQUE INDEX idx_password_reset_tokens_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_password_reset_tokens_user ON password_reset_tokens(user_id);

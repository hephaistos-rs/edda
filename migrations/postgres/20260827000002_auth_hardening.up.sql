-- PostgreSQL counterpart of sqlite/20260827000002_auth_hardening.up.sql.
-- No STRICT (Postgres is natively strictly typed). `BLOB` becomes `BYTEA`.
CREATE TABLE oauth_identities (
    id         TEXT PRIMARY KEY NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider   TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE UNIQUE INDEX idx_oauth_identities_provider_subject ON oauth_identities(provider, subject_id);
CREATE INDEX idx_oauth_identities_user ON oauth_identities(user_id);

CREATE TABLE totp_secrets (
    user_id           TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_ciphertext BYTEA NOT NULL,
    created_at        BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    activated_at      BIGINT
);

CREATE TABLE totp_recovery_codes (
    id         TEXT PRIMARY KEY NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    BIGINT,
    created_at BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE INDEX idx_totp_recovery_codes_user ON totp_recovery_codes(user_id);
CREATE UNIQUE INDEX idx_totp_recovery_codes_hash ON totp_recovery_codes(code_hash);

CREATE TABLE webauthn_credentials (
    id           TEXT PRIMARY KEY NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label        TEXT NOT NULL,
    passkey_json TEXT NOT NULL,
    created_at   BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    last_used_at BIGINT
);

CREATE INDEX idx_webauthn_credentials_user ON webauthn_credentials(user_id);

CREATE TABLE password_reset_tokens (
    id         TEXT PRIMARY KEY NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    expires_at BIGINT NOT NULL,
    used_at    BIGINT
);

CREATE UNIQUE INDEX idx_password_reset_tokens_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_password_reset_tokens_user ON password_reset_tokens(user_id);

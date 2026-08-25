-- MySQL/MariaDB counterpart of sqlite/20260827000002_auth_hardening.up.sql.
-- Every column this crate decodes as a Rust `String` is `VARCHAR`, not
-- `TEXT` — `sqlx::Any` decodes MySQL `TEXT` as a blob, not a string (the
-- same reasoning already documented in the `repositories`/`lfs` MySQL
-- migrations). `BLOB` (not `VARCHAR`) is correct for `secret_ciphertext`
-- precisely because that column *is* decoded as raw bytes.
CREATE TABLE oauth_identities (
    id         VARCHAR(36) PRIMARY KEY NOT NULL,
    user_id    VARCHAR(36) NOT NULL,
    provider   VARCHAR(64) NOT NULL,
    subject_id VARCHAR(255) NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_oauth_identities_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_oauth_identities_provider_subject ON oauth_identities(provider, subject_id);
CREATE INDEX idx_oauth_identities_user ON oauth_identities(user_id);

CREATE TABLE totp_secrets (
    user_id           VARCHAR(36) PRIMARY KEY NOT NULL,
    secret_ciphertext BLOB NOT NULL,
    created_at        BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    activated_at      BIGINT,
    CONSTRAINT fk_totp_secrets_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE totp_recovery_codes (
    id         VARCHAR(36) PRIMARY KEY NOT NULL,
    user_id    VARCHAR(36) NOT NULL,
    code_hash  VARCHAR(64) NOT NULL,
    used_at    BIGINT,
    created_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_totp_recovery_codes_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_totp_recovery_codes_user ON totp_recovery_codes(user_id);
CREATE UNIQUE INDEX idx_totp_recovery_codes_hash ON totp_recovery_codes(code_hash);

-- `passkey_json` (`webauthn-rs`'s serialized `Passkey`) is comfortably
-- under a few KB in practice — `VARCHAR(8192)` is generous headroom
-- while staying a plain `VARCHAR` (needed for `String` decoding, and for
-- this to be the only large column in the table, safely inside InnoDB's
-- row-size limit).
CREATE TABLE webauthn_credentials (
    id           VARCHAR(36) PRIMARY KEY NOT NULL,
    user_id      VARCHAR(36) NOT NULL,
    label        VARCHAR(255) NOT NULL,
    passkey_json VARCHAR(8192) NOT NULL,
    created_at   BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    last_used_at BIGINT,
    CONSTRAINT fk_webauthn_credentials_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_webauthn_credentials_user ON webauthn_credentials(user_id);

CREATE TABLE password_reset_tokens (
    id         VARCHAR(36) PRIMARY KEY NOT NULL,
    user_id    VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    expires_at BIGINT NOT NULL,
    used_at    BIGINT,
    CONSTRAINT fk_password_reset_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_password_reset_tokens_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_password_reset_tokens_user ON password_reset_tokens(user_id);

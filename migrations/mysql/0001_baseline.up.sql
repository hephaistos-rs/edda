-- MySQL/MariaDB counterpart of sqlite/0001_baseline.up.sql — the Phase 9
-- one-time schema baseline (plan.local.md §12.2). See the SQLite file's
-- header for the full rationale and the list of what changed beyond
-- flattening the 25-migration chain.
--
-- MySQL/MariaDB conventions carried over from the original chain:
-- `VARCHAR(n)` everywhere a value is decoded as a Rust `String` (`sqlx::
-- Any` decodes MySQL `TEXT` as a blob, not a string); `VARCHAR(36)` for
-- UUIDv7-as-text ids; `BLOB` only where the column really is raw bytes;
-- `BIGINT` timestamps with `UNIX_TIMESTAMP()` defaults; case-insensitive
-- uniqueness via a `LOWER(...)` STORED generated shadow column plus a
-- plain unique index (MariaDB rejects a functional unique index); the
-- one-owner-per-repository invariant via the `owner_marker` generated
-- column (InnoDB has no partial index); named `CONSTRAINT fk_*` foreign
-- keys; a 255-char prefix on the `lfs_locks(path)` index (InnoDB key
-- length limit); a plain `(processed_at, occurred_at)` composite index
-- where the other backends use a partial one.

CREATE TABLE users (
    id                          VARCHAR(36) PRIMARY KEY NOT NULL,
    username                    VARCHAR(255) NOT NULL,
    username_lower              VARCHAR(255) AS (LOWER(username)) STORED,
    email                       VARCHAR(255) NOT NULL,
    email_lower                 VARCHAR(255) AS (LOWER(email)) STORED,
    password_hash               VARCHAR(255) NOT NULL,
    is_admin                    INTEGER NOT NULL DEFAULT 0,
    disabled_at                 BIGINT,
    email_notifications_enabled INTEGER NOT NULL DEFAULT 1,
    email_verified_at           BIGINT,
    approved_at                 BIGINT,
    created_at                  BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP())
);

CREATE UNIQUE INDEX idx_users_username_ci ON users (username_lower);
CREATE UNIQUE INDEX idx_users_email_ci ON users (email_lower);

CREATE TABLE organizations (
    id           VARCHAR(36) PRIMARY KEY NOT NULL,
    name         VARCHAR(255) NOT NULL,
    name_lower   VARCHAR(255) AS (LOWER(name)) STORED,
    display_name VARCHAR(255),
    require_2fa  INTEGER NOT NULL DEFAULT 0,
    created_at   BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP())
);

CREATE UNIQUE INDEX idx_organizations_name_ci ON organizations (name_lower);

CREATE TABLE teams (
    id              VARCHAR(36) PRIMARY KEY NOT NULL,
    organization_id VARCHAR(36) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    permission      VARCHAR(16) NOT NULL CHECK (permission IN ('none', 'read', 'write', 'admin')),
    created_at      BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_teams_organization FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_teams_org_name ON teams(organization_id, name);

CREATE TABLE team_members (
    team_id  VARCHAR(36) NOT NULL,
    user_id  VARCHAR(36) NOT NULL,
    added_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    PRIMARY KEY (team_id, user_id),
    CONSTRAINT fk_team_members_team FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
    CONSTRAINT fk_team_members_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_team_members_user_id ON team_members(user_id);

CREATE TABLE team_unit_permissions (
    team_id    VARCHAR(36) NOT NULL,
    unit       VARCHAR(16) NOT NULL CHECK (unit IN ('code', 'issues', 'pull_requests', 'releases', 'wiki', 'projects', 'packages', 'actions')),
    permission VARCHAR(16) NOT NULL CHECK (permission IN ('none', 'read', 'write', 'admin')),
    PRIMARY KEY (team_id, unit),
    CONSTRAINT fk_team_unit_permissions_team FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE
);

-- Typed owner FK pair (see the SQLite baseline header). The FKs have no
-- `ON DELETE` action (InnoDB defaults to RESTRICT): deleting an account
-- or org that still owns repositories fails, and ownership hand-off must
-- happen first.
CREATE TABLE repositories (
    id            VARCHAR(36) PRIMARY KEY NOT NULL,
    owner_user_id VARCHAR(36),
    owner_org_id  VARCHAR(36),
    name          VARCHAR(255) NOT NULL,
    description   VARCHAR(1024),
    visibility    VARCHAR(16) NOT NULL CHECK (visibility IN ('public', 'private')),
    forked_from   VARCHAR(36),
    created_at    BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_repositories_owner_user FOREIGN KEY (owner_user_id) REFERENCES users(id),
    CONSTRAINT fk_repositories_owner_org FOREIGN KEY (owner_org_id) REFERENCES organizations(id),
    CONSTRAINT chk_repositories_one_owner CHECK ((owner_user_id IS NOT NULL) + (owner_org_id IS NOT NULL) = 1)
);

CREATE UNIQUE INDEX idx_repositories_user_owner_name ON repositories(owner_user_id, name);
CREATE UNIQUE INDEX idx_repositories_org_owner_name ON repositories(owner_org_id, name);
CREATE INDEX idx_repositories_owner_user ON repositories(owner_user_id);
CREATE INDEX idx_repositories_owner_org ON repositories(owner_org_id);
CREATE INDEX idx_repositories_forked_from ON repositories(forked_from);

CREATE TABLE repo_access (
    repository_id   VARCHAR(36) NOT NULL,
    subject_user_id VARCHAR(36),
    subject_team_id VARCHAR(36),
    role            VARCHAR(16) NOT NULL CHECK (role IN ('read', 'write', 'admin', 'owner')),
    added_at        BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    -- NULL for every non-owner row (InnoDB unique indexes treat multiple
    -- NULLs as distinct), the repository's id for an owner row — so a
    -- second owner grant collides on `idx_repo_access_one_owner`.
    owner_marker    VARCHAR(36) AS (IF(role = 'owner', repository_id, NULL)) STORED,
    CONSTRAINT fk_repo_access_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
    CONSTRAINT fk_repo_access_subject_user FOREIGN KEY (subject_user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_repo_access_subject_team FOREIGN KEY (subject_team_id) REFERENCES teams(id) ON DELETE CASCADE,
    CONSTRAINT chk_repo_access_one_subject CHECK ((subject_user_id IS NOT NULL) + (subject_team_id IS NOT NULL) = 1)
);

CREATE UNIQUE INDEX idx_repo_access_user ON repo_access(repository_id, subject_user_id);
CREATE UNIQUE INDEX idx_repo_access_team ON repo_access(repository_id, subject_team_id);
CREATE INDEX idx_repo_access_repository_id ON repo_access(repository_id);
CREATE INDEX idx_repo_access_subject_user ON repo_access(subject_user_id);
CREATE INDEX idx_repo_access_subject_team ON repo_access(subject_team_id);
CREATE UNIQUE INDEX idx_repo_access_one_owner ON repo_access(owner_marker);

CREATE TABLE repo_number_counters (
    repository_id VARCHAR(36) PRIMARY KEY NOT NULL,
    next_number   BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT fk_repo_number_counters_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE TABLE access_tokens (
    id               VARCHAR(36) PRIMARY KEY NOT NULL,
    user_id          VARCHAR(36) NOT NULL,
    name             VARCHAR(255) NOT NULL,
    token_hash       VARCHAR(64) NOT NULL UNIQUE,
    repository_scope VARCHAR(2048) NOT NULL,
    token_scope      VARCHAR(255) NOT NULL DEFAULT '"All"',
    created_at       BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    last_used_at     BIGINT,
    CONSTRAINT fk_access_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_access_tokens_user_id ON access_tokens(user_id);

CREATE TABLE ssh_keys (
    id           VARCHAR(36) PRIMARY KEY NOT NULL,
    user_id      VARCHAR(36) NOT NULL,
    fingerprint  VARCHAR(128) NOT NULL UNIQUE,
    public_key   VARCHAR(4096) NOT NULL,
    title        VARCHAR(255) NOT NULL,
    created_at   BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    last_used_at BIGINT,
    CONSTRAINT fk_ssh_keys_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_ssh_keys_user_id ON ssh_keys(user_id);

CREATE TABLE deploy_keys (
    id           VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id VARCHAR(36) NOT NULL,
    fingerprint  VARCHAR(128) NOT NULL UNIQUE,
    public_key   VARCHAR(4096) NOT NULL,
    title        VARCHAR(255) NOT NULL,
    read_only    INTEGER NOT NULL DEFAULT 1,
    created_at   BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    last_used_at BIGINT,
    CONSTRAINT fk_deploy_keys_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE INDEX idx_deploy_keys_repository_id ON deploy_keys(repository_id);

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

CREATE TABLE email_verification_tokens (
    id         VARCHAR(36) PRIMARY KEY NOT NULL,
    user_id    VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    expires_at BIGINT NOT NULL,
    used_at    BIGINT,
    CONSTRAINT fk_email_verification_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_email_verification_tokens_hash ON email_verification_tokens(token_hash);
CREATE INDEX idx_email_verification_tokens_user ON email_verification_tokens(user_id);

CREATE TABLE login_attempts (
    attempt_key     VARCHAR(320) PRIMARY KEY NOT NULL,
    failure_count   INTEGER NOT NULL DEFAULT 0,
    first_failed_at BIGINT NOT NULL,
    last_failed_at  BIGINT NOT NULL,
    locked_until    BIGINT
);

CREATE TABLE audit_events (
    id          VARCHAR(36) PRIMARY KEY NOT NULL,
    occurred_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    event_type  VARCHAR(128) NOT NULL,
    actor_id    VARCHAR(36),
    target_type VARCHAR(64),
    target_id   VARCHAR(255),
    detail_json VARCHAR(4096),
    CONSTRAINT fk_audit_events_actor FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_audit_events_occurred_at ON audit_events(occurred_at);
CREATE INDEX idx_audit_events_actor ON audit_events(actor_id);

CREATE TABLE lfs_objects (
    repository_id VARCHAR(36) NOT NULL,
    oid           VARCHAR(64) NOT NULL,
    size_bytes    BIGINT NOT NULL,
    storage_key   VARCHAR(512) NOT NULL,
    created_at    BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    PRIMARY KEY (repository_id, oid),
    CONSTRAINT fk_lfs_objects_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE TABLE lfs_locks (
    id            VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id VARCHAR(36) NOT NULL,
    path          VARCHAR(1024) NOT NULL,
    owner_id      VARCHAR(36) NOT NULL,
    created_at    BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_lfs_locks_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
    CONSTRAINT fk_lfs_locks_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_lfs_locks_repository_path ON lfs_locks(repository_id, path(255));

CREATE TABLE pull_requests (
    id                   VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id        VARCHAR(36) NOT NULL,
    number               BIGINT NOT NULL,
    title                VARCHAR(255) NOT NULL,
    body                 VARCHAR(8192),
    author_id            VARCHAR(36) NOT NULL,
    source_repository_id VARCHAR(36) NOT NULL,
    source_branch        VARCHAR(255) NOT NULL,
    target_branch        VARCHAR(255) NOT NULL,
    state                VARCHAR(16) NOT NULL CHECK (state IN ('open', 'draft', 'merged', 'closed')),
    merged_at            BIGINT,
    merge_commit         VARCHAR(64),
    merge_strategy       VARCHAR(16) CHECK (merge_strategy IN ('merge')),
    closed_at            BIGINT,
    close_reason         VARCHAR(16) CHECK (close_reason IN ('completed', 'not_planned')),
    created_at           BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_pull_requests_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
    CONSTRAINT fk_pull_requests_author FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_pull_requests_source_repository FOREIGN KEY (source_repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_pull_requests_repo_number ON pull_requests(repository_id, number);
CREATE INDEX idx_pull_requests_repo_state ON pull_requests(repository_id, state);

CREATE TABLE pr_reviews (
    id              VARCHAR(36) PRIMARY KEY NOT NULL,
    pull_request_id VARCHAR(36) NOT NULL,
    reviewer_id     VARCHAR(36) NOT NULL,
    state           VARCHAR(32) NOT NULL CHECK (state IN ('approved', 'changes_requested', 'commented')),
    body            VARCHAR(8192),
    created_at      BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_pr_reviews_pull_request FOREIGN KEY (pull_request_id) REFERENCES pull_requests(id) ON DELETE CASCADE,
    CONSTRAINT fk_pr_reviews_reviewer FOREIGN KEY (reviewer_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_pr_reviews_pull_request ON pr_reviews(pull_request_id);

CREATE TABLE pr_comments (
    id                VARCHAR(36) PRIMARY KEY NOT NULL,
    pull_request_id   VARCHAR(36) NOT NULL,
    author_id         VARCHAR(36) NOT NULL,
    body              VARCHAR(8192) NOT NULL,
    anchor_file_path  VARCHAR(1024),
    anchor_line_start INTEGER,
    anchor_line_end   INTEGER,
    anchor_commit_sha VARCHAR(64),
    created_at        BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_pr_comments_pull_request FOREIGN KEY (pull_request_id) REFERENCES pull_requests(id) ON DELETE CASCADE,
    CONSTRAINT fk_pr_comments_author FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT chk_pr_comments_anchor CHECK (
        (anchor_file_path IS NULL AND anchor_line_start IS NULL AND anchor_line_end IS NULL AND anchor_commit_sha IS NULL)
        OR
        (anchor_file_path IS NOT NULL AND anchor_line_start IS NOT NULL AND anchor_line_end IS NOT NULL AND anchor_commit_sha IS NOT NULL)
    )
);

CREATE INDEX idx_pr_comments_pull_request ON pr_comments(pull_request_id);

CREATE TABLE milestones (
    id            VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id VARCHAR(36) NOT NULL,
    title         VARCHAR(255) NOT NULL,
    description   VARCHAR(1024),
    due_on        BIGINT,
    state         VARCHAR(16) NOT NULL CHECK (state IN ('open', 'closed')),
    CONSTRAINT fk_milestones_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE INDEX idx_milestones_repository ON milestones(repository_id);

CREATE TABLE issues (
    id            VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id VARCHAR(36) NOT NULL,
    number        BIGINT NOT NULL,
    title         VARCHAR(255) NOT NULL,
    body          VARCHAR(8192),
    author_id     VARCHAR(36) NOT NULL,
    state         VARCHAR(16) NOT NULL CHECK (state IN ('open', 'closed')),
    closed_at     BIGINT,
    close_reason  VARCHAR(16) CHECK (close_reason IN ('completed', 'not_planned')),
    milestone_id  VARCHAR(36),
    created_at    BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_issues_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
    CONSTRAINT fk_issues_author FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_issues_milestone FOREIGN KEY (milestone_id) REFERENCES milestones(id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX idx_issues_repo_number ON issues(repository_id, number);
CREATE INDEX idx_issues_repo_state ON issues(repository_id, state);
CREATE INDEX idx_issues_milestone ON issues(milestone_id);

CREATE TABLE issue_comments (
    id         VARCHAR(36) PRIMARY KEY NOT NULL,
    issue_id   VARCHAR(36) NOT NULL,
    author_id  VARCHAR(36) NOT NULL,
    body       VARCHAR(8192) NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_issue_comments_issue FOREIGN KEY (issue_id) REFERENCES issues(id) ON DELETE CASCADE,
    CONSTRAINT fk_issue_comments_author FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_issue_comments_issue ON issue_comments(issue_id);

CREATE TABLE labels (
    id            VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id VARCHAR(36) NOT NULL,
    name          VARCHAR(255) NOT NULL,
    color         VARCHAR(32) NOT NULL,
    description   VARCHAR(1024),
    archived_at   BIGINT,
    CONSTRAINT fk_labels_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_labels_repo_name ON labels(repository_id, name);

CREATE TABLE issue_labels (
    issue_id VARCHAR(36) NOT NULL,
    label_id VARCHAR(36) NOT NULL,
    PRIMARY KEY (issue_id, label_id),
    CONSTRAINT fk_issue_labels_issue FOREIGN KEY (issue_id) REFERENCES issues(id) ON DELETE CASCADE,
    CONSTRAINT fk_issue_labels_label FOREIGN KEY (label_id) REFERENCES labels(id) ON DELETE CASCADE
);

CREATE INDEX idx_issue_labels_label ON issue_labels(label_id);

CREATE TABLE branch_protection_rules (
    id                 VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id      VARCHAR(36) NOT NULL,
    branch             VARCHAR(255) NOT NULL,
    required_approvals INTEGER NOT NULL DEFAULT 1 CHECK (required_approvals >= 0),
    CONSTRAINT fk_branch_protection_rules_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_branch_protection_repo_branch ON branch_protection_rules(repository_id, branch);

CREATE TABLE jobs (
    id           VARCHAR(36) PRIMARY KEY NOT NULL,
    payload      VARCHAR(8192) NOT NULL,
    status       VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    run_at       BIGINT NOT NULL,
    last_error   VARCHAR(2048),
    created_at   BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP())
);

CREATE INDEX idx_jobs_status_run_at ON jobs(status, run_at);

CREATE TABLE releases (
    id            VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id VARCHAR(36) NOT NULL,
    tag_name      VARCHAR(255) NOT NULL,
    target_commit VARCHAR(64) NOT NULL,
    name          VARCHAR(255) NOT NULL,
    body          VARCHAR(8192),
    draft         INTEGER NOT NULL DEFAULT 0,
    prerelease    INTEGER NOT NULL DEFAULT 0,
    published_at  BIGINT,
    author_id     VARCHAR(36) NOT NULL,
    created_at    BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_releases_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
    CONSTRAINT fk_releases_author FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_releases_repo_tag ON releases(repository_id, tag_name);
CREATE INDEX idx_releases_repo ON releases(repository_id);

CREATE TABLE release_assets (
    id           VARCHAR(36) PRIMARY KEY NOT NULL,
    release_id   VARCHAR(36) NOT NULL,
    filename     VARCHAR(1024) NOT NULL,
    size_bytes   BIGINT NOT NULL,
    content_type VARCHAR(255) NOT NULL,
    storage_key  VARCHAR(1024) NOT NULL,
    created_at   BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_release_assets_release FOREIGN KEY (release_id) REFERENCES releases(id) ON DELETE CASCADE
);

CREATE INDEX idx_release_assets_release ON release_assets(release_id);

CREATE TABLE webhooks (
    id                VARCHAR(36) PRIMARY KEY NOT NULL,
    repository_id     VARCHAR(36) NOT NULL,
    target_url        VARCHAR(2048) NOT NULL,
    secret_ciphertext BLOB NOT NULL,
    events            VARCHAR(2048) NOT NULL,
    active            INTEGER NOT NULL DEFAULT 1,
    created_at        BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_webhooks_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE INDEX idx_webhooks_repository ON webhooks(repository_id);

CREATE TABLE webhook_deliveries (
    id              VARCHAR(36) PRIMARY KEY NOT NULL,
    webhook_id      VARCHAR(36) NOT NULL,
    event           VARCHAR(64) NOT NULL,
    payload         VARCHAR(8192) NOT NULL,
    response_status INTEGER,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    delivered_at    BIGINT,
    created_at      BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_webhook_deliveries_webhook FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
);

CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);

CREATE TABLE notifications (
    id           VARCHAR(36) PRIMARY KEY NOT NULL,
    user_id      VARCHAR(36) NOT NULL,
    kind         VARCHAR(32) NOT NULL CHECK (kind IN ('mention', 'pr_review_requested', 'issue_assigned')),
    subject_type VARCHAR(32) NOT NULL CHECK (subject_type IN ('pull_request', 'issue')),
    subject_id   VARCHAR(36) NOT NULL,
    read_at      BIGINT,
    created_at   BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    CONSTRAINT fk_notifications_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_notifications_user_read ON notifications(user_id, read_at);
CREATE INDEX idx_notifications_dedupe_lookup ON notifications(user_id, kind, subject_type, subject_id);

CREATE TABLE events (
    id             VARCHAR(36) PRIMARY KEY NOT NULL,
    occurred_at    BIGINT NOT NULL,
    aggregate_type VARCHAR(64) NOT NULL,
    aggregate_id   VARCHAR(36) NOT NULL,
    kind           VARCHAR(64) NOT NULL,
    payload_json   VARCHAR(8192) NOT NULL,
    processed_at   BIGINT
);

CREATE INDEX idx_events_unprocessed ON events(processed_at, occurred_at);
CREATE INDEX idx_events_aggregate ON events(aggregate_type, aggregate_id);

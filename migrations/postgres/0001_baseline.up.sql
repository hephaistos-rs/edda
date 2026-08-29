-- PostgreSQL counterpart of sqlite/0001_baseline.up.sql — the Phase 9
-- one-time schema baseline (plan.local.md §12.2). See the SQLite file's
-- header for the full rationale and the list of what changed beyond
-- flattening the 25-migration chain.
--
-- PostgreSQL conventions carried over from the original chain: no
-- `STRICT` (natively strict), `BIGINT` timestamps with
-- `extract(epoch from now())::bigint` defaults, case-insensitive text
-- uniqueness as `LOWER(...)` functional unique indexes (no `citext`
-- dependency), `INTEGER` 0/1 boolean-shaped flags, native partial
-- unique indexes, `num_nonnulls(...)` for the one-of `CHECK`.

CREATE TABLE users (
    id                          TEXT PRIMARY KEY NOT NULL,
    username                    TEXT NOT NULL,
    email                       TEXT NOT NULL,
    password_hash               TEXT NOT NULL,
    is_admin                    INTEGER NOT NULL DEFAULT 0,
    disabled_at                 BIGINT,
    email_notifications_enabled INTEGER NOT NULL DEFAULT 1,
    email_verified_at           BIGINT DEFAULT (extract(epoch from now())::bigint),
    approved_at                 BIGINT DEFAULT (extract(epoch from now())::bigint),
    created_at                  BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE UNIQUE INDEX idx_users_username_ci ON users (LOWER(username));
CREATE UNIQUE INDEX idx_users_email_ci ON users (LOWER(email));

CREATE TABLE organizations (
    id           TEXT PRIMARY KEY NOT NULL,
    name         TEXT NOT NULL,
    display_name TEXT,
    require_2fa  INTEGER NOT NULL DEFAULT 0,
    created_at   BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE UNIQUE INDEX idx_organizations_name_ci ON organizations (LOWER(name));

CREATE TABLE teams (
    id              TEXT PRIMARY KEY NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    permission      TEXT NOT NULL CHECK (permission IN ('none', 'read', 'write', 'admin')),
    created_at      BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE UNIQUE INDEX idx_teams_org_name ON teams(organization_id, name);

CREATE TABLE team_members (
    team_id  TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    PRIMARY KEY (team_id, user_id)
);

CREATE INDEX idx_team_members_user_id ON team_members(user_id);

CREATE TABLE team_unit_permissions (
    team_id    TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    unit       TEXT NOT NULL CHECK (unit IN ('code', 'issues', 'pull_requests', 'releases', 'wiki', 'projects', 'packages', 'actions')),
    permission TEXT NOT NULL CHECK (permission IN ('none', 'read', 'write', 'admin')),
    PRIMARY KEY (team_id, unit)
);

CREATE TABLE repositories (
    id            TEXT PRIMARY KEY NOT NULL,
    owner_user_id TEXT REFERENCES users(id),
    owner_org_id  TEXT REFERENCES organizations(id),
    name          TEXT NOT NULL,
    description   TEXT,
    visibility    TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
    forked_from   TEXT,
    created_at    BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    CHECK (num_nonnulls(owner_user_id, owner_org_id) = 1)
);

CREATE UNIQUE INDEX idx_repositories_user_owner_name ON repositories(owner_user_id, name);
CREATE UNIQUE INDEX idx_repositories_org_owner_name ON repositories(owner_org_id, name);
CREATE INDEX idx_repositories_owner_user ON repositories(owner_user_id);
CREATE INDEX idx_repositories_owner_org ON repositories(owner_org_id);
CREATE INDEX idx_repositories_forked_from ON repositories(forked_from);

CREATE TABLE repo_access (
    repository_id   TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    subject_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    subject_team_id TEXT REFERENCES teams(id) ON DELETE CASCADE,
    role            TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin', 'owner')),
    added_at        BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    CHECK (num_nonnulls(subject_user_id, subject_team_id) = 1)
);

CREATE UNIQUE INDEX idx_repo_access_user ON repo_access(repository_id, subject_user_id);
CREATE UNIQUE INDEX idx_repo_access_team ON repo_access(repository_id, subject_team_id);
CREATE INDEX idx_repo_access_repository_id ON repo_access(repository_id);
CREATE INDEX idx_repo_access_subject_user ON repo_access(subject_user_id);
CREATE INDEX idx_repo_access_subject_team ON repo_access(subject_team_id);
CREATE UNIQUE INDEX idx_repo_access_one_owner ON repo_access(repository_id) WHERE role = 'owner';

CREATE TABLE repo_number_counters (
    repository_id TEXT PRIMARY KEY NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    next_number   BIGINT NOT NULL DEFAULT 1
);

CREATE TABLE access_tokens (
    id               TEXT PRIMARY KEY NOT NULL,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    token_hash       TEXT NOT NULL UNIQUE,
    repository_scope TEXT NOT NULL DEFAULT '"All"',
    token_scope      TEXT NOT NULL DEFAULT '"All"',
    created_at       BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    last_used_at     BIGINT
);

CREATE INDEX idx_access_tokens_user_id ON access_tokens(user_id);

CREATE TABLE ssh_keys (
    id           TEXT PRIMARY KEY NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint  TEXT NOT NULL UNIQUE,
    public_key   TEXT NOT NULL,
    title        TEXT NOT NULL,
    created_at   BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    last_used_at BIGINT
);

CREATE INDEX idx_ssh_keys_user_id ON ssh_keys(user_id);

CREATE TABLE deploy_keys (
    id           TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint  TEXT NOT NULL UNIQUE,
    public_key   TEXT NOT NULL,
    title        TEXT NOT NULL,
    read_only    INTEGER NOT NULL DEFAULT 1,
    created_at   BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    last_used_at BIGINT
);

CREATE INDEX idx_deploy_keys_repository_id ON deploy_keys(repository_id);

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

CREATE TABLE email_verification_tokens (
    id         TEXT PRIMARY KEY NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    expires_at BIGINT NOT NULL,
    used_at    BIGINT
);

CREATE UNIQUE INDEX idx_email_verification_tokens_hash ON email_verification_tokens(token_hash);
CREATE INDEX idx_email_verification_tokens_user ON email_verification_tokens(user_id);

CREATE TABLE login_attempts (
    attempt_key     TEXT PRIMARY KEY NOT NULL,
    failure_count   INTEGER NOT NULL DEFAULT 0,
    first_failed_at BIGINT NOT NULL,
    last_failed_at  BIGINT NOT NULL,
    locked_until    BIGINT
);

CREATE TABLE audit_events (
    id          TEXT PRIMARY KEY NOT NULL,
    occurred_at BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    event_type  TEXT NOT NULL,
    actor_id    TEXT REFERENCES users(id) ON DELETE SET NULL,
    target_type TEXT,
    target_id   TEXT,
    detail_json TEXT
);

CREATE INDEX idx_audit_events_occurred_at ON audit_events(occurred_at);
CREATE INDEX idx_audit_events_actor ON audit_events(actor_id);

CREATE TABLE lfs_objects (
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    oid           TEXT NOT NULL,
    size_bytes    BIGINT NOT NULL,
    storage_key   TEXT NOT NULL,
    created_at    BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    PRIMARY KEY (repository_id, oid)
);

CREATE TABLE lfs_locks (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    path          TEXT NOT NULL,
    owner_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE UNIQUE INDEX idx_lfs_locks_repository_path ON lfs_locks(repository_id, path);

CREATE TABLE pull_requests (
    id                   TEXT PRIMARY KEY NOT NULL,
    repository_id        TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    number               BIGINT NOT NULL,
    title                TEXT NOT NULL,
    body                 TEXT,
    author_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    source_branch        TEXT NOT NULL,
    target_branch        TEXT NOT NULL,
    state                TEXT NOT NULL CHECK (state IN ('open', 'draft', 'merged', 'closed')),
    merged_at            BIGINT,
    merge_commit         TEXT,
    merge_strategy       TEXT CHECK (merge_strategy IN ('merge')),
    closed_at            BIGINT,
    close_reason         TEXT CHECK (close_reason IN ('completed', 'not_planned')),
    created_at           BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE UNIQUE INDEX idx_pull_requests_repo_number ON pull_requests(repository_id, number);
CREATE INDEX idx_pull_requests_repo_state ON pull_requests(repository_id, state);

CREATE TABLE pr_reviews (
    id              TEXT PRIMARY KEY NOT NULL,
    pull_request_id TEXT NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
    reviewer_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state           TEXT NOT NULL CHECK (state IN ('approved', 'changes_requested', 'commented')),
    body            TEXT,
    created_at      BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE INDEX idx_pr_reviews_pull_request ON pr_reviews(pull_request_id);

CREATE TABLE pr_comments (
    id                TEXT PRIMARY KEY NOT NULL,
    pull_request_id   TEXT NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
    author_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body              TEXT NOT NULL,
    anchor_file_path  TEXT,
    anchor_line_start INTEGER,
    anchor_line_end   INTEGER,
    anchor_commit_sha TEXT,
    created_at        BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    CHECK (
        (anchor_file_path IS NULL AND anchor_line_start IS NULL AND anchor_line_end IS NULL AND anchor_commit_sha IS NULL)
        OR
        (anchor_file_path IS NOT NULL AND anchor_line_start IS NOT NULL AND anchor_line_end IS NOT NULL AND anchor_commit_sha IS NOT NULL)
    )
);

CREATE INDEX idx_pr_comments_pull_request ON pr_comments(pull_request_id);

CREATE TABLE milestones (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    title         TEXT NOT NULL,
    description   TEXT,
    due_on        BIGINT,
    state         TEXT NOT NULL CHECK (state IN ('open', 'closed'))
);

CREATE INDEX idx_milestones_repository ON milestones(repository_id);

CREATE TABLE issues (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    number        BIGINT NOT NULL,
    title         TEXT NOT NULL,
    body          TEXT,
    author_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state         TEXT NOT NULL CHECK (state IN ('open', 'closed')),
    closed_at     BIGINT,
    close_reason  TEXT CHECK (close_reason IN ('completed', 'not_planned')),
    milestone_id  TEXT REFERENCES milestones(id) ON DELETE SET NULL,
    created_at    BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE UNIQUE INDEX idx_issues_repo_number ON issues(repository_id, number);
CREATE INDEX idx_issues_repo_state ON issues(repository_id, state);
CREATE INDEX idx_issues_milestone ON issues(milestone_id);

CREATE TABLE issue_comments (
    id         TEXT PRIMARY KEY NOT NULL,
    issue_id   TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    author_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE INDEX idx_issue_comments_issue ON issue_comments(issue_id);

CREATE TABLE labels (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    color         TEXT NOT NULL,
    description   TEXT,
    archived_at   BIGINT
);

CREATE UNIQUE INDEX idx_labels_repo_name ON labels(repository_id, name);

CREATE TABLE issue_labels (
    issue_id TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    label_id TEXT NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
    PRIMARY KEY (issue_id, label_id)
);

CREATE INDEX idx_issue_labels_label ON issue_labels(label_id);

CREATE TABLE branch_protection_rules (
    id                 TEXT PRIMARY KEY NOT NULL,
    repository_id      TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    branch             TEXT NOT NULL,
    required_approvals INTEGER NOT NULL DEFAULT 1 CHECK (required_approvals >= 0)
);

CREATE UNIQUE INDEX idx_branch_protection_repo_branch ON branch_protection_rules(repository_id, branch);

CREATE TABLE jobs (
    id           TEXT PRIMARY KEY NOT NULL,
    payload      TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    run_at       BIGINT NOT NULL,
    last_error   TEXT,
    created_at   BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE INDEX idx_jobs_status_run_at ON jobs(status, run_at);

CREATE TABLE releases (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    tag_name      TEXT NOT NULL,
    target_commit TEXT NOT NULL,
    name          TEXT NOT NULL,
    body          TEXT,
    draft         INTEGER NOT NULL DEFAULT 0,
    prerelease    INTEGER NOT NULL DEFAULT 0,
    published_at  BIGINT,
    author_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE UNIQUE INDEX idx_releases_repo_tag ON releases(repository_id, tag_name);
CREATE INDEX idx_releases_repo ON releases(repository_id);

CREATE TABLE release_assets (
    id           TEXT PRIMARY KEY NOT NULL,
    release_id   TEXT NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    size_bytes   BIGINT NOT NULL,
    content_type TEXT NOT NULL,
    storage_key  TEXT NOT NULL,
    created_at   BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE INDEX idx_release_assets_release ON release_assets(release_id);

CREATE TABLE webhooks (
    id                TEXT PRIMARY KEY NOT NULL,
    repository_id     TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    target_url        TEXT NOT NULL,
    secret_ciphertext BYTEA NOT NULL,
    events            TEXT NOT NULL,
    active            INTEGER NOT NULL DEFAULT 1,
    created_at        BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE INDEX idx_webhooks_repository ON webhooks(repository_id);

CREATE TABLE webhook_deliveries (
    id              TEXT PRIMARY KEY NOT NULL,
    webhook_id      TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event           TEXT NOT NULL,
    payload         TEXT NOT NULL,
    response_status INTEGER,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    delivered_at    BIGINT,
    created_at      BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);

CREATE TABLE notifications (
    id           TEXT PRIMARY KEY NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('mention', 'pr_review_requested', 'issue_assigned')),
    subject_type TEXT NOT NULL CHECK (subject_type IN ('pull_request', 'issue')),
    subject_id   TEXT NOT NULL,
    read_at      BIGINT,
    created_at   BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE INDEX idx_notifications_user_read ON notifications(user_id, read_at);
CREATE INDEX idx_notifications_dedupe_lookup ON notifications(user_id, kind, subject_type, subject_id);

CREATE TABLE events (
    id             TEXT PRIMARY KEY NOT NULL,
    occurred_at    BIGINT NOT NULL,
    aggregate_type TEXT NOT NULL,
    aggregate_id   TEXT NOT NULL,
    kind           TEXT NOT NULL,
    payload_json   TEXT NOT NULL,
    processed_at   BIGINT
);

CREATE INDEX idx_events_unprocessed ON events(occurred_at) WHERE processed_at IS NULL;
CREATE INDEX idx_events_aggregate ON events(aggregate_type, aggregate_id);

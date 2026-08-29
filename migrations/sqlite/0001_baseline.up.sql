-- Phase 9 one-time schema baseline (plan.local.md §12.2). This single
-- file replaces the 25 incremental SQLite migrations that preceded it —
-- a deliberate, documented discontinuity, safe only because Edda has no
-- deployments yet. After this, migrations resume incrementally and a CI
-- schema-parity test (crates/edda-db/tests/schema_parity.rs) guards that
-- the three backends stay in logical lockstep.
--
-- What changed from the collapsed chain, beyond flattening:
--   * `repositories.(owner_type, owner_id)` and
--     `repo_access.(subject_type, subject_id)` — previously polymorphic
--     text pairs with no referential integrity — become typed, nullable
--     foreign-key columns with a `CHECK` that exactly one is set
--     (`owner_user_id`/`owner_org_id`, `subject_user_id`/`subject_team_id`).
--   * `users.email_verified_at` / `users.approved_at` (Phase 9 H2/S3:
--     email verification + admin approval queue).
--   * `email_verification_tokens` (Phase 9).
--   * `organizations.require_2fa` (org-enforced 2FA scaffold).
--   * `branch_protection_rules.required_approvals` gains `CHECK (>= 0)`.
--
-- SQLite conventions carried over from the original chain: `STRICT`
-- tables, `unixepoch()` column defaults (a safety net — application code
-- always binds `now` explicitly, see `edda_db::now_unix`), `COLLATE
-- NOCASE` for case-insensitive text uniqueness, `INTEGER` 0/1 for
-- boolean-shaped flags, partial unique indexes for one-of invariants.
--
-- Tables are ordered so every inline `REFERENCES` target already exists
-- (PostgreSQL/MySQL require this; kept here too for a single readable
-- order across all three backends).

CREATE TABLE users (
    id                          TEXT PRIMARY KEY NOT NULL,
    username                    TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email                       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash               TEXT NOT NULL,
    is_admin                    INTEGER NOT NULL DEFAULT 0,
    disabled_at                 INTEGER,
    email_notifications_enabled INTEGER NOT NULL DEFAULT 1,
    -- NULL until the account's email address is confirmed (Phase 9). When
    -- the active `RegistrationPolicy` doesn't require verification this is
    -- stamped at signup; otherwise the email-verification flow sets it.
    email_verified_at           INTEGER,
    -- NULL while an account awaits admin approval (Phase 9 `Approval`
    -- registration mode). `Open`/`Closed` modes stamp it at creation.
    approved_at                 INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE TABLE organizations (
    id           TEXT PRIMARY KEY NOT NULL,
    name         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT,
    -- Org-enforced 2FA scaffold (plan.local.md §Phase 9 Database). Not
    -- yet consulted by the auth path — the column lands now so turning it
    -- on later is not a schema change.
    require_2fa  INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE TABLE teams (
    id              TEXT PRIMARY KEY NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    permission      TEXT NOT NULL CHECK (permission IN ('none', 'read', 'write', 'admin')),
    created_at      INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE UNIQUE INDEX idx_teams_org_name ON teams(organization_id, name);

CREATE TABLE team_members (
    team_id  TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (team_id, user_id)
) STRICT;

CREATE INDEX idx_team_members_user_id ON team_members(user_id);

CREATE TABLE team_unit_permissions (
    team_id    TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    unit       TEXT NOT NULL CHECK (unit IN ('code', 'issues', 'pull_requests', 'releases', 'wiki', 'projects', 'packages', 'actions')),
    permission TEXT NOT NULL CHECK (permission IN ('none', 'read', 'write', 'admin')),
    PRIMARY KEY (team_id, unit)
) STRICT;

-- A repository is owned by exactly one of a user or an organization —
-- two nullable typed FK columns plus a `CHECK` that precisely one is
-- set, replacing the old `(owner_type TEXT, owner_id TEXT)` polymorphic
-- pair which carried no referential integrity. `ON DELETE` is left as
-- the default (`NO ACTION` / restrict): deleting an account or org that
-- still owns repositories fails at the database, and the caller
-- (`edda-cli user delete`, the admin API) must transfer or delete those
-- repositories first — ownership hand-off is a deliberate operation, not
-- a delete side effect. No `default_branch` or any other column `gix`
-- can answer — that lives only in the git repository, read live.
CREATE TABLE repositories (
    id            TEXT PRIMARY KEY NOT NULL,
    owner_user_id TEXT REFERENCES users(id),
    owner_org_id  TEXT REFERENCES organizations(id),
    name          TEXT NOT NULL,
    description   TEXT,
    visibility    TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
    forked_from   TEXT,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
    CHECK ((owner_user_id IS NOT NULL) + (owner_org_id IS NOT NULL) = 1)
) STRICT;

-- A given owner can't have two repositories with the same name. Two
-- indexes, one per owner kind: a user-owned repo has `owner_org_id`
-- NULL (and vice versa), and SQLite treats NULLs as distinct in a
-- UNIQUE index, so each index only constrains rows of its own kind.
CREATE UNIQUE INDEX idx_repositories_user_owner_name ON repositories(owner_user_id, name);
CREATE UNIQUE INDEX idx_repositories_org_owner_name ON repositories(owner_org_id, name);
CREATE INDEX idx_repositories_owner_user ON repositories(owner_user_id);
CREATE INDEX idx_repositories_owner_org ON repositories(owner_org_id);
CREATE INDEX idx_repositories_forked_from ON repositories(forked_from);

-- Four-tier role model (Read/Write/Admin/Owner). The grantee is exactly
-- one of a user or a team — typed nullable FK columns plus a `CHECK`,
-- replacing the old `(subject_type TEXT, subject_id TEXT)` polymorphic
-- pair. Both FKs cascade: removing a user or team removes their grants.
CREATE TABLE repo_access (
    repository_id   TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    subject_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    subject_team_id TEXT REFERENCES teams(id) ON DELETE CASCADE,
    role            TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin', 'owner')),
    added_at        INTEGER NOT NULL DEFAULT (unixepoch()),
    CHECK ((subject_user_id IS NOT NULL) + (subject_team_id IS NOT NULL) = 1)
) STRICT;

CREATE UNIQUE INDEX idx_repo_access_user ON repo_access(repository_id, subject_user_id);
CREATE UNIQUE INDEX idx_repo_access_team ON repo_access(repository_id, subject_team_id);
CREATE INDEX idx_repo_access_repository_id ON repo_access(repository_id);
CREATE INDEX idx_repo_access_subject_user ON repo_access(subject_user_id);
CREATE INDEX idx_repo_access_subject_team ON repo_access(subject_team_id);

-- Exactly one Owner grant per repository at all times — the invariant
-- `edda-domain`'s authorization functions assume holds.
CREATE UNIQUE INDEX idx_repo_access_one_owner ON repo_access(repository_id) WHERE role = 'owner';

-- Pull requests and issues share one per-repository number sequence,
-- allocated by a compare-and-swap loop in `edda-db`.
CREATE TABLE repo_number_counters (
    repository_id TEXT PRIMARY KEY NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    next_number   INTEGER NOT NULL DEFAULT 1
) STRICT;

CREATE TABLE access_tokens (
    id               TEXT PRIMARY KEY NOT NULL,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    token_hash       TEXT NOT NULL UNIQUE,
    -- JSON `edda_domain::RepositoryScope` — which repositories.
    repository_scope TEXT NOT NULL DEFAULT '"All"',
    -- JSON `edda_domain::TokenScope` — which kinds of operation.
    token_scope      TEXT NOT NULL DEFAULT '"All"',
    created_at       INTEGER NOT NULL DEFAULT (unixepoch()),
    last_used_at     INTEGER
) STRICT;

CREATE INDEX idx_access_tokens_user_id ON access_tokens(user_id);

CREATE TABLE ssh_keys (
    id           TEXT PRIMARY KEY NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint  TEXT NOT NULL UNIQUE,
    public_key   TEXT NOT NULL,
    title        TEXT NOT NULL,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
    last_used_at INTEGER
) STRICT;

CREATE INDEX idx_ssh_keys_user_id ON ssh_keys(user_id);

-- Per-repository SSH deploy keys: a key that authenticates as the
-- repository, not a user. `read_only = 1` permits `git-upload-pack`
-- only; `read_only = 0` also permits `git-receive-pack`.
CREATE TABLE deploy_keys (
    id           TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint  TEXT NOT NULL UNIQUE,
    public_key   TEXT NOT NULL,
    title        TEXT NOT NULL,
    read_only    INTEGER NOT NULL DEFAULT 1,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
    last_used_at INTEGER
) STRICT;

CREATE INDEX idx_deploy_keys_repository_id ON deploy_keys(repository_id);

-- Linked OAuth/OIDC identities. `(provider, subject_id)` is what a
-- returning login looks up by; `subject_id` is the provider's immutable
-- `sub` claim, never the email.
CREATE TABLE oauth_identities (
    id         TEXT PRIMARY KEY NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider   TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE UNIQUE INDEX idx_oauth_identities_provider_subject ON oauth_identities(provider, subject_id);
CREATE INDEX idx_oauth_identities_user ON oauth_identities(user_id);

-- TOTP shared secret, AES-256-GCM encrypted at rest (`edda_auth::secret_box`).
CREATE TABLE totp_secrets (
    user_id           TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_ciphertext BLOB NOT NULL,
    created_at        INTEGER NOT NULL DEFAULT (unixepoch()),
    activated_at      INTEGER
) STRICT;

CREATE TABLE totp_recovery_codes (
    id         TEXT PRIMARY KEY NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_totp_recovery_codes_user ON totp_recovery_codes(user_id);
CREATE UNIQUE INDEX idx_totp_recovery_codes_hash ON totp_recovery_codes(code_hash);

CREATE TABLE webauthn_credentials (
    id           TEXT PRIMARY KEY NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label        TEXT NOT NULL,
    passkey_json TEXT NOT NULL,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
    last_used_at INTEGER
) STRICT;

CREATE INDEX idx_webauthn_credentials_user ON webauthn_credentials(user_id);

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

-- Phase 9: single-use, short-lived, hashed the same way as password
-- reset tokens. The request/confirm flow lives in
-- `edda_auth::email_verification`.
CREATE TABLE email_verification_tokens (
    id         TEXT PRIMARY KEY NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
) STRICT;

CREATE UNIQUE INDEX idx_email_verification_tokens_hash ON email_verification_tokens(token_hash);
CREATE INDEX idx_email_verification_tokens_user ON email_verification_tokens(user_id);

-- Per-(account, client-IP) failed-login counter for brute-force
-- throttling (`edda_auth::login_throttle`).
CREATE TABLE login_attempts (
    attempt_key     TEXT PRIMARY KEY NOT NULL,
    failure_count   INTEGER NOT NULL DEFAULT 0,
    first_failed_at INTEGER NOT NULL,
    last_failed_at  INTEGER NOT NULL,
    locked_until    INTEGER
) STRICT;

-- The audit log. `actor_id` is nullable (a failed login against an
-- unknown username has no resolved actor) and `ON DELETE SET NULL` (a
-- deleted user's trail is retained). `detail_json` carries the
-- event-specific fields as a JSON object.
CREATE TABLE audit_events (
    id          TEXT PRIMARY KEY NOT NULL,
    occurred_at INTEGER NOT NULL DEFAULT (unixepoch()),
    event_type  TEXT NOT NULL,
    actor_id    TEXT REFERENCES users(id) ON DELETE SET NULL,
    target_type TEXT,
    target_id   TEXT,
    detail_json TEXT
) STRICT;

CREATE INDEX idx_audit_events_occurred_at ON audit_events(occurred_at);
CREATE INDEX idx_audit_events_actor ON audit_events(actor_id);

CREATE TABLE lfs_objects (
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    oid           TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    storage_key   TEXT NOT NULL,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (repository_id, oid)
) STRICT;

CREATE TABLE lfs_locks (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    path          TEXT NOT NULL,
    owner_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE UNIQUE INDEX idx_lfs_locks_repository_path ON lfs_locks(repository_id, path);

-- `source_repository_id`/`source_branch` model a PR's source as a
-- repository/branch pair; a cross-repo (fork) PR has
-- `source_repository_id <> repository_id` (the same-repo `CHECK` was
-- dropped in Phase 5).
CREATE TABLE pull_requests (
    id                   TEXT PRIMARY KEY NOT NULL,
    repository_id        TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    number               INTEGER NOT NULL,
    title                TEXT NOT NULL,
    body                 TEXT,
    author_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    source_branch        TEXT NOT NULL,
    target_branch        TEXT NOT NULL,
    state                TEXT NOT NULL CHECK (state IN ('open', 'draft', 'merged', 'closed')),
    merged_at            INTEGER,
    merge_commit         TEXT,
    merge_strategy       TEXT CHECK (merge_strategy IN ('merge')),
    closed_at            INTEGER,
    close_reason         TEXT CHECK (close_reason IN ('completed', 'not_planned')),
    created_at           INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE UNIQUE INDEX idx_pull_requests_repo_number ON pull_requests(repository_id, number);
CREATE INDEX idx_pull_requests_repo_state ON pull_requests(repository_id, state);

CREATE TABLE pr_reviews (
    id              TEXT PRIMARY KEY NOT NULL,
    pull_request_id TEXT NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
    reviewer_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state           TEXT NOT NULL CHECK (state IN ('approved', 'changes_requested', 'commented')),
    body            TEXT,
    created_at      INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

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
    created_at        INTEGER NOT NULL DEFAULT (unixepoch()),
    CHECK (
        (anchor_file_path IS NULL AND anchor_line_start IS NULL AND anchor_line_end IS NULL AND anchor_commit_sha IS NULL)
        OR
        (anchor_file_path IS NOT NULL AND anchor_line_start IS NOT NULL AND anchor_line_end IS NOT NULL AND anchor_commit_sha IS NOT NULL)
    )
) STRICT;

CREATE INDEX idx_pr_comments_pull_request ON pr_comments(pull_request_id);

CREATE TABLE milestones (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    title         TEXT NOT NULL,
    description   TEXT,
    due_on        INTEGER,
    state         TEXT NOT NULL CHECK (state IN ('open', 'closed'))
) STRICT;

CREATE INDEX idx_milestones_repository ON milestones(repository_id);

CREATE TABLE issues (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    number        INTEGER NOT NULL,
    title         TEXT NOT NULL,
    body          TEXT,
    author_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state         TEXT NOT NULL CHECK (state IN ('open', 'closed')),
    closed_at     INTEGER,
    close_reason  TEXT CHECK (close_reason IN ('completed', 'not_planned')),
    milestone_id  TEXT REFERENCES milestones(id) ON DELETE SET NULL,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE UNIQUE INDEX idx_issues_repo_number ON issues(repository_id, number);
CREATE INDEX idx_issues_repo_state ON issues(repository_id, state);
CREATE INDEX idx_issues_milestone ON issues(milestone_id);

CREATE TABLE issue_comments (
    id         TEXT PRIMARY KEY NOT NULL,
    issue_id   TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    author_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_issue_comments_issue ON issue_comments(issue_id);

CREATE TABLE labels (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    color         TEXT NOT NULL,
    description   TEXT,
    archived_at   INTEGER
) STRICT;

CREATE UNIQUE INDEX idx_labels_repo_name ON labels(repository_id, name);

CREATE TABLE issue_labels (
    issue_id TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    label_id TEXT NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
    PRIMARY KEY (issue_id, label_id)
) STRICT;

CREATE INDEX idx_issue_labels_label ON issue_labels(label_id);

-- A rule's existence for `branch` blocks direct pushes and requires
-- `required_approvals` latest-review approvals to merge. `CHECK (>= 0)`
-- added in Phase 9 (a negative approval count is nonsense).
CREATE TABLE branch_protection_rules (
    id                 TEXT PRIMARY KEY NOT NULL,
    repository_id      TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    branch             TEXT NOT NULL,
    required_approvals INTEGER NOT NULL DEFAULT 1 CHECK (required_approvals >= 0)
) STRICT;

CREATE UNIQUE INDEX idx_branch_protection_repo_branch ON branch_protection_rules(repository_id, branch);

CREATE TABLE jobs (
    id           TEXT PRIMARY KEY NOT NULL,
    payload      TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    run_at       INTEGER NOT NULL,
    last_error   TEXT,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

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
    published_at  INTEGER,
    author_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE UNIQUE INDEX idx_releases_repo_tag ON releases(repository_id, tag_name);
CREATE INDEX idx_releases_repo ON releases(repository_id);

CREATE TABLE release_assets (
    id           TEXT PRIMARY KEY NOT NULL,
    release_id   TEXT NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    size_bytes   INTEGER NOT NULL,
    content_type TEXT NOT NULL,
    storage_key  TEXT NOT NULL,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_release_assets_release ON release_assets(release_id);

CREATE TABLE webhooks (
    id                TEXT PRIMARY KEY NOT NULL,
    repository_id     TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    target_url        TEXT NOT NULL,
    secret_ciphertext BLOB NOT NULL,
    events            TEXT NOT NULL,
    active            INTEGER NOT NULL DEFAULT 1,
    created_at        INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_webhooks_repository ON webhooks(repository_id);

CREATE TABLE webhook_deliveries (
    id              TEXT PRIMARY KEY NOT NULL,
    webhook_id      TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event           TEXT NOT NULL,
    payload         TEXT NOT NULL,
    response_status INTEGER,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    delivered_at    INTEGER,
    created_at      INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);

-- `subject_type`/`subject_id` stays polymorphic here — low integrity
-- stakes, high churn (plan.local.md §12.2 keeps `notifications`/`events`
-- polymorphic on purpose).
CREATE TABLE notifications (
    id           TEXT PRIMARY KEY NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('mention', 'pr_review_requested', 'issue_assigned')),
    subject_type TEXT NOT NULL CHECK (subject_type IN ('pull_request', 'issue')),
    subject_id   TEXT NOT NULL,
    read_at      INTEGER,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_notifications_user_read ON notifications(user_id, read_at);
CREATE INDEX idx_notifications_dedupe_lookup ON notifications(user_id, kind, subject_type, subject_id);

-- Transactional outbox. `aggregate_type`/`aggregate_id` locate the
-- entity; no foreign key — events outlive the rows they reference.
CREATE TABLE events (
    id             TEXT PRIMARY KEY NOT NULL,
    occurred_at    INTEGER NOT NULL,
    aggregate_type TEXT NOT NULL,
    aggregate_id   TEXT NOT NULL,
    kind           TEXT NOT NULL,
    payload_json   TEXT NOT NULL,
    processed_at   INTEGER
) STRICT;

CREATE INDEX idx_events_unprocessed ON events(occurred_at) WHERE processed_at IS NULL;
CREATE INDEX idx_events_aggregate ON events(aggregate_type, aggregate_id);

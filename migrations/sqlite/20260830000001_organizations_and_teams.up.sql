-- Organizations share the global username namespace with `users.username`
-- (the org-vs-username collision rule) — enforced by a combined
-- uniqueness check in `edda-auth`, called from both signup and
-- organization creation. This table's own unique index only guarantees
-- organization names are unique among themselves; the cross-table half of
-- the check is application-level, the same check-then-insert trade-off
-- `NotificationRepo::insert_if_new` already accepts.
CREATE TABLE organizations (
    id           TEXT PRIMARY KEY NOT NULL,
    name         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

-- Every organization gets a default "Owners" team at creation time,
-- created by application code (not this migration) alongside the
-- organization row itself, mirroring Forgejo's own model: its members
-- administer the organization and everything it owns. This is what a
-- repository created under an organization grants its `owner` role to
-- (see the `team_repo_access` migration) — `AccessSubject` has no
-- separate `Organization` variant of its own, so an org-owned repo's
-- single mandatory `owner` grant is always a team grant, never a bare org
-- reference.
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

-- Per-unit override of a team's default `permission` — `'code'` is the
-- only unit currently wired into repository authorization (see
-- `edda_domain::team::Team::code_permission`); the rest of Forgejo's unit
-- list is modeled now so a later change adding issue/PR/release-scoped
-- team permissions is additive, not a schema change.
CREATE TABLE team_unit_permissions (
    team_id    TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    unit       TEXT NOT NULL CHECK (unit IN ('code', 'issues', 'pull_requests', 'releases', 'wiki', 'projects', 'packages', 'actions')),
    permission TEXT NOT NULL CHECK (permission IN ('none', 'read', 'write', 'admin')),
    PRIMARY KEY (team_id, unit)
) STRICT;

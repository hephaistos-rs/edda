-- PostgreSQL counterpart of sqlite/20260830000001_organizations_and_teams.up.sql.
-- Case-insensitive organization-name uniqueness is index-based (LOWER(...))
-- rather than a COLLATE NOCASE column, matching the `users` migration's
-- own reasoning (avoids requiring the citext extension).
CREATE TABLE organizations (
    id           TEXT PRIMARY KEY NOT NULL,
    name         TEXT NOT NULL,
    display_name TEXT,
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

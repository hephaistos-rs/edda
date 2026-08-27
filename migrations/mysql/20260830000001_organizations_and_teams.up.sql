-- MySQL/MariaDB counterpart of sqlite/20260830000001_organizations_and_teams.up.sql.
-- Case-insensitive organization-name uniqueness uses the same
-- lowercased-shadow-column technique as `users.username_lower`
-- (MariaDB rejects a direct functional unique index — confirmed against a
-- real `mariadb:12.3.3` instance while writing the `users` migration).
CREATE TABLE organizations (
    id           VARCHAR(36) PRIMARY KEY NOT NULL,
    name         VARCHAR(255) NOT NULL,
    name_lower   VARCHAR(255) AS (LOWER(name)) STORED,
    display_name VARCHAR(255),
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

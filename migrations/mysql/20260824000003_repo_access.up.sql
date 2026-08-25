-- MySQL/MariaDB counterpart of sqlite/20260824000003_repo_access.up.sql.
--
-- The one-owner-per-repository invariant: SQLite and PostgreSQL both
-- enforce it with a partial/filtered unique index
-- (`idx_repo_access_one_owner ... WHERE role = 'owner'`), which MySQL/
-- MariaDB has no equivalent for. The standard InnoDB workaround —
-- genuinely backend-specific, not a portability shortcut — is a
-- generated column that's NULL for every non-owner row (InnoDB unique
-- indexes treat multiple NULLs as distinct, so any number of non-owner
-- rows coexist) and holds the repository's own id for an owner row (so a
-- second owner row for the same repository collides on the unique index
-- the normal way). This isolates the divergence to one column and one
-- index; every other column in this table is identical in shape to the
-- other two backends.
CREATE TABLE repo_access (
    repository_id VARCHAR(36) NOT NULL,
    user_id       VARCHAR(36) NOT NULL,
    role          VARCHAR(16) NOT NULL CHECK (role IN ('read', 'write', 'admin', 'owner')),
    added_at      BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    owner_marker  VARCHAR(36) AS (IF(role = 'owner', repository_id, NULL)) STORED,
    PRIMARY KEY (repository_id, user_id),
    CONSTRAINT fk_repo_access_repository FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
    CONSTRAINT fk_repo_access_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_repo_access_repository_id ON repo_access(repository_id);

CREATE UNIQUE INDEX idx_repo_access_one_owner ON repo_access(owner_marker);

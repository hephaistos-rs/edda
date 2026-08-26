-- MySQL/MariaDB counterpart of sqlite/20260829000002_releases.up.sql.
-- `body` is bounded `VARCHAR`, not `TEXT` — the `Any`-decodes-MySQL-`TEXT`-
-- as-`BLOB` reason explained in the `repositories` migration.
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

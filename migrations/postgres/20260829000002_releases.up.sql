-- PostgreSQL counterpart of sqlite/20260829000002_releases.up.sql.
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

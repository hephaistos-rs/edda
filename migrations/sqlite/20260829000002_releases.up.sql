-- `draft`/`prerelease` are boolean-shaped `INTEGER` (0/1) — same
-- convention as `users.is_admin` (SQLite has no native `BOOLEAN`, and this
-- keeps one decode path across every backend rather than a per-backend
-- bool story). `target_commit` is the tag's commit id at creation time,
-- not re-derived from the tag on every read — see
-- `edda_domain::release::Release`'s doc comment.
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

-- `storage_key` mirrors `lfs_objects.storage_key`'s pattern: an opaque,
-- filesystem-relative path under the repo's own storage root
-- (`RepoStore`), not an absolute path. `content_type` is stored for
-- display only — never trusted when serving the file back (see
-- `edda_domain::release::ReleaseAsset`'s doc comment).
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

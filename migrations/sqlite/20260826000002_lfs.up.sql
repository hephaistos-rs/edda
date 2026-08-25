-- Git LFS objects: content-addressed, keyed by (repository_id, oid) rather
-- than a synthetic id — the object's identity already is its content hash.
-- `storage_key` is where the bytes live under this repository's own LFS
-- storage root (see `edda_git::store::RepoStore::lfs_object_path`), kept
-- as a stored column rather than recomputed from `oid` so a future non-
-- filesystem storage backend can change the layout without a migration.
CREATE TABLE lfs_objects (
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    oid           TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    storage_key   TEXT NOT NULL,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (repository_id, oid)
) STRICT;

-- Git LFS file locks (the locking extension `git lfs lock`/`unlock` use).
-- `(repository_id, path)` is unique while a lock is held — the file can't
-- have two outstanding locks at once.
CREATE TABLE lfs_locks (
    id            TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    path          TEXT NOT NULL,
    owner_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE UNIQUE INDEX idx_lfs_locks_repository_path ON lfs_locks(repository_id, path);

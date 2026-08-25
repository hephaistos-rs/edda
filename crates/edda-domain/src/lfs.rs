use crate::ids::{LfsLockId, RepositoryId, UserId};

/// One content-addressed Git LFS object. Keyed by `(repository_id, oid)`,
/// not its own id — the object's identity *is* its content hash, so a
/// synthetic id would only be redundant. `oid` is the hex-encoded SHA-256
/// digest Git LFS pointer files reference; `size_bytes` is redundant with
/// the stored blob's own size but is part of the LFS batch API's request/
/// response shape, so keeping it alongside avoids a filesystem stat on
/// every batch request. `storage_key` is where the actual bytes live,
/// relative to this repository's own LFS storage root — kept as a plain
/// column (not recomputed from `oid` at read time) so a future non-
/// filesystem storage backend can change the layout without a data
/// migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LfsObject {
    pub repository_id: RepositoryId,
    pub oid: String,
    pub size_bytes: i64,
    pub storage_key: String,
}

/// A Git LFS file lock (the locking extension real `git lfs lock`/`unlock`
/// use to coordinate exclusive edits on files that can't be usefully
/// merged, e.g. binary assets). `path` is the repository-relative file
/// path being locked, unique per repository while the lock is held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LfsLock {
    pub id: LfsLockId,
    pub repository_id: RepositoryId,
    pub path: String,
    pub owner_id: UserId,
    pub created_at: i64,
}

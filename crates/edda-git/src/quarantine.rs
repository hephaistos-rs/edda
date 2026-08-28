//! Inbound-pack ingestion for `git-receive-pack`.
//!
//! A push's pack is streamed into a **quarantine** directory
//! (`objects/pack/incoming-<n>/`) as a real indexed `.pack`/`.idx` via
//! `gix-pack` bundle-write — never as thousands of loose objects. Every
//! new ref tip and its object closure is then checked for connectivity
//! (fsck-lite) against the quarantined pack plus the repo's existing
//! store. Only if that passes — and the caller's ref compare-and-swap and
//! branch-protection checks pass — is the pack **promoted** (moved into
//! the live `objects/pack/`).
//!
//! A rejected push calls [`Quarantine::discard`], which removes the whole
//! quarantine directory: the object store is left byte-identical to
//! before. The old receive path wrote each object loose *before* checking
//! the ref updates, so a rejected non-fast-forward push left orphaned
//! objects that nothing ever collected (S7).

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use gix::ObjectId;
use gix_object::Kind;

use crate::GitError;

/// Hard ceiling on the fsck-lite connectivity walk, so a pathological pack
/// can't make the check run unbounded. Same order of magnitude as
/// `transfer::MAX_IMPORTED_OBJECTS`.
const MAX_FSCK_OBJECTS: usize = 2_000_000;

static QUARANTINE_SEQ: AtomicU64 = AtomicU64::new(0);

/// A pack written into a quarantine directory, not yet part of the repo's
/// object store. Either [`promote`](Self::promote) it once every ref
/// update is known good, or [`discard`](Self::discard) it.
#[derive(Debug)]
pub struct Quarantine {
    dir: PathBuf,
    pack_path: Option<PathBuf>,
    index_path: Option<PathBuf>,
}

/// Streams `pack` (the raw pack section of a `git-receive-pack` request)
/// into a fresh quarantine directory under the repo, writing a real
/// indexed `.pack`/`.idx` via `gix-pack` bundle-write. Thin packs are
/// resolved against objects already in `repo`. Nothing is added to the
/// live object store yet.
///
/// CPU-bound (delta resolution + zlib): call from a blocking context.
pub fn write_pack(repo: &gix::Repository, pack: &[u8]) -> Result<Quarantine, GitError> {
    let seq = QUARANTINE_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = repo
        .git_dir()
        .join("objects")
        .join("pack")
        .join(format!("incoming-{}-{nanos}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir)?;

    let written = (|| {
        let mut reader = std::io::Cursor::new(pack);
        let interrupt = AtomicBool::new(false);
        let outcome = gix_pack::Bundle::write_to_directory(
            &mut reader,
            Some(&dir),
            &mut gix::progress::Discard,
            &interrupt,
            Some(repo.objects.clone()),
            gix_pack::bundle::write::Options {
                // One thread per push: a busy server already runs many
                // pushes concurrently, and per-push rayon fan-out would
                // oversubscribe. Delta-heavy pushes get the `gix-pack
                // data::output` fast path in a later phase.
                thread_limit: Some(1),
                ..Default::default()
            },
        )
        .map_err(|err| GitError::Git(format!("bad pack: {err}")))?;

        // Bundle-write drops a `.keep` file to stop GC until a ref points
        // at the pack. This pack is still quarantined, so that bookkeeping
        // is ours to do — drop the file now.
        if let Some(keep) = &outcome.keep_path {
            let _ = std::fs::remove_file(keep);
        }
        Ok::<_, GitError>((outcome.data_path, outcome.index_path))
    })();

    match written {
        Ok((pack_path, index_path)) => Ok(Quarantine {
            dir,
            pack_path,
            index_path,
        }),
        Err(err) => {
            let _ = std::fs::remove_dir_all(&dir);
            Err(err)
        }
    }
}

impl Quarantine {
    /// fsck-lite: every id in `tips`, and its whole object closure, must
    /// resolve — looking in the quarantined pack first, then the repo's
    /// live store. A truncated pack, a dangling thin-pack base, or a tree
    /// entry pointing at a missing object all fail here, before anything
    /// is promoted.
    ///
    /// CPU-bound: call from a blocking context.
    pub fn fsck(&self, repo: &gix::Repository, tips: &[ObjectId]) -> Result<(), GitError> {
        let bundle = match &self.index_path {
            Some(index) => Some(
                gix_pack::Bundle::at(index, gix_hash::Kind::Sha1)
                    .map_err(|err| GitError::Git(format!("reopening quarantined pack: {err}")))?,
            ),
            // An empty pack: every tip must already be in the repo.
            None => None,
        };
        let mut inflate = gix_zlib::Inflate::default();
        let mut cache = gix_pack::cache::Never;

        let mut seen: HashSet<ObjectId> = HashSet::new();
        let mut queue: VecDeque<ObjectId> = tips.iter().copied().collect();
        let mut visited = 0usize;

        while let Some(id) = queue.pop_front() {
            if !seen.insert(id) {
                continue;
            }
            visited += 1;
            if visited > MAX_FSCK_OBJECTS {
                return Err(GitError::Git(format!(
                    "fsck: object graph exceeds {MAX_FSCK_OBJECTS} objects — refusing the push"
                )));
            }

            let mut buf = Vec::new();
            let resolved: Option<(Kind, Vec<u8>)> = {
                let from_pack = match &bundle {
                    Some(bundle) => bundle
                        .find(&id, &mut buf, &mut inflate, &mut cache)
                        .map_err(|err| GitError::Git(format!("fsck: decoding {id}: {err}")))?,
                    None => None,
                };
                match from_pack {
                    Some((data, _)) => Some((data.kind, data.data.to_vec())),
                    None => repo
                        .find_object(id)
                        .ok()
                        .map(|object| (object.kind, object.data.clone())),
                }
            };

            let Some((kind, data)) = resolved else {
                return Err(GitError::Git(format!(
                    "fsck: the push references object {id}, which is in neither the pack \
                     nor the repository"
                )));
            };

            enqueue_children(&mut queue, kind, &data)?;
        }
        Ok(())
    }

    /// Moves the quarantined `.pack`/`.idx` into the repo's live
    /// `objects/pack/` and removes the (now-empty) quarantine directory.
    /// Returns a handle that can still [roll the pack back
    /// out](PromotedPack::rollback) if a *subsequent* step (the ref
    /// transaction) fails — the pack is a self-contained unit, and until a
    /// ref points at it, removing it again leaves the store as it was.
    pub fn promote(self, repo: &gix::Repository) -> Result<PromotedPack, GitError> {
        let pack_dir = repo.git_dir().join("objects").join("pack");
        let mut moved = Vec::new();
        // `.pack` first, then `.idx`: a concurrent reader must never see
        // an index that points at a pack that isn't in place yet.
        for src in [self.pack_path.as_ref(), self.index_path.as_ref()]
            .into_iter()
            .flatten()
        {
            let name = src
                .file_name()
                .ok_or_else(|| GitError::Git("quarantined pack file has no name".to_string()))?;
            let dest = pack_dir.join(name);
            std::fs::rename(src, &dest)?;
            moved.push(dest);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
        Ok(PromotedPack { paths: moved })
    }

    /// Removes the quarantine directory wholesale — the push is rejected
    /// and the object store is left exactly as it was.
    pub fn discard(self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A pack that has been moved into `objects/pack/` but which no ref points
/// at yet. Drop it (do nothing) once a ref update has committed, or
/// [`rollback`](Self::rollback) it if that update failed.
#[derive(Debug)]
pub struct PromotedPack {
    paths: Vec<PathBuf>,
}

impl PromotedPack {
    /// Deletes the promoted `.pack`/`.idx` again — safe because nothing
    /// references it, so the object store returns to its pre-push state.
    pub fn rollback(self) {
        for path in self.paths {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Pushes whatever `data` (an object of type `kind`) references onto
/// `queue`: a commit's tree and parents, a tree's entries, an annotated
/// tag's target. Blobs reference nothing.
fn enqueue_children(
    queue: &mut VecDeque<ObjectId>,
    kind: Kind,
    data: &[u8],
) -> Result<(), GitError> {
    match kind {
        Kind::Commit => {
            let commit = gix_object::CommitRef::from_bytes(data, gix_hash::Kind::Sha1)
                .map_err(|err| GitError::Git(err.to_string()))?;
            queue.push_back(commit.tree());
            queue.extend(commit.parents());
        }
        Kind::Tree => {
            let tree = gix_object::TreeRef::from_bytes(data, gix_hash::Kind::Sha1)
                .map_err(|err| GitError::Git(err.to_string()))?;
            queue.extend(tree.entries.iter().map(|entry| entry.oid.to_owned()));
        }
        Kind::Tag => {
            let tag = gix_object::TagRef::from_bytes(data, gix_hash::Kind::Sha1)
                .map_err(|err| GitError::Git(err.to_string()))?;
            queue.push_back(tag.target());
        }
        Kind::Blob => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "edda-git-quarantine-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn empty_tree(repo: &gix::Repository) -> ObjectId {
        repo.write_object(gix_object::Tree::empty())
            .unwrap()
            .detach()
    }

    fn commit(repo: &gix::Repository, tree: ObjectId, parents: &[ObjectId], msg: &str) -> ObjectId {
        let sig = gix_actor::Signature {
            name: "t".into(),
            email: "t@e".into(),
            time: gix::date::Time::new(1_700_000_000, 0),
        };
        repo.write_object(gix_object::Commit {
            tree,
            parents: parents.iter().copied().collect(),
            author: sig.clone(),
            committer: sig,
            encoding: None,
            message: msg.into(),
            extra_headers: Vec::new(),
        })
        .unwrap()
        .detach()
    }

    /// A minimal whole-object pack (via this crate's own builder) for
    /// `commit` and everything it reaches, so the quarantine path has a
    /// real pack to ingest without shelling out to `git`.
    fn pack_for(repo: &gix::Repository, tip: ObjectId) -> Vec<u8> {
        crate::pack::build_pack(repo, &[tip]).unwrap()
    }

    #[test]
    fn a_good_pack_ingests_fscks_and_promotes() {
        let dir = tmp("promote");
        gix::init_bare(&dir).unwrap();
        let source = gix::open(&dir).unwrap();
        let tree = empty_tree(&source);
        let c1 = commit(&source, tree, &[], "one");
        let c2 = commit(&source, tree, &[c1], "two");
        let pack = pack_for(&source, c2);

        // Fresh target repo; ingest the pack into quarantine.
        let target_dir = tmp("promote-target");
        gix::init_bare(&target_dir).unwrap();
        let target = gix::open(&target_dir).unwrap();
        assert!(target.find_object(c2).is_err(), "not in the store yet");

        let quarantine = write_pack(&target, &pack).unwrap();
        // Still invisible to the live store.
        assert!(gix::open(&target_dir).unwrap().find_object(c2).is_err());

        quarantine.fsck(&target, &[c2]).unwrap();
        quarantine.promote(&target).unwrap();

        // Now visible, and the quarantine dir is gone.
        let promoted = gix::open(&target_dir).unwrap();
        assert!(promoted.find_object(c2).is_ok());
        assert!(promoted.find_object(c1).is_ok());
        assert!(promoted.find_object(tree).is_ok());
        let incoming: Vec<_> = std::fs::read_dir(target_dir.join("objects/pack"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("incoming-"))
            .collect();
        assert!(incoming.is_empty(), "quarantine dir should be gone");

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&target_dir);
    }

    #[test]
    fn a_discarded_quarantine_leaves_the_store_byte_identical() {
        let dir = tmp("discard");
        gix::init_bare(&dir).unwrap();
        let source = gix::open(&dir).unwrap();
        let tree = empty_tree(&source);
        let c1 = commit(&source, tree, &[], "one");
        let pack = pack_for(&source, c1);

        let target_dir = tmp("discard-target");
        gix::init_bare(&target_dir).unwrap();
        let target = gix::open(&target_dir).unwrap();

        let before: Vec<_> = std::fs::read_dir(target_dir.join("objects/pack"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();

        let quarantine = write_pack(&target, &pack).unwrap();
        quarantine.discard();

        let after: Vec<_> = std::fs::read_dir(target_dir.join("objects/pack"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(before, after, "discard must leave objects/pack untouched");
        assert!(gix::open(&target_dir).unwrap().find_object(c1).is_err());

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&target_dir);
    }

    #[test]
    fn fsck_rejects_a_tip_that_is_in_neither_the_pack_nor_the_repo() {
        let dir = tmp("fsck-miss");
        gix::init_bare(&dir).unwrap();
        let source = gix::open(&dir).unwrap();
        let tree = empty_tree(&source);
        let c1 = commit(&source, tree, &[], "one");
        let c2 = commit(&source, tree, &[c1], "two");
        // Pack contains only c1's closure...
        let pack = pack_for(&source, c1);

        let target_dir = tmp("fsck-miss-target");
        gix::init_bare(&target_dir).unwrap();
        let target = gix::open(&target_dir).unwrap();
        let quarantine = write_pack(&target, &pack).unwrap();

        // ...but the "push" claims to advance a ref to c2.
        let err = quarantine.fsck(&target, &[c2]).unwrap_err();
        assert!(matches!(err, GitError::Git(_)));

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&target_dir);
    }

    #[test]
    fn write_pack_rejects_a_truncated_pack() {
        let dir = tmp("trunc");
        gix::init_bare(&dir).unwrap();
        let source = gix::open(&dir).unwrap();
        let tree = empty_tree(&source);
        let c1 = commit(&source, tree, &[], "one");
        let mut pack = pack_for(&source, c1);
        pack.truncate(pack.len() / 2);

        let target_dir = tmp("trunc-target");
        gix::init_bare(&target_dir).unwrap();
        let target = gix::open(&target_dir).unwrap();

        let err = write_pack(&target, &pack).unwrap_err();
        assert!(matches!(err, GitError::Git(_)));
        // No quarantine dir left behind.
        let leftover: Vec<_> = std::fs::read_dir(target_dir.join("objects/pack"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("incoming-"))
            .collect();
        assert!(leftover.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&target_dir);
    }
}

//! Repository housekeeping the Phase 12 scheduler drives: sweeping
//! abandoned receive-pack quarantine directories, and a modest per-repo
//! garbage collection.
//!
//! All functions here are blocking filesystem walks — call them from a
//! `spawn_blocking` context, never an async task.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::store::RepoStore;
use crate::GitError;

/// What a quarantine sweep reclaimed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuarantineSweep {
    pub directories_removed: u64,
    pub bytes_reclaimed: u64,
}

impl QuarantineSweep {
    fn add(&mut self, other: QuarantineSweep) {
        self.directories_removed += other.directories_removed;
        self.bytes_reclaimed += other.bytes_reclaimed;
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn dir_size(path: &Path) -> u64 {
    let mut total = 0;
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            total += dir_size(&entry.path());
        } else {
            total += meta.len();
        }
    }
    total
}

/// Removes `objects/pack/incoming-*` directories older than
/// `max_age_secs` in one repository. A quarantine directory only exists
/// while a push's receive critical section runs (all synchronous, in one
/// `spawn_blocking`), so anything this old is from a crashed or killed
/// push and holds no reachable objects.
fn sweep_one(git_dir: &Path, max_age_secs: u64) -> QuarantineSweep {
    let pack_dir = git_dir.join("objects").join("pack");
    let Ok(entries) = std::fs::read_dir(&pack_dir) else {
        return QuarantineSweep::default();
    };
    let cutoff = now_secs().saturating_sub(max_age_secs);
    let mut swept = QuarantineSweep::default();
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with("incoming-") {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_dir() {
            continue;
        }
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if modified > cutoff {
            continue;
        }
        let path = entry.path();
        let bytes = dir_size(&path);
        if std::fs::remove_dir_all(&path).is_ok() {
            swept.add(QuarantineSweep {
                directories_removed: 1,
                bytes_reclaimed: bytes,
            });
        }
    }
    swept
}

/// Sweeps abandoned quarantine directories across every repository in the
/// store — the `prune_quarantine` maintenance task.
pub fn sweep_quarantine(
    store: &dyn RepoStore,
    max_age_secs: u64,
) -> Result<QuarantineSweep, GitError> {
    let names = store.list_repo_names().map_err(GitError::from)?;
    let mut total = QuarantineSweep::default();
    for name in names {
        total.add(sweep_one(&store.repo_dir(&name), max_age_secs));
    }
    Ok(total)
}

/// What one repository's GC did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RepoGcOutcome {
    pub quarantine: QuarantineSweep,
    pub empty_dirs_removed: u64,
}

/// Recursively removes empty directories under `root` (but never `root`
/// itself). Returns how many were removed.
fn prune_empty_dirs(root: &Path) -> u64 {
    fn walk(path: &Path, is_root: bool, removed: &mut u64) -> bool {
        let Ok(entries) = std::fs::read_dir(path) else {
            return false;
        };
        let mut child_dirs = Vec::new();
        let mut has_file = false;
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                has_file = true;
                continue;
            };
            if file_type.is_dir() {
                child_dirs.push(entry.path());
            } else {
                has_file = true;
            }
        }
        let mut all_children_gone = true;
        for child in &child_dirs {
            if !walk(child, false, removed) {
                all_children_gone = false;
            }
        }
        if !is_root && !has_file && all_children_gone {
            if std::fs::remove_dir(path).is_ok() {
                *removed += 1;
                return true;
            }
            return false;
        }
        false
    }
    let mut removed = 0;
    walk(root, true, &mut removed);
    removed
}

/// A conservative per-repository garbage collection (the `repo_gc_sweep`
/// task fans this out, and `edda-cli repo gc` calls it directly): sweep
/// this repo's stale quarantine directories with a one-hour floor, then
/// remove now-empty directories under `objects/` and `refs/`.
///
/// It deliberately does **not** repack loose objects into a pack — that
/// needs `gix-pack`'s object-output writer, the benchmark-gated Phase 7b
/// work that has not landed. What it reclaims is abandoned-push
/// quarantine bytes and directory clutter, which is where a churned
/// Edda repo actually accumulates dead weight today.
pub fn repo_gc(store: &dyn RepoStore, name: &str) -> Result<RepoGcOutcome, GitError> {
    let git_dir = store.repo_dir(name);
    if !git_dir.is_dir() {
        return Err(GitError::NotFound(name.to_string()));
    }
    const ONE_HOUR: u64 = 3600;
    let quarantine = sweep_one(&git_dir, ONE_HOUR);
    let mut empty_dirs_removed = prune_empty_dirs(&git_dir.join("objects"));
    empty_dirs_removed += prune_empty_dirs(&git_dir.join("refs"));
    Ok(RepoGcOutcome {
        quarantine,
        empty_dirs_removed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LocalFsStore;
    use crate::{create_repo, LockRegistry};

    fn tmp(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "edda-git-maint-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[tokio::test]
    async fn the_sweep_age_gate_keeps_a_fresh_incoming_dir_and_removes_an_aged_one() {
        let root = tmp("sweep");
        let store = LocalFsStore::new(root.clone());
        let locks = LockRegistry::new();
        create_repo(&store, &locks, "alice/demo").await.unwrap();
        let pack = store.repo_dir("alice/demo").join("objects").join("pack");

        // An "old" dir: created, then let ~1.1s pass so its mtime is
        // comfortably past a 1-second floor.
        std::fs::create_dir_all(pack.join("incoming-old")).unwrap();
        std::fs::write(pack.join("incoming-old").join("blob"), b"0123456789").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1_100));
        // A "fresh" dir, created just before the sweep.
        std::fs::create_dir_all(pack.join("incoming-fresh")).unwrap();

        // Nothing is old enough for a one-day floor.
        assert_eq!(
            sweep_quarantine(&store, 86_400).unwrap(),
            QuarantineSweep::default()
        );
        assert!(pack.join("incoming-old").exists());

        // A one-second floor catches the aged dir but not the fresh one.
        let swept = sweep_quarantine(&store, 1).unwrap();
        assert_eq!(swept.directories_removed, 1);
        assert_eq!(swept.bytes_reclaimed, 10);
        assert!(!pack.join("incoming-old").exists());
        assert!(pack.join("incoming-fresh").exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn repo_gc_reports_a_missing_repo_and_prunes_empty_dirs_in_an_existing_one() {
        let root = tmp("gc");
        let store = LocalFsStore::new(root.clone());
        let locks = LockRegistry::new();
        create_repo(&store, &locks, "alice/demo").await.unwrap();

        assert!(matches!(
            repo_gc(&store, "alice/ghost"),
            Err(GitError::NotFound(_))
        ));

        let stray = store
            .repo_dir("alice/demo")
            .join("refs")
            .join("edda")
            .join("empty");
        std::fs::create_dir_all(&stray).unwrap();
        let outcome = repo_gc(&store, "alice/demo").unwrap();
        assert!(outcome.empty_dirs_removed >= 1);
        assert!(!stray.exists());

        let _ = std::fs::remove_dir_all(&root);
    }
}

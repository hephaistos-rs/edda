//! Ref updates over `gix-ref` transactions: packed-refs aware, atomic
//! across every ref in one push, reflog-writing, and with correct
//! compare-and-swap.
//!
//! Replaces the previous hand-rolled loose-file CAS (`apply_ref_update`),
//! which read `refs/heads/<branch>` as a plain file and was blind to
//! `packed-refs`: after a `git pack-refs`, the loose file is gone, so a
//! stale (non-fast-forward) push read the ref as `0000…`, mistook itself
//! for a *branch creation*, and silently overwrote history. `gix-ref`
//! reads the *effective* value (loose or packed) and rejects the stale
//! push — that is the H6 fix.

use gix::refs::transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog};
use gix::refs::{FullName, Target};
use gix::ObjectId;

use crate::GitError;

/// The all-zeros object id git's wire protocols use for "no such object" —
/// a ref command's old-id when creating a ref, or its new-id when deleting
/// one. Kept as a string constant because that is how it travels on the
/// wire; [`update_refs`] parses it back out.
pub const ZERO_ID: &str = "0000000000000000000000000000000000000000";

/// One ref-update command with git compare-and-swap semantics — the shape
/// `receive-pack` parses off the wire (`<old> <new> <ref>`).
pub struct RefUpdate {
    /// Fully-qualified: `refs/heads/main`, `refs/tags/v1`, …
    pub name: String,
    /// The value the caller believes the ref currently holds, hex-encoded,
    /// or [`ZERO_ID`] to mean "this ref must not exist yet" (a create).
    pub expected_old: String,
    /// The value to set, hex-encoded, or [`ZERO_ID`] to delete the ref.
    pub new: String,
}

/// Applies every update in `updates` as one atomic `gix-ref` transaction —
/// all succeed or none do (a push that touches several refs is
/// all-or-nothing). Each precondition is checked against the ref's
/// *effective* current value (loose **or** `packed-refs`), and a reflog
/// entry is written for the refs git itself would log (`refs/heads/**`,
/// `HEAD`) — never for `refs/tags/**` or the internal `refs/edda/**`.
///
/// `reflog_message` is the text recorded on each reflog line (`"push"`,
/// `"merge"`, …).
///
/// On a precondition mismatch — a stale non-fast-forward push, a create
/// racing another create, a delete of a ref that has since moved — returns
/// `GitError::Git` and writes nothing.
pub fn update_refs(
    repo: &gix::Repository,
    updates: &[RefUpdate],
    reflog_message: &str,
) -> Result<(), GitError> {
    if updates.is_empty() {
        return Ok(());
    }

    let edits = updates
        .iter()
        .map(|update| ref_edit(update, reflog_message))
        .collect::<Result<Vec<_>, _>>()?;

    // Our bare server repos default the ref store to `WriteReflog::Disable`
    // (git's own rule for bare repos). Push/merge history *is* worth a
    // reflog for recovery and audit, so run the transaction against a
    // private clone of the store switched to `Normal`, which still logs
    // only the refs git would.
    let mut store = repo.refs.clone();
    store.write_reflog = gix::refs::store::WriteReflog::Normal;

    let signature = gix_actor::Signature {
        name: "edda".into(),
        email: "edda@localhost".into(),
        time: gix::date::Time::now_utc(),
    };
    let mut time_buf = gix::date::parse::TimeBuf::default();
    let committer = signature.to_ref(&mut time_buf);

    let lock_fail =
        gix::lock::acquire::Fail::AfterDurationWithBackoff(std::time::Duration::from_secs(1));
    let prepared = store
        .transaction()
        .prepare(edits, lock_fail, lock_fail)
        .map_err(|err| GitError::Git(err.to_string()))?;
    prepared
        .commit(Some(committer))
        .map_err(|err| GitError::Git(err.to_string()))?;
    Ok(())
}

/// Force-sets `name` to `new` regardless of its current value (create or
/// update, never a delete). For Edda-internal ref bookkeeping only — the
/// interim `refs/edda/pull-heads/*` that [`crate::transfer`] maintains —
/// where the previous value carries no meaning. A real push always goes
/// through [`update_refs`] so its CAS is enforced.
pub fn force_set_ref(repo: &gix::Repository, name: &str, new: ObjectId) -> Result<(), GitError> {
    let edit = RefEdit {
        change: Change::Update {
            log: LogChange {
                mode: RefLog::AndReference,
                force_create_reflog: false,
                message: "edda: internal ref update".into(),
            },
            expected: PreviousValue::Any,
            new: Target::Object(new),
        },
        name: full_name(name)?,
        deref: false,
    };
    repo.edit_reference(edit)
        .map_err(|err| GitError::Git(err.to_string()))?;
    Ok(())
}

/// Points `HEAD` at `refs/heads/<branch>` symbolically — the job the
/// hand-rolled `HEAD` file write in `fix_unborn_head` used to do, now
/// through `gix`'s ref-editing API so it goes via the same locking and
/// packed-refs-aware path as every other ref write.
pub fn point_head_at(repo: &gix::Repository, branch: &str) -> Result<(), GitError> {
    let edit = RefEdit {
        change: Change::Update {
            log: LogChange {
                mode: RefLog::AndReference,
                force_create_reflog: false,
                message: "edda: set HEAD".into(),
            },
            expected: PreviousValue::Any,
            new: Target::Symbolic(full_name(&format!("refs/heads/{branch}"))?),
        },
        name: full_name("HEAD")?,
        deref: false,
    };
    repo.edit_reference(edit)
        .map_err(|err| GitError::Git(err.to_string()))?;
    Ok(())
}

fn full_name(name: &str) -> Result<FullName, GitError> {
    FullName::try_from(name)
        .map_err(|err| GitError::Git(format!("invalid ref name {name:?}: {err}")))
}

fn parse_oid(hex: &str) -> Result<ObjectId, GitError> {
    ObjectId::from_hex(hex.as_bytes())
        .map_err(|_| GitError::Git(format!("not a valid object id: {hex:?}")))
}

fn ref_edit(update: &RefUpdate, message: &str) -> Result<RefEdit, GitError> {
    let creating = update.expected_old == ZERO_ID;
    let deleting = update.new == ZERO_ID;

    let expected = if creating {
        // A create with a stale idea of the ref (someone else created it
        // first) must be rejected — that is what `MustNotExist` does. On a
        // `<zero> <zero> <ref>` no-op, be permissive instead.
        if deleting {
            PreviousValue::Any
        } else {
            PreviousValue::MustNotExist
        }
    } else {
        PreviousValue::MustExistAndMatch(Target::Object(parse_oid(&update.expected_old)?))
    };

    let change = if deleting {
        Change::Delete {
            expected,
            log: RefLog::AndReference,
        }
    } else {
        Change::Update {
            log: LogChange {
                mode: RefLog::AndReference,
                force_create_reflog: false,
                message: message.into(),
            },
            expected,
            new: Target::Object(parse_oid(&update.new)?),
        }
    };

    Ok(RefEdit {
        change,
        name: full_name(&update.name)?,
        deref: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "edda-git-refs-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Writes a minimal real commit object with an empty tree and returns
    /// its id — enough for a ref to point at.
    fn commit(repo: &gix::Repository, parents: &[ObjectId], message: &str) -> ObjectId {
        let empty_tree = repo
            .write_object(gix_object::Tree::empty())
            .unwrap()
            .detach();
        let sig = gix_actor::Signature {
            name: "t".into(),
            email: "t@e".into(),
            time: gix::date::Time::new(1_700_000_000, 0),
        };
        let object = gix_object::Commit {
            tree: empty_tree,
            parents: parents.iter().copied().collect(),
            author: sig.clone(),
            committer: sig,
            encoding: None,
            message: message.into(),
            extra_headers: Vec::new(),
        };
        repo.write_object(object).unwrap().detach()
    }

    #[test]
    fn a_create_then_a_fast_forward_update_then_a_delete_all_apply() {
        let dir = tmp("lifecycle");
        gix::init_bare(&dir).unwrap();
        let repo = gix::open(&dir).unwrap();

        let c1 = commit(&repo, &[], "one");
        update_refs(
            &repo,
            &[RefUpdate {
                name: "refs/heads/main".into(),
                expected_old: ZERO_ID.into(),
                new: c1.to_string(),
            }],
            "push",
        )
        .unwrap();
        assert_eq!(
            repo.find_reference("refs/heads/main")
                .unwrap()
                .target()
                .id(),
            c1
        );

        let c2 = commit(&repo, &[c1], "two");
        update_refs(
            &repo,
            &[RefUpdate {
                name: "refs/heads/main".into(),
                expected_old: c1.to_string(),
                new: c2.to_string(),
            }],
            "push",
        )
        .unwrap();

        // The reflog exists and records the move (H6 acceptance criterion).
        let reflog = std::fs::read_to_string(dir.join("logs/refs/heads/main")).unwrap();
        assert_eq!(reflog.lines().count(), 2);
        assert!(reflog.contains(&c1.to_string()) && reflog.contains(&c2.to_string()));

        update_refs(
            &repo,
            &[RefUpdate {
                name: "refs/heads/main".into(),
                expected_old: c2.to_string(),
                new: ZERO_ID.into(),
            }],
            "push",
        )
        .unwrap();
        assert!(repo.find_reference("refs/heads/main").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_update_is_rejected_even_when_the_ref_is_only_in_packed_refs() {
        let dir = tmp("packed");
        gix::init_bare(&dir).unwrap();
        let repo = gix::open(&dir).unwrap();

        let c1 = commit(&repo, &[], "one");
        update_refs(
            &repo,
            &[RefUpdate {
                name: "refs/heads/main".into(),
                expected_old: ZERO_ID.into(),
                new: c1.to_string(),
            }],
            "push",
        )
        .unwrap();

        // Collapse the loose ref into packed-refs, exactly as `git
        // pack-refs --all` would — the loose file is gone afterwards.
        std::fs::write(
            dir.join("packed-refs"),
            format!("# pack-refs with: peeled fully-peeled sorted \n{c1} refs/heads/main\n"),
        )
        .unwrap();
        let _ = std::fs::remove_file(dir.join("refs/heads/main"));
        let repo = gix::open(&dir).unwrap();

        // A push whose old-id is the zero id (the bug: "the loose file is
        // missing, so this must be a create") must now be rejected,
        // because the effective value read from packed-refs is `c1`.
        let c2 = commit(&repo, &[c1], "two");
        let err = update_refs(
            &repo,
            &[RefUpdate {
                name: "refs/heads/main".into(),
                expected_old: ZERO_ID.into(),
                new: c2.to_string(),
            }],
            "push",
        )
        .unwrap_err();
        assert!(matches!(err, GitError::Git(_)));

        // And the ref did not move.
        assert_eq!(
            gix::open(&dir)
                .unwrap()
                .find_reference("refs/heads/main")
                .unwrap()
                .target()
                .id(),
            c1
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_multi_ref_push_is_all_or_nothing() {
        let dir = tmp("atomic");
        gix::init_bare(&dir).unwrap();
        let repo = gix::open(&dir).unwrap();
        let c1 = commit(&repo, &[], "one");

        // Two creates in one transaction: the second is impossible (its
        // old-id doesn't match a nonexistent ref), so neither may land.
        let err = update_refs(
            &repo,
            &[
                RefUpdate {
                    name: "refs/heads/main".into(),
                    expected_old: ZERO_ID.into(),
                    new: c1.to_string(),
                },
                RefUpdate {
                    name: "refs/heads/dev".into(),
                    expected_old: c1.to_string(), // wrong: dev does not exist
                    new: c1.to_string(),
                },
            ],
            "push",
        )
        .unwrap_err();
        assert!(matches!(err, GitError::Git(_)));
        assert!(repo.find_reference("refs/heads/main").is_err());
        assert!(repo.find_reference("refs/heads/dev").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn force_set_ref_ignores_the_previous_value() {
        let dir = tmp("force");
        gix::init_bare(&dir).unwrap();
        let repo = gix::open(&dir).unwrap();
        let c1 = commit(&repo, &[], "one");
        let c2 = commit(&repo, &[c1], "two");

        force_set_ref(&repo, "refs/edda/pull-heads/1", c1).unwrap();
        force_set_ref(&repo, "refs/edda/pull-heads/1", c2).unwrap();
        assert_eq!(
            repo.find_reference("refs/edda/pull-heads/1")
                .unwrap()
                .target()
                .id(),
            c2
        );
        // Internal refs get no reflog.
        assert!(!dir.join("logs/refs/edda/pull-heads/1").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn point_head_at_writes_a_symbolic_ref() {
        let dir = tmp("head");
        gix::init_bare(&dir).unwrap();
        let repo = gix::open(&dir).unwrap();
        let c1 = commit(&repo, &[], "one");
        update_refs(
            &repo,
            &[RefUpdate {
                name: "refs/heads/trunk".into(),
                expected_old: ZERO_ID.into(),
                new: c1.to_string(),
            }],
            "push",
        )
        .unwrap();

        point_head_at(&repo, "trunk").unwrap();
        let head = std::fs::read_to_string(dir.join("HEAD")).unwrap();
        assert_eq!(head.trim(), "ref: refs/heads/trunk");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

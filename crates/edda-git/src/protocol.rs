//! The git smart-protocol request/response orchestration shared by every
//! transport (`edda-http`'s HTTP bridge, `edda-ssh`'s SSH bridge).
//! Everything here operates on plain byte buffers (`&[u8]` in,
//! `bytes::Bytes`/`Vec<u8>` out) — no HTTP or SSH types appear anywhere in
//! this module. A transport's own job shrinks to: authenticate, resolve
//! which repository, read raw request bytes from its own I/O, call one of
//! the functions here, and write the raw response bytes back via its own
//! I/O. This module exists specifically so SSH does not become a second
//! implementation of the git wire protocol.
//!
//! The one place HTTP and SSH genuinely differ at the wire level is ref
//! advertisement: HTTP's `info/refs?service=...` prepends a `# service=`
//! comment pkt-line that SSH's direct `git-upload-pack`/`git-receive-pack`
//! exec never sends. [`write_ref_advertisement`] writes only the shared
//! part (ref lines + flush); a caller that needs the service line adds it
//! itself.

use std::path::PathBuf;

use bytes::Bytes;
use gix::ObjectId;

use crate::pack::{build_pack_excluding, parse_pack, write_loose_object};
use crate::pktline::{read_pkt_line, write_flush, write_pkt_line, PktLine};
use crate::store::RepoStore;
use crate::{
    apply_ref_update, fix_unborn_head, open_repo_dir, pick_default_branch, GitError, LockRegistry,
    ZERO_ID,
};

pub const UPLOAD_PACK_CAPABILITIES: &str = "agent=edda/0.1.0";
pub const RECEIVE_PACK_CAPABILITIES: &str = "report-status agent=edda/0.1.0";

/// HEAD (if it resolves) plus every local branch — everything a client
/// needs to clone and check out the default branch. No tags: nothing in
/// Edda creates one yet.
///
/// HEAD can be unborn on disk (points at a branch, e.g. "master", that a
/// push never actually created — see `fix_unborn_head`'s doc comment) even
/// though real branches exist: without a HEAD line at all here, a cloning
/// client has nothing to check out and fails outright, so this falls back
/// to the same branch preference used everywhere else.
pub fn advertised_refs(repo: &gix::Repository) -> Result<Vec<(ObjectId, String)>, GitError> {
    let mut branches = Vec::new();
    if let Ok(platform) = repo.references() {
        if let Ok(local) = platform.local_branches() {
            for reference in local.filter_map(Result::ok) {
                if let Some(id) = reference.target().try_id() {
                    branches.push((id.to_owned(), reference.name().shorten().to_string()));
                }
            }
        }
    }

    let mut refs = Vec::new();

    let head = repo.head_id().ok().map(|id| id.detach()).or_else(|| {
        let names: Vec<String> = branches.iter().map(|(_, name)| name.clone()).collect();
        let chosen = pick_default_branch(&names)?;
        branches
            .iter()
            .find(|(_, name)| name == chosen)
            .map(|(id, _)| *id)
    });
    if let Some(id) = head {
        refs.push((id, "HEAD".to_string()));
    }

    refs.extend(
        branches
            .into_iter()
            .map(|(id, name)| (id, format!("refs/heads/{name}"))),
    );

    Ok(refs)
}

/// Writes the shared part of a ref advertisement (ref lines + flush) — no
/// service-line prefix. Callers that need one (only HTTP's `info/refs`
/// does) prepend it themselves before calling this.
pub fn write_ref_advertisement(out: &mut Vec<u8>, refs: &[(ObjectId, String)], capabilities: &str) {
    if refs.is_empty() {
        // No refs to advertise (empty repo) — git still expects a line here
        // so the client learns server capabilities; the all-zero id is the
        // documented placeholder for "no real ref".
        let zero_id = "0".repeat(40);
        write_pkt_line(
            out,
            format!("{zero_id} capabilities^{{}}\0{capabilities}\n").as_bytes(),
        );
    } else {
        for (i, (oid, ref_name)) in refs.iter().enumerate() {
            let line = if i == 0 {
                format!("{oid} {ref_name}\0{capabilities}\n")
            } else {
                format!("{oid} {ref_name}\n")
            };
            write_pkt_line(out, line.as_bytes());
        }
    }
    write_flush(out);
}

/// Opens `name`'s repo and builds its ref advertisement — the whole
/// "resolve repo, list refs" step both `info_refs` (HTTP) and an
/// upload-pack/receive-pack exec's first phase (SSH) need identically.
pub fn build_ref_advertisement(
    store: &dyn RepoStore,
    name: &str,
    capabilities: &str,
) -> Result<Vec<u8>, GitError> {
    let repo = open_repo_dir(store, name)?;
    let refs = advertised_refs(&repo)?;
    let mut out = Vec::new();
    write_ref_advertisement(&mut out, &refs, capabilities);
    Ok(out)
}

pub struct UploadPackRequest {
    pub wants: Vec<ObjectId>,
    pub haves: Vec<ObjectId>,
}

/// Parses an upload-pack request body: `want` lines up to the first
/// flush, then `have` lines up to a literal `done` line (or the input
/// running out).
///
/// Edda never advertises `multi_ack`/`multi_ack_detailed`
/// ([`UPLOAD_PACK_CAPABILITIES`] carries neither) — per the base git
/// protocol (`Documentation/technical/pack-protocol.txt`), a client that
/// doesn't see either capability advertised sends everything it intends
/// to (`want`s, then `have`s) in one uninterrupted burst followed by
/// `done`, without waiting for an intermediate ACK/NAK after each batch.
/// That's what makes reading straight through to `done` — rather than
/// implementing per-batch ACK/NAK round-trips — both correct and
/// non-blocking on every transport, including SSH's live channel.
pub fn parse_upload_pack_request(body: &[u8]) -> UploadPackRequest {
    let mut pos = 0;
    let mut wants = Vec::new();
    while let Some(line) = read_pkt_line(body, &mut pos) {
        match line {
            PktLine::Flush => break,
            PktLine::Data(data) => {
                if let Some(id) = parse_oid_line(data, "want ") {
                    wants.push(id);
                }
            }
        }
    }

    let mut haves = Vec::new();
    loop {
        match read_pkt_line(body, &mut pos) {
            None => break,
            Some(PktLine::Flush) => continue,
            Some(PktLine::Data(data)) => {
                let text = String::from_utf8_lossy(data);
                if text.trim_end() == "done" {
                    break;
                }
                if let Some(id) = parse_oid_line(data, "have ") {
                    haves.push(id);
                }
            }
        }
    }

    UploadPackRequest { wants, haves }
}

fn parse_oid_line(data: &[u8], prefix: &str) -> Option<ObjectId> {
    let text = String::from_utf8_lossy(data);
    let rest = text.trim_end().strip_prefix(prefix)?;
    let oid_hex = rest.split_whitespace().next()?;
    ObjectId::from_hex(oid_hex.as_bytes()).ok()
}

/// Whether `body` (as buffered *so far*) contains a complete upload-pack
/// request — i.e. parsing reaches a literal `done` line rather than
/// running out of bytes first. HTTP never needs this (it always has the
/// complete POST body up front); a live channel transport (`edda-ssh`)
/// calls this after every chunk of incoming data to know whether to keep
/// buffering or hand the accumulated bytes to [`parse_upload_pack_request`].
pub fn upload_pack_request_is_complete(body: &[u8]) -> bool {
    let mut pos = 0;
    loop {
        match read_pkt_line(body, &mut pos) {
            Some(PktLine::Flush) => break,
            Some(PktLine::Data(_)) => continue,
            None => return false,
        }
    }
    loop {
        match read_pkt_line(body, &mut pos) {
            None => return false,
            Some(PktLine::Flush) => continue,
            Some(PktLine::Data(data)) => {
                if String::from_utf8_lossy(data).trim_end() == "done" {
                    return true;
                }
            }
        }
    }
}

/// Runs upload-pack against an already-open repo: builds the pack for
/// `request.wants` minus what's reachable from `request.haves` (real
/// have/done negotiation, not a stubbed "send everything"), and returns the
/// complete wire response (a `NAK` line followed by the raw pack bytes)
/// ready to write directly to either transport's output.
///
/// Runs the actual walk on the blocking pool (real CPU work: object-graph
/// traversal and zlib deflation, not I/O) and re-enters the calling span
/// inside it, so `git.build_pack` nests under whichever span the caller is
/// in rather than showing up orphaned — the exact `spawn_blocking`/span
/// dance every caller previously had to write for itself now lives in
/// exactly one place.
pub async fn build_upload_pack_response(
    repo: gix::Repository,
    request: UploadPackRequest,
) -> Result<Vec<u8>, GitError> {
    let current_span = tracing::Span::current();
    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| build_pack_excluding(&repo, &request.wants, &request.haves))
    })
    .await
    .map_err(|_| GitError::Git("pack build task panicked".to_string()))?;
    let pack = result?;

    let mut out = Vec::new();
    // No side-band negotiated (not advertised in the ref advertisement),
    // so a plain NAK line — "here's the pack" — followed by the raw pack
    // bytes with no further framing.
    write_pkt_line(&mut out, b"NAK\n");
    out.extend_from_slice(&pack);
    Ok(out)
}

/// Opens `name` and runs the complete upload-pack cycle against `body`
/// (the request bytes read verbatim off either transport). This is what a
/// transport calls once it has the whole request buffered.
pub async fn run_upload_pack(
    store: &dyn RepoStore,
    name: &str,
    body: Bytes,
) -> Result<Vec<u8>, GitError> {
    let repo = open_repo_dir(store, name)?;
    let request = parse_upload_pack_request(&body);
    if request.wants.is_empty() {
        return Err(GitError::Git("no \"want\" lines in request".to_string()));
    }
    build_upload_pack_response(repo, request).await
}

pub struct RefCommand {
    pub old_id: String,
    pub new_id: String,
    pub ref_name: String,
}

/// Parses receive-pack's ref-update commands: pkt-lines up to the first
/// flush; the pack data (if any command isn't a pure delete) follows
/// immediately after with no further pkt-line framing, running to the end
/// of `body`. Returns the parsed commands and the byte offset the pack
/// data (if any) starts at.
pub fn parse_receive_pack_commands(body: &[u8]) -> Result<(Vec<RefCommand>, usize), String> {
    let mut pos = 0;
    let mut commands = Vec::new();
    loop {
        match read_pkt_line(body, &mut pos) {
            Some(PktLine::Flush) | None => break,
            Some(PktLine::Data(line)) => {
                let text = String::from_utf8_lossy(line);
                // Capabilities ride after a NUL on the first line only.
                let text = text.split('\0').next().unwrap_or(&text).trim_end();
                let mut parts = text.splitn(3, ' ');
                let (Some(old_id), Some(new_id), Some(ref_name)) =
                    (parts.next(), parts.next(), parts.next())
                else {
                    return Err(format!("malformed ref-update command: {text:?}"));
                };
                commands.push(RefCommand {
                    old_id: old_id.to_string(),
                    new_id: new_id.to_string(),
                    ref_name: ref_name.to_string(),
                });
            }
        }
    }
    Ok((commands, pos))
}

/// Runs receive-pack: parses and stores the pack (if any command isn't a
/// pure delete), applies each ref-update command with compare-and-swap
/// semantics, and repairs an unborn HEAD if anything succeeded. Returns
/// the wire response (`report-status` lines). The caller must hold
/// `locks`'s lock for `name` for the duration of this call (and open the
/// repo/resolve the on-disk directory itself, since it also needs the
/// directory for the lock — see `run_receive_pack` for the common case
/// that does both).
pub async fn apply_receive_pack(
    repo: gix::Repository,
    git_dir: PathBuf,
    commands: Vec<RefCommand>,
    pack_data: Bytes,
) -> Result<Vec<u8>, String> {
    if commands.is_empty() {
        return Err("no ref-update commands in request".to_string());
    }

    let needs_pack = commands.iter().any(|command| command.new_id != ZERO_ID);
    if needs_pack {
        // Same reasoning as `build_upload_pack_response`: delta resolution
        // and re-deflating every object to write it out as a loose object
        // is real CPU work — run it on the blocking pool.
        let git_dir_for_pack = git_dir.clone();
        let current_span = tracing::Span::current();
        let outcome = tokio::task::spawn_blocking(move || {
            current_span.in_scope(|| {
                let objects =
                    parse_pack(&repo, &pack_data).map_err(|err| format!("bad pack: {err}"))?;
                for object in &objects {
                    write_loose_object(&git_dir_for_pack, object.kind, &object.data)
                        .map_err(|err| format!("couldn't store object {}: {err}", object.id))?;
                }
                Ok::<_, String>(())
            })
        })
        .await;
        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(message)) => return Err(message),
            Err(_) => return Err("pack processing task panicked".to_string()),
        }
    }

    let mut results = Vec::with_capacity(commands.len());
    for command in &commands {
        let outcome = apply_ref_update(
            &git_dir,
            &command.ref_name,
            &command.old_id,
            &command.new_id,
        );
        results.push((command.ref_name.clone(), outcome));
    }

    // A push can create the repo's first branch under a name HEAD doesn't
    // point at yet (see `fix_unborn_head`'s doc comment) — repair it now
    // so a client cloning right after this push gets a working checkout.
    if results.iter().any(|(_, outcome)| outcome.is_ok()) {
        let _ = fix_unborn_head(&git_dir);
    }

    let mut out = Vec::new();
    write_pkt_line(&mut out, b"unpack ok\n");
    for (ref_name, outcome) in &results {
        let line = match outcome {
            Ok(()) => format!("ok {ref_name}\n"),
            Err(reason) => format!("ng {ref_name} {reason}\n"),
        };
        write_pkt_line(&mut out, line.as_bytes());
    }
    write_flush(&mut out);
    Ok(out)
}

/// Opens `name`, holds `locks`'s per-repo lock for the duration (a push is
/// a write: it must not land while, say, someone deletes the repo out
/// from under it via the web UI, or another push races it), and runs the
/// complete receive-pack cycle against `body`.
pub async fn run_receive_pack(
    store: &dyn RepoStore,
    locks: &LockRegistry,
    name: &str,
    body: Bytes,
) -> Result<Vec<u8>, GitError> {
    let git_dir = crate::validated_repo_dir(store, name)?;
    let repo = gix::open(&git_dir).map_err(|err| GitError::Git(err.to_string()))?;

    let lock = locks.lock_for(name);
    let _guard = lock.lock().await;

    let (commands, pos) = parse_receive_pack_commands(&body).map_err(GitError::Git)?;
    let pack_data = body.slice(pos..);
    apply_receive_pack(repo, git_dir, commands, pack_data)
        .await
        .map_err(GitError::Git)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::write_loose_object;
    use crate::pktline::write_pkt_line as pkt;
    use gix_object::Kind;

    #[test]
    fn parse_upload_pack_request_reads_wants_then_haves_then_done() {
        let mut body = Vec::new();
        pkt(&mut body, format!("want {}\n", "a".repeat(40)).as_bytes());
        pkt(&mut body, format!("want {}\n", "b".repeat(40)).as_bytes());
        write_flush(&mut body);
        pkt(&mut body, format!("have {}\n", "c".repeat(40)).as_bytes());
        pkt(&mut body, b"done\n");

        let request = parse_upload_pack_request(&body);
        assert_eq!(request.wants.len(), 2);
        assert_eq!(request.haves.len(), 1);
    }

    #[test]
    fn parse_upload_pack_request_with_no_haves_still_reads_wants() {
        let mut body = Vec::new();
        pkt(&mut body, format!("want {}\n", "a".repeat(40)).as_bytes());
        write_flush(&mut body);
        // No haves, no "done" — a client that already has everything just
        // stops here.

        let request = parse_upload_pack_request(&body);
        assert_eq!(request.wants.len(), 1);
        assert!(request.haves.is_empty());
    }

    #[test]
    fn upload_pack_request_completeness_detects_partial_buffers() {
        let mut body = Vec::new();
        pkt(&mut body, format!("want {}\n", "a".repeat(40)).as_bytes());
        assert!(
            !upload_pack_request_is_complete(&body),
            "no flush yet — incomplete"
        );

        write_flush(&mut body);
        assert!(
            !upload_pack_request_is_complete(&body),
            "wants ended but no done yet — incomplete"
        );

        pkt(&mut body, format!("have {}\n", "b".repeat(40)).as_bytes());
        assert!(
            !upload_pack_request_is_complete(&body),
            "still no done — incomplete"
        );

        pkt(&mut body, b"done\n");
        assert!(
            upload_pack_request_is_complete(&body),
            "done seen — complete"
        );
    }

    #[test]
    fn parse_receive_pack_commands_reads_commands_and_locates_pack_start() {
        let mut body = Vec::new();
        pkt(
            &mut body,
            format!("{} {} refs/heads/main\n", "0".repeat(40), "a".repeat(40)).as_bytes(),
        );
        write_flush(&mut body);
        body.extend_from_slice(b"PACK-DATA-GOES-HERE");

        let (commands, pack_start) = parse_receive_pack_commands(&body).unwrap();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].ref_name, "refs/heads/main");
        assert_eq!(&body[pack_start..], b"PACK-DATA-GOES-HERE");
    }

    #[test]
    fn parse_receive_pack_commands_rejects_malformed_lines() {
        let mut body = Vec::new();
        pkt(&mut body, b"not-a-valid-command\n");
        write_flush(&mut body);

        assert!(parse_receive_pack_commands(&body).is_err());
    }

    /// Writes a minimal, real git commit object (raw encoding, not through
    /// `gix`'s own commit-construction API — this is fixture setup for the
    /// test below, exercising exactly the byte format
    /// `build_pack_excluding` already has to parse via
    /// `gix_object::CommitRef::from_bytes`).
    fn write_commit(
        git_dir: &std::path::Path,
        tree: gix::ObjectId,
        parents: &[gix::ObjectId],
        message: &str,
    ) -> gix::ObjectId {
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            body.push_str(&format!("parent {parent}\n"));
        }
        body.push_str("author Test <test@example.com> 1700000000 +0000\n");
        body.push_str("committer Test <test@example.com> 1700000000 +0000\n\n");
        body.push_str(message);
        body.push('\n');
        write_loose_object(git_dir, Kind::Commit, body.as_bytes()).unwrap()
    }

    fn pack_object_count(pack: &[u8]) -> u32 {
        // Pack header: "PACK" + 4-byte version + 4-byte big-endian object
        // count (see `pack::serialize_pack`).
        u32::from_be_bytes([pack[8], pack[9], pack[10], pack[11]])
    }

    #[test]
    fn build_pack_excluding_omits_objects_reachable_from_haves() {
        let root = std::env::temp_dir().join(format!("edda-protocol-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        gix::init_bare(&root).unwrap();

        // A tiny, fixed empty-tree object — its id is a well-known
        // constant in git (the SHA-1 of an empty tree), reused here for
        // both commits so the test is about commit/blob-count exclusion,
        // not tree contents.
        let empty_tree = write_loose_object(&root, Kind::Tree, b"").unwrap();

        let commit1 = write_commit(&root, empty_tree, &[], "first commit");
        let commit2 = write_commit(&root, empty_tree, &[commit1], "second commit");

        let repo = gix::open(&root).unwrap();

        // Full history from commit2: commit2, commit1, and the (shared)
        // empty tree — 3 objects.
        let full = build_pack_excluding(&repo, &[commit2], &[]).unwrap();
        assert_eq!(pack_object_count(&full), 3);

        // With commit1 as a `have`, only commit2 itself is new — the tree
        // is already excluded via commit1's own reachability, and commit1
        // itself is excluded directly.
        let incremental = build_pack_excluding(&repo, &[commit2], &[commit1]).unwrap();
        assert_eq!(pack_object_count(&incremental), 1);

        let _ = std::fs::remove_dir_all(&root);
    }
}

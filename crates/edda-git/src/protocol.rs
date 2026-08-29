//! The git smart-protocol request/response orchestration shared by every
//! transport (`edda-app`'s HTTP bridge, `edda-ssh`'s SSH bridge).
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

use crate::hooks::{self, AppliedRef, ReceiveChecks, ReceiveOutcome};
use crate::pack::{build_shallow_pack, Deepen, ShallowSpec};
use crate::pktline::{read_pkt_line, write_flush, write_pkt_line, PktLine};
use crate::quarantine::{self, Quarantine};
use crate::refs::{update_refs, RefUpdate};
use crate::store::RepoStore;
use crate::{
    fix_unborn_head, open_repo_dir, pick_default_branch, sideband, GitError, LockRegistry, ZERO_ID,
};

/// `side-band-64k`: multiplex the pack stream with progress/error channels
/// (see [`crate::sideband`]) — every modern `git` negotiates it when
/// advertised. `ofs-delta`: we understand offset-delta packs (the client
/// may send a smaller one on push; our own upload-pack output stays
/// whole-object until the Phase 7b delta pipeline).
///
/// This is the set advertised over **SSH**. `shallow` is deliberately
/// absent: `git clone --depth N` over a stateful transport needs a
/// two-message exchange (learn the boundary, then fetch), and `edda-ssh`
/// closes the channel after the single [`run_upload_pack`] call — a stateful
/// SSH shallow handshake is a follow-up. Over HTTP (stateless-RPC, each
/// request self-contained) shallow *is* supported — see
/// [`UPLOAD_PACK_CAPABILITIES_STATELESS`].
pub const UPLOAD_PACK_CAPABILITIES: &str = "side-band-64k ofs-delta agent=edda/0.1.0";

/// [`UPLOAD_PACK_CAPABILITIES`] plus `shallow` — advertised over HTTP,
/// where the client's two shallow-negotiation requests are each a complete,
/// independent POST (`build_upload_pack_response` answers the first, which
/// carries no `done`, with just the `shallow`/`unshallow` list).
pub const UPLOAD_PACK_CAPABILITIES_STATELESS: &str =
    "side-band-64k ofs-delta shallow agent=edda/0.1.0";
/// `delete-refs` is advertised so `git push origin :branch` is allowed at
/// all — a client refuses to send a deletion command otherwise.
/// `ofs-delta` lets the client send an offset-delta-compressed pack, which
/// `gix-pack`'s bundle-write resolves on ingest.
pub const RECEIVE_PACK_CAPABILITIES: &str = "report-status delete-refs ofs-delta agent=edda/0.1.0";

/// HEAD (if it resolves), every local branch, then every tag — everything
/// a client needs to clone, check out the default branch, and fetch tags.
/// Edda's tags are lightweight (`refs/tags/<name>` straight to a commit —
/// see `crate::tags`), so no peeled `^{}` lines are needed.
///
/// HEAD can be unborn on disk (points at a branch, e.g. "master", that a
/// push never actually created — see `fix_unborn_head`'s doc comment) even
/// though real branches exist: without a HEAD line at all here, a cloning
/// client has nothing to check out and fails outright, so this falls back
/// to the same branch preference used everywhere else.
pub fn advertised_refs(repo: &gix::Repository) -> Result<Vec<(ObjectId, String)>, GitError> {
    let mut branches = Vec::new();
    let mut tags = Vec::new();
    if let Ok(platform) = repo.references() {
        if let Ok(local) = platform.local_branches() {
            for reference in local.filter_map(Result::ok) {
                if let Some(id) = reference.target().try_id() {
                    branches.push((id.to_owned(), reference.name().shorten().to_string()));
                }
            }
        }
        if let Ok(tag_refs) = platform.tags() {
            for mut reference in tag_refs.filter_map(Result::ok) {
                // A lightweight tag's target *is* the commit id; peel
                // anyway so a stray annotated tag still advertises its
                // commit rather than the tag object.
                if let Ok(id) = reference.peel_to_id() {
                    tags.push((id.detach(), reference.name().shorten().to_string()));
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
    refs.extend(
        tags.into_iter()
            .map(|(id, name)| (id, format!("refs/tags/{name}"))),
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
    /// Capability tokens the client listed on its first `want` line
    /// (space-separated, after the OID) — e.g. `side-band-64k`,
    /// `ofs-delta`, `no-progress`, `agent=…`.
    pub capabilities: Vec<String>,
    /// Commits the client already has as shallow boundaries (`shallow <id>`
    /// lines) — empty for a full clone or a fresh shallow clone.
    pub shallow: Vec<ObjectId>,
    /// The `deepen` / `deepen-since` request, if any.
    pub deepen: Deepen,
    /// A `done` line closed the request. Absent on a shallow clone's
    /// *first* stateless request, whose only job is to learn the shallow
    /// boundary — that one gets the `shallow`/`unshallow` list and no pack.
    pub done: bool,
}

impl UploadPackRequest {
    /// The client negotiated `side-band-64k`: the pack response must be
    /// multiplexed (see [`crate::sideband`]). Every current `git` does
    /// this whenever the server advertises it.
    #[must_use]
    pub fn wants_side_band_64k(&self) -> bool {
        self.capabilities.iter().any(|cap| cap == "side-band-64k")
    }

    /// The client did *not* pass `no-progress` — a channel-2 progress line
    /// is welcome. Only meaningful alongside side-band.
    #[must_use]
    pub fn wants_progress(&self) -> bool {
        !self.capabilities.iter().any(|cap| cap == "no-progress")
    }
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
    let mut capabilities = Vec::new();
    let mut shallow = Vec::new();
    let mut deepen = Deepen::None;
    while let Some(line) = read_pkt_line(body, &mut pos) {
        match line {
            PktLine::Flush => break,
            PktLine::Data(data) => {
                let text = String::from_utf8_lossy(data);
                let text = text.trim_end();
                if let Some(rest) = text.strip_prefix("want ") {
                    let mut fields = rest.split_whitespace();
                    let Some(id) = fields
                        .next()
                        .and_then(|hex| ObjectId::from_hex(hex.as_bytes()).ok())
                    else {
                        continue;
                    };
                    // Capabilities ride only on the *first* `want` line.
                    if wants.is_empty() {
                        capabilities = fields.map(str::to_string).collect();
                    }
                    wants.push(id);
                } else if let Some(rest) = text.strip_prefix("shallow ") {
                    if let Ok(id) = ObjectId::from_hex(rest.trim().as_bytes()) {
                        shallow.push(id);
                    }
                } else if let Some(rest) = text.strip_prefix("deepen-since ") {
                    if let Ok(seconds) = rest.trim().parse::<i64>() {
                        deepen = Deepen::Since(seconds);
                    }
                } else if let Some(rest) = text.strip_prefix("deepen ") {
                    // `deepen-not` is not honoured yet — a client that sends
                    // it gets a slightly deeper (never shallower, so safe)
                    // history than requested.
                    if let Ok(depth) = rest.trim().parse::<u32>() {
                        if depth > 0 {
                            deepen = Deepen::Depth(depth);
                        }
                    }
                }
            }
        }
    }

    let mut haves = Vec::new();
    let mut done = false;
    loop {
        match read_pkt_line(body, &mut pos) {
            None => break,
            Some(PktLine::Flush) => continue,
            Some(PktLine::Data(data)) => {
                let text = String::from_utf8_lossy(data);
                if text.trim_end() == "done" {
                    done = true;
                    break;
                }
                if let Some(id) = parse_oid_line(data, "have ") {
                    haves.push(id);
                }
            }
        }
    }

    UploadPackRequest {
        wants,
        haves,
        capabilities,
        shallow,
        deepen,
        done,
    }
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
/// complete wire response ready to write directly to either transport's
/// output.
///
/// The response always opens with a plain `NAK` pkt-line (acknowledgments
/// are never multiplexed). If the client negotiated `side-band-64k` the
/// pack then follows as channel-1 pkt-lines — with an optional channel-2
/// progress line — terminated by a flush; otherwise the raw pack bytes
/// follow with no further framing (byte-identical to the pre-Phase-7 wire).
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
    let side_band = request.wants_side_band_64k();
    let with_progress = side_band && request.wants_progress();
    let shallow_only = request.deepen != Deepen::None && !request.done;
    let current_span = tracing::Span::current();
    let built = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let spec = ShallowSpec {
                client_shallow: request.shallow,
                deepen: request.deepen,
            };
            build_shallow_pack(&repo, &request.wants, &request.haves, &spec)
        })
    })
    .await
    .map_err(|_| GitError::Git("pack build task panicked".to_string()))??;

    let mut out = Vec::new();

    // Shallow negotiation section (plain pkt-lines, never multiplexed) —
    // present for every `deepen` request. A `git clone --depth N` client
    // sends a first stateless request with no `done`, whose whole purpose
    // is to learn this list; it then sends the real request (with `done`)
    // and gets the list again, then the pack.
    if request.deepen != Deepen::None {
        for id in &built.new_shallow {
            write_pkt_line(&mut out, format!("shallow {id}\n").as_bytes());
        }
        for id in &built.unshallow {
            write_pkt_line(&mut out, format!("unshallow {id}\n").as_bytes());
        }
        write_flush(&mut out);
    }
    if shallow_only {
        return Ok(out);
    }

    write_pkt_line(&mut out, b"NAK\n");
    if side_band {
        if with_progress {
            sideband::write_progress(
                &mut out,
                &format!("Total {} objects, done.\n", pack_object_count(&built.pack)),
            );
        }
        sideband::write_pack_data(&mut out, &built.pack);
        write_flush(&mut out);
    } else {
        out.extend_from_slice(&built.pack);
    }
    Ok(out)
}

/// The object count from a pack header (`PACK` + 4-byte version + 4-byte
/// big-endian count) — 0 if `pack` is too short to have one.
fn pack_object_count(pack: &[u8]) -> u32 {
    match pack.get(8..12) {
        Some(bytes) => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        None => 0,
    }
}

/// Opens `name` and runs the complete upload-pack cycle against `body`
/// (the request bytes read verbatim off either transport). This is what a
/// transport calls once it has the whole request buffered.
///
/// An empty request (no `want` lines — just a flush) is answered with an
/// empty `Ok`, not an error: `git`'s HTTP transport sends exactly this as
/// a *probe* before streaming a large chunked fetch request, and aborts
/// the whole operation unless the probe gets a 2xx back.
pub async fn run_upload_pack(
    store: &dyn RepoStore,
    name: &str,
    body: Bytes,
) -> Result<Vec<u8>, GitError> {
    let repo = open_repo_dir(store, name)?;
    let request = parse_upload_pack_request(&body);
    if request.wants.is_empty() {
        return Ok(Vec::new());
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

/// Runs receive-pack:
///
/// 1. streams the request's pack (if any command isn't a pure delete)
///    into a **quarantine** directory as a real indexed `.pack`/`.idx`
///    via `gix-pack` bundle-write — never as loose objects;
/// 2. fsck-lite: every new ref tip and its object closure must resolve
///    (against the quarantined pack, then the repo);
/// 3. applies **all** ref-update commands as one atomic `gix-ref`
///    transaction with git compare-and-swap semantics — the push lands
///    entirely or not at all;
/// 4. promotes the quarantined pack into the live store, or, on **any**
///    failure above, removes the quarantine wholesale — leaving the
///    object store byte-identical to before;
/// 5. repairs an unborn HEAD if the push landed.
///
/// Returns a [`ReceiveOutcome`]: the wire response (`report-status`
/// lines) and the ref updates that actually landed. The caller must hold
/// `locks`'s lock for `name` for the duration of this call — see
/// `run_receive_pack` for the common case.
///
/// `checks` carries the resolved branch-protection / quota state this push
/// is evaluated against (empty — the common case — means no restriction).
/// This crate has no notion of *why* a branch is protected or *who* is
/// pushing (no `edda-db`/`edda-auth` dependency, by design); the caller
/// resolves that against `BranchProtectionRule`s and the pushing actor
/// *before* calling this. See [`crate::hooks`].
pub async fn apply_receive_pack(
    repo: gix::Repository,
    git_dir: PathBuf,
    commands: Vec<RefCommand>,
    pack_data: Bytes,
    checks: ReceiveChecks,
) -> Result<ReceiveOutcome, String> {
    if commands.is_empty() {
        // `git`'s HTTP transport probes a large chunked push with a bare
        // flush pkt (no commands) and aborts unless that probe gets a 2xx
        // — so an empty request is a benign no-op, not an error.
        return Ok(ReceiveOutcome {
            response: Vec::new(),
            applied: Vec::new(),
        });
    }

    // Pack ingest, fsck, hooks, ref transaction and promotion are all
    // CPU/FS work — one hop onto the blocking pool for the lot.
    let current_span = tracing::Span::current();
    match tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| receive_blocking(repo, git_dir, commands, pack_data, &checks))
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err("receive-pack task panicked".to_string()),
    }
}

/// Drops the quarantine directory unless it was explicitly promoted or
/// taken — so every early return from [`receive_blocking`] leaves the
/// object store byte-identical.
struct QuarantineGuard(Option<Quarantine>);

impl Drop for QuarantineGuard {
    fn drop(&mut self) {
        if let Some(quarantine) = self.0.take() {
            quarantine.discard();
        }
    }
}

/// The synchronous body of [`apply_receive_pack`] — see its doc comment
/// for the sequence. Runs entirely on the blocking pool.
fn receive_blocking(
    repo: gix::Repository,
    git_dir: PathBuf,
    commands: Vec<RefCommand>,
    pack_data: Bytes,
    checks: &ReceiveChecks,
) -> Result<ReceiveOutcome, String> {
    let needs_pack = commands.iter().any(|command| command.new_id != ZERO_ID);

    let quarantine = if needs_pack {
        Some(quarantine::write_pack(&repo, &pack_data).map_err(|err| err.to_string())?)
    } else {
        None
    };
    // From here on, any early return discards the quarantine via `Drop`.
    let mut guard = QuarantineGuard(quarantine);

    let applied: Result<(), String> = (|| {
        // Pre-ingest hook checks: the direct-push block (glob-matched) and
        // the size quota. A push that trips either is rejected in full —
        // atomic semantics mean no ref in it lands.
        if let Some(reason) = hooks::blocked_ref_rejection(checks, &commands) {
            return Err(reason);
        }
        if let Some(reason) = hooks::quota_rejection(checks, pack_data.len() as u64) {
            return Err(reason);
        }

        if let Some(quarantine) = guard.0.as_ref() {
            let tips = commands
                .iter()
                .filter(|command| command.new_id != ZERO_ID)
                .map(|command| {
                    ObjectId::from_hex(command.new_id.as_bytes())
                        .map_err(|_| format!("not a valid object id: {}", command.new_id))
                })
                .collect::<Result<Vec<_>, _>>()?;
            quarantine
                .fsck(&repo, &tips)
                .map_err(|err| err.to_string())?;
        }

        // Promote the pack into the live store *before* the ref
        // transaction, so a committed ref never points at objects that
        // aren't really there. If a later step fails, roll the pack back
        // out — nothing references it yet.
        let mut promoted = match guard.0.take() {
            Some(quarantine) => Some(quarantine.promote(&repo).map_err(|err| err.to_string())?),
            None => None,
        };

        // Post-promote hook checks: linear history / signed commits, which
        // need every added commit to resolve against the live store.
        if !checks.linear_history_ref_patterns.is_empty()
            || !checks.signed_commit_ref_patterns.is_empty()
        {
            let fresh = gix::open(&git_dir).map_err(|err| err.to_string())?;
            if let Some(reason) = hooks::history_rejection(&fresh, checks, &commands) {
                if let Some(promoted) = promoted.take() {
                    promoted.rollback();
                }
                return Err(reason);
            }
        }

        let updates: Vec<RefUpdate> = commands
            .iter()
            .map(|command| RefUpdate {
                name: command.ref_name.clone(),
                expected_old: command.old_id.clone(),
                new: command.new_id.clone(),
            })
            .collect();
        match update_refs(&repo, &updates, "push") {
            Ok(()) => Ok(()),
            Err(err) => {
                if let Some(promoted) = promoted.take() {
                    promoted.rollback();
                }
                Err(err.to_string())
            }
        }
    })();

    if applied.is_ok() {
        // A push can create the repo's first branch under a name HEAD
        // doesn't point at yet — repair it so a client cloning right after
        // gets a working checkout.
        let _ = fix_unborn_head(&git_dir);
    }

    let mut out = Vec::new();
    write_pkt_line(&mut out, b"unpack ok\n");
    for command in &commands {
        let line = match &applied {
            Ok(()) => format!("ok {}\n", command.ref_name),
            Err(reason) => format!("ng {} {reason}\n", command.ref_name),
        };
        write_pkt_line(&mut out, line.as_bytes());
    }
    write_flush(&mut out);

    let applied_refs = match &applied {
        Ok(()) => commands
            .iter()
            .map(|command| AppliedRef {
                name: command.ref_name.clone(),
                old: command.old_id.clone(),
                new: command.new_id.clone(),
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    Ok(ReceiveOutcome {
        response: out,
        applied: applied_refs,
    })
}

/// Opens `name`, holds `locks`'s per-repo lock for the duration (a push is
/// a write: it must not land while, say, someone deletes the repo out
/// from under it via the web UI, or another push races it), and runs the
/// complete receive-pack cycle against `body`. See
/// [`apply_receive_pack`]'s doc comment for `checks`.
pub async fn run_receive_pack(
    store: &dyn RepoStore,
    locks: &LockRegistry,
    name: &str,
    body: Bytes,
    checks: ReceiveChecks,
) -> Result<ReceiveOutcome, GitError> {
    let git_dir = crate::validated_repo_dir(store, name)?;
    let repo = gix::open(&git_dir).map_err(|err| GitError::Git(err.to_string()))?;

    let lock = locks.lock_for(name);
    let _guard = lock.lock().await;

    let (commands, pos) = parse_receive_pack_commands(&body).map_err(GitError::Git)?;
    let pack_data = body.slice(pos..);
    apply_receive_pack(repo, git_dir, commands, pack_data, checks)
        .await
        .map_err(GitError::Git)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::{build_pack_excluding, write_loose_object};
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

    #[test]
    fn capabilities_are_parsed_from_the_first_want_line_only() {
        let mut body = Vec::new();
        pkt(
            &mut body,
            format!(
                "want {} side-band-64k ofs-delta agent=git/2.43\n",
                "a".repeat(40)
            )
            .as_bytes(),
        );
        // A second want line's trailing tokens must NOT be read as caps.
        pkt(
            &mut body,
            format!("want {} not-a-capability\n", "b".repeat(40)).as_bytes(),
        );
        write_flush(&mut body);
        pkt(&mut body, b"done\n");

        let request = parse_upload_pack_request(&body);
        assert_eq!(request.wants.len(), 2);
        assert_eq!(
            request.capabilities,
            vec!["side-band-64k", "ofs-delta", "agent=git/2.43"]
        );
        assert!(request.wants_side_band_64k());
        assert!(request.wants_progress());
    }

    /// Fixture repo with two commits over an empty tree; returns
    /// `(root_dir, tip_id)`.
    fn seed_two_commit_repo(tag: &str) -> (std::path::PathBuf, gix::ObjectId) {
        let root = std::env::temp_dir().join(format!(
            "edda-protocol-sideband-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        gix::init_bare(&root).unwrap();
        let empty_tree = write_loose_object(&root, Kind::Tree, b"").unwrap();
        let c1 = write_commit(&root, empty_tree, &[], "first");
        let c2 = write_commit(&root, empty_tree, &[c1], "second");
        (root, c2)
    }

    #[test]
    fn shallow_and_deepen_lines_are_parsed_alongside_wants() {
        let mut body = Vec::new();
        pkt(
            &mut body,
            format!("want {} side-band-64k\n", "a".repeat(40)).as_bytes(),
        );
        pkt(
            &mut body,
            format!("shallow {}\n", "b".repeat(40)).as_bytes(),
        );
        pkt(&mut body, b"deepen 1\n");
        write_flush(&mut body);
        pkt(&mut body, b"done\n");

        let request = parse_upload_pack_request(&body);
        assert_eq!(request.wants.len(), 1);
        assert_eq!(request.shallow.len(), 1);
        assert_eq!(request.deepen, Deepen::Depth(1));
    }

    #[tokio::test]
    async fn build_shallow_pack_truncates_the_commit_graph_at_the_requested_depth() {
        let root =
            std::env::temp_dir().join(format!("edda-protocol-shallow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        gix::init_bare(&root).unwrap();
        let empty_tree = write_loose_object(&root, Kind::Tree, b"").unwrap();
        let c1 = write_commit(&root, empty_tree, &[], "first");
        let c2 = write_commit(&root, empty_tree, &[c1], "second");
        let c3 = write_commit(&root, empty_tree, &[c2], "third");
        let repo = gix::open(&root).unwrap();

        // depth 1: only the tip commit + the shared empty tree; the tip is
        // the new shallow boundary (it has a parent that was withheld).
        let d1 = build_shallow_pack(
            &repo,
            &[c3],
            &[],
            &ShallowSpec {
                client_shallow: Vec::new(),
                deepen: Deepen::Depth(1),
            },
        )
        .unwrap();
        assert_eq!(pack_object_count(&d1.pack), 2);
        assert_eq!(d1.new_shallow, vec![c3]);
        assert!(d1.unshallow.is_empty());

        // depth 2: tip + its parent; the parent is now the boundary.
        let d2 = build_shallow_pack(
            &repo,
            &[c3],
            &[],
            &ShallowSpec {
                client_shallow: Vec::new(),
                deepen: Deepen::Depth(2),
            },
        )
        .unwrap();
        assert_eq!(pack_object_count(&d2.pack), 3);
        assert_eq!(d2.new_shallow, vec![c2]);

        // A client that already had `c3` shallow, now deepening to 2, is
        // told to unshallow it.
        let deepened = build_shallow_pack(
            &repo,
            &[c3],
            &[],
            &ShallowSpec {
                client_shallow: vec![c3],
                deepen: Deepen::Depth(2),
            },
        )
        .unwrap();
        assert_eq!(deepened.unshallow, vec![c3]);
        assert_eq!(deepened.new_shallow, vec![c2]);
        assert!(c1 != c2 && c2 != c3);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_side_band_response_multiplexes_the_pack_and_a_raw_one_does_not() {
        let (root, tip) = seed_two_commit_repo("mux");

        // No side-band: NAK line, then raw pack bytes (byte-identical to
        // the pre-Phase-7 wire).
        let repo = gix::open(&root).unwrap();
        let raw = build_upload_pack_response(
            repo,
            UploadPackRequest {
                wants: vec![tip],
                haves: Vec::new(),
                capabilities: Vec::new(),
                shallow: Vec::new(),
                deepen: Deepen::None,
                done: true,
            },
        )
        .await
        .unwrap();
        let mut pos = 0;
        assert_eq!(read_pkt_line(&raw, &mut pos), Some(PktLine::Data(b"NAK\n")));
        assert_eq!(&raw[pos..pos + 4], b"PACK");

        // side-band-64k: NAK line, then channel-2 progress, then channel-1
        // pack packets, then a flush. Reassembled channel-1 == the pack.
        let repo = gix::open(&root).unwrap();
        let muxed = build_upload_pack_response(
            repo,
            UploadPackRequest {
                wants: vec![tip],
                haves: Vec::new(),
                capabilities: vec!["side-band-64k".to_string()],
                shallow: Vec::new(),
                deepen: Deepen::None,
                done: true,
            },
        )
        .await
        .unwrap();

        let mut pos = 0;
        assert_eq!(
            read_pkt_line(&muxed, &mut pos),
            Some(PktLine::Data(b"NAK\n"))
        );
        let mut pack = Vec::new();
        let mut saw_progress = false;
        loop {
            match read_pkt_line(&muxed, &mut pos) {
                Some(PktLine::Data(frame)) => match frame[0] {
                    sideband::BAND_PACK => pack.extend_from_slice(&frame[1..]),
                    sideband::BAND_PROGRESS => saw_progress = true,
                    other => panic!("unexpected band {other}"),
                },
                Some(PktLine::Flush) => break,
                None => panic!("side-band stream ended without a flush"),
            }
        }
        assert!(saw_progress, "a progress line was sent on channel 2");
        assert_eq!(&pack[..4], b"PACK");
        assert_eq!(pack, raw[pos_after_nak(&raw)..], "same pack, just framed");

        let _ = std::fs::remove_dir_all(&root);
    }

    fn pos_after_nak(response: &[u8]) -> usize {
        let mut pos = 0;
        read_pkt_line(response, &mut pos);
        pos
    }
}

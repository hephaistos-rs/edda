//! Git smart-HTTP, implemented directly against `gix` — no `git` subprocess
//! anywhere. Speaks protocol v0 (the classic pkt-line protocol): simpler
//! than v2, and a server that never advertises v2 support is exactly how a
//! real client falls back to it, so this needs no special negotiation to
//! get real `git` clients to use it.
//!
//! Read path (`info/refs` + `git-upload-pack`, i.e. clone/fetch) sends every
//! object reachable from what the client asked for — it ignores the
//! client's "have" lines, so every fetch re-sends the full requested
//! history rather than just what's new. Correct, not efficient; real
//! want/have negotiation is a lot more protocol to implement and isn't
//! needed for the common case (clone) to work.

mod pktline;

use axum::body::{Body, Bytes};
use axum::extract::{Path, RawQuery};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_login::{AuthSession, AuthnBackend};
use base64::Engine;

use crate::auth::{Backend, Credentials, User};
use crate::git::pack::{build_pack, parse_pack, write_loose_object};
use crate::git::store::LocalFsStore;
use crate::git::{apply_ref_update, fix_unborn_head, repo_lock, validated_repo_dir, GitError, ZERO_ID};
use pktline::{read_pkt_line, read_pkt_lines_until_flush, write_flush, write_pkt_line, PktLine};

pub fn routes() -> Router {
    Router::new()
        // axum only allows one `{param}` per path segment — it can't match
        // `{name}.git` (parameter mixed with literal text) directly, so the
        // whole segment is captured and `.git` is stripped in `repo_name`.
        .route("/{repo}/info/refs", get(info_refs))
        .route("/{repo}/git-upload-pack", post(upload_pack))
        .route("/{repo}/git-receive-pack", post(receive_pack))
}

fn repo_name(repo: &str) -> Result<&str, Response> {
    repo.strip_suffix(".git").ok_or_else(|| (StatusCode::NOT_FOUND, "expected a \"<name>.git\" path").into_response())
}

fn open_repo(name: &str) -> Result<gix::Repository, Response> {
    let store = LocalFsStore::from_env();
    let dir =
        validated_repo_dir(&store, name).map_err(|err| (StatusCode::NOT_FOUND, err.to_string()).into_response())?;
    gix::open(&dir).map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())
}

async fn info_refs(Path(repo): Path<String>, RawQuery(query): RawQuery) -> Response {
    let name = match repo_name(&repo) {
        Ok(name) => name,
        Err(response) => return response,
    };
    let Some(service) = query.as_deref().and_then(|q| q.strip_prefix("service=")) else {
        return (StatusCode::BAD_REQUEST, "expected ?service=git-upload-pack or git-receive-pack").into_response();
    };
    let service = service.to_string();

    let repo = match open_repo(name) {
        Ok(repo) => repo,
        Err(response) => return response,
    };

    let refs = match advertised_refs(&repo) {
        Ok(refs) => refs,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

    // Capabilities are supposed to be negotiated as the intersection of what
    // the client wants and what's advertised here — a strict client has no
    // reason to expect (or correctly parse) a report-status-formatted
    // receive-pack response unless the server actually said it supports it.
    let capabilities =
        if service == "git-receive-pack" { "report-status agent=edda/0.1.0" } else { "agent=edda/0.1.0" };

    let mut body = Vec::new();
    write_pkt_line(&mut body, format!("# service={service}\n").as_bytes());
    write_flush(&mut body);

    if refs.is_empty() {
        // No refs to advertise (empty repo) — git still expects a line here
        // so the client learns server capabilities; the all-zero id is the
        // documented placeholder for "no real ref".
        let zero_id = "0".repeat(40);
        write_pkt_line(&mut body, format!("{zero_id} capabilities^{{}}\0{capabilities}\n").as_bytes());
    } else {
        for (i, (oid, ref_name)) in refs.iter().enumerate() {
            let line = if i == 0 {
                format!("{oid} {ref_name}\0{capabilities}\n")
            } else {
                format!("{oid} {ref_name}\n")
            };
            write_pkt_line(&mut body, line.as_bytes());
        }
    }
    write_flush(&mut body);

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", format!("application/x-{service}-advertisement"))
        .header("Cache-Control", "no-cache")
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// HEAD (if it resolves) plus every local branch — everything a client
/// needs to clone and check out the default branch. No tags: nothing in
/// Edda creates one yet.
///
/// HEAD can be unborn on disk (points at a branch, e.g. "master", that a
/// push never actually created — see `fix_unborn_head`'s doc comment) even
/// though real branches exist: without a HEAD line at all here, a cloning
/// client has nothing to check out and fails outright, so this falls back
/// to the same branch preference used everywhere else.
fn advertised_refs(repo: &gix::Repository) -> Result<Vec<(gix::ObjectId, String)>, GitError> {
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
        let chosen = crate::git::pick_default_branch(&names)?;
        branches.iter().find(|(_, name)| name == chosen).map(|(id, _)| *id)
    });
    if let Some(id) = head {
        refs.push((id, "HEAD".to_string()));
    }

    refs.extend(branches.into_iter().map(|(id, name)| (id, format!("refs/heads/{name}"))));

    Ok(refs)
}

async fn upload_pack(Path(repo): Path<String>, body: Bytes) -> Response {
    let name = match repo_name(&repo) {
        Ok(name) => name,
        Err(response) => return response,
    };
    let repo = match open_repo(name) {
        Ok(repo) => repo,
        Err(response) => return response,
    };

    let wants: Vec<gix::ObjectId> = read_pkt_lines_until_flush(&body)
        .into_iter()
        .filter_map(|line| {
            let text = String::from_utf8_lossy(line);
            let rest = text.trim_end().strip_prefix("want ")?;
            let oid_hex = rest.split_whitespace().next()?;
            gix::ObjectId::from_hex(oid_hex.as_bytes()).ok()
        })
        .collect();
    // "have"/"done" lines are intentionally not parsed — see the module doc
    // comment: every fetch sends everything reachable from `wants`.

    if wants.is_empty() {
        return (StatusCode::BAD_REQUEST, "no \"want\" lines in request").into_response();
    }

    let pack = match build_pack(&repo, &wants) {
        Ok(pack) => pack,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

    let mut out = Vec::new();
    // No side-band negotiated (not advertised in `info_refs`), so a plain
    // NAK line — "no common base found, here's everything" — followed by
    // the raw pack bytes with no further framing.
    write_pkt_line(&mut out, b"NAK\n");
    out.extend_from_slice(&pack);

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-git-upload-pack-result")
        .body(Body::from(out))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

struct RefCommand {
    old_id: String,
    new_id: String,
    ref_name: String,
}

/// The browser session (`AuthSession`, cookie-based) doesn't reach the `git`
/// CLI — it has no cookie jar. Real git clients authenticate HTTP pushes via
/// `Authorization: Basic <base64 email:password>`, so that's checked here
/// too, against the same `Backend::authenticate` login already uses.
async fn authenticate_basic(backend: &Backend, headers: &HeaderMap) -> Option<User> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (email, password) = text.split_once(':')?;
    let creds = Credentials { email: email.to_string(), password: password.to_string() };
    backend.authenticate(creds).await.ok()?
}

async fn receive_pack(auth: AuthSession<Backend>, headers: HeaderMap, Path(repo): Path<String>, body: Bytes) -> Response {
    // Any push is a write, and there's no per-repo ownership model yet — any
    // logged-in user can push to any repo. That's the same coarse trust
    // level the UI's create/update/delete already assumes; the finer-grained
    // "who owns this repo" question is a separate, later feature.
    let authenticated = auth.user.is_some() || authenticate_basic(&auth.backend, &headers).await.is_some();
    if !authenticated {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"edda\"")
            .body(Body::from("login required to push"))
            .unwrap_or_else(|_| StatusCode::UNAUTHORIZED.into_response());
    }

    let name = match repo_name(&repo) {
        Ok(name) => name,
        Err(response) => return response,
    };

    let store = LocalFsStore::from_env();
    let git_dir = match validated_repo_dir(&store, name) {
        Ok(dir) => dir,
        Err(err) => return (StatusCode::NOT_FOUND, err.to_string()).into_response(),
    };
    let repo_handle = match gix::open(&git_dir) {
        Ok(repo) => repo,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

    // A push is a write: hold the same per-repo lock Edda's own
    // create/update/delete use, so it can't land while, say, someone
    // deletes the repo out from under it via the UI.
    let lock = repo_lock(name);
    let _guard = lock.lock().await;

    // Commands come first as pkt-lines, ending in a flush; the pack data (if
    // any command isn't a pure delete) follows immediately after with no
    // further pkt-line framing, running to the end of the body.
    let mut pos = 0;
    let mut commands = Vec::new();
    loop {
        match read_pkt_line(&body, &mut pos) {
            Some(PktLine::Flush) | None => break,
            Some(PktLine::Data(line)) => {
                let text = String::from_utf8_lossy(line);
                // Capabilities ride after a NUL on the first line only.
                let text = text.split('\0').next().unwrap_or(&text).trim_end();
                let mut parts = text.splitn(3, ' ');
                let (Some(old_id), Some(new_id), Some(ref_name)) = (parts.next(), parts.next(), parts.next()) else {
                    return (StatusCode::BAD_REQUEST, format!("malformed ref-update command: {text:?}")).into_response();
                };
                commands.push(RefCommand { old_id: old_id.to_string(), new_id: new_id.to_string(), ref_name: ref_name.to_string() });
            }
        }
    }

    if commands.is_empty() {
        return (StatusCode::BAD_REQUEST, "no ref-update commands in request").into_response();
    }

    let needs_pack = commands.iter().any(|command| command.new_id != ZERO_ID);
    if needs_pack {
        let pack_data = &body[pos..];
        let objects = match parse_pack(&repo_handle, pack_data) {
            Ok(objects) => objects,
            Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("bad pack: {err}")).into_response(),
        };
        for object in &objects {
            if let Err(err) = write_loose_object(&git_dir, object.kind, &object.data) {
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("couldn't store object {}: {err}", object.id))
                    .into_response();
            }
        }
    }

    let mut results = Vec::with_capacity(commands.len());
    for command in &commands {
        let outcome = apply_ref_update(&git_dir, &command.ref_name, &command.old_id, &command.new_id);
        results.push((command.ref_name.clone(), outcome));
    }

    // A push can create the repo's first branch under a name HEAD doesn't
    // point at yet (see `fix_unborn_head`'s doc comment) — repair it now so
    // a client cloning right after this push gets a working checkout.
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

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-git-receive-pack-result")
        .body(Body::from(out))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

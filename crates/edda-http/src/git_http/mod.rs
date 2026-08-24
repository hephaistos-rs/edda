//! Git smart-HTTP, implemented directly against `gix` (via `edda-git`) —
//! no `git` subprocess anywhere. Speaks protocol v0 (the classic pkt-line
//! protocol): simpler than v2, and a server that never advertises v2
//! support is exactly how a real client falls back to it, so this needs
//! no special negotiation to get real `git` clients to use it.
//!
//! Read path (`info/refs` + `git-upload-pack`, i.e. clone/fetch) sends
//! every object reachable from what the client asked for — it ignores the
//! client's "have" lines, so every fetch re-sends the full requested
//! history rather than just what's new (`review.local.md` gap G1;
//! plan.local.md §17 Phase 2 is where this is addressed — not this
//! phase).

mod pktline;

use axum::body::{Body, Bytes};
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_login::{AuthSession, AuthnBackend};
use base64::Engine;

use edda_auth::Backend;
use edda_domain::{ActorContext, AuthzError, Repository};
use edda_git::pack::{build_pack, parse_pack, write_loose_object};
use edda_git::{apply_ref_update, fix_unborn_head, validated_repo_dir, GitError, ZERO_ID};
use pktline::{read_pkt_line, read_pkt_lines_until_flush, write_flush, write_pkt_line, PktLine};

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        // axum only allows one `{param}` per path segment — it can't match
        // `{repo}.git` (parameter mixed with literal text) directly, so the
        // whole segment is captured and `.git` is stripped in `repo_identity`.
        .route("/{owner}/{repo}/info/refs", get(info_refs))
        .route("/{owner}/{repo}/git-upload-pack", post(upload_pack))
        .route("/{owner}/{repo}/git-receive-pack", post(receive_pack))
}

/// Joins the URL's `{owner}` and `{repo}.git` segments into the
/// `{owner}/{repo}` filesystem identity `edda-git` operates on. This is
/// distinct from (though derived the same way as) the DB-level owner
/// username + repo name pair `edda-auth`'s `AuthorizationService` resolves
/// — both ultimately come from the same two URL segments.
// The early-return-a-`Response` pattern below is the idiomatic shape for
// axum handler helpers (an `Err(Response)` short-circuits straight to the
// caller's `return response`) — boxing it to satisfy `result_large_err`
// would only add an allocation to a hot path for no correctness benefit.
#[allow(clippy::result_large_err)]
fn repo_identity(owner: &str, repo: &str) -> Result<String, Response> {
    let name = repo
        .strip_suffix(".git")
        .ok_or_else(|| (StatusCode::NOT_FOUND, "expected a \"<name>.git\" path").into_response())?;
    Ok(format!("{owner}/{name}"))
}

#[allow(clippy::result_large_err)]
fn open_repo(state: &AppState, name: &str) -> Result<gix::Repository, Response> {
    let dir = validated_repo_dir(state.store.as_ref(), name)
        .map_err(|err| (StatusCode::NOT_FOUND, err.to_string()).into_response())?;
    gix::open(&dir)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())
}

fn not_found_response(owner: &str, repo: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        format!("no repository named \"{owner}/{repo}\""),
    )
        .into_response()
}

fn unauthorized_response(message: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", "Basic realm=\"edda\"")
        .body(Body::from(message))
        .unwrap_or_else(|_| StatusCode::UNAUTHORIZED.into_response())
}

/// Resolves the calling identity for the git-HTTP bridge specifically: a
/// browser session cookie doesn't reach the `git` CLI (it has no cookie
/// jar), so real git clients authenticate pushes via
/// `Authorization: Basic <base64 user:pass>`. Both fields are checked for
/// a personal access token first (conventions differ on which field
/// callers put it in), falling back to a real account password only if
/// neither is a token — same preference order a mature git host like
/// Gitea uses.
async fn resolve_actor(
    state: &AppState,
    auth: &AuthSession<Backend>,
    headers: &HeaderMap,
) -> ActorContext {
    if let Some(session_user) = &auth.user {
        return ActorContext::User(session_user.user.id);
    }

    let Some(value) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return ActorContext::Anonymous;
    };
    let Some(encoded) = value.strip_prefix("Basic ") else {
        return ActorContext::Anonymous;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return ActorContext::Anonymous;
    };
    let Ok(text) = String::from_utf8(decoded) else {
        return ActorContext::Anonymous;
    };
    let Some((identity, secret)) = text.split_once(':') else {
        return ActorContext::Anonymous;
    };

    if let Some((user, scope)) = edda_auth::tokens::authenticate(&state.pool, secret).await {
        return ActorContext::Token {
            user_id: user.id,
            scope,
        };
    }
    if let Some((user, scope)) = edda_auth::tokens::authenticate(&state.pool, identity).await {
        return ActorContext::Token {
            user_id: user.id,
            scope,
        };
    }

    let creds = edda_auth::Credentials {
        email: identity.to_string(),
        password: secret.to_string(),
    };
    match state.backend.authenticate(creds).await {
        Ok(Some(session_user)) => ActorContext::User(session_user.user.id),
        _ => ActorContext::Anonymous,
    }
}

/// Gate for `info_refs`/`upload_pack` (the clone/fetch path). A public
/// repository never resolves an actor at all — this is the hot path for
/// every clone, most of which are public. Same 401-vs-404 split as
/// `require_write_access`: no credentials at all gets a `WWW-Authenticate`
/// 401 (a real git client retries with creds); a real identity that just
/// isn't allowed to read this repo gets 404, not 403 — a private repo's
/// existence shouldn't be distinguishable from a repo that was never
/// created (see `edda_domain::AuthzError`'s doc comment).
async fn require_read_access(
    state: &AppState,
    auth: &AuthSession<Backend>,
    headers: &HeaderMap,
    owner: &str,
    repository: &Repository,
) -> Result<(), Response> {
    if !repository.is_private() {
        return Ok(());
    }
    let actor = resolve_actor(state, auth, headers).await;
    match state.authz.check_read(&actor, repository).await {
        Ok(()) => Ok(()),
        Err(AuthzError::NotFound) if matches!(actor, ActorContext::Anonymous) => {
            Err(unauthorized_response("login required to read this repo"))
        }
        Err(_) => Err(not_found_response(owner, &repository.name)),
    }
}

async fn require_write_access(
    state: &AppState,
    auth: &AuthSession<Backend>,
    headers: &HeaderMap,
    owner: &str,
    repository: &Repository,
) -> Result<(), Response> {
    let actor = resolve_actor(state, auth, headers).await;
    match state.authz.check_write(&actor, repository).await {
        Ok(()) => Ok(()),
        Err(AuthzError::NotFound) if matches!(actor, ActorContext::Anonymous) => {
            Err(unauthorized_response("login required to push"))
        }
        Err(AuthzError::NotFound) => Err(not_found_response(owner, &repository.name)),
        Err(AuthzError::Forbidden) => Err((
            StatusCode::FORBIDDEN,
            "you don't have write access to this repo",
        )
            .into_response()),
    }
}

async fn info_refs(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> Response {
    let identity = match repo_identity(&owner, &repo) {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    let Some(service) = query.as_deref().and_then(|q| q.strip_prefix("service=")) else {
        return (
            StatusCode::BAD_REQUEST,
            "expected ?service=git-upload-pack or git-receive-pack",
        )
            .into_response();
    };
    let service = service.to_string();

    let repo_name = repo.trim_end_matches(".git");
    let repository = match state.authz.repository_by_name(&owner, repo_name).await {
        Ok(repository) => repository,
        Err(_) => return not_found_response(&owner, repo_name),
    };
    // Both services just advertise ref names here (no write happens until
    // `git-receive-pack`'s own POST) but a private repo's ref names are
    // still information an outsider shouldn't get either way.
    if let Err(response) = require_read_access(&state, &auth, &headers, &owner, &repository).await {
        return response;
    }

    let repo = match open_repo(&state, &identity) {
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
    let capabilities = if service == "git-receive-pack" {
        "report-status agent=edda/0.1.0"
    } else {
        "agent=edda/0.1.0"
    };

    let mut body = Vec::new();
    write_pkt_line(&mut body, format!("# service={service}\n").as_bytes());
    write_flush(&mut body);

    if refs.is_empty() {
        // No refs to advertise (empty repo) — git still expects a line here
        // so the client learns server capabilities; the all-zero id is the
        // documented placeholder for "no real ref".
        let zero_id = "0".repeat(40);
        write_pkt_line(
            &mut body,
            format!("{zero_id} capabilities^{{}}\0{capabilities}\n").as_bytes(),
        );
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
        .header(
            "Content-Type",
            format!("application/x-{service}-advertisement"),
        )
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
        let chosen = edda_git::pick_default_branch(&names)?;
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

#[tracing::instrument(name = "git.upload_pack", skip_all, fields(repo.owner = %owner, repo = %repo))]
async fn upload_pack(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let identity = match repo_identity(&owner, &repo) {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    let repo_name = repo.trim_end_matches(".git");
    let repository = match state.authz.repository_by_name(&owner, repo_name).await {
        Ok(repository) => repository,
        Err(_) => return not_found_response(&owner, repo_name),
    };
    if let Err(response) = require_read_access(&state, &auth, &headers, &owner, &repository).await {
        return response;
    }
    let repo = match open_repo(&state, &identity) {
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

    // Walking the object graph and zlib-deflating every reachable object is
    // real CPU work, not I/O — run it on the blocking pool so it doesn't tie
    // up one of the async runtime's worker threads (and everything else
    // scheduled on it) for however long a large clone takes.
    //
    // `spawn_blocking` runs the closure on a fresh OS thread with no tracing
    // context of its own — a span doesn't cross that boundary automatically.
    // Capturing the current span here and re-entering it inside the closure
    // is what makes `git.build_pack` show up nested under `git.upload_pack`
    // rather than as an orphaned span.
    let current_span = tracing::Span::current();
    let pack = match tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| build_pack(&repo, &wants))
    })
    .await
    {
        Ok(Ok(pack)) => pack,
        Ok(Err(err)) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "pack build task panicked",
            )
                .into_response()
        }
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

#[tracing::instrument(name = "git.receive_pack", skip_all, fields(repo.owner = %owner, repo = %repo))]
async fn receive_pack(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let identity = match repo_identity(&owner, &repo) {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    let name = identity.as_str();
    let repo_name = repo.trim_end_matches(".git");

    let repository = match state.authz.repository_by_name(&owner, repo_name).await {
        Ok(repository) => repository,
        Err(_) => return not_found_response(&owner, repo_name),
    };
    if let Err(response) = require_write_access(&state, &auth, &headers, &owner, &repository).await
    {
        return response;
    }

    let git_dir = match validated_repo_dir(state.store.as_ref(), name) {
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
    let lock = state.locks.lock_for(name);
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
                let (Some(old_id), Some(new_id), Some(ref_name)) =
                    (parts.next(), parts.next(), parts.next())
                else {
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("malformed ref-update command: {text:?}"),
                    )
                        .into_response();
                };
                commands.push(RefCommand {
                    old_id: old_id.to_string(),
                    new_id: new_id.to_string(),
                    ref_name: ref_name.to_string(),
                });
            }
        }
    }

    if commands.is_empty() {
        return (StatusCode::BAD_REQUEST, "no ref-update commands in request").into_response();
    }

    let needs_pack = commands.iter().any(|command| command.new_id != ZERO_ID);
    if needs_pack {
        // Same reasoning as `upload_pack`: delta resolution and re-deflating
        // every object to write it out as a loose object is real CPU work —
        // move it to the blocking pool rather than occupy an async worker
        // thread for the duration. `body.slice` is a cheap refcount bump
        // (shares the same buffer), not a copy, so this isn't paying to
        // duplicate the pack.
        let pack_data = body.slice(pos..);
        let git_dir_for_pack = git_dir.clone();
        // Same `spawn_blocking`-doesn't-inherit-the-current-span caveat as
        // `upload_pack` above — capture and re-enter explicitly so
        // `git.parse_pack` nests under `git.receive_pack`.
        let current_span = tracing::Span::current();
        let outcome = tokio::task::spawn_blocking(move || {
            current_span.in_scope(|| {
                let objects = parse_pack(&repo_handle, &pack_data)
                    .map_err(|err| format!("bad pack: {err}"))?;
                for object in &objects {
                    write_loose_object(&git_dir_for_pack, object.kind, &object.data)
                        .map_err(|err| format!("couldn't store object {}: {err}", object.id))?;
                }
                Ok::<_, String>(objects)
            })
        })
        .await;
        match outcome {
            Ok(Ok(_)) => {}
            Ok(Err(message)) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "pack processing task panicked",
                )
                    .into_response()
            }
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

//! Git smart-HTTP: the HTTP-specific half of the bridge. All the actual
//! git wire-protocol orchestration (parsing want/have/ref-update lines,
//! building packs, applying ref updates) now lives in
//! `edda_git::protocol`, shared verbatim with `edda-ssh`'s git-over-SSH
//! bridge — this module's job is only:
//! resolve the repository from the URL, authenticate/authorize, read the
//! request bytes, call `edda_git::protocol`, and frame the response as
//! HTTP (status/headers/content-type). See `edda_git::protocol`'s own
//! module doc for why the split is drawn exactly there.

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_login::{AuthSession, AuthnBackend};
use base64::Engine;
use bytes::Bytes;

use edda_auth::Backend;
use edda_domain::{ActorContext, AuthzError, Repository};
use edda_git::protocol;

use crate::state::AppState;

/// An upload-pack request body is a want/have list, not a pack — a few KiB
/// even for a huge repo. This is a generous absolute ceiling so a
/// malformed or hostile client can't stream an unbounded "request" at us;
/// it is unrelated to `EDDA_GIT_MAX_PACK_BYTES`, which bounds the *inbound
/// pack* on the receive path.
const UPLOAD_PACK_MAX_REQUEST_BYTES: u64 = 64 * 1024 * 1024;

pub fn routes() -> Router<AppState> {
    Router::new()
        // axum only allows one `{param}` per path segment — it can't match
        // `{repo}.git` (parameter mixed with literal text) directly, so the
        // whole segment is captured and `.git` is stripped below.
        .route("/{owner}/{repo}/info/refs", get(info_refs))
        .route("/{owner}/{repo}/git-upload-pack", post(upload_pack))
        .route("/{owner}/{repo}/git-receive-pack", post(receive_pack))
        // A real `git push`/`fetch` pack legitimately dwarfs axum's ~2 MiB
        // `DefaultBodyLimit`. Turn it off here and enforce Edda's own,
        // git-aware ceilings instead (`read_body_capped`, driven by
        // `EDDA_GIT_MAX_PACK_BYTES`).
        .layer(DefaultBodyLimit::disable())
}

/// Reads a request body fully into memory, refusing it with `413 Payload
/// Too Large` once it passes `limit` bytes — Edda's explicit git/LFS
/// transfer ceiling on routes where axum's `DefaultBodyLimit` is disabled.
///
/// This still buffers the whole body; it bounds memory by the *configured*
/// cap rather than streaming to disk. The receive path's true
/// stream-to-quarantine handling arrives with the `gix-pack` bundle-write
/// step; every other caller here (`upload-pack` requests, LFS objects)
/// legitimately fits in memory under its cap.
pub(crate) async fn read_body_capped(body: Body, limit: u64) -> Result<Bytes, Response> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    axum::body::to_bytes(body, limit).await.map_err(|err| {
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("request body rejected (limit {limit} bytes): {err}"),
        )
            .into_response()
    })
}

/// Joins the URL's `{owner}` and `{repo}.git` segments into the
/// `{owner}/{repo}` filesystem identity `edda-git` operates on, and the
/// bare repo-name (still needed separately for the DB-level
/// `AuthorizationService` lookup, which resolves by owner *username* + repo
/// name rather than by this filesystem-shaped identity).
pub(crate) fn repo_names<'repo>(owner: &str, repo: &'repo str) -> Option<(String, &'repo str)> {
    let name = repo.strip_suffix(".git")?;
    Some((format!("{owner}/{name}"), name))
}

pub(crate) fn not_found_response(owner: &str, repo: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        format!("no repository named \"{owner}/{repo}\""),
    )
        .into_response()
}

pub(crate) fn unauthorized_response(message: &'static str) -> Response {
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
pub(crate) async fn resolve_actor(
    state: &AppState,
    auth: &AuthSession<Backend>,
    headers: &HeaderMap,
) -> ActorContext {
    if let Some(session_user) = &auth.user {
        // Absolute session TTL (S10), same check as the `/api/v1` `Actor`
        // extractor. A too-old cookie session falls through to Basic auth.
        let login_at = auth
            .session
            .get::<i64>(crate::auth_routes::SESSION_LOGIN_AT)
            .await
            .ok()
            .flatten();
        if !crate::auth_routes::session_login_expired(
            login_at,
            state.config.session.absolute_ttl_secs,
        ) {
            return ActorContext::User(session_user.user.id);
        }
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

    if let Some((user, scope, token_scope)) =
        edda_auth::tokens::authenticate(&state.pool, secret).await
    {
        return ActorContext::Token {
            user_id: user.id,
            scope,
            token_scope,
        };
    }
    if let Some((user, scope, token_scope)) =
        edda_auth::tokens::authenticate(&state.pool, identity).await
    {
        return ActorContext::Token {
            user_id: user.id,
            scope,
            token_scope,
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
pub(crate) async fn require_read_access(
    state: &AppState,
    auth: &AuthSession<Backend>,
    headers: &HeaderMap,
    owner: &str,
    repository: &Repository,
) -> Result<(), Response> {
    // Instance-private mode (Phase 9, `EDDA_REQUIRE_SIGNIN_VIEW`): no
    // anonymous access to any repository over git-HTTP, public included.
    if state.config.require_signin_to_view {
        let actor = resolve_actor(state, auth, headers).await;
        if matches!(actor, ActorContext::Anonymous) {
            return Err(unauthorized_response(
                "this instance requires sign-in to read any repository",
            ));
        }
    }
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

pub(crate) async fn require_write_access(
    state: &AppState,
    auth: &AuthSession<Backend>,
    headers: &HeaderMap,
    owner: &str,
    repository: &Repository,
) -> Result<(), Response> {
    let actor = resolve_actor(state, auth, headers).await;
    // A `repo:read` PAT authenticates fine but may not push — reject before
    // the role check, with the same 403 a non-collaborator identity gets.
    if !actor.permits_token_scope(edda_domain::TokenScope::RepoWrite) {
        return Err((
            StatusCode::FORBIDDEN,
            "this token's scope does not permit pushing",
        )
            .into_response());
    }
    // Phase 9: when the instance requires email verification, an account
    // whose address is still unconfirmed may not push.
    if let Some(user_id) = actor.user_id() {
        if let Ok(Some(status)) = edda_db::UserRepo::account_status(&state.pool, user_id).await {
            if edda_auth::require_verified_for_write(&status, &state.config.registration).is_err() {
                return Err((
                    StatusCode::FORBIDDEN,
                    "verify your email address before pushing",
                )
                    .into_response());
            }
        }
    }
    match state.authz.check_write(&actor, repository).await {
        Ok(()) => Ok(()),
        Err(AuthzError::NotFound) if matches!(actor, ActorContext::Anonymous) => {
            Err(unauthorized_response("login required to push"))
        }
        Err(AuthzError::NotFound) => Err(not_found_response(owner, &repository.name)),
        // An anonymous actor pushing to a *public* repo also needs a 401,
        // not a 403: `can_write_repository` reports `Forbidden` here (not
        // `NotFound`, since a public repo's existence isn't a secret) but
        // the client still hasn't been asked to authenticate at all yet.
        // A real `git push` embeds credentials in the remote URL but only
        // sends them once a request has actually been challenged with
        // 401 — the read-only `info/refs` request that precedes every
        // push never gets that challenge for a public repo, so without
        // this case the client never learns it needs to retry with
        // credentials, and a 403 here is treated as terminal, not
        // retryable. Only once the actor is a *known* identity (User or
        // Token) that still lacks sufficient role does this mean "you
        // authenticated, but you're not allowed" — a real 403.
        Err(AuthzError::Forbidden) if matches!(actor, ActorContext::Anonymous) => {
            Err(unauthorized_response("login required to push"))
        }
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
    let Some((identity, repo_name)) = repo_names(&owner, &repo) else {
        return (StatusCode::NOT_FOUND, "expected a \"<name>.git\" path").into_response();
    };
    let Some(service) = query.as_deref().and_then(|q| q.strip_prefix("service=")) else {
        return (
            StatusCode::BAD_REQUEST,
            "expected ?service=git-upload-pack or git-receive-pack",
        )
            .into_response();
    };

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

    // Capabilities are supposed to be negotiated as the intersection of
    // what the client wants and what's advertised here — a strict client
    // has no reason to expect (or correctly parse) a report-status-formatted
    // receive-pack response unless the server actually said it supports it.
    let capabilities = if service == "git-receive-pack" {
        protocol::RECEIVE_PACK_CAPABILITIES
    } else {
        // HTTP is stateless-RPC: the client's shallow negotiation is two
        // self-contained POSTs, which `run_upload_pack` handles — so
        // `shallow` is advertised here (but not over SSH).
        protocol::UPLOAD_PACK_CAPABILITIES_STATELESS
    };

    let advertisement =
        match protocol::build_ref_advertisement(state.store.as_ref(), &identity, capabilities) {
            Ok(body) => body,
            Err(err) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
        };

    // The `# service=` comment line is HTTP-smart-protocol-specific — a
    // direct SSH `git-upload-pack`/`git-receive-pack` exec never sends
    // one, since there's no separate "which service?" negotiation over
    // SSH (see `edda_git::protocol`'s module doc).
    let mut body = Vec::new();
    edda_git::pktline::write_pkt_line(&mut body, format!("# service={service}\n").as_bytes());
    edda_git::pktline::write_flush(&mut body);
    body.extend_from_slice(&advertisement);

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

#[tracing::instrument(name = "git.upload_pack", skip_all, fields(repo.owner = %owner, repo = %repo))]
async fn upload_pack(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    body: Body,
) -> Response {
    let Some((identity, repo_name)) = repo_names(&owner, &repo) else {
        return (StatusCode::NOT_FOUND, "expected a \"<name>.git\" path").into_response();
    };
    let repository = match state.authz.repository_by_name(&owner, repo_name).await {
        Ok(repository) => repository,
        Err(_) => return not_found_response(&owner, repo_name),
    };
    if let Err(response) = require_read_access(&state, &auth, &headers, &owner, &repository).await {
        return response;
    }

    let body = match read_body_capped(body, UPLOAD_PACK_MAX_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(response) => return response,
    };

    let out = match protocol::run_upload_pack(state.store.as_ref(), &identity, body).await {
        Ok(out) => out,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-git-upload-pack-result")
        .body(Body::from(out))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[tracing::instrument(name = "git.receive_pack", skip_all, fields(repo.owner = %owner, repo = %repo))]
async fn receive_pack(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    body: Body,
) -> Response {
    let Some((identity, repo_name)) = repo_names(&owner, &repo) else {
        return (StatusCode::NOT_FOUND, "expected a \"<name>.git\" path").into_response();
    };

    let repository = match state.authz.repository_by_name(&owner, repo_name).await {
        Ok(repository) => repository,
        Err(_) => return not_found_response(&owner, repo_name),
    };
    if let Err(response) = require_write_access(&state, &auth, &headers, &owner, &repository).await
    {
        return response;
    }

    let body = match read_body_capped(body, state.config.git_limits.max_pack_bytes).await {
        Ok(body) => body,
        Err(response) => return response,
    };

    let actor = resolve_actor(&state, &auth, &headers).await;
    let checks = state
        .authz
        .resolve_receive_checks(
            &actor,
            &repository,
            state
                .config
                .git_limits
                .max_repo_size_bytes
                .and_then(|bytes| i64::try_from(bytes).ok()),
        )
        .await
        .map(to_git_checks)
        .unwrap_or_default();

    let outcome = match protocol::run_receive_pack(
        state.store.as_ref(),
        &state.locks,
        &identity,
        body,
        checks,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-git-receive-pack-result")
        .body(Body::from(outcome.response))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// The trivial field copy from `edda-auth`'s transport-neutral resolution
/// to `edda-git`'s `ReceiveChecks` (`edda-auth` must not name an
/// `edda-git` type — see that crate's root).
fn to_git_checks(resolved: edda_auth::ResolvedReceiveChecks) -> edda_git::ReceiveChecks {
    edda_git::ReceiveChecks {
        blocked_ref_patterns: resolved.blocked_ref_patterns,
        linear_history_ref_patterns: resolved.linear_history_ref_patterns,
        signed_commit_ref_patterns: resolved.signed_commit_ref_patterns,
        max_repo_bytes: resolved.max_repo_bytes,
        current_repo_bytes: resolved.current_repo_bytes,
    }
}

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
use axum::extract::{Path, RawQuery, State};
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

pub fn routes() -> Router<AppState> {
    Router::new()
        // axum only allows one `{param}` per path segment — it can't match
        // `{repo}.git` (parameter mixed with literal text) directly, so the
        // whole segment is captured and `.git` is stripped below.
        .route("/{owner}/{repo}/info/refs", get(info_refs))
        .route("/{owner}/{repo}/git-upload-pack", post(upload_pack))
        .route("/{owner}/{repo}/git-receive-pack", post(receive_pack))
}

/// Joins the URL's `{owner}` and `{repo}.git` segments into the
/// `{owner}/{repo}` filesystem identity `edda-git` operates on, and the
/// bare repo-name (still needed separately for the DB-level
/// `AuthorizationService` lookup, which resolves by owner *username* + repo
/// name rather than by this filesystem-shaped identity).
fn repo_names<'repo>(owner: &str, repo: &'repo str) -> Option<(String, &'repo str)> {
    let name = repo.strip_suffix(".git")?;
    Some((format!("{owner}/{name}"), name))
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
        protocol::UPLOAD_PACK_CAPABILITIES
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
    body: Bytes,
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
    body: Bytes,
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

    let out = match protocol::run_receive_pack(state.store.as_ref(), &state.locks, &identity, body)
        .await
    {
        Ok(out) => out,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-git-receive-pack-result")
        .body(Body::from(out))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

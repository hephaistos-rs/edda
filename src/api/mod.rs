//! Git smart-HTTP bridge: lets a real `git` client `clone`/`fetch`/`push`
//! against Edda over HTTP. Bridges to `git http-backend` as a CGI-style
//! subprocess rather than reimplementing the pack/wire protocol — `gix` has
//! no server-side receive-pack/upload-pack support, and hand-rolling it would
//! be its own multi-week project on top of everything else here. This makes
//! `git` an actual runtime dependency on the machine hosting Edda, not just
//! something a client needs — a deliberate, visible tradeoff, not an
//! accident.

use axum::body::{Body, Bytes};
use axum::extract::{Path, RawQuery};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::git::store::LocalFsStore;
use crate::git::{fix_unborn_head, repo_lock, validated_repo_dir};

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

async fn info_refs(Path(repo): Path<String>, RawQuery(query): RawQuery, headers: HeaderMap) -> Response {
    let name = match repo_name(&repo) {
        Ok(name) => name,
        Err(response) => return response,
    };
    run_backend(name, "info/refs", "GET", query.as_deref(), &headers, Bytes::new(), false).await
}

async fn upload_pack(Path(repo): Path<String>, headers: HeaderMap, body: Bytes) -> Response {
    let name = match repo_name(&repo) {
        Ok(name) => name,
        Err(response) => return response,
    };
    // Read-only (fetch/clone): no lock needed, git's own object model is
    // already safe to read concurrently with anything.
    run_backend(name, "git-upload-pack", "POST", None, &headers, body, false).await
}

async fn receive_pack(Path(repo): Path<String>, headers: HeaderMap, body: Bytes) -> Response {
    let name = match repo_name(&repo) {
        Ok(name) => name,
        Err(response) => return response,
    };
    // A push is a write: hold the same per-repo lock Edda's own
    // create/update/delete use, so a push can't land while, say, someone
    // deletes the repo out from under it via the UI.
    let response = run_backend(name, "git-receive-pack", "POST", None, &headers, body, true).await;

    // A push can create the repo's first branch under a name HEAD doesn't
    // point at yet (see `fix_unborn_head`'s doc comment) — repair it now so a
    // client cloning right after this push gets a working checkout.
    if response.status().is_success() {
        let store = LocalFsStore::from_env();
        if let Ok(dir) = validated_repo_dir(&store, name) {
            let _ = fix_unborn_head(&dir);
        }
    }

    response
}

async fn run_backend(
    name: &str,
    service_path: &str,
    method: &str,
    query: Option<&str>,
    headers: &HeaderMap,
    body: Bytes,
    take_lock: bool,
) -> Response {
    let store = LocalFsStore::from_env();
    let repo_dir = match validated_repo_dir(&store, name) {
        Ok(dir) => dir,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };

    let (Some(project_root), Some(repo_dir_name)) = (repo_dir.parent(), repo_dir.file_name()) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "couldn't resolve repo path").into_response();
    };
    let path_info = format!("/{}/{service_path}", repo_dir_name.to_string_lossy());

    let lock = take_lock.then(|| repo_lock(name));
    let _guard = match &lock {
        Some(lock) => Some(lock.lock().await),
        None => None,
    };

    let mut cmd = Command::new("git");
    cmd.arg("http-backend")
        .env_clear()
        .env("GIT_PROJECT_ROOT", project_root)
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("PATH_INFO", &path_info)
        .env("REQUEST_METHOD", method)
        .env("QUERY_STRING", query.unwrap_or(""))
        .env("CONTENT_LENGTH", body.len().to_string())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    if let Some(content_type) = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) {
        cmd.env("CONTENT_TYPE", content_type);
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("couldn't start git http-backend: {err}"))
                .into_response();
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        // Errors here (e.g. a broken pipe if the backend exits early) don't
        // matter — the exit status and stdout below are the real signal.
        let _ = stdin.write_all(&body).await;
        let _ = stdin.shutdown().await;
    }

    let output = match child.wait_with_output().await {
        Ok(output) => output,
        Err(err) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("git http-backend failed: {err}")).into_response();
        }
    };

    if !output.status.success() && output.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("git http-backend exited with {}: {stderr}", output.status))
            .into_response();
    }

    parse_cgi_response(&output.stdout)
}

/// `git http-backend` speaks CGI: a block of `Header: value` lines, a blank
/// line, then the raw response body. Translates that into a real HTTP
/// response instead of passing the CGI framing straight through.
fn parse_cgi_response(raw: &[u8]) -> Response {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2)));

    let Some((idx, sep_len)) = split else {
        // No header/body separator found (shouldn't happen for a well-formed
        // CGI response) — fall back to treating the whole thing as the body.
        return (StatusCode::OK, Body::from(raw.to_vec())).into_response();
    };

    let header_block = &raw[..idx];
    let body = raw[idx + sep_len..].to_vec();

    let mut status = StatusCode::OK;
    let mut builder = Response::builder();

    for line in header_block.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else { continue };
        let name = String::from_utf8_lossy(&line[..colon]).trim().to_string();
        let value = String::from_utf8_lossy(&line[colon + 1..]).trim().to_string();

        if name.eq_ignore_ascii_case("status") {
            // CGI's "Status" header looks like "200 OK" or "404 Not Found".
            if let Some(code) = value.split_whitespace().next().and_then(|s| s.parse::<u16>().ok()) {
                if let Ok(parsed) = StatusCode::from_u16(code) {
                    status = parsed;
                }
            }
            continue;
        }

        if let (Ok(header_name), Ok(header_value)) = (HeaderName::try_from(name), HeaderValue::try_from(value)) {
            builder = builder.header(header_name, header_value);
        }
    }

    builder.status(status).body(Body::from(body)).unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

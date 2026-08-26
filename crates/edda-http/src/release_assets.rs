//! Release asset upload/download — raw axum routes, not Dioxus server
//! functions, for the same reason `edda_http::lfs` is: real binary
//! transfer needs streaming request/response bodies, which Dioxus's
//! `#[get]`/`#[post]` macros don't support. Release *metadata* (create/
//! list/publish) is a Dioxus server function (`edda-web`'s
//! `release_server`) — this module only ever touches the bytes.
//!
//! Upload enforces §13's "size limits enforced before buffering the full
//! body in memory" rule via `Field::chunk()` (per-chunk streaming, not
//! `Field::bytes()`, which would buffer the whole upload first) and
//! serves every asset back as `application/octet-stream` regardless of
//! its stored `content_type` — the "never let a client-supplied
//! `Content-Type` influence how Edda itself serves the file back" rule,
//! since trusting it could turn an uploaded `text/html` asset into a
//! same-origin XSS vector.

use axum::body::Body;
use axum::extract::{Multipart, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_login::AuthSession;

use edda_auth::Backend;
use edda_db::{ReleaseAssetRepo, ReleaseRepo};
use edda_domain::ReleaseAssetId;

use crate::git_http::{not_found_response, require_read_access, require_write_access};
use crate::state::AppState;

/// Unlike the git-http bridge's `{repo}` segment (which always carries a
/// literal `.git` suffix, e.g. `demo.git`, stripped by `git_http::
/// repo_names`), this crate's other routes take a plain repo-name segment
/// straight from the URL — so the filesystem identity is just
/// `{owner}/{repo}` directly, no suffix to strip.
fn identity_for(owner: &str, repo: &str) -> String {
    format!("{owner}/{repo}")
}

/// 200 MiB — generous for a release binary/archive while still bounding
/// worst-case disk/memory use per upload; revisit if a real use case
/// needs more (there's no architectural reason this couldn't grow, it's
/// just an initial, deliberately conservative default).
const MAX_ASSET_BYTES: u64 = 200 * 1024 * 1024;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/{owner}/{repo}/releases/{tag}/assets", post(upload_asset))
        .route(
            "/{owner}/{repo}/releases/{tag}/assets/{filename}",
            get(download_asset),
        )
}

/// Rejects anything that could escape `releases/{release_id}/` on disk or
/// isn't a reasonable filename — no path separators, no `.`/`..`, no
/// control characters, capped length. The client's claimed filename never
/// reaches a filesystem path otherwise unvalidated.
fn is_safe_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\'])
        && name.bytes().all(|b| b >= 0x20 && b != 0x7f)
}

async fn upload_asset(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    headers: HeaderMap,
    Path((owner, repo, tag)): Path<(String, String, String)>,
    mut multipart: Multipart,
) -> Response {
    let identity = identity_for(&owner, &repo);
    let repository = match state.authz.repository_by_name(&owner, &repo).await {
        Ok(repository) => repository,
        Err(_) => return not_found_response(&owner, &repo),
    };
    if let Err(response) = require_write_access(&state, &auth, &headers, &owner, &repository).await
    {
        return response;
    }
    let release = match ReleaseRepo::find_by_repository_and_tag(&state.pool, repository.id, &tag)
        .await
    {
        Ok(Some(release)) => release,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such release").into_response(),
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

    let field = match multipart.next_field().await {
        Ok(Some(field)) => field,
        Ok(None) => {
            return (StatusCode::BAD_REQUEST, "no file field in the upload").into_response()
        }
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };
    let Some(filename) = field.file_name().map(str::to_string) else {
        return (StatusCode::BAD_REQUEST, "the upload field has no filename").into_response();
    };
    if !is_safe_filename(&filename) {
        return (StatusCode::BAD_REQUEST, "invalid filename").into_response();
    }
    let content_type = field
        .content_type()
        .unwrap_or("application/octet-stream")
        .to_string();

    let storage_key = format!("{}/{filename}", release.id);
    let path = state.store.release_asset_path(&identity, &storage_key);
    if let Some(parent) = path.parent() {
        if let Err(err) = tokio::fs::create_dir_all(parent).await {
            return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
        }
    }

    let mut file = match tokio::fs::File::create(&path).await {
        Ok(file) => file,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    let mut total: u64 = 0;
    let mut field = field;
    loop {
        let chunk = match field.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(err) => {
                let _ = tokio::fs::remove_file(&path).await;
                return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
            }
        };
        total += chunk.len() as u64;
        if total > MAX_ASSET_BYTES {
            let _ = tokio::fs::remove_file(&path).await;
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "asset exceeds the size limit",
            )
                .into_response();
        }
        use tokio::io::AsyncWriteExt;
        if let Err(err) = file.write_all(&chunk).await {
            let _ = tokio::fs::remove_file(&path).await;
            return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
        }
    }

    if let Err(err) = ReleaseAssetRepo::insert(
        &state.pool,
        ReleaseAssetId::new(),
        release.id,
        &filename,
        total as i64,
        &content_type,
        &storage_key,
    )
    .await
    {
        let _ = tokio::fs::remove_file(&path).await;
        return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }

    StatusCode::CREATED.into_response()
}

async fn download_asset(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    headers: HeaderMap,
    Path((owner, repo, tag, filename)): Path<(String, String, String, String)>,
) -> Response {
    let identity = identity_for(&owner, &repo);
    let repository = match state.authz.repository_by_name(&owner, &repo).await {
        Ok(repository) => repository,
        Err(_) => return not_found_response(&owner, &repo),
    };
    let release = match ReleaseRepo::find_by_repository_and_tag(&state.pool, repository.id, &tag)
        .await
    {
        Ok(Some(release)) => release,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such release").into_response(),
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    // A draft release is collaborator-only — the same visibility rule as
    // its metadata applies to its assets, so this doesn't leak a draft
    // asset to a plain repository reader.
    let access_check = if release.is_visible_to_readers() {
        require_read_access(&state, &auth, &headers, &owner, &repository).await
    } else {
        require_write_access(&state, &auth, &headers, &owner, &repository).await
    };
    if let Err(response) = access_check {
        return response;
    }

    let asset =
        match ReleaseAssetRepo::find_by_release_and_filename(&state.pool, release.id, &filename)
            .await
        {
            Ok(Some(asset)) => asset,
            Ok(None) => return (StatusCode::NOT_FOUND, "no such asset").into_response(),
            Err(err) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
        };

    let path = state
        .store
        .release_asset_path(&identity, &asset.storage_key);
    match tokio::fs::read(&path).await {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            // Always `application/octet-stream` — see this module's doc
            // comment for why the stored (client-claimed) content type is
            // never used here.
            .header("Content-Type", "application/octet-stream")
            .header(
                "Content-Disposition",
                format!(
                    "attachment; filename=\"{}\"",
                    asset.filename.replace('"', "")
                ),
            )
            .body(Body::from(bytes))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Err(_) => (StatusCode::NOT_FOUND, "asset not found on disk").into_response(),
    }
}

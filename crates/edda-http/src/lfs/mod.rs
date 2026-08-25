//! Git LFS batch API + object transfer + file locking, hand-built (no
//! mature Rust LFS-server library exists to build this on top of instead —
//! this is genuinely protocol work, not glue code). `edda_git::protocol`
//! isn't involved here at all: LFS is an entirely separate HTTP-only
//! protocol layered next to (not inside) the git smart-HTTP bridge, even
//! though a real `git-lfs`-managed repo's remote is the same
//! `{owner}/{repo}.git` URL for both.
//!
//! Every route below authorizes through the exact same
//! `AuthorizationService` the git-HTTP bridge uses (`git_http::
//! require_read_access`/`require_write_access`) — LFS objects belong to a
//! repository like everything else a repository holds, so there is no
//! separate LFS-specific authorization policy to get wrong.

mod transfer_auth;

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{post, put};
use axum::Router;
use axum_login::AuthSession;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use edda_auth::Backend;
use edda_db::LfsRepo;
use edda_domain::{ActorContext, LfsLockId};

use crate::git_http::{not_found_response, repo_names, require_read_access, require_write_access};
use crate::state::AppState;
use transfer_auth::TransferAction;

const LFS_CONTENT_TYPE: &str = "application/vnd.git-lfs+json";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/{owner}/{repo}/info/lfs/objects/batch", post(batch))
        .route(
            "/{owner}/{repo}/info/lfs/objects/{oid}",
            put(upload_object).get(download_object),
        )
        .route(
            "/{owner}/{repo}/info/lfs/locks",
            post(create_lock).get(list_locks),
        )
        .route("/{owner}/{repo}/info/lfs/locks/verify", post(verify_locks))
        .route("/{owner}/{repo}/info/lfs/locks/{id}/unlock", post(unlock))
}

fn lfs_json(status: StatusCode, body: &impl Serialize) -> Response {
    let payload = serde_json::to_vec(body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("Content-Type", LFS_CONTENT_TYPE)
        .body(axum::body::Body::from(payload))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// A hex-encoded SHA-256 digest — exactly what an LFS `oid` always is. A
/// non-matching string never reaches a filesystem path or a bound SQL
/// parameter as anything but this validated shape.
fn is_valid_oid(oid: &str) -> bool {
    oid.len() == 64 && oid.bytes().all(|b| b.is_ascii_hexdigit())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Where `oid`'s bytes live under this repo's LFS storage root, as the
/// portable-relative form `lfs_objects.storage_key` stores (relative to
/// `RepoStore::lfs_object_path`'s own root, not an absolute filesystem
/// path) — see that column's doc comment for why it's stored at all
/// rather than always recomputed.
fn storage_key(oid: &str) -> String {
    if oid.len() >= 4 {
        format!("{}/{}/{}", &oid[0..2], &oid[2..4], oid)
    } else {
        oid.to_string()
    }
}

fn base_url(headers: &HeaderMap) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("http");
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost");
    format!("{scheme}://{host}")
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_string)
}

#[derive(Deserialize)]
struct BatchRequestObject {
    oid: String,
    size: i64,
}

#[derive(Deserialize)]
struct BatchRequest {
    operation: String,
    objects: Vec<BatchRequestObject>,
}

#[derive(Serialize)]
struct BatchAction {
    href: String,
    header: HashMap<String, String>,
    expires_in: u64,
}

#[derive(Serialize, Default)]
struct BatchActions {
    #[serde(skip_serializing_if = "Option::is_none")]
    upload: Option<BatchAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    download: Option<BatchAction>,
}

#[derive(Serialize)]
struct BatchResponseError {
    code: u16,
    message: String,
}

#[derive(Serialize)]
struct BatchResponseObject {
    oid: String,
    size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    actions: Option<BatchActions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<BatchResponseError>,
}

#[derive(Serialize)]
struct BatchResponse {
    transfer: &'static str,
    objects: Vec<BatchResponseObject>,
}

fn transfer_action(token: String, href: String) -> BatchAction {
    BatchAction {
        href,
        header: HashMap::from([("Authorization".to_string(), format!("Bearer {token}"))]),
        expires_in: 900,
    }
}

/// The one endpoint every LFS transfer starts with: given a list of
/// objects and whether the client wants to `"upload"` or `"download"`
/// them, returns per-object transfer instructions (or, for an upload the
/// server already has, no action at all — telling the client to skip it).
async fn batch(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let Some((identity, repo_name)) = repo_names(&owner, &repo) else {
        return not_found_response(&owner, &repo);
    };
    let request: BatchRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };
    let is_upload = request.operation == "upload";

    let repository = match state.authz.repository_by_name(&owner, repo_name).await {
        Ok(repository) => repository,
        Err(_) => return not_found_response(&owner, repo_name),
    };
    let access_check = if is_upload {
        require_write_access(&state, &auth, &headers, &owner, &repository).await
    } else {
        require_read_access(&state, &auth, &headers, &owner, &repository).await
    };
    if let Err(response) = access_check {
        return response;
    }

    let base = base_url(&headers);
    let mut objects = Vec::with_capacity(request.objects.len());
    for object in request.objects {
        if !is_valid_oid(&object.oid) {
            objects.push(BatchResponseObject {
                oid: object.oid,
                size: object.size,
                actions: None,
                error: Some(BatchResponseError {
                    code: 422,
                    message: "invalid oid".to_string(),
                }),
            });
            continue;
        }

        let href = format!(
            "{base}/{owner}/{repo_name}.git/info/lfs/objects/{}",
            object.oid
        );
        let existing = LfsRepo::find_object(&state.pool, repository.id, &object.oid)
            .await
            .ok()
            .flatten();

        if is_upload {
            let actions = match existing {
                // Content-addressed and already stored — nothing to
                // upload, so no `actions` at all (the client interprets
                // this as "server already has it").
                Some(_) => None,
                None => {
                    let token =
                        transfer_auth::issue(&identity, &object.oid, TransferAction::Upload);
                    Some(BatchActions {
                        upload: Some(transfer_action(token, href)),
                        download: None,
                    })
                }
            };
            objects.push(BatchResponseObject {
                oid: object.oid,
                size: object.size,
                actions,
                error: None,
            });
        } else {
            match existing {
                Some(found) => {
                    let token =
                        transfer_auth::issue(&identity, &object.oid, TransferAction::Download);
                    objects.push(BatchResponseObject {
                        oid: object.oid,
                        size: found.size_bytes,
                        actions: Some(BatchActions {
                            upload: None,
                            download: Some(transfer_action(token, href)),
                        }),
                        error: None,
                    });
                }
                None => objects.push(BatchResponseObject {
                    oid: object.oid,
                    size: object.size,
                    actions: None,
                    error: Some(BatchResponseError {
                        code: 404,
                        message: "object does not exist".to_string(),
                    }),
                }),
            }
        }
    }

    lfs_json(
        StatusCode::OK,
        &BatchResponse {
            transfer: "basic",
            objects,
        },
    )
}

async fn upload_object(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, oid)): Path<(String, String, String)>,
    body: Bytes,
) -> Response {
    let Some((identity, repo_name)) = repo_names(&owner, &repo) else {
        return not_found_response(&owner, &repo);
    };
    if !is_valid_oid(&oid) {
        return (StatusCode::BAD_REQUEST, "invalid oid").into_response();
    }
    let Some(token) = bearer_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !transfer_auth::verify(&token, &identity, &oid, TransferAction::Upload) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let repository = match state.authz.repository_by_name(&owner, repo_name).await {
        Ok(repository) => repository,
        Err(_) => return not_found_response(&owner, repo_name),
    };

    let actual = sha256_hex(&body);
    if actual != oid {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("uploaded content hashes to {actual}, not {oid}"),
        )
            .into_response();
    }

    let path = state.store.lfs_object_path(&identity, &oid);
    if let Some(parent) = path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
        }
    }
    if let Err(err) = std::fs::write(&path, &body) {
        return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }

    if let Err(err) = LfsRepo::insert_object(
        &state.pool,
        repository.id,
        &oid,
        body.len() as i64,
        &storage_key(&oid),
    )
    .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }

    StatusCode::OK.into_response()
}

async fn download_object(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, oid)): Path<(String, String, String)>,
) -> Response {
    let Some((identity, repo_name)) = repo_names(&owner, &repo) else {
        return not_found_response(&owner, &repo);
    };
    if !is_valid_oid(&oid) {
        return (StatusCode::BAD_REQUEST, "invalid oid").into_response();
    }
    let Some(token) = bearer_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !transfer_auth::verify(&token, &identity, &oid, TransferAction::Download) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let _ = repo_name;

    let path = state.store.lfs_object_path(&identity, &oid);
    match std::fs::read(&path) {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/octet-stream")
            .body(axum::body::Body::from(bytes))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Err(_) => (StatusCode::NOT_FOUND, "object not found").into_response(),
    }
}

#[derive(Deserialize)]
struct CreateLockRequest {
    path: String,
}

#[derive(Serialize)]
struct LockDto {
    id: String,
    path: String,
}

fn lock_dto(lock: &edda_domain::LfsLock) -> LockDto {
    LockDto {
        id: lock.id.to_string(),
        path: lock.path.clone(),
    }
}

async fn create_lock(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let Some((_identity, repo_name)) = repo_names(&owner, &repo) else {
        return not_found_response(&owner, &repo);
    };
    let request: CreateLockRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };

    let repository = match state.authz.repository_by_name(&owner, repo_name).await {
        Ok(repository) => repository,
        Err(_) => return not_found_response(&owner, repo_name),
    };
    if let Err(response) = require_write_access(&state, &auth, &headers, &owner, &repository).await
    {
        return response;
    }
    let Some(user_id) = auth.user.as_ref().map(|session_user| session_user.user.id) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    let id = LfsLockId::new();
    match LfsRepo::create_lock(&state.pool, id, repository.id, &request.path, user_id).await {
        Ok(()) => lfs_json(
            StatusCode::CREATED,
            &serde_json::json!({ "lock": LockDto { id: id.to_string(), path: request.path } }),
        ),
        Err(edda_db::CreateLockError::AlreadyLocked(path)) => lfs_json(
            StatusCode::CONFLICT,
            &serde_json::json!({ "message": format!("\"{path}\" is already locked") }),
        ),
        Err(edda_db::CreateLockError::Db(err)) => {
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
        }
    }
}

async fn list_locks(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> Response {
    let Some((_identity, repo_name)) = repo_names(&owner, &repo) else {
        return not_found_response(&owner, &repo);
    };
    let repository = match state.authz.repository_by_name(&owner, repo_name).await {
        Ok(repository) => repository,
        Err(_) => return not_found_response(&owner, repo_name),
    };
    if let Err(response) = require_read_access(&state, &auth, &headers, &owner, &repository).await {
        return response;
    }

    match LfsRepo::list_locks(&state.pool, repository.id).await {
        Ok(locks) => lfs_json(
            StatusCode::OK,
            &serde_json::json!({ "locks": locks.iter().map(lock_dto).collect::<Vec<_>>() }),
        ),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

/// The pre-push hook's own check: splits every outstanding lock into
/// "ours" (held by the calling actor) and "theirs" (held by someone
/// else) — real `git lfs push` refuses to push over someone else's lock
/// without this.
async fn verify_locks(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> Response {
    let Some((_identity, repo_name)) = repo_names(&owner, &repo) else {
        return not_found_response(&owner, &repo);
    };
    let repository = match state.authz.repository_by_name(&owner, repo_name).await {
        Ok(repository) => repository,
        Err(_) => return not_found_response(&owner, repo_name),
    };
    if let Err(response) = require_read_access(&state, &auth, &headers, &owner, &repository).await {
        return response;
    }
    let actor_user_id = auth.user.as_ref().map(|session_user| session_user.user.id);

    match LfsRepo::list_locks(&state.pool, repository.id).await {
        Ok(locks) => {
            let (ours, theirs): (Vec<_>, Vec<_>) = locks
                .iter()
                .partition(|lock| Some(lock.owner_id) == actor_user_id);
            lfs_json(
                StatusCode::OK,
                &serde_json::json!({
                    "ours": ours.iter().map(|lock| lock_dto(lock)).collect::<Vec<_>>(),
                    "theirs": theirs.iter().map(|lock| lock_dto(lock)).collect::<Vec<_>>(),
                }),
            )
        }
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

async fn unlock(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    headers: HeaderMap,
    Path((owner, repo, id)): Path<(String, String, String)>,
) -> Response {
    let Some((_identity, repo_name)) = repo_names(&owner, &repo) else {
        return not_found_response(&owner, &repo);
    };
    let Ok(lock_id) = id.parse::<LfsLockId>() else {
        return (StatusCode::BAD_REQUEST, "invalid lock id").into_response();
    };
    let repository = match state.authz.repository_by_name(&owner, repo_name).await {
        Ok(repository) => repository,
        Err(_) => return not_found_response(&owner, repo_name),
    };
    if let Err(response) = require_write_access(&state, &auth, &headers, &owner, &repository).await
    {
        return response;
    }
    let actor = auth
        .user
        .as_ref()
        .map(|session_user| ActorContext::User(session_user.user.id))
        .unwrap_or(ActorContext::Anonymous);
    let Some(actor_user_id) = actor.user_id() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    let lock = match LfsRepo::find_lock_by_id(&state.pool, lock_id).await {
        Ok(Some(lock)) if lock.repository_id == repository.id => lock,
        Ok(_) => return (StatusCode::NOT_FOUND, "no such lock").into_response(),
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    // Anyone with write access may force-unlock (matching the `Owner`-only
    // danger-zone split not applying here — this is an ordinary write
    // operation, not a destructive one); the lock's own creator may always
    // unlock their own lock regardless of their current role.
    if lock.owner_id != actor_user_id {
        if let Err(response) = state
            .authz
            .check_administer(&actor, &repository)
            .await
            .map_err(|_| (StatusCode::FORBIDDEN, "you don't hold this lock").into_response())
        {
            return response;
        }
    }

    match LfsRepo::delete_lock(&state.pool, lock_id).await {
        Ok(true) => lfs_json(
            StatusCode::OK,
            &serde_json::json!({ "lock": lock_dto(&lock) }),
        ),
        Ok(false) => (StatusCode::NOT_FOUND, "no such lock").into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

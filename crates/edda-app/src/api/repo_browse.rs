//! `/api/v1/repos/{owner}/{repo}/{tree,blob,branches,commits,search}` and
//! `.../commits/{id}/diff` — read-only repository browsing. Every response
//! body that carries source text is rendered server-side (`rendered_html`
//! for blobs, per-line `html` for diffs) so the UI never runs a renderer.
//!
//! Every blocking `edda-git` call here goes through [`super::git_read`] —
//! the blocking pool, span-propagated, request-timeout-bounded (A9/M2).

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::HeaderValue;
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use edda_api_types::{
    BlameDto, BlameHunkDto, BlobDto, CommitLogEntryDto, DiffHunkDto, DiffLineDto, DiffLineKind,
    FileDiffDto, SearchMatchDto, TreeEntryDto,
};

use super::repos::read_repo_identity;
use super::{git_read, Actor};
use crate::services::ServiceError;
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/repos/{owner}/{repo}/tree", get(tree))
        .route("/api/v1/repos/{owner}/{repo}/blob", get(blob))
        .route("/api/v1/repos/{owner}/{repo}/branches", get(branches))
        .route("/api/v1/repos/{owner}/{repo}/commits", get(commits))
        .route(
            "/api/v1/repos/{owner}/{repo}/commits/{commit_id}/diff",
            get(commit_diff),
        )
        .route("/api/v1/repos/{owner}/{repo}/search", get(search))
        .route("/api/v1/repos/{owner}/{repo}/blame", get(blame))
        .route("/api/v1/repos/{owner}/{repo}/archive", get(archive))
}

#[derive(Deserialize)]
pub struct BranchPathQuery {
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Deserialize)]
pub struct BranchQuery {
    #[serde(default)]
    pub branch: Option<String>,
}

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub query: String,
}

#[derive(Deserialize)]
pub struct BlameQuery {
    /// A branch name, tag, or commit-ish. Defaults to `HEAD`. A path
    /// segment isn't used (a branch name can contain `/`), matching how
    /// `tree`/`blob` take `branch` as a query parameter.
    #[serde(default)]
    pub rev: Option<String>,
    pub path: String,
}

#[derive(Deserialize)]
pub struct ArchiveQuery {
    /// A branch name, tag, or commit-ish. Defaults to `HEAD`.
    #[serde(default)]
    pub rev: Option<String>,
    /// `tar.gz` (default) or `zip`.
    #[serde(default)]
    pub format: Option<String>,
}

async fn tree(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<BranchPathQuery>,
) -> Result<Json<Vec<TreeEntryDto>>, ServiceError> {
    let identity = read_repo_identity(&state, actor.context(), &owner, &repo).await?;
    let path = q.path.unwrap_or_default();
    let store = state.store.clone();
    let branch = q.branch.clone();
    let entries = git_read("browse_tree", move || {
        edda_git::browse_tree(store.as_ref(), &identity, branch.as_deref(), &path)
    })
    .await?;
    Ok(Json(
        entries
            .into_iter()
            .map(|entry| TreeEntryDto {
                name: entry.name,
                is_dir: entry.is_dir,
                size: entry.size,
            })
            .collect(),
    ))
}

async fn blob(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<BranchPathQuery>,
) -> Result<Json<BlobDto>, ServiceError> {
    let identity = read_repo_identity(&state, actor.context(), &owner, &repo).await?;
    let path = q.path.unwrap_or_default();
    let store = state.store.clone();
    let branch = q.branch.clone();
    let blob = git_read("read_blob", move || {
        edda_git::read_blob(store.as_ref(), &identity, branch.as_deref(), &path)
    })
    .await?;
    Ok(Json(blob_dto(blob)))
}

async fn branches(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<String>>, ServiceError> {
    let identity = read_repo_identity(&state, actor.context(), &owner, &repo).await?;
    let store = state.store.clone();
    let branches = git_read("list_branches", move || {
        edda_git::list_branches(store.as_ref(), &identity)
    })
    .await?;
    Ok(Json(branches))
}

async fn commits(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<BranchQuery>,
) -> Result<Json<Vec<CommitLogEntryDto>>, ServiceError> {
    let identity = read_repo_identity(&state, actor.context(), &owner, &repo).await?;
    let store = state.store.clone();
    let branch = q.branch.clone();
    let entries = git_read("commit_log", move || {
        edda_git::commit_log(store.as_ref(), &identity, branch.as_deref(), 50)
    })
    .await?;
    Ok(Json(
        entries
            .into_iter()
            .map(|entry| CommitLogEntryDto {
                id: entry.id,
                summary: entry.summary,
                author_name: entry.author_name,
                unix_seconds: entry.unix_seconds,
            })
            .collect(),
    ))
}

async fn commit_diff(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, commit_id)): Path<(String, String, String)>,
) -> Result<Json<Vec<FileDiffDto>>, ServiceError> {
    let identity = read_repo_identity(&state, actor.context(), &owner, &repo).await?;
    let store = state.store.clone();
    let diffs = git_read("commit_diff", move || {
        edda_git::commit_diff(store.as_ref(), &identity, &commit_id)
    })
    .await?;
    Ok(Json(diffs.into_iter().map(file_diff_dto).collect()))
}

async fn search(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<SearchQuery>,
) -> Result<Json<Vec<SearchMatchDto>>, ServiceError> {
    let identity = read_repo_identity(&state, actor.context(), &owner, &repo).await?;
    if q.query.trim().is_empty() {
        return Ok(Json(Vec::new()));
    }
    let store = state.store.clone();
    let branch = q.branch.clone();
    let query = q.query.clone();
    let matches = git_read("search_tree", move || {
        edda_git::search_tree(store.as_ref(), &identity, branch.as_deref(), &query)
    })
    .await?;
    Ok(Json(
        matches
            .into_iter()
            .map(|m| SearchMatchDto {
                path: m.path,
                line_number: m.line_number,
                line: m.line,
            })
            .collect(),
    ))
}

async fn blame(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<BlameQuery>,
) -> Result<Json<BlameDto>, ServiceError> {
    let identity = read_repo_identity(&state, actor.context(), &owner, &repo).await?;
    let store = state.store.clone();
    let rev = q.rev.clone().unwrap_or_else(|| "HEAD".to_string());
    let path = q.path.clone();
    let blame = git_read("blame", move || {
        edda_git::blame(store.as_ref(), &identity, &rev, &path)
    })
    .await?;
    Ok(Json(BlameDto {
        hunks: blame
            .hunks
            .into_iter()
            .map(|hunk| BlameHunkDto {
                start_line: hunk.start_line,
                line_count: hunk.line_count,
                commit_id: hunk.commit_id,
                summary: hunk.summary,
                author_name: hunk.author_name,
                author_unix_seconds: hunk.author_unix_seconds,
            })
            .collect(),
        lines: blame.lines,
    }))
}

async fn archive(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<ArchiveQuery>,
) -> Result<Response, ServiceError> {
    let identity = read_repo_identity(&state, actor.context(), &owner, &repo).await?;
    let format = match q.format.as_deref().unwrap_or("tar.gz") {
        "tar.gz" | "tgz" | "targz" => edda_git::ArchiveFormat::TarGz,
        "zip" => edda_git::ArchiveFormat::Zip,
        other => {
            return Err(ServiceError::Validation(format!(
                "unknown archive format {other:?} — use \"tar.gz\" or \"zip\""
            )))
        }
    };
    let rev = q.rev.clone().unwrap_or_else(|| "HEAD".to_string());
    // A ref like `feature/x` and any odd bytes must not leak into the
    // header; keep it to a safe filename token.
    let safe_rev: String = rev
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let filename = format!("{repo}-{safe_rev}.{ext}", ext = format.extension());

    let store = state.store.clone();
    let rev_for_task = rev.clone();
    let bytes = git_read("archive", move || {
        edda_git::archive(store.as_ref(), &identity, &rev_for_task, format)
    })
    .await?;

    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static(format.content_type()),
    );
    response.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    Ok(response)
}

/// `README`/`README.md`/`README.markdown`, case-insensitively — an
/// exact-name match, so `readme-notes.md` stays a plain text file.
fn is_readme_filename(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "readme.md" | "readme.markdown" | "readme"
    )
}

fn blob_dto(blob: edda_git::BlobContent) -> BlobDto {
    let rendered_html = match (&blob.content, blob.is_binary) {
        (Some(content), false) if is_readme_filename(&blob.name) => {
            Some(edda_render::markdown::render(content))
        }
        (Some(content), false) => Some(edda_render::syntax::highlight(content, &blob.name)),
        _ => None,
    };
    BlobDto {
        name: blob.name,
        size: blob.size,
        is_binary: blob.is_binary,
        content: blob.content,
        rendered_html,
    }
}

/// `edda_render::syntax::highlight` wraps its output in a shared
/// `<pre class="edda-highlight"><code>…</code></pre>`; a diff wants one
/// highlighted fragment per line, so this strips that wrapper back off.
fn highlighted_line_html(text: &str, filename_hint: &str) -> String {
    let wrapped = edda_render::syntax::highlight(text, filename_hint);
    wrapped
        .strip_prefix("<pre class=\"edda-highlight\"><code>")
        .and_then(|rest| rest.strip_suffix("</code></pre>"))
        .unwrap_or(wrapped.as_str())
        .to_string()
}

pub(crate) fn file_diff_dto(diff: edda_git::FileDiff) -> FileDiffDto {
    let filename_hint = diff
        .new_path
        .clone()
        .or_else(|| diff.old_path.clone())
        .unwrap_or_default();
    let hunks = diff
        .hunks
        .into_iter()
        .map(|hunk| DiffHunkDto {
            old_start: hunk.old_start,
            old_lines: hunk.old_lines,
            new_start: hunk.new_start,
            new_lines: hunk.new_lines,
            lines: hunk
                .lines
                .into_iter()
                .map(|line| {
                    let (kind, text) = match line {
                        edda_git::DiffLine::Context(text) => (DiffLineKind::Context, text),
                        edda_git::DiffLine::Added(text) => (DiffLineKind::Added, text),
                        edda_git::DiffLine::Removed(text) => (DiffLineKind::Removed, text),
                    };
                    DiffLineDto {
                        kind,
                        html: highlighted_line_html(&text, &filename_hint),
                    }
                })
                .collect(),
        })
        .collect();
    FileDiffDto {
        old_path: diff.old_path,
        new_path: diff.new_path,
        is_binary: diff.is_binary,
        is_rename: diff.is_rename,
        is_too_large: diff.is_too_large,
        hunks,
    }
}

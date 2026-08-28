//! `/api/v1/repos/{owner}/{repo}/{tree,blob,branches,commits,search}` and
//! `.../commits/{id}/diff` — read-only repository browsing. Every response
//! body that carries source text is rendered server-side (`rendered_html`
//! for blobs, per-line `html` for diffs) so the UI never runs a renderer.
//!
//! The blocking `edda-git` calls here run inline, matching the pre-cutover
//! code; wrapping them in `spawn_blocking` + a request timeout is the
//! Phase 7 A9/M2 sweep, tracked there.

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use edda_api_types::{
    BlobDto, CommitLogEntryDto, DiffHunkDto, DiffLineDto, DiffLineKind, FileDiffDto,
    SearchMatchDto, TreeEntryDto,
};

use super::repos::read_repo_identity;
use super::Actor;
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

async fn tree(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<BranchPathQuery>,
) -> Result<Json<Vec<TreeEntryDto>>, ServiceError> {
    let identity = read_repo_identity(&state, actor.context(), &owner, &repo).await?;
    let path = q.path.unwrap_or_default();
    let entries =
        edda_git::browse_tree(state.store.as_ref(), &identity, q.branch.as_deref(), &path)?;
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
    let blob = edda_git::read_blob(state.store.as_ref(), &identity, q.branch.as_deref(), &path)?;
    Ok(Json(blob_dto(blob)))
}

async fn branches(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<String>>, ServiceError> {
    let identity = read_repo_identity(&state, actor.context(), &owner, &repo).await?;
    Ok(Json(edda_git::list_branches(
        state.store.as_ref(),
        &identity,
    )?))
}

async fn commits(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<BranchQuery>,
) -> Result<Json<Vec<CommitLogEntryDto>>, ServiceError> {
    let identity = read_repo_identity(&state, actor.context(), &owner, &repo).await?;
    let entries = edda_git::commit_log(state.store.as_ref(), &identity, q.branch.as_deref(), 50)?;
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
    let diffs = edda_git::commit_diff(state.store.as_ref(), &identity, &commit_id)?;
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
    let matches = edda_git::search_tree(
        state.store.as_ref(),
        &identity,
        q.branch.as_deref(),
        &q.query,
    )?;
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
            new_start: hunk.new_start,
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
        hunks,
    }
}

//! `/api/v1/repos/{owner}/{repo}/pulls` — pull-request lifecycle.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use edda_domain::{DiffAnchor, PrState, PullRequest};

use super::{read_repo, Actor};
use crate::services::pull_request::NewPullRequestInput;
use crate::services::{PullRequestService, ServiceError};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/repos/{owner}/{repo}/pulls", get(list).post(create))
        .route("/api/v1/repos/{owner}/{repo}/pulls/{number}", get(get_one))
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/merge",
            post(merge),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/comments",
            post(comment),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/reviews",
            post(review),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/close",
            post(close),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/reopen",
            post(reopen),
        )
}

#[derive(Serialize)]
pub struct PullRequestDto {
    pub number: i64,
    pub title: String,
    pub body: Option<String>,
    pub source_branch: String,
    pub target_branch: String,
    pub state: PrStateDto,
    pub created_at: i64,
}

#[derive(Serialize)]
pub struct PrStateDto {
    pub status: &'static str,
    pub merged_at: Option<i64>,
    pub merge_commit: Option<String>,
    pub closed_at: Option<i64>,
}

impl From<&PullRequest> for PullRequestDto {
    fn from(pr: &PullRequest) -> Self {
        let state = match &pr.state {
            PrState::Open => PrStateDto {
                status: "open",
                merged_at: None,
                merge_commit: None,
                closed_at: None,
            },
            PrState::Draft => PrStateDto {
                status: "draft",
                merged_at: None,
                merge_commit: None,
                closed_at: None,
            },
            PrState::Merged {
                merged_at,
                merge_commit,
                ..
            } => PrStateDto {
                status: "merged",
                merged_at: Some(*merged_at),
                merge_commit: Some(merge_commit.clone()),
                closed_at: None,
            },
            PrState::Closed { closed_at, .. } => PrStateDto {
                status: "closed",
                merged_at: None,
                merge_commit: None,
                closed_at: Some(*closed_at),
            },
        };
        Self {
            number: pr.number,
            title: pr.title.clone(),
            body: pr.body.clone(),
            source_branch: pr.source.branch.clone(),
            target_branch: pr.target.clone(),
            state,
            created_at: pr.created_at,
        }
    }
}

async fn list(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<PullRequestDto>>, ServiceError> {
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    let prs = edda_db::PullRequestRepo::list_for_repository(&state.pool, repository.id).await?;
    Ok(Json(prs.iter().map(PullRequestDto::from).collect()))
}

async fn get_one(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<Json<PullRequestDto>, ServiceError> {
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    let pr =
        edda_db::PullRequestRepo::find_by_repository_and_number(&state.pool, repository.id, number)
            .await?
            .ok_or(ServiceError::NotFound)?;
    Ok(Json(PullRequestDto::from(&pr)))
}

#[derive(Deserialize)]
pub struct CreatePullBody {
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
    pub source_branch: String,
    pub target_branch: String,
    #[serde(default)]
    pub draft: bool,
}

#[derive(Serialize)]
pub struct CreatedPullDto {
    pub number: i64,
}

async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<CreatePullBody>,
) -> Result<Json<CreatedPullDto>, ServiceError> {
    actor.require_user()?;
    let number = PullRequestService::from_state(&state)
        .open(
            actor.context(),
            &owner,
            &repo,
            NewPullRequestInput {
                title: body.title,
                body: body.body,
                source_branch: body.source_branch,
                target_branch: body.target_branch,
                draft: body.draft,
            },
        )
        .await?;
    Ok(Json(CreatedPullDto { number }))
}

#[derive(Serialize)]
pub struct MergedPullDto {
    pub merge_commit: String,
}

async fn merge(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<Json<MergedPullDto>, ServiceError> {
    actor.require_user()?;
    let outcome = PullRequestService::from_state(&state)
        .merge(actor.context(), &owner, &repo, number)
        .await?;
    Ok(Json(MergedPullDto {
        merge_commit: outcome.merge_commit,
    }))
}

#[derive(Deserialize)]
pub struct CommentBody {
    pub body: String,
    #[serde(default)]
    pub anchor: Option<AnchorInput>,
}

#[derive(Deserialize)]
pub struct AnchorInput {
    pub file_path: String,
    pub line_start: u32,
    pub line_end: u32,
    pub commit_sha: String,
}

async fn comment(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Json(body): Json<CommentBody>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    let anchor = body.anchor.map(|a| DiffAnchor {
        file_path: a.file_path,
        line_range: (a.line_start, a.line_end),
        commit_sha: a.commit_sha,
    });
    PullRequestService::from_state(&state)
        .add_comment(actor.context(), &owner, &repo, number, &body.body, anchor)
        .await?;
    Ok(Json(()))
}

#[derive(Deserialize)]
pub struct ReviewBody {
    /// One of `approved` / `changes_requested` / `commented`.
    pub state: String,
    #[serde(default)]
    pub body: Option<String>,
}

async fn review(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Json(body): Json<ReviewBody>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    PullRequestService::from_state(&state)
        .submit_review(
            actor.context(),
            &owner,
            &repo,
            number,
            &body.state,
            body.body,
        )
        .await?;
    Ok(Json(()))
}

async fn close(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    PullRequestService::from_state(&state)
        .close(actor.context(), &owner, &repo, number)
        .await?;
    Ok(Json(()))
}

async fn reopen(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    PullRequestService::from_state(&state)
        .reopen(actor.context(), &owner, &repo, number)
        .await?;
    Ok(Json(()))
}

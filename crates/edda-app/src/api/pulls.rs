//! `/api/v1/repos/{owner}/{repo}/pulls` — pull-request lifecycle. List
//! and detail bodies/comments/reviews are rendered server-side; `can_merge`
//! is resolved server-side too, so the UI never reimplements that decision.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};

use edda_api_types::{
    AddCommentRequest, CreatePullRequest, CreatedNumberDto, MergedPullDto, PrCommentDto,
    PrReviewDto, PrStateDto, PullRequestDetailDto, PullRequestDto, SubmitReviewRequest,
};
use edda_db::DbPool;
use edda_domain::{ActorContext, DiffAnchor, PrState, PullRequest, UserId};

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

fn pr_state_dto(state: &PrState) -> PrStateDto {
    match state {
        PrState::Open => PrStateDto::Open,
        PrState::Draft => PrStateDto::Draft,
        PrState::Merged {
            merged_at,
            merge_commit,
            ..
        } => PrStateDto::Merged {
            merged_at: *merged_at,
            merge_commit: merge_commit.clone(),
        },
        PrState::Closed { closed_at, reason } => PrStateDto::Closed {
            closed_at: *closed_at,
            reason: reason.as_db_str().to_string(),
        },
    }
}

async fn username_for(pool: &DbPool, user_id: UserId) -> Result<String, ServiceError> {
    Ok(edda_db::UserRepo::find_by_id(pool, user_id)
        .await?
        .map(|row| row.user.username)
        .unwrap_or_else(|| "(unknown)".to_string()))
}

async fn pr_dto(pool: &DbPool, pr: &PullRequest) -> Result<PullRequestDto, ServiceError> {
    Ok(PullRequestDto {
        number: pr.number,
        title: pr.title.clone(),
        body_html: pr.body.as_deref().map(edda_render::markdown::render),
        author_username: username_for(pool, pr.author_id).await?,
        source_branch: pr.source.branch.clone(),
        target_branch: pr.target.clone(),
        state: pr_state_dto(&pr.state),
        created_at: pr.created_at,
    })
}

async fn list(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<PullRequestDto>>, ServiceError> {
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    let prs = edda_db::PullRequestRepo::list_for_repository(&state.pool, repository.id).await?;
    let mut out = Vec::with_capacity(prs.len());
    for pr in &prs {
        out.push(pr_dto(&state.pool, pr).await?);
    }
    Ok(Json(out))
}

async fn get_one(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<Json<PullRequestDetailDto>, ServiceError> {
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    let pr =
        edda_db::PullRequestRepo::find_by_repository_and_number(&state.pool, repository.id, number)
            .await?
            .ok_or(ServiceError::NotFound)?;

    let comment_rows = edda_db::PrCommentRepo::list_for_pull_request(&state.pool, pr.id).await?;
    let mut comments = Vec::with_capacity(comment_rows.len());
    for comment in &comment_rows {
        comments.push(PrCommentDto {
            author_username: username_for(&state.pool, comment.author_id).await?,
            body_html: edda_render::markdown::render(&comment.body),
            anchor_file_path: comment.anchor.as_ref().map(|a| a.file_path.clone()),
            anchor_line_start: comment.anchor.as_ref().map(|a| a.line_range.0),
            anchor_line_end: comment.anchor.as_ref().map(|a| a.line_range.1),
            created_at: comment.created_at,
        });
    }

    let review_rows = edda_db::PrReviewRepo::list_for_pull_request(&state.pool, pr.id).await?;
    let mut reviews = Vec::with_capacity(review_rows.len());
    for r in &review_rows {
        reviews.push(PrReviewDto {
            reviewer_username: username_for(&state.pool, r.reviewer_id).await?,
            state: r.state.as_db_str().to_string(),
            body_html: r.body.as_deref().map(edda_render::markdown::render),
            created_at: r.created_at,
        });
    }

    let can_merge = pr.state.is_open()
        && match actor.context() {
            ActorContext::Anonymous => false,
            resolved => state
                .authz
                .check_merge_pull_request(resolved, &repository, &pr.target, &review_rows)
                .await
                .is_ok(),
        };

    Ok(Json(PullRequestDetailDto {
        pull_request: pr_dto(&state.pool, &pr).await?,
        comments,
        reviews,
        can_merge,
    }))
}

async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<CreatePullRequest>,
) -> Result<Json<CreatedNumberDto>, ServiceError> {
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
    Ok(Json(CreatedNumberDto { number }))
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

async fn comment(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Json(body): Json<AddCommentRequest>,
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

async fn review(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Json(body): Json<SubmitReviewRequest>,
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

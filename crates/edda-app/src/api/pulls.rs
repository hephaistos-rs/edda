//! `/api/v1/repos/{owner}/{repo}/pulls` — pull-request lifecycle. List
//! and detail bodies/comments/reviews are rendered server-side; `can_merge`
//! is resolved server-side too, so the UI never reimplements that decision.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};

use edda_api_types::{
    AddCommentRequest, CreatePullRequest, CreatedNumberDto, FileDiffDto, MergeRequest,
    MergedPullDto, PrCommentDto, PrReviewDto, PrStateDto, PullRequestDetailDto, PullRequestDto,
    SubmitReviewRequest, UsernameRequest,
};
use edda_db::DbPool;
use edda_domain::{
    ActorContext, DiffAnchor, MergeStrategy, PrState, PullRequest, RepositoryId, UserId,
};

use super::repo_browse::file_diff_dto;
use super::{git_read, read_repo, Actor};
use crate::services::pull_request::{pull_head_ref, NewPullRequestInput};
use crate::services::{git_identity, PullRequestService, ServiceError};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/repos/{owner}/{repo}/pulls", get(list).post(create))
        .route("/api/v1/repos/{owner}/{repo}/pulls/{number}", get(get_one))
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/diff",
            get(diff),
        )
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
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/ready",
            post(mark_ready),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/draft",
            post(convert_to_draft),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/requested-reviewers",
            post(request_review),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/requested-reviewers/{username}",
            axum::routing::delete(cancel_review_request),
        )
}

fn pr_state_dto(state: &PrState) -> PrStateDto {
    match state {
        PrState::Open => PrStateDto::Open,
        PrState::Draft => PrStateDto::Draft,
        PrState::Merged {
            merged_at,
            merge_commit,
            strategy,
        } => PrStateDto::Merged {
            merged_at: *merged_at,
            merge_commit: merge_commit.clone(),
            strategy: strategy.as_db_str().to_string(),
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

async fn pr_dto(
    pool: &DbPool,
    owner: &str,
    repo: &str,
    target_repository_id: RepositoryId,
    pr: &PullRequest,
) -> Result<PullRequestDto, ServiceError> {
    let is_cross_repo = pr.source.repository_id != target_repository_id;
    let source_owner =
        edda_db::RepositoryRepo::find_by_id_with_owner_username(pool, pr.source.repository_id)
            .await?
            .map(|(_, owner)| owner)
            .unwrap_or_else(|| "(unknown)".to_string());
    let ctx = crate::render::RefContext { owner, repo };
    Ok(PullRequestDto {
        number: pr.number,
        title: pr.title.clone(),
        body_html: pr
            .body
            .as_deref()
            .map(|body| crate::render::body_html(body, ctx)),
        author_username: username_for(pool, pr.author_id).await?,
        source_owner,
        source_branch: pr.source.branch.clone(),
        target_branch: pr.target.clone(),
        is_cross_repo,
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
        out.push(pr_dto(&state.pool, &owner, &repo, repository.id, pr).await?);
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

    let ctx = crate::render::RefContext {
        owner: &owner,
        repo: &repo,
    };
    let comment_rows = edda_db::PrCommentRepo::list_for_pull_request(&state.pool, pr.id).await?;
    let mut comments = Vec::with_capacity(comment_rows.len());
    for comment in &comment_rows {
        comments.push(PrCommentDto {
            author_username: username_for(&state.pool, comment.author_id).await?,
            body_html: crate::render::body_html(&comment.body, ctx),
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
            body_html: r
                .body
                .as_deref()
                .map(|body| crate::render::body_html(body, ctx)),
            created_at: r.created_at,
        });
    }

    let mut requested_reviewers = Vec::new();
    for request in edda_db::ReviewRequestRepo::list_for_pull_request(&state.pool, pr.id).await? {
        requested_reviewers.push(username_for(&state.pool, request.reviewer_id).await?);
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
        pull_request: pr_dto(&state.pool, &owner, &repo, repository.id, &pr).await?,
        comments,
        reviews,
        requested_reviewers,
        can_merge,
    }))
}

/// The changes this pull request proposes: a three-dot `target...head`
/// diff, rendered server-side like every other diff in `/api/v1`. For a
/// fork-sourced PR the head side is the internal pull-head ref the open
/// path imported into this repository, so browsing a cross-repo PR's diff
/// needs no second object store.
async fn diff(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<Json<Vec<FileDiffDto>>, ServiceError> {
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    let pr =
        edda_db::PullRequestRepo::find_by_repository_and_number(&state.pool, repository.id, number)
            .await?
            .ok_or(ServiceError::NotFound)?;

    let identity = git_identity(&owner, &repo);
    let base_ref = format!("refs/heads/{}", pr.target);
    let head_ref = if pr.source.repository_id == repository.id {
        format!("refs/heads/{}", pr.source.branch)
    } else {
        pull_head_ref(pr.id)
    };
    let store = state.store.clone();
    let diffs = git_read("diff_refs", move || {
        edda_git::diff_refs(store.as_ref(), &identity, &base_ref, &head_ref)
    })
    .await?;
    Ok(Json(diffs.into_iter().map(file_diff_dto).collect()))
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
                source_owner: body.source_owner,
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
    body: Option<Json<MergeRequest>>,
) -> Result<Json<MergedPullDto>, ServiceError> {
    actor.require_user()?;
    let requested = body.map(|Json(b)| b).unwrap_or_default();
    let strategy = match requested.strategy.as_deref() {
        None | Some("") => MergeStrategy::Merge,
        Some(s) => MergeStrategy::from_db_str(s)
            .ok_or_else(|| ServiceError::Validation(format!("unknown merge strategy {s:?}")))?,
    };
    let outcome = PullRequestService::from_state(&state)
        .merge(actor.context(), &owner, &repo, number, strategy)
        .await?;
    Ok(Json(MergedPullDto {
        merge_commit: outcome.merge_commit,
        strategy: strategy.as_db_str().to_string(),
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

async fn mark_ready(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    PullRequestService::from_state(&state)
        .mark_ready(actor.context(), &owner, &repo, number)
        .await?;
    Ok(Json(()))
}

async fn convert_to_draft(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    PullRequestService::from_state(&state)
        .convert_to_draft(actor.context(), &owner, &repo, number)
        .await?;
    Ok(Json(()))
}

async fn request_review(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Json(body): Json<UsernameRequest>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    PullRequestService::from_state(&state)
        .request_review(actor.context(), &owner, &repo, number, &body.username)
        .await?;
    Ok(Json(()))
}

async fn cancel_review_request(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number, username)): Path<(String, String, i64, String)>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    PullRequestService::from_state(&state)
        .cancel_review_request(actor.context(), &owner, &repo, number, &username)
        .await?;
    Ok(Json(()))
}

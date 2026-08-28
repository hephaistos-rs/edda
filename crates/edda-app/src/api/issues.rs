//! `/api/v1/repos/{owner}/{repo}` — issues, labels, milestones. Bodies and
//! comments are rendered server-side.

use axum::extract::{Path, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};

use edda_api_types::{
    ApplyLabelRequest, BodyRequest, CreateIssueRequest, CreateLabelRequest, CreateMilestoneRequest,
    CreatedNumberDto, IssueCommentDto, IssueDetailDto, IssueDto, IssueStateDto, LabelDto,
    MilestoneDto, SetMilestoneRequest,
};
use edda_db::DbPool;
use edda_domain::{Issue, IssueState, LabelId, MilestoneId, UserId};

use super::{read_repo, Actor};
use crate::services::issue::NewIssueInput;
use crate::services::{IssueService, ServiceError};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/repos/{owner}/{repo}/issues",
            get(list).post(create),
        )
        .route("/api/v1/repos/{owner}/{repo}/issues/{number}", get(get_one))
        .route(
            "/api/v1/repos/{owner}/{repo}/issues/{number}/comments",
            post(comment),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/issues/{number}/close",
            post(close),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/issues/{number}/reopen",
            post(reopen),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/issues/{number}/labels",
            post(apply_label),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/issues/{number}/labels/{label_id}",
            axum::routing::delete(remove_label),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/issues/{number}/milestone",
            put(set_milestone),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/labels",
            get(list_labels).post(create_label),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/milestones",
            get(list_milestones).post(create_milestone),
        )
}

fn issue_state_dto(state: &IssueState) -> IssueStateDto {
    match state {
        IssueState::Open => IssueStateDto::Open,
        IssueState::Closed { closed_at, reason } => IssueStateDto::Closed {
            closed_at: *closed_at,
            reason: reason.as_db_str().to_string(),
        },
    }
}

fn label_dto(label: edda_domain::Label) -> LabelDto {
    LabelDto {
        id: label.id.to_string(),
        name: label.name,
        color: label.color,
        description: label.description,
    }
}

async fn username_for(pool: &DbPool, user_id: UserId) -> Result<String, ServiceError> {
    Ok(edda_db::UserRepo::find_by_id(pool, user_id)
        .await?
        .map(|row| row.user.username)
        .unwrap_or_else(|| "(unknown)".to_string()))
}

async fn issue_dto(pool: &DbPool, issue: &Issue) -> Result<IssueDto, ServiceError> {
    let milestone_title = match issue.milestone_id {
        Some(milestone_id) => {
            edda_db::MilestoneRepo::list_for_repository(pool, issue.repository_id)
                .await?
                .into_iter()
                .find(|m| m.id == milestone_id)
                .map(|m| m.title)
        }
        None => None,
    };
    Ok(IssueDto {
        number: issue.number,
        title: issue.title.clone(),
        body_html: issue.body.as_deref().map(edda_render::markdown::render),
        author_username: username_for(pool, issue.author_id).await?,
        state: issue_state_dto(&issue.state),
        milestone_title,
        created_at: issue.created_at,
    })
}

async fn list(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<IssueDto>>, ServiceError> {
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    let issues = edda_db::IssueRepo::list_for_repository(&state.pool, repository.id).await?;
    let mut out = Vec::with_capacity(issues.len());
    for issue in &issues {
        out.push(issue_dto(&state.pool, issue).await?);
    }
    Ok(Json(out))
}

async fn get_one(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<Json<IssueDetailDto>, ServiceError> {
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    let issue =
        edda_db::IssueRepo::find_by_repository_and_number(&state.pool, repository.id, number)
            .await?
            .ok_or(ServiceError::NotFound)?;

    let comment_rows = edda_db::IssueCommentRepo::list_for_issue(&state.pool, issue.id).await?;
    let mut comments = Vec::with_capacity(comment_rows.len());
    for comment in &comment_rows {
        comments.push(IssueCommentDto {
            author_username: username_for(&state.pool, comment.author_id).await?,
            body_html: edda_render::markdown::render(&comment.body),
            created_at: comment.created_at,
        });
    }

    let labels = edda_db::LabelRepo::list_for_issue(&state.pool, issue.id)
        .await?
        .into_iter()
        .map(label_dto)
        .collect();

    Ok(Json(IssueDetailDto {
        issue: issue_dto(&state.pool, &issue).await?,
        comments,
        labels,
    }))
}

async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<CreateIssueRequest>,
) -> Result<Json<CreatedNumberDto>, ServiceError> {
    actor.require_user()?;
    let number = IssueService::from_state(&state)
        .open(
            actor.context(),
            &owner,
            &repo,
            NewIssueInput {
                title: body.title,
                body: body.body,
            },
        )
        .await?;
    Ok(Json(CreatedNumberDto { number }))
}

async fn comment(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Json(body): Json<BodyRequest>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    IssueService::from_state(&state)
        .add_comment(actor.context(), &owner, &repo, number, &body.body)
        .await?;
    Ok(Json(()))
}

async fn close(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    IssueService::from_state(&state)
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
    IssueService::from_state(&state)
        .reopen(actor.context(), &owner, &repo, number)
        .await?;
    Ok(Json(()))
}

async fn list_labels(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<LabelDto>>, ServiceError> {
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    let labels = edda_db::LabelRepo::list_for_repository(&state.pool, repository.id).await?;
    Ok(Json(labels.into_iter().map(label_dto).collect()))
}

async fn create_label(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<CreateLabelRequest>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    IssueService::from_state(&state)
        .create_label(
            actor.context(),
            &owner,
            &repo,
            &body.name,
            &body.color,
            body.description.as_deref(),
        )
        .await?;
    Ok(Json(()))
}

async fn apply_label(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Json(body): Json<ApplyLabelRequest>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    let label_id: LabelId = body.label_id.parse().map_err(|_| ServiceError::NotFound)?;
    IssueService::from_state(&state)
        .apply_label(actor.context(), &owner, &repo, number, label_id)
        .await?;
    Ok(Json(()))
}

async fn remove_label(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number, label_id)): Path<(String, String, i64, String)>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    let label_id: LabelId = label_id.parse().map_err(|_| ServiceError::NotFound)?;
    IssueService::from_state(&state)
        .remove_label(actor.context(), &owner, &repo, number, label_id)
        .await?;
    Ok(Json(()))
}

async fn list_milestones(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<MilestoneDto>>, ServiceError> {
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    let milestones =
        edda_db::MilestoneRepo::list_for_repository(&state.pool, repository.id).await?;
    Ok(Json(
        milestones
            .into_iter()
            .map(|m| MilestoneDto {
                id: m.id.to_string(),
                title: m.title,
                description: m.description,
                due_on: m.due_on,
                state: m.state.as_db_str().to_string(),
            })
            .collect(),
    ))
}

async fn create_milestone(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<CreateMilestoneRequest>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    IssueService::from_state(&state)
        .create_milestone(
            actor.context(),
            &owner,
            &repo,
            &body.title,
            body.description.as_deref(),
            body.due_on,
        )
        .await?;
    Ok(Json(()))
}

async fn set_milestone(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Json(body): Json<SetMilestoneRequest>,
) -> Result<Json<()>, ServiceError> {
    actor.require_user()?;
    let milestone_id = body
        .milestone_id
        .map(|id| id.parse::<MilestoneId>())
        .transpose()
        .map_err(|_| ServiceError::NotFound)?;
    IssueService::from_state(&state)
        .set_milestone(actor.context(), &owner, &repo, number, milestone_id)
        .await?;
    Ok(Json(()))
}

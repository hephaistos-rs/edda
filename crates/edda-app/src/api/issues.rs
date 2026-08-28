//! `/api/v1/repos/{owner}/{repo}` — issues, labels, milestones.

use axum::extract::{Path, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use edda_domain::{Issue, IssueState, LabelId, MilestoneId};

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
        .route("/api/v1/repos/{owner}/{repo}/labels", post(create_label))
        .route(
            "/api/v1/repos/{owner}/{repo}/milestones",
            post(create_milestone),
        )
}

#[derive(Serialize)]
pub struct IssueDto {
    pub number: i64,
    pub title: String,
    pub body: Option<String>,
    pub state: IssueStateDto,
    pub created_at: i64,
}

#[derive(Serialize)]
pub struct IssueStateDto {
    pub status: &'static str,
    pub closed_at: Option<i64>,
}

impl From<&Issue> for IssueDto {
    fn from(issue: &Issue) -> Self {
        let state = match &issue.state {
            IssueState::Open => IssueStateDto {
                status: "open",
                closed_at: None,
            },
            IssueState::Closed { closed_at, .. } => IssueStateDto {
                status: "closed",
                closed_at: Some(*closed_at),
            },
        };
        Self {
            number: issue.number,
            title: issue.title.clone(),
            body: issue.body.clone(),
            state,
            created_at: issue.created_at,
        }
    }
}

async fn list(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<IssueDto>>, ServiceError> {
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    let issues = edda_db::IssueRepo::list_for_repository(&state.pool, repository.id).await?;
    Ok(Json(issues.iter().map(IssueDto::from).collect()))
}

async fn get_one(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<Json<IssueDto>, ServiceError> {
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    let issue =
        edda_db::IssueRepo::find_by_repository_and_number(&state.pool, repository.id, number)
            .await?
            .ok_or(ServiceError::NotFound)?;
    Ok(Json(IssueDto::from(&issue)))
}

#[derive(Deserialize)]
pub struct CreateIssueBody {
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Serialize)]
pub struct CreatedIssueDto {
    pub number: i64,
}

async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<CreateIssueBody>,
) -> Result<Json<CreatedIssueDto>, ServiceError> {
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
    Ok(Json(CreatedIssueDto { number }))
}

#[derive(Deserialize)]
pub struct CommentBody {
    pub body: String,
}

async fn comment(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Json(body): Json<CommentBody>,
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

#[derive(Deserialize)]
pub struct CreateLabelBody {
    pub name: String,
    pub color: String,
    #[serde(default)]
    pub description: Option<String>,
}

async fn create_label(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<CreateLabelBody>,
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

#[derive(Deserialize)]
pub struct ApplyLabelBody {
    pub label_id: String,
}

async fn apply_label(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Json(body): Json<ApplyLabelBody>,
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

#[derive(Deserialize)]
pub struct CreateMilestoneBody {
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub due_on: Option<i64>,
}

async fn create_milestone(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<CreateMilestoneBody>,
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

#[derive(Deserialize)]
pub struct SetMilestoneBody {
    #[serde(default)]
    pub milestone_id: Option<String>,
}

async fn set_milestone(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Json(body): Json<SetMilestoneBody>,
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

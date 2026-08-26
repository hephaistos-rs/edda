//! Issue server functions — same shape/reasoning as `pr_server`.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IssueDto {
    pub number: i64,
    pub title: String,
    pub body_html: Option<String>,
    pub author_username: String,
    pub state: IssueStateDto,
    pub milestone_title: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IssueStateDto {
    Open,
    Closed { closed_at: i64, reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IssueCommentDto {
    pub author_username: String,
    pub body_html: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LabelDto {
    pub id: String,
    pub name: String,
    pub color: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MilestoneDto {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub due_on: Option<i64>,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IssueDetailDto {
    pub issue: IssueDto,
    pub comments: Vec<IssueCommentDto>,
    pub labels: Vec<LabelDto>,
}

#[cfg(feature = "server")]
async fn username_for(
    pool: &edda_db::DbPool,
    user_id: edda_domain::UserId,
) -> Result<String, ServerFnError> {
    edda_db::UserRepo::find_by_id(pool, user_id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?
        .map(|row| row.user.username)
        .ok_or_else(|| ServerFnError::new("that account no longer exists"))
}

#[cfg(feature = "server")]
fn issue_state_dto(state: &edda_domain::IssueState) -> IssueStateDto {
    match state {
        edda_domain::IssueState::Open => IssueStateDto::Open,
        edda_domain::IssueState::Closed { closed_at, reason } => IssueStateDto::Closed {
            closed_at: *closed_at,
            reason: reason.as_db_str().to_string(),
        },
    }
}

#[cfg(feature = "server")]
async fn issue_dto(
    pool: &edda_db::DbPool,
    issue: &edda_domain::Issue,
) -> Result<IssueDto, ServerFnError> {
    let milestone_title = match issue.milestone_id {
        Some(milestone_id) => {
            edda_db::MilestoneRepo::list_for_repository(pool, issue.repository_id)
                .await
                .map_err(|err| ServerFnError::new(err.to_string()))?
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

#[cfg(feature = "server")]
fn label_dto(label: edda_domain::Label) -> LabelDto {
    LabelDto {
        id: label.id.to_string(),
        name: label.name,
        color: label.color,
        description: label.description,
    }
}

#[post("/api/repos/:owner/:name/issues", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "issue.create", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn create_issue(
    owner: String,
    name: String,
    title: String,
    body: Option<String>,
) -> Result<i64, ServerFnError> {
    let shared = crate::shared::get();
    let (repository, actor) = crate::server::require_write_access(&auth, &owner, &name).await?;
    let user_id = actor.user_id().expect("User actor");

    if title.trim().is_empty() {
        return Err(ServerFnError::new("an issue needs a title"));
    }
    let number = edda_db::IssueRepo::insert(
        &shared.pool,
        edda_domain::IssueId::new(),
        repository.id,
        title.trim(),
        body.as_deref().filter(|b| !b.trim().is_empty()),
        user_id,
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(number)
}

#[get("/api/repos/:owner/:name/issues", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "issue.list", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn list_issues(owner: String, name: String) -> Result<Vec<IssueDto>, ServerFnError> {
    let shared = crate::shared::get();
    let repository = crate::server::require_read_access(&auth, &owner, &name).await?;
    let issues = edda_db::IssueRepo::list_for_repository(&shared.pool, repository.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    let mut out = Vec::with_capacity(issues.len());
    for issue in &issues {
        out.push(issue_dto(&shared.pool, issue).await?);
    }
    Ok(out)
}

#[get("/api/repos/:owner/:name/issues/:number", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "issue.get", skip_all, err, fields(repo.owner = %owner, repo.name = %name, issue.number = number))]
pub async fn get_issue(
    owner: String,
    name: String,
    number: i64,
) -> Result<IssueDetailDto, ServerFnError> {
    let shared = crate::shared::get();
    let repository = crate::server::require_read_access(&auth, &owner, &name).await?;
    let issue =
        edda_db::IssueRepo::find_by_repository_and_number(&shared.pool, repository.id, number)
            .await
            .map_err(|err| ServerFnError::new(err.to_string()))?
            .ok_or_else(|| ServerFnError::new("no such issue"))?;

    let comment_rows = edda_db::IssueCommentRepo::list_for_issue(&shared.pool, issue.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    let mut comments = Vec::with_capacity(comment_rows.len());
    for comment in &comment_rows {
        comments.push(IssueCommentDto {
            author_username: username_for(&shared.pool, comment.author_id).await?,
            body_html: edda_render::markdown::render(&comment.body),
            created_at: comment.created_at,
        });
    }

    let labels = edda_db::LabelRepo::list_for_issue(&shared.pool, issue.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?
        .into_iter()
        .map(label_dto)
        .collect();

    Ok(IssueDetailDto {
        issue: issue_dto(&shared.pool, &issue).await?,
        comments,
        labels,
    })
}

#[post("/api/repos/:owner/:name/issues/:number/comments", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "issue.comment", skip_all, err, fields(repo.owner = %owner, repo.name = %name, issue.number = number))]
pub async fn add_issue_comment(
    owner: String,
    name: String,
    number: i64,
    body: String,
) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();
    let (repository, actor) = crate::server::require_write_access(&auth, &owner, &name).await?;
    let user_id = actor.user_id().expect("User actor");
    if body.trim().is_empty() {
        return Err(ServerFnError::new("a comment can't be empty"));
    }

    let issue =
        edda_db::IssueRepo::find_by_repository_and_number(&shared.pool, repository.id, number)
            .await
            .map_err(|err| ServerFnError::new(err.to_string()))?
            .ok_or_else(|| ServerFnError::new("no such issue"))?;
    edda_db::IssueCommentRepo::insert(
        &shared.pool,
        edda_domain::IssueCommentId::new(),
        issue.id,
        user_id,
        body.trim(),
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?;

    crate::mentions::dispatch_mentions(
        &shared.pool,
        body.trim(),
        user_id,
        edda_domain::MentionSource::IssueComment { issue_id: issue.id },
        &format!("You were mentioned on issue #{number}"),
        &format!(
            "You were mentioned in a comment on issue #{number} (\"{}\") in {owner}/{name}.",
            issue.title
        ),
    )
    .await;

    Ok(())
}

#[post("/api/repos/:owner/:name/issues/:number/close", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "issue.close", skip_all, err, fields(repo.owner = %owner, repo.name = %name, issue.number = number))]
pub async fn close_issue(owner: String, name: String, number: i64) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();
    let (repository, _actor) = crate::server::require_write_access(&auth, &owner, &name).await?;
    let issue =
        edda_db::IssueRepo::find_by_repository_and_number(&shared.pool, repository.id, number)
            .await
            .map_err(|err| ServerFnError::new(err.to_string()))?
            .ok_or_else(|| ServerFnError::new("no such issue"))?;
    if !issue.state.is_open() {
        return Err(ServerFnError::new("this issue is already closed"));
    }
    let closed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs() as i64;
    edda_db::IssueRepo::update_state(
        &shared.pool,
        issue.id,
        &edda_domain::IssueState::Closed {
            closed_at,
            reason: edda_domain::CloseReason::Completed,
        },
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

#[post("/api/repos/:owner/:name/issues/:number/reopen", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "issue.reopen", skip_all, err, fields(repo.owner = %owner, repo.name = %name, issue.number = number))]
pub async fn reopen_issue(owner: String, name: String, number: i64) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();
    let (repository, _actor) = crate::server::require_write_access(&auth, &owner, &name).await?;
    let issue =
        edda_db::IssueRepo::find_by_repository_and_number(&shared.pool, repository.id, number)
            .await
            .map_err(|err| ServerFnError::new(err.to_string()))?
            .ok_or_else(|| ServerFnError::new("no such issue"))?;
    edda_db::IssueRepo::update_state(&shared.pool, issue.id, &edda_domain::IssueState::Open)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

#[get("/api/repos/:owner/:name/labels", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "label.list", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn list_labels(owner: String, name: String) -> Result<Vec<LabelDto>, ServerFnError> {
    let shared = crate::shared::get();
    let repository = crate::server::require_read_access(&auth, &owner, &name).await?;
    let labels = edda_db::LabelRepo::list_for_repository(&shared.pool, repository.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(labels.into_iter().map(label_dto).collect())
}

#[post("/api/repos/:owner/:name/labels", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "label.create", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn create_label(
    owner: String,
    name: String,
    label_name: String,
    color: String,
    description: Option<String>,
) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();
    let (repository, _actor) = crate::server::require_write_access(&auth, &owner, &name).await?;
    if label_name.trim().is_empty() {
        return Err(ServerFnError::new("a label needs a name"));
    }
    edda_db::LabelRepo::insert(
        &shared.pool,
        edda_domain::LabelId::new(),
        repository.id,
        label_name.trim(),
        &color,
        description.as_deref().filter(|d| !d.trim().is_empty()),
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

#[post("/api/repos/:owner/:name/issues/:number/labels", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "issue.apply_label", skip_all, err, fields(repo.owner = %owner, repo.name = %name, issue.number = number))]
pub async fn apply_label_to_issue(
    owner: String,
    name: String,
    number: i64,
    label_id: String,
) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();
    let (repository, _actor) = crate::server::require_write_access(&auth, &owner, &name).await?;
    let issue =
        edda_db::IssueRepo::find_by_repository_and_number(&shared.pool, repository.id, number)
            .await
            .map_err(|err| ServerFnError::new(err.to_string()))?
            .ok_or_else(|| ServerFnError::new("no such issue"))?;
    let label_id: edda_domain::LabelId = label_id
        .parse()
        .map_err(|_| ServerFnError::new("no such label"))?;
    let label = edda_db::LabelRepo::list_for_repository(&shared.pool, repository.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?
        .into_iter()
        .find(|l| l.id == label_id)
        .ok_or_else(|| ServerFnError::new("no such label"))?;

    edda_db::LabelRepo::apply_to_issue(&shared.pool, issue.id, &label)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

#[post("/api/repos/:owner/:name/issues/:number/labels/:label_id/remove", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "issue.remove_label", skip_all, err, fields(repo.owner = %owner, repo.name = %name, issue.number = number))]
pub async fn remove_label_from_issue(
    owner: String,
    name: String,
    number: i64,
    label_id: String,
) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();
    let (repository, _actor) = crate::server::require_write_access(&auth, &owner, &name).await?;
    let issue =
        edda_db::IssueRepo::find_by_repository_and_number(&shared.pool, repository.id, number)
            .await
            .map_err(|err| ServerFnError::new(err.to_string()))?
            .ok_or_else(|| ServerFnError::new("no such issue"))?;
    let label_id: edda_domain::LabelId = label_id
        .parse()
        .map_err(|_| ServerFnError::new("no such label"))?;
    edda_db::LabelRepo::remove_from_issue(&shared.pool, issue.id, label_id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

#[get("/api/repos/:owner/:name/milestones", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "milestone.list", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn list_milestones(
    owner: String,
    name: String,
) -> Result<Vec<MilestoneDto>, ServerFnError> {
    let shared = crate::shared::get();
    let repository = crate::server::require_read_access(&auth, &owner, &name).await?;
    let milestones = edda_db::MilestoneRepo::list_for_repository(&shared.pool, repository.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(milestones
        .into_iter()
        .map(|m| MilestoneDto {
            id: m.id.to_string(),
            title: m.title,
            description: m.description,
            due_on: m.due_on,
            state: m.state.as_db_str().to_string(),
        })
        .collect())
}

#[post("/api/repos/:owner/:name/milestones", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "milestone.create", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn create_milestone(
    owner: String,
    name: String,
    title: String,
    description: Option<String>,
    due_on: Option<i64>,
) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();
    let (repository, _actor) = crate::server::require_write_access(&auth, &owner, &name).await?;
    if title.trim().is_empty() {
        return Err(ServerFnError::new("a milestone needs a title"));
    }
    edda_db::MilestoneRepo::insert(
        &shared.pool,
        edda_domain::MilestoneId::new(),
        repository.id,
        title.trim(),
        description.as_deref().filter(|d| !d.trim().is_empty()),
        due_on,
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

#[post("/api/repos/:owner/:name/issues/:number/milestone", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "issue.set_milestone", skip_all, err, fields(repo.owner = %owner, repo.name = %name, issue.number = number))]
pub async fn set_issue_milestone(
    owner: String,
    name: String,
    number: i64,
    milestone_id: Option<String>,
) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();
    let (repository, _actor) = crate::server::require_write_access(&auth, &owner, &name).await?;
    let issue =
        edda_db::IssueRepo::find_by_repository_and_number(&shared.pool, repository.id, number)
            .await
            .map_err(|err| ServerFnError::new(err.to_string()))?
            .ok_or_else(|| ServerFnError::new("no such issue"))?;
    let milestone_id = milestone_id
        .map(|id| id.parse::<edda_domain::MilestoneId>())
        .transpose()
        .map_err(|_| ServerFnError::new("no such milestone"))?;
    edda_db::IssueRepo::set_milestone(&shared.pool, issue.id, milestone_id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

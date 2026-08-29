//! `/api/v1/repos/{owner}/{repo}/statuses/{sha}` — the seam an external CI
//! system reports build/test results through. Edda never *runs* CI (see
//! `plan.local.md` §15); a rule's `required_status_checks` list is
//! consulted by the merge path against whatever an external runner has
//! posted here.
//!
//! `POST` needs **write** access (and, for a token, the `repo:write`
//! scope) — a CI system authenticates with a scoped PAT or deploy-key-
//! backed token the same as any other writer. `GET` needs read.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};

use edda_api_types::{CommitStatusDto, CreateCommitStatusRequest};
use edda_domain::{CommitStatus, CommitStatusId, CommitStatusState, TokenScope};

use super::{read_repo, Actor};
use crate::services::ServiceError;
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/api/v1/repos/{owner}/{repo}/statuses/{sha}",
        get(list).post(create),
    )
}

fn status_dto(status: CommitStatus) -> CommitStatusDto {
    CommitStatusDto {
        context: status.context,
        state: status.state.as_db_str().to_string(),
        target_url: status.target_url,
        description: status.description,
        created_at: status.created_at,
        updated_at: status.updated_at,
    }
}

async fn list(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, sha)): Path<(String, String, String)>,
) -> Result<Json<Vec<CommitStatusDto>>, ServiceError> {
    actor.require_scope(TokenScope::RepoRead)?;
    let repository = read_repo(&state, actor.context(), &owner, &repo).await?;
    let statuses =
        edda_db::CommitStatusRepo::list_for_commit(&state.pool, repository.id, &sha).await?;
    Ok(Json(statuses.into_iter().map(status_dto).collect()))
}

async fn create(
    State(state): State<AppState>,
    actor: Actor,
    Path((owner, repo, sha)): Path<(String, String, String)>,
    Json(body): Json<CreateCommitStatusRequest>,
) -> Result<Json<CommitStatusDto>, ServiceError> {
    actor.require_user()?;
    actor.require_scope(TokenScope::RepoWrite)?;
    let repository = state.authz.repository_by_name(&owner, &repo).await?;
    state
        .authz
        .check_write(actor.context(), &repository)
        .await?;

    let context = body.context.trim();
    if context.is_empty() {
        return Err(ServiceError::Validation(
            "a status needs a non-empty context".to_string(),
        ));
    }
    let status_state = CommitStatusState::from_db_str(body.state.trim()).ok_or_else(|| {
        ServiceError::Validation(
            "state must be one of: pending, success, failure, error".to_string(),
        )
    })?;

    let id = edda_db::CommitStatusRepo::upsert(
        &state.pool,
        CommitStatusId::new(),
        repository.id,
        &sha,
        context,
        status_state,
        body.target_url.as_deref().filter(|u| !u.trim().is_empty()),
        body.description.as_deref().filter(|d| !d.trim().is_empty()),
    )
    .await?;

    let stored = edda_db::CommitStatusRepo::list_for_commit(&state.pool, repository.id, &sha)
        .await?
        .into_iter()
        .find(|s| s.id == id)
        .ok_or(ServiceError::Db(edda_db::DbError::RowNotFound))?;
    Ok(Json(status_dto(stored)))
}

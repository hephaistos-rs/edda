//! `/api/v1/*` — the versioned, documented, external-tooling-facing REST
//! surface. Deliberately separate from both the Dioxus-internal
//! server-function RPC path (`edda-web`, unversioned, never a public
//! contract) and the git-HTTP bridge's Basic-auth-or-token resolution
//! (`git_http::resolve_actor`): only `Authorization: Bearer <PAT>` is
//! accepted here, never a session cookie or HTTP Basic — which is why
//! CSRF isn't a concern on this surface at all.
//!
//! Versioning policy: `/api/v1/` is additive-only (new optional fields,
//! new endpoints); a breaking change needs `/api/v2/`, not a change here.
//! Resource shape follows the URL conventions the git-hosting-tooling
//! ecosystem already expects (`/repos/{owner}/{repo}/...`) without
//! claiming Forgejo/GitHub wire-compatibility — DTOs are defined fresh
//! from `edda-domain`'s entities.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use edda_domain::{ActorContext, AuthzError, Issue, IssueState, PrState, PullRequest, Repository};

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/repos/{owner}/{repo}", get(get_repo))
        .route("/api/v1/repos/{owner}/{repo}/pulls", get(list_pulls))
        .route("/api/v1/repos/{owner}/{repo}/pulls/{number}", get(get_pull))
        .route("/api/v1/repos/{owner}/{repo}/issues", get(list_issues))
        .route(
            "/api/v1/repos/{owner}/{repo}/issues/{number}",
            get(get_issue),
        )
}

/// Resolved solely from a bearer token — never a session cookie (see this
/// module's own doc comment for why that's a deliberate omission, not an
/// oversight).
async fn resolve_actor(state: &AppState, headers: &HeaderMap) -> ActorContext {
    let Some(token) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return ActorContext::Anonymous;
    };
    match edda_auth::tokens::authenticate(&state.pool, token).await {
        Some((user, scope)) => ActorContext::Token {
            user_id: user.id,
            scope,
        },
        None => ActorContext::Anonymous,
    }
}

#[derive(Serialize)]
struct ApiErrorBody {
    error: ApiErrorDetail,
}

#[derive(Serialize)]
struct ApiErrorDetail {
    code: &'static str,
    message: String,
}

fn api_error(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiErrorBody {
            error: ApiErrorDetail {
                code,
                message: message.into(),
            },
        }),
    )
        .into_response()
}

/// `AuthzError::NotFound` -> `404`, `AuthzError::Forbidden` -> `403` — the
/// same information-hiding mapping used everywhere else in this workspace,
/// re-checked here rather than assumed to carry over automatically.
fn authz_error_response(err: AuthzError) -> Response {
    match err {
        AuthzError::NotFound => api_error(StatusCode::NOT_FOUND, "not_found", "not found"),
        AuthzError::Forbidden => api_error(StatusCode::FORBIDDEN, "forbidden", "forbidden"),
    }
}

async fn read_checked_repository(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    repo: &str,
) -> Result<Repository, Response> {
    let actor = resolve_actor(state, headers).await;
    let repository = state
        .authz
        .repository_by_name(owner, repo)
        .await
        .map_err(authz_error_response)?;
    state
        .authz
        .check_read(&actor, &repository)
        .await
        .map_err(authz_error_response)?;
    Ok(repository)
}

#[derive(Serialize)]
struct RepositoryDto {
    id: String,
    owner: String,
    name: String,
    description: Option<String>,
    private: bool,
}

fn repository_dto(owner: &str, repository: &Repository) -> RepositoryDto {
    RepositoryDto {
        id: repository.id.to_string(),
        owner: owner.to_string(),
        name: repository.name.clone(),
        description: repository.description.clone(),
        private: repository.is_private(),
    }
}

async fn get_repo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> Response {
    match read_checked_repository(&state, &headers, &owner, &repo).await {
        Ok(repository) => Json(repository_dto(&owner, &repository)).into_response(),
        Err(response) => response,
    }
}

#[derive(Serialize)]
struct PrStateDto {
    status: &'static str,
    merged_at: Option<i64>,
    merge_commit: Option<String>,
    closed_at: Option<i64>,
}

fn pr_state_dto(state: &PrState) -> PrStateDto {
    match state {
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
    }
}

#[derive(Serialize)]
struct PullRequestDto {
    number: i64,
    title: String,
    body: Option<String>,
    source_branch: String,
    target_branch: String,
    state: PrStateDto,
    created_at: i64,
}

fn pull_request_dto(pr: &PullRequest) -> PullRequestDto {
    PullRequestDto {
        number: pr.number,
        title: pr.title.clone(),
        body: pr.body.clone(),
        source_branch: pr.source.branch.clone(),
        target_branch: pr.target.clone(),
        state: pr_state_dto(&pr.state),
        created_at: pr.created_at,
    }
}

async fn list_pulls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> Response {
    let repository = match read_checked_repository(&state, &headers, &owner, &repo).await {
        Ok(repository) => repository,
        Err(response) => return response,
    };
    match edda_db::PullRequestRepo::list_for_repository(&state.pool, repository.id).await {
        Ok(prs) => Json(prs.iter().map(pull_request_dto).collect::<Vec<_>>()).into_response(),
        Err(err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            err.to_string(),
        ),
    }
}

async fn get_pull(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Response {
    let repository = match read_checked_repository(&state, &headers, &owner, &repo).await {
        Ok(repository) => repository,
        Err(response) => return response,
    };
    match edda_db::PullRequestRepo::find_by_repository_and_number(
        &state.pool,
        repository.id,
        number,
    )
    .await
    {
        Ok(Some(pr)) => Json(pull_request_dto(&pr)).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "not_found", "no such pull request"),
        Err(err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            err.to_string(),
        ),
    }
}

#[derive(Serialize)]
struct IssueStateDto {
    status: &'static str,
    closed_at: Option<i64>,
}

fn issue_state_dto(state: &IssueState) -> IssueStateDto {
    match state {
        IssueState::Open => IssueStateDto {
            status: "open",
            closed_at: None,
        },
        IssueState::Closed { closed_at, .. } => IssueStateDto {
            status: "closed",
            closed_at: Some(*closed_at),
        },
    }
}

#[derive(Serialize)]
struct IssueDto {
    number: i64,
    title: String,
    body: Option<String>,
    state: IssueStateDto,
    created_at: i64,
}

fn issue_dto(issue: &Issue) -> IssueDto {
    IssueDto {
        number: issue.number,
        title: issue.title.clone(),
        body: issue.body.clone(),
        state: issue_state_dto(&issue.state),
        created_at: issue.created_at,
    }
}

async fn list_issues(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> Response {
    let repository = match read_checked_repository(&state, &headers, &owner, &repo).await {
        Ok(repository) => repository,
        Err(response) => return response,
    };
    match edda_db::IssueRepo::list_for_repository(&state.pool, repository.id).await {
        Ok(issues) => Json(issues.iter().map(issue_dto).collect::<Vec<_>>()).into_response(),
        Err(err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            err.to_string(),
        ),
    }
}

async fn get_issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Response {
    let repository = match read_checked_repository(&state, &headers, &owner, &repo).await {
        Ok(repository) => repository,
        Err(response) => return response,
    };
    match edda_db::IssueRepo::find_by_repository_and_number(&state.pool, repository.id, number)
        .await
    {
        Ok(Some(issue)) => Json(issue_dto(&issue)).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "not_found", "no such issue"),
        Err(err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            err.to_string(),
        ),
    }
}

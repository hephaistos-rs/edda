//! Pull-request server functions — same `#[get]`/`#[post]` Dioxus
//! server-function shape `server.rs` already uses for repo browsing (see
//! that file's `require_read_access`/`require_write_access`, reused
//! here), not raw `edda-http` axum routes: pull requests are page
//! *content* (markdown bodies rendered at read time, comment/review
//! threads) in the same sense repo browsing/diffs already are, not
//! account/token/collaborator management (which is where `edda-http`'s
//! raw routes are reserved for — see that crate's own doc comment).

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PullRequestDto {
    pub number: i64,
    pub title: String,
    pub body_html: Option<String>,
    pub author_username: String,
    pub source_branch: String,
    pub target_branch: String,
    pub state: PrStateDto,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PrStateDto {
    Open,
    Draft,
    Merged {
        merged_at: i64,
        merge_commit: String,
    },
    Closed {
        closed_at: i64,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PrCommentDto {
    pub author_username: String,
    pub body_html: String,
    pub anchor_file_path: Option<String>,
    pub anchor_line_start: Option<u32>,
    pub anchor_line_end: Option<u32>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PrReviewDto {
    pub reviewer_username: String,
    pub state: String,
    pub body_html: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PullRequestDetailDto {
    pub pull_request: PullRequestDto,
    pub comments: Vec<PrCommentDto>,
    pub reviews: Vec<PrReviewDto>,
    /// Whether the caller may currently merge this PR — resolved
    /// server-side (branch protection, review count, write access) so
    /// the UI never has to reimplement that decision.
    pub can_merge: bool,
}

#[cfg(feature = "server")]
fn pr_state_dto(state: &edda_domain::PrState) -> PrStateDto {
    match state {
        edda_domain::PrState::Open => PrStateDto::Open,
        edda_domain::PrState::Draft => PrStateDto::Draft,
        edda_domain::PrState::Merged {
            merged_at,
            merge_commit,
            ..
        } => PrStateDto::Merged {
            merged_at: *merged_at,
            merge_commit: merge_commit.clone(),
        },
        edda_domain::PrState::Closed { closed_at, reason } => PrStateDto::Closed {
            closed_at: *closed_at,
            reason: reason.as_db_str().to_string(),
        },
    }
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
async fn pr_dto(
    pool: &edda_db::DbPool,
    pr: &edda_domain::PullRequest,
) -> Result<PullRequestDto, ServerFnError> {
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

// Each parameter here is a distinct client-visible field of this
// server-function's request body (the `#[post]` macro maps them
// 1:1, plus the macro-injected `auth` extractor clippy also counts) —
// bundling them into a struct wouldn't reduce the real API surface,
// only hide it behind one more indirection.
#[allow(clippy::too_many_arguments)]
#[post("/api/repos/:owner/:name/pulls", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "pull_request.create", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn create_pull_request(
    owner: String,
    name: String,
    title: String,
    body: Option<String>,
    source_branch: String,
    target_branch: String,
    draft: bool,
) -> Result<i64, ServerFnError> {
    let shared = crate::shared::get();
    let (repository, actor) = crate::server::require_write_access(&auth, &owner, &name).await?;
    let user_id = actor
        .user_id()
        .expect("require_write_access only returns ActorContext::User");

    if title.trim().is_empty() {
        return Err(ServerFnError::new("a pull request needs a title"));
    }

    let number = edda_db::PullRequestRepo::insert(
        &shared.pool,
        edda_domain::PullRequestId::new(),
        repository.id,
        edda_db::NewPullRequest {
            title: title.trim(),
            body: body.as_deref().filter(|b| !b.trim().is_empty()),
            author_id: user_id,
            source: &edda_domain::PrRef {
                repository_id: repository.id,
                branch: source_branch,
            },
            target: &target_branch,
            draft,
        },
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(number)
}

#[get("/api/repos/:owner/:name/pulls", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "pull_request.list", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn list_pull_requests(
    owner: String,
    name: String,
) -> Result<Vec<PullRequestDto>, ServerFnError> {
    let shared = crate::shared::get();
    let repository = crate::server::require_read_access(&auth, &owner, &name).await?;
    let prs = edda_db::PullRequestRepo::list_for_repository(&shared.pool, repository.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    let mut out = Vec::with_capacity(prs.len());
    for pr in &prs {
        out.push(pr_dto(&shared.pool, pr).await?);
    }
    Ok(out)
}

#[get("/api/repos/:owner/:name/pulls/:number", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "pull_request.get", skip_all, err, fields(repo.owner = %owner, repo.name = %name, pr.number = number))]
pub async fn get_pull_request(
    owner: String,
    name: String,
    number: i64,
) -> Result<PullRequestDetailDto, ServerFnError> {
    let shared = crate::shared::get();
    let repository = crate::server::require_read_access(&auth, &owner, &name).await?;
    let pr = edda_db::PullRequestRepo::find_by_repository_and_number(
        &shared.pool,
        repository.id,
        number,
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?
    .ok_or_else(|| ServerFnError::new("no such pull request"))?;

    let comment_rows = edda_db::PrCommentRepo::list_for_pull_request(&shared.pool, pr.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    let mut comments = Vec::with_capacity(comment_rows.len());
    for comment in &comment_rows {
        comments.push(PrCommentDto {
            author_username: username_for(&shared.pool, comment.author_id).await?,
            body_html: edda_render::markdown::render(&comment.body),
            anchor_file_path: comment.anchor.as_ref().map(|a| a.file_path.clone()),
            anchor_line_start: comment.anchor.as_ref().map(|a| a.line_range.0),
            anchor_line_end: comment.anchor.as_ref().map(|a| a.line_range.1),
            created_at: comment.created_at,
        });
    }

    let review_rows = edda_db::PrReviewRepo::list_for_pull_request(&shared.pool, pr.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    let mut reviews = Vec::with_capacity(review_rows.len());
    for review in &review_rows {
        reviews.push(PrReviewDto {
            reviewer_username: username_for(&shared.pool, review.reviewer_id).await?,
            state: review.state.as_db_str().to_string(),
            body_html: review.body.as_deref().map(edda_render::markdown::render),
            created_at: review.created_at,
        });
    }

    let can_merge = pr.state.is_open()
        && match &auth.user {
            Some(session_user) => {
                let actor = edda_domain::ActorContext::User(session_user.user.id);
                shared
                    .authz
                    .check_merge_pull_request(&actor, &repository, &pr.target, &review_rows)
                    .await
                    .is_ok()
            }
            None => false,
        };

    Ok(PullRequestDetailDto {
        pull_request: pr_dto(&shared.pool, &pr).await?,
        comments,
        reviews,
        can_merge,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CommentAnchorInput {
    pub file_path: String,
    pub line_start: u32,
    pub line_end: u32,
    pub commit_sha: String,
}

#[post("/api/repos/:owner/:name/pulls/:number/comments", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "pull_request.comment", skip_all, err, fields(repo.owner = %owner, repo.name = %name, pr.number = number))]
pub async fn add_pull_request_comment(
    owner: String,
    name: String,
    number: i64,
    body: String,
    anchor: Option<CommentAnchorInput>,
) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();
    let Some(session_user) = &auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let actor = edda_domain::ActorContext::User(session_user.user.id);

    let anchor = anchor.map(|a| edda_domain::DiffAnchor {
        file_path: a.file_path,
        line_range: (a.line_start, a.line_end),
        commit_sha: a.commit_sha,
    });

    // Authorization (write on the repo), the comment insert, and one
    // `UserMentioned` outbox event per `@mention` are the service's job —
    // all in one transaction so no mention notification is lost or fired
    // for a comment that rolled back.
    edda_http::services::PullRequestService::new(
        shared.pool.clone(),
        shared.store.clone(),
        shared.locks.clone(),
        shared.authz.clone(),
    )
    .add_comment(&actor, &owner, &name, number, &body, anchor)
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?;

    Ok(())
}

#[post("/api/repos/:owner/:name/pulls/:number/reviews", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "pull_request.review", skip_all, err, fields(repo.owner = %owner, repo.name = %name, pr.number = number))]
pub async fn submit_pull_request_review(
    owner: String,
    name: String,
    number: i64,
    state: String,
    body: Option<String>,
) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();
    let (repository, actor) = crate::server::require_write_access(&auth, &owner, &name).await?;
    let user_id = actor.user_id().expect("User actor");

    let review_state = edda_domain::ReviewState::from_db_str(&state)
        .ok_or_else(|| ServerFnError::new("unrecognized review state"))?;
    let pr = edda_db::PullRequestRepo::find_by_repository_and_number(
        &shared.pool,
        repository.id,
        number,
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?
    .ok_or_else(|| ServerFnError::new("no such pull request"))?;

    edda_db::PrReviewRepo::insert(
        &shared.pool,
        edda_domain::PrReviewId::new(),
        pr.id,
        user_id,
        review_state,
        body.as_deref().filter(|b| !b.trim().is_empty()),
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

/// Thin transport in front of `PullRequestService::merge` — resolve the
/// session actor and hand off. The service owns the authorize → hold the
/// repository lock → git merge → (PR state + `PullRequestMerged` outbox
/// event, one transaction) sequence and its documented failure windows.
#[post("/api/repos/:owner/:name/pulls/:number/merge", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "pull_request.merge", skip_all, err, fields(repo.owner = %owner, repo.name = %name, pr.number = number))]
pub async fn merge_pull_request(
    owner: String,
    name: String,
    number: i64,
) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();
    let Some(session_user) = &auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let user = &session_user.user;
    let actor = edda_domain::ActorContext::User(user.id);

    edda_http::services::PullRequestService::new(
        shared.pool.clone(),
        shared.store.clone(),
        shared.locks.clone(),
        shared.authz.clone(),
    )
    .merge(&actor, &owner, &name, number, &user.username, &user.email)
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?;

    Ok(())
}

#[cfg(feature = "server")]
fn edda_domain_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs() as i64
}

#[post("/api/repos/:owner/:name/pulls/:number/close", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "pull_request.close", skip_all, err, fields(repo.owner = %owner, repo.name = %name, pr.number = number))]
pub async fn close_pull_request(
    owner: String,
    name: String,
    number: i64,
) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();
    let (repository, _actor) = crate::server::require_write_access(&auth, &owner, &name).await?;
    let pr = edda_db::PullRequestRepo::find_by_repository_and_number(
        &shared.pool,
        repository.id,
        number,
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?
    .ok_or_else(|| ServerFnError::new("no such pull request"))?;
    if !pr.state.is_open() {
        return Err(ServerFnError::new(
            "this pull request is already merged or closed",
        ));
    }

    let closed_state = edda_domain::PrState::Closed {
        closed_at: edda_domain_now(),
        reason: edda_domain::CloseReason::NotPlanned,
    };
    edda_db::PullRequestRepo::update_state(&shared.pool, pr.id, &closed_state)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

// Constructed only in this module's `#[get]` handler body, which the
// server-fn macro strips from the client build — where the type then
// survives solely in the endpoint's return signature.
#[cfg_attr(not(feature = "server"), allow(dead_code))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BranchProtectionDto {
    pub id: String,
    pub branch: String,
    pub required_approvals: i64,
}

#[get("/api/repos/:owner/:name/branch-protection", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "branch_protection.list", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn list_branch_protection_rules(
    owner: String,
    name: String,
) -> Result<Vec<BranchProtectionDto>, ServerFnError> {
    let shared = crate::shared::get();
    let repository = crate::server::require_read_access(&auth, &owner, &name).await?;
    let rules = edda_db::BranchProtectionRepo::list_for_repository(&shared.pool, repository.id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(rules
        .into_iter()
        .map(|rule| BranchProtectionDto {
            id: rule.id.to_string(),
            branch: rule.branch,
            required_approvals: rule.required_approvals,
        })
        .collect())
}

/// Owner/Admin only (`check_administer`, not `check_write`) — a branch-
/// protection rule constrains what *anyone* including other collaborators
/// may do, the same tier of decision as danger-zone repository settings.
#[post("/api/repos/:owner/:name/branch-protection", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "branch_protection.create", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn create_branch_protection_rule(
    owner: String,
    name: String,
    branch: String,
    required_approvals: i64,
) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();
    let repository = shared
        .authz
        .repository_by_name(&owner, &name)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    let Some(session_user) = &auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let actor = edda_domain::ActorContext::User(session_user.user.id);
    shared
        .authz
        .check_administer(&actor, &repository)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;

    if branch.trim().is_empty() || required_approvals < 0 {
        return Err(ServerFnError::new(
            "a valid branch name and a non-negative required-approvals count are needed",
        ));
    }
    edda_db::BranchProtectionRepo::insert(
        &shared.pool,
        edda_domain::BranchProtectionRuleId::new(),
        repository.id,
        branch.trim(),
        required_approvals,
    )
    .await
    .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

#[post("/api/repos/:owner/:name/branch-protection/:id/delete", auth: axum_login::AuthSession<edda_auth::Backend>)]
#[tracing::instrument(name = "branch_protection.delete", skip_all, err, fields(repo.owner = %owner, repo.name = %name))]
pub async fn delete_branch_protection_rule(
    owner: String,
    name: String,
    id: String,
) -> Result<(), ServerFnError> {
    let shared = crate::shared::get();
    let repository = shared
        .authz
        .repository_by_name(&owner, &name)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    let Some(session_user) = &auth.user else {
        return Err(ServerFnError::new("login required"));
    };
    let actor = edda_domain::ActorContext::User(session_user.user.id);
    shared
        .authz
        .check_administer(&actor, &repository)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;

    let rule_id = id
        .parse()
        .map_err(|_| ServerFnError::new("no such branch protection rule"))?;
    edda_db::BranchProtectionRepo::delete(&shared.pool, repository.id, rule_id)
        .await
        .map_err(|err| ServerFnError::new(err.to_string()))?;
    Ok(())
}

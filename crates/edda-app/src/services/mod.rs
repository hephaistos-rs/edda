//! The application-service layer (plan.local.md §4.10).
//!
//! A service owns the *transaction boundary* and the *Git↔SQL ordering*
//! for a multi-step operation, and — new in Phase 3 — writes the
//! operation's `edda_domain::DomainEvent` to the `events` outbox
//! (`edda_db::EventRepo::append`) **in the same transaction** as the state
//! change. `edda_jobs::spawn_dispatcher` drains that outbox to background
//! jobs, so a webhook or notification can no longer be lost to a crash in
//! the window between "state committed" and "world told".
//!
//! Services take plain values and return [`ServiceError`] — no `axum`, no
//! request types (§4.10: this is why the module can later be lifted into
//! its own `edda-application` crate). `crate::api` wraps each in a thin
//! `/api/v1` axum handler; the Dioxus server functions call the same
//! services until the UI is cut over to the HTTP surface.

pub mod audit;
pub mod branch_protection;
pub mod collaborator;
pub mod deploy_key;
pub mod issue;
pub mod mentions;
pub mod notification;
pub mod organization;
pub mod pull_request;
pub mod release;
pub mod repository;
pub mod team;
pub mod webhook;

pub use branch_protection::BranchProtectionService;
pub use collaborator::CollaboratorService;
pub use deploy_key::DeployKeyService;
pub use issue::IssueService;
pub use notification::NotificationService;
pub use organization::OrganizationService;
pub use pull_request::PullRequestService;
pub use release::ReleaseService;
pub use repository::RepositoryService;
pub use team::TeamService;
pub use webhook::WebhookService;

/// The uniform failure type every service method returns. `crate::api`'s
/// `impl IntoResponse for ServiceError` maps it to `{ "error": { code,
/// message } }` + a status via [`ServiceError::http_status`] /
/// [`ServiceError::code`] — the one mapping point (§14.2). Kept
/// framework-free here so `services` can become its own crate.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("not found")]
    NotFound,
    /// The actor is known but lacks the permission this operation needs.
    #[error("forbidden")]
    Forbidden,
    /// The request is well-formed but conflicts with current state (a PR
    /// that is already merged, a name already taken).
    #[error("{0}")]
    Conflict(String),
    /// The request shape is invalid. Phase 4 replaces the `String` with a
    /// per-field `Vec<FieldError>` fed by the extractor's validation.
    #[error("{0}")]
    Validation(String),
    /// No usable actor identity at all (as opposed to [`Self::Forbidden`],
    /// where the actor is authenticated but unauthorized).
    #[error("authentication required")]
    Unauthorized,
    #[error(transparent)]
    Git(#[from] edda_git::GitError),
    #[error(transparent)]
    Db(#[from] edda_db::DbError),
}

impl From<edda_domain::AuthzError> for ServiceError {
    fn from(err: edda_domain::AuthzError) -> Self {
        match err {
            // `NotFound` masks `Forbidden` for private repositories — the
            // authz layer already collapsed "doesn't exist" and "you may
            // not know it exists" into one variant; keep that here.
            edda_domain::AuthzError::NotFound => ServiceError::NotFound,
            edda_domain::AuthzError::Forbidden => ServiceError::Forbidden,
        }
    }
}

impl From<edda_db::repo_number_repo::NextNumberError> for ServiceError {
    fn from(err: edda_db::repo_number_repo::NextNumberError) -> Self {
        match err {
            edda_db::repo_number_repo::NextNumberError::Contended(_) => ServiceError::Conflict(
                "too many concurrent writes to this repository — try again".to_string(),
            ),
            edda_db::repo_number_repo::NextNumberError::Db(err) => ServiceError::Db(err),
        }
    }
}

impl From<edda_db::pull_request_repo::InsertPullRequestError> for ServiceError {
    fn from(err: edda_db::pull_request_repo::InsertPullRequestError) -> Self {
        match err {
            edda_db::pull_request_repo::InsertPullRequestError::NextNumber(err) => err.into(),
            edda_db::pull_request_repo::InsertPullRequestError::Db(err) => ServiceError::Db(err),
        }
    }
}

impl From<edda_db::repository_repo::InsertRepositoryError> for ServiceError {
    fn from(err: edda_db::repository_repo::InsertRepositoryError) -> Self {
        match err {
            edda_db::repository_repo::InsertRepositoryError::AlreadyExists(_) => {
                ServiceError::Conflict("a repository with that name already exists".to_string())
            }
            edda_db::repository_repo::InsertRepositoryError::Db(err) => ServiceError::Db(err),
        }
    }
}

impl From<edda_db::issue_repo::InsertIssueError> for ServiceError {
    fn from(err: edda_db::issue_repo::InsertIssueError) -> Self {
        match err {
            edda_db::issue_repo::InsertIssueError::NextNumber(err) => err.into(),
            edda_db::issue_repo::InsertIssueError::Db(err) => ServiceError::Db(err),
        }
    }
}

impl From<edda_db::label_repo::InsertLabelError> for ServiceError {
    fn from(err: edda_db::label_repo::InsertLabelError) -> Self {
        match err {
            edda_db::label_repo::InsertLabelError::AlreadyExists(_) => {
                ServiceError::Conflict("a label with that name already exists".to_string())
            }
            edda_db::label_repo::InsertLabelError::Db(err) => ServiceError::Db(err),
        }
    }
}

impl From<edda_db::branch_protection_repo::InsertBranchProtectionError> for ServiceError {
    fn from(err: edda_db::branch_protection_repo::InsertBranchProtectionError) -> Self {
        match err {
            edda_db::branch_protection_repo::InsertBranchProtectionError::AlreadyExists(_) => {
                ServiceError::Conflict("that branch is already protected".to_string())
            }
            edda_db::branch_protection_repo::InsertBranchProtectionError::Db(err) => {
                ServiceError::Db(err)
            }
        }
    }
}

impl From<edda_db::release_repo::InsertReleaseError> for ServiceError {
    fn from(err: edda_db::release_repo::InsertReleaseError) -> Self {
        match err {
            edda_db::release_repo::InsertReleaseError::AlreadyExists => {
                ServiceError::Conflict("a release for that tag already exists".to_string())
            }
            edda_db::release_repo::InsertReleaseError::Db(err) => ServiceError::Db(err),
        }
    }
}

impl From<edda_db::team_repo::InsertTeamError> for ServiceError {
    fn from(err: edda_db::team_repo::InsertTeamError) -> Self {
        match err {
            edda_db::team_repo::InsertTeamError::AlreadyExists(_) => {
                ServiceError::Conflict("a team with that name already exists".to_string())
            }
            edda_db::team_repo::InsertTeamError::Db(err) => ServiceError::Db(err),
        }
    }
}

impl From<edda_auth::organization::CreateOrganizationError> for ServiceError {
    fn from(err: edda_auth::organization::CreateOrganizationError) -> Self {
        use edda_auth::organization::CreateOrganizationError as E;
        match err {
            E::NameTaken => ServiceError::Conflict("that name is already taken".to_string()),
            E::InvalidName => ServiceError::Validation(err.to_string()),
            E::Db(err) => ServiceError::Db(err),
        }
    }
}

impl ServiceError {
    /// The HTTP status a handler should return for this error. The single
    /// mapping point (§14.2) — every transport in front of the service
    /// layer routes through here rather than re-deciding.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            ServiceError::NotFound => 404,
            ServiceError::Forbidden => 403,
            ServiceError::Conflict(_) => 409,
            ServiceError::Validation(_) => 422,
            ServiceError::Unauthorized => 401,
            // A git-level conflict (merge conflicts) is the caller's
            // problem to resolve; everything else git/db is ours.
            ServiceError::Git(edda_git::GitError::Conflict(_)) => 409,
            ServiceError::Git(_) | ServiceError::Db(_) => 500,
        }
    }

    /// A stable, machine-readable slug for the `{ "error": { "code" } }`
    /// wire field — clients switch on this, never on the human `message`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            ServiceError::NotFound => "not_found",
            ServiceError::Forbidden => "forbidden",
            ServiceError::Conflict(_) => "conflict",
            ServiceError::Validation(_) => "validation",
            ServiceError::Unauthorized => "unauthorized",
            ServiceError::Git(edda_git::GitError::Conflict(_)) => "conflict",
            ServiceError::Git(_) | ServiceError::Db(_) => "internal_error",
        }
    }

    /// The client-facing `message`. Client-error variants carry their own
    /// text; `Db`/`Git` internals never reach the wire (a bare "internal
    /// error" instead — the detail is logged, not returned).
    #[must_use]
    pub fn client_message(&self) -> String {
        match self {
            ServiceError::NotFound => "not found".to_string(),
            ServiceError::Forbidden => "forbidden".to_string(),
            ServiceError::Conflict(msg) | ServiceError::Validation(msg) => msg.clone(),
            ServiceError::Unauthorized => "authentication required".to_string(),
            ServiceError::Git(err @ edda_git::GitError::Conflict(_)) => err.to_string(),
            ServiceError::Git(_) | ServiceError::Db(_) => "internal error".to_string(),
        }
    }
}

/// Current unix time in seconds — services stamp `merged_at` / event
/// `occurred_at` with one reading taken in application code, the same
/// convention `edda-db` follows internally.
pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs() as i64
}

/// The `{owner}/{repo}` string every `edda-git` entry point and clone URL
/// uses as a repository's on-disk identity.
pub(crate) fn git_identity(owner: &str, name: &str) -> String {
    format!("{owner}/{name}")
}

/// Resolve `actor` to the acting user (username + email), or
/// `Unauthorized` when the request carried no user identity at all.
pub(crate) async fn acting_user(
    pool: &edda_db::DbPool,
    actor: &edda_domain::ActorContext,
) -> Result<edda_domain::User, ServiceError> {
    let user_id = actor.user_id().ok_or(ServiceError::Unauthorized)?;
    Ok(edda_db::UserRepo::find_by_id(pool, user_id)
        .await?
        .ok_or(ServiceError::Unauthorized)?
        .user)
}

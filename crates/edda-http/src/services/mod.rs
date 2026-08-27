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
//! its own `edda-application` crate). Phase 3 ports only the two paths that
//! already emitted domain events — pull-request merge and the
//! comment/`@mention` fan-out; the remaining services land in Phase 4 as
//! each handler is moved off its Dioxus server function (§7.1).

pub mod issue;
pub mod mentions;
pub mod pull_request;

pub use issue::IssueService;
pub use pull_request::PullRequestService;

/// The uniform failure type every service method returns. A handler maps
/// it to a transport response via [`ServiceError::http_status`] (plan
/// §14.2 makes that an `impl IntoResponse` once the handlers are axum, in
/// Phase 4 — kept as a plain `u16` here so this module stays
/// framework-free).
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

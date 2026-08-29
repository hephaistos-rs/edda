//! `PullRequestService` — open / comment / review / merge / close /
//! reopen. The merge and comment paths write a `DomainEvent` to the outbox
//! in the same transaction as their state change (see [`super`]).

use std::sync::Arc;

use edda_auth::AuthorizationService;
use edda_db::{
    BranchProtectionRepo, CommitStatusRepo, DbPool, EventRepo, IssueRepo, NewPullRequest,
    PrCommentRepo, PrReviewRepo, PullRequestRepo, RepositoryRepo, ReviewRequestRepo,
};
use edda_domain::{
    parse_closing_references, parse_head_ref, ActorContext, CloseReason, DiffAnchor, DomainEvent,
    EventId, IssueState, MentionSource, MergeStrategy, PrCommentId, PrRef, PrReviewId, PrState,
    PullRequest, PullRequestId, Repository, ReviewState,
};
use edda_git::store::RepoStore;
use edda_git::{LockRegistry, MergeOutcome};

use super::{git_identity, mentions, now_unix, ServiceError};
use crate::AppState;

/// What a caller supplies to open a pull request.
pub struct NewPullRequestInput {
    pub title: String,
    pub body: Option<String>,
    /// The account owning the fork the source branch lives in, for a
    /// cross-repository (fork-sourced) pull request. `None` — or equal to
    /// the target owner — is a same-repository PR. When `None`,
    /// `source_branch` is additionally checked for the `owner:branch`
    /// form.
    pub source_owner: Option<String>,
    pub source_branch: String,
    pub target_branch: String,
    pub draft: bool,
}

/// The Edda-internal ref, in the *target* repository, that a
/// cross-repository pull request's imported source tip lives at. Keyed by
/// the PR's id (stable, known before the number is allocated) so opening
/// the PR needs no ordering dance between the DB insert and the git
/// import. Also read by `api::pulls`'s diff endpoint.
pub(crate) fn pull_head_ref(id: PullRequestId) -> String {
    format!("refs/edda/pull-heads/{id}")
}

/// Constructed per request from `AppState`'s shared handles. Cloning is
/// cheap — `DbPool` and the `Arc`s are handle clones.
#[derive(Clone)]
pub struct PullRequestService {
    pool: DbPool,
    store: Arc<dyn RepoStore>,
    locks: Arc<LockRegistry>,
    authz: AuthorizationService,
}

impl PullRequestService {
    pub fn new(
        pool: DbPool,
        store: Arc<dyn RepoStore>,
        locks: Arc<LockRegistry>,
        authz: AuthorizationService,
    ) -> Self {
        Self {
            pool,
            store,
            locks,
            authz,
        }
    }

    #[must_use]
    pub fn from_state(state: &AppState) -> Self {
        Self::new(
            state.pool.clone(),
            state.store.clone(),
            state.locks.clone(),
            state.authz.clone(),
        )
    }

    /// Open a pull request. For a same-repository PR: write access on the
    /// repository. For a cross-repository (fork-sourced) PR: write on the
    /// fork + read on the target (`can_open_cross_repo_pull_request`), and
    /// the fork's source tip is copied into the target's object store now
    /// (interim — Phase 14 replaces the copy with object-store alternates)
    /// so the later merge/diff never has to know a second store exists.
    /// Returns the new PR's number.
    pub async fn open(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        input: NewPullRequestInput,
    ) -> Result<i64, ServiceError> {
        let author_id = actor.user_id().ok_or(ServiceError::Unauthorized)?;
        if input.title.trim().is_empty() {
            return Err(ServiceError::Validation(
                "a pull request needs a title".to_string(),
            ));
        }

        let target = self.authz.repository_by_name(owner, name).await?;

        // Resolve the source side: an explicit `source_owner`, else an
        // `owner:branch` prefix on `source_branch`, else this same repo.
        let (source_owner, source_branch): (Option<&str>, &str) = match &input.source_owner {
            Some(o) => (Some(o.as_str()), input.source_branch.as_str()),
            None => parse_head_ref(&input.source_branch),
        };
        let source_branch = source_branch.to_string();

        let source = match source_owner {
            Some(o) if !o.eq_ignore_ascii_case(owner) => {
                self.authz.repository_by_name(o, name).await?
            }
            _ => target.clone(),
        };

        let pr_id = PullRequestId::new();

        if source.id == target.id {
            self.authz.check_write(actor, &target).await?;
        } else {
            self.authz
                .check_open_cross_repo_pull_request(actor, &source, &target)
                .await?;

            let source_identity = self.repo_identity(&source).await?;
            let target_identity = git_identity(owner, name);
            let head_ref = pull_head_ref(pr_id);

            // Git side first (an orphan pull-head ref is cheap to gc; a PR
            // row whose head won't resolve is not), under the target
            // repo's lock so nothing else writes it mid-import.
            let lock = self.locks.lock_for(&target_identity);
            let _guard = lock.lock().await;
            edda_git::import_branch_tip(
                self.store.as_ref(),
                &source_identity,
                &source_branch,
                &target_identity,
                &head_ref,
            )?;
        }

        let mut tx = self.pool.begin().await?;
        let number = PullRequestRepo::insert(
            &mut tx,
            pr_id,
            target.id,
            NewPullRequest {
                title: input.title.trim(),
                body: input.body.as_deref().filter(|b| !b.trim().is_empty()),
                author_id,
                source: &PrRef {
                    repository_id: source.id,
                    branch: source_branch,
                },
                target: &input.target_branch,
                draft: input.draft,
            },
        )
        .await?;
        EventRepo::append(
            &mut tx,
            EventId::new(),
            &DomainEvent::PullRequestOpened {
                pull_request_id: pr_id,
                repository_id: target.id,
                opened_by_id: author_id,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(number)
    }

    /// The `{owner}/{name}` on-disk identity of an arbitrary repository row
    /// (its owner may be a user or an organization) — used to turn a
    /// cross-repo PR's stored `source.repository_id` back into something
    /// `edda-git` can open.
    async fn repo_identity(&self, repository: &Repository) -> Result<String, ServiceError> {
        let (_, owner_username) =
            RepositoryRepo::find_by_id_with_owner_username(&self.pool, repository.id)
                .await?
                .ok_or(ServiceError::NotFound)?;
        Ok(git_identity(&owner_username, &repository.name))
    }

    /// Submit a review (approve / request changes / comment). Write access
    /// — a reviewer needn't be able to merge, only to be a collaborator.
    pub async fn submit_review(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
        state: &str,
        body: Option<String>,
    ) -> Result<(), ServiceError> {
        let (repository, reviewer_id) = self.write_checked(actor, owner, name).await?;
        let review_state = ReviewState::from_db_str(state)
            .ok_or_else(|| ServiceError::Validation("unrecognized review state".to_string()))?;
        let pr = self.load_pr(repository.id, number).await?;

        let mut tx = self.pool.begin().await?;
        PrReviewRepo::insert(
            &mut tx,
            PrReviewId::new(),
            pr.id,
            reviewer_id,
            review_state,
            body.as_deref().filter(|b| !b.trim().is_empty()),
        )
        .await?;
        EventRepo::append(
            &mut tx,
            EventId::new(),
            &DomainEvent::PullRequestReviewSubmitted {
                pull_request_id: pr.id,
                repository_id: repository.id,
                reviewer_id,
                state: review_state,
            },
        )
        .await?;
        tx.commit().await?;
        // A submitted review satisfies any outstanding request for this
        // reviewer.
        ReviewRequestRepo::delete(&self.pool, pr.id, reviewer_id).await?;
        Ok(())
    }

    /// Request a review from a user (manually — a CODEOWNERS match takes
    /// the same `review_requests` path). Write access. Idempotent; emits
    /// `ReviewRequested` in the same transaction as the row insert.
    pub async fn request_review(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
        reviewer_username: &str,
    ) -> Result<(), ServiceError> {
        let (repository, actor_id) = self.write_checked(actor, owner, name).await?;
        let pr = self.load_pr(repository.id, number).await?;
        let reviewer = edda_db::UserRepo::find_by_username(&self.pool, reviewer_username)
            .await?
            .ok_or(ServiceError::NotFound)?;

        let mut tx = self.pool.begin().await?;
        let newly_requested = ReviewRequestRepo::insert_if_new(
            &mut tx,
            edda_domain::ReviewRequestId::new(),
            pr.id,
            reviewer.id,
        )
        .await?;
        if newly_requested {
            EventRepo::append(
                &mut tx,
                EventId::new(),
                &DomainEvent::ReviewRequested {
                    pull_request_id: pr.id,
                    repository_id: repository.id,
                    reviewer_id: reviewer.id,
                    requested_by_id: actor_id,
                },
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Withdraw a pending review request. Write access.
    pub async fn cancel_review_request(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
        reviewer_username: &str,
    ) -> Result<(), ServiceError> {
        let (repository, _) = self.write_checked(actor, owner, name).await?;
        let pr = self.load_pr(repository.id, number).await?;
        let reviewer = edda_db::UserRepo::find_by_username(&self.pool, reviewer_username)
            .await?
            .ok_or(ServiceError::NotFound)?;
        ReviewRequestRepo::delete(&self.pool, pr.id, reviewer.id).await?;
        Ok(())
    }

    /// Take a draft pull request out of draft (`Draft` -> `Open`).
    /// Repository writer or the PR's own author.
    pub async fn mark_ready(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
    ) -> Result<(), ServiceError> {
        let (_, pr, _) = self
            .author_or_write_checked(actor, owner, name, number)
            .await?;
        if !matches!(pr.state, PrState::Draft) {
            return Err(ServiceError::Conflict(
                "this pull request is not a draft".to_string(),
            ));
        }
        PullRequestRepo::update_state(&self.pool, pr.id, &PrState::Open).await?;
        Ok(())
    }

    /// Put an open pull request back into draft (`Open` -> `Draft`).
    /// Repository writer or the PR's own author.
    pub async fn convert_to_draft(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
    ) -> Result<(), ServiceError> {
        let (_, pr, _) = self
            .author_or_write_checked(actor, owner, name, number)
            .await?;
        if !matches!(pr.state, PrState::Open) {
            return Err(ServiceError::Conflict(
                "only an open pull request can be converted to a draft".to_string(),
            ));
        }
        PullRequestRepo::update_state(&self.pool, pr.id, &PrState::Draft).await?;
        Ok(())
    }

    /// Close an open pull request (without merging). Repository writer or
    /// the PR's own author.
    pub async fn close(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
    ) -> Result<(), ServiceError> {
        let (repository, pr, actor_id) = self
            .author_or_write_checked(actor, owner, name, number)
            .await?;
        if !pr.state.is_open() {
            return Err(ServiceError::Conflict(
                "this pull request is already merged or closed".to_string(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        PullRequestRepo::update_state(
            &mut tx,
            pr.id,
            &PrState::Closed {
                closed_at: now_unix(),
                reason: CloseReason::NotPlanned,
            },
        )
        .await?;
        EventRepo::append(
            &mut tx,
            EventId::new(),
            &DomainEvent::PullRequestClosed {
                pull_request_id: pr.id,
                repository_id: repository.id,
                closed_by_id: actor_id,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Reopen a closed (not merged) pull request. Write access.
    pub async fn reopen(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
    ) -> Result<(), ServiceError> {
        let (repository, actor_id) = self.write_checked(actor, owner, name).await?;
        let pr = self.load_pr(repository.id, number).await?;
        if !matches!(pr.state, PrState::Closed { .. }) {
            return Err(ServiceError::Conflict(
                "only a closed pull request can be reopened".to_string(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        PullRequestRepo::update_state(&mut tx, pr.id, &PrState::Open).await?;
        EventRepo::append(
            &mut tx,
            EventId::new(),
            &DomainEvent::PullRequestReopened {
                pull_request_id: pr.id,
                repository_id: repository.id,
                reopened_by_id: actor_id,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn load_pr(
        &self,
        repository_id: edda_domain::RepositoryId,
        number: i64,
    ) -> Result<PullRequest, ServiceError> {
        PullRequestRepo::find_by_repository_and_number(&self.pool, repository_id, number)
            .await?
            .ok_or(ServiceError::NotFound)
    }

    async fn write_checked(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
    ) -> Result<(Repository, edda_domain::UserId), ServiceError> {
        let user_id = actor.user_id().ok_or(ServiceError::Unauthorized)?;
        let repository = self.authz.repository_by_name(owner, name).await?;
        self.authz.check_write(actor, &repository).await?;
        Ok((repository, user_id))
    }

    /// Passes for a repository writer *or* the pull request's own author —
    /// so a fork contributor can comment on, toggle the draft state of, or
    /// close their own cross-repository pull request even without write
    /// access to the target repository (the Phase 5 restriction that
    /// blocked this).
    async fn author_or_write_checked(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
    ) -> Result<(Repository, PullRequest, edda_domain::UserId), ServiceError> {
        let user_id = actor.user_id().ok_or(ServiceError::Unauthorized)?;
        let repository = self.authz.repository_by_name(owner, name).await?;
        let pr = self.load_pr(repository.id, number).await?;
        if pr.author_id != user_id {
            self.authz.check_write(actor, &repository).await?;
        }
        Ok((repository, pr, user_id))
    }

    /// Authorize, then hold the repository's lock across the *whole* git
    /// merge + SQL update so no other write interleaves. The PR state
    /// change and the `PullRequestMerged` outbox event commit together:
    /// the webhook can't fire for a merge that rolled back, and can't be
    /// lost if the process dies right after the merge.
    ///
    /// If the git merge fails (conflicts) nothing SQL was touched. If the
    /// transaction fails after a successful git merge, the merge commit
    /// exists but the PR still reads open — the same narrow, accepted
    /// window the pre-service code documented (git and SQL share no
    /// coordinator), and strictly better than the reverse.
    pub async fn merge(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
        strategy: MergeStrategy,
    ) -> Result<MergeOutcome, ServiceError> {
        let committer = super::acting_user(&self.pool, actor).await?;
        let repository = self.authz.repository_by_name(owner, name).await?;
        let pr = PullRequestRepo::find_by_repository_and_number(&self.pool, repository.id, number)
            .await?
            .ok_or(ServiceError::NotFound)?;
        if !pr.state.is_open() {
            return Err(ServiceError::Conflict(
                "this pull request is already merged or closed".to_string(),
            ));
        }

        let reviews = PrReviewRepo::list_for_pull_request(&self.pool, pr.id).await?;
        self.authz
            .check_merge_pull_request(actor, &repository, &pr.target, &reviews)
            .await?;

        // Required-status-check gate: when the target branch's protection
        // rule lists check contexts, the PR's head commit (the tip of its
        // source branch, in its source repository) must have a green
        // status for each. External CI reports these via the status API.
        if let Some(rule) =
            BranchProtectionRepo::find_matching(&self.pool, repository.id, &pr.target).await?
        {
            if !rule.required_status_checks.is_empty() {
                let head_identity = if pr.source.repository_id == repository.id {
                    git_identity(owner, name)
                } else {
                    let (source_repo, source_owner) =
                        RepositoryRepo::find_by_id_with_owner_username(
                            &self.pool,
                            pr.source.repository_id,
                        )
                        .await?
                        .ok_or(ServiceError::NotFound)?;
                    git_identity(&source_owner, &source_repo.name)
                };
                let head_sha = edda_git::resolve_branch_commit(
                    self.store.as_ref(),
                    &head_identity,
                    &pr.source.branch,
                )?;
                // Statuses are reported against the *target* repository
                // (where the PR and its CI configuration live) keyed by the
                // head commit sha.
                let statuses =
                    CommitStatusRepo::list_for_commit(&self.pool, repository.id, &head_sha).await?;
                if !edda_domain::required_checks_satisfied(&rule.required_status_checks, &statuses)
                {
                    return Err(ServiceError::Conflict(
                        "the required status checks are not all passing on the head commit"
                            .to_string(),
                    ));
                }
            }
        }

        let identity = git_identity(owner, name);
        let lock = self.locks.lock_for(&identity);
        let _guard = lock.lock().await;

        // Resolve the incoming side to a ref in the *target* repo. Same-repo
        // PRs merge straight from `refs/heads/{source}`; a fork-sourced PR
        // re-imports the fork's current tip (it may have moved since the PR
        // opened) into the internal pull-head ref and merges from that — the
        // fork is never written to.
        let (source_ref, source_label) = if pr.source.repository_id == repository.id {
            (
                format!("refs/heads/{}", pr.source.branch),
                pr.source.branch.clone(),
            )
        } else {
            let (source_repo, source_owner) =
                RepositoryRepo::find_by_id_with_owner_username(&self.pool, pr.source.repository_id)
                    .await?
                    .ok_or(ServiceError::NotFound)?;
            let source_identity = git_identity(&source_owner, &source_repo.name);
            let head_ref = pull_head_ref(pr.id);
            edda_git::import_branch_tip(
                self.store.as_ref(),
                &source_identity,
                &pr.source.branch,
                &identity,
                &head_ref,
            )?;
            (head_ref, format!("{source_owner}:{}", pr.source.branch))
        };

        // Squash merges want the PR's own title/body as the commit message;
        // the merge-commit strategy wants the conventional summary line;
        // rebase and fast-forward reuse the incoming commits' messages.
        let message = match strategy {
            MergeStrategy::Squash => {
                match pr.body.as_deref().map(str::trim).filter(|b| !b.is_empty()) {
                    Some(body) => format!("{} (#{number})\n\n{body}", pr.title),
                    None => format!("{} (#{number})", pr.title),
                }
            }
            _ => format!("Merge pull request #{number} from {source_label}"),
        };

        let outcome = edda_git::merge_pull_request(
            self.store.as_ref(),
            &identity,
            &source_ref,
            &source_label,
            &pr.target,
            strategy,
            &committer.username,
            &committer.email,
            &message,
        )?;

        let merged_state = PrState::Merged {
            merged_at: now_unix(),
            merge_commit: outcome.merge_commit.clone(),
            strategy,
        };

        // Same-repository issues named by a closing keyword in the PR's
        // title or body (`closes #12`) are closed in the same transaction
        // as the merge — `owner/repo#n` closing refs are left for a later
        // phase (they need a write check on the other repo).
        let closing_numbers: Vec<i64> = {
            let text = format!("{}\n{}", pr.title, pr.body.as_deref().unwrap_or(""));
            parse_closing_references(&text)
                .into_iter()
                .filter(|cref| cref.repository.is_none())
                .map(|cref| cref.number)
                .collect()
        };
        let actor_user_id = actor.user_id();

        let mut tx = self.pool.begin().await?;
        PullRequestRepo::update_state(&mut tx, pr.id, &merged_state).await?;
        EventRepo::append(
            &mut tx,
            EventId::new(),
            &DomainEvent::PullRequestMerged {
                pull_request_id: pr.id,
                repository_id: repository.id,
            },
        )
        .await?;
        for issue_number in closing_numbers {
            let Some(issue) =
                IssueRepo::find_by_repository_and_number(&mut tx, repository.id, issue_number)
                    .await?
            else {
                continue;
            };
            if !issue.state.is_open() {
                continue;
            }
            IssueRepo::update_state(
                &mut tx,
                issue.id,
                &IssueState::Closed {
                    closed_at: now_unix(),
                    reason: CloseReason::Completed,
                },
            )
            .await?;
            if let Some(closed_by_id) = actor_user_id {
                EventRepo::append(
                    &mut tx,
                    EventId::new(),
                    &DomainEvent::IssueClosed {
                        issue_id: issue.id,
                        repository_id: repository.id,
                        closed_by_id,
                        via_pull_request: Some(pr.id),
                    },
                )
                .await?;
            }
        }
        tx.commit().await?;

        if let Some(actor_id) = actor.user_id() {
            super::audit::record(
                &self.pool,
                super::audit::AuditEntry::new("pull_request.merge", &actor_id.to_string())
                    .target("repository", &repository.id.to_string())
                    .detail(serde_json::json!({
                        "number": number,
                        "merge_commit": outcome.merge_commit,
                        "strategy": strategy.as_db_str(),
                    })),
            )
            .await;
        }
        Ok(outcome)
    }

    /// Post a comment on a pull request. The insert and one
    /// `UserMentioned` event per resolved `@mention` commit as a unit —
    /// so every mention notification is on the outbox, or none is (the
    /// comment rolled back).
    pub async fn add_comment(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
        body: &str,
        anchor: Option<DiffAnchor>,
    ) -> Result<PrCommentId, ServiceError> {
        let body = body.trim();
        if body.is_empty() {
            return Err(ServiceError::Validation(
                "a comment can't be empty".to_string(),
            ));
        }

        // A repository writer or the PR's own author (a fork contributor
        // commenting on their own cross-repo PR).
        let (_, pr, commenter) = self
            .author_or_write_checked(actor, owner, name, number)
            .await?;

        let mentioned = mentions::resolve(&self.pool, body, commenter).await?;
        let source = MentionSource::PullRequestComment {
            pull_request_id: pr.id,
        };

        let comment_id = PrCommentId::new();
        let mut tx = self.pool.begin().await?;
        PrCommentRepo::insert(&mut tx, comment_id, pr.id, commenter, body, anchor.as_ref()).await?;
        for mentioned_user_id in mentioned {
            EventRepo::append(
                &mut tx,
                EventId::new(),
                &DomainEvent::UserMentioned {
                    mentioned_user_id,
                    mentioned_by_user_id: commenter,
                    source,
                },
            )
            .await?;
        }
        tx.commit().await?;

        Ok(comment_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edda_db::{EventRepo, NewPullRequest, PullRequestRepo, RepositoryRepo, UserRepo};
    use edda_domain::{
        DomainEvent, PrRef, PullRequestId, Repository, RepositoryId, RepositoryOwner, UserId,
        Visibility,
    };
    use edda_git::store::LocalFsStore;

    async fn user(pool: &DbPool, name: &str) -> UserId {
        let id = UserId::new();
        UserRepo::insert(pool, id, name, &format!("{name}@example.com"), "x")
            .await
            .unwrap();
        id
    }

    fn service(pool: &DbPool) -> PullRequestService {
        // `add_comment` never touches the store or the lock registry — a
        // throwaway store rooted at the temp dir is fine for these tests.
        PullRequestService::new(
            pool.clone(),
            Arc::new(LocalFsStore::new(std::env::temp_dir())),
            Arc::new(LockRegistry::new()),
            AuthorizationService::new(pool.clone()),
        )
    }

    async fn repo_with_pr(pool: &DbPool, owner: UserId) -> i64 {
        let repository = Repository {
            id: RepositoryId::new(),
            owner: RepositoryOwner::User(owner),
            name: "demo".to_string(),
            description: None,
            visibility: Visibility::Public,
            forked_from: None,
        };
        RepositoryRepo::insert_with_owner(pool, &repository, owner)
            .await
            .unwrap();
        PullRequestRepo::insert(
            pool,
            PullRequestId::new(),
            repository.id,
            NewPullRequest {
                title: "Add a thing",
                body: None,
                author_id: owner,
                source: &PrRef {
                    repository_id: repository.id,
                    branch: "feature".to_string(),
                },
                target: "main",
                draft: false,
            },
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn a_comment_writes_one_mention_event_per_distinct_resolved_handle() {
        let pool = edda_db::test_pool().await;
        let author = user(&pool, "alice").await;
        let bob = user(&pool, "bob").await;
        let _carol = user(&pool, "carol").await;
        let number = repo_with_pr(&pool, author).await;

        service(&pool)
            .add_comment(
                &ActorContext::User(author),
                "alice",
                "demo",
                number,
                "@bob @bob @alice @ghost — @bob only, no self-mention, no typo",
                None,
            )
            .await
            .unwrap();

        let outbox = EventRepo::fetch_unprocessed(&pool, 50).await.unwrap();
        assert_eq!(outbox.len(), 1);
        assert!(matches!(
            outbox[0].event,
            DomainEvent::UserMentioned { mentioned_user_id, .. } if mentioned_user_id == bob
        ));
    }

    #[tokio::test]
    async fn a_comment_with_no_mentions_writes_no_events() {
        let pool = edda_db::test_pool().await;
        let author = user(&pool, "alice").await;
        let number = repo_with_pr(&pool, author).await;

        service(&pool)
            .add_comment(
                &ActorContext::User(author),
                "alice",
                "demo",
                number,
                "just a plain comment",
                None,
            )
            .await
            .unwrap();

        assert!(EventRepo::fetch_unprocessed(&pool, 50)
            .await
            .unwrap()
            .is_empty());
    }

    /// A PR owned by `author`, whose account has no access to the repo
    /// (the fork-contributor shape). Returns `(repo_owner, number)`.
    async fn repo_with_foreign_authored_pr(
        pool: &DbPool,
        author: UserId,
        draft: bool,
    ) -> (UserId, i64) {
        let owner = user(pool, "maintainer").await;
        let repository = Repository {
            id: RepositoryId::new(),
            owner: RepositoryOwner::User(owner),
            name: "demo".to_string(),
            description: None,
            visibility: Visibility::Public,
            forked_from: None,
        };
        RepositoryRepo::insert_with_owner(pool, &repository, owner)
            .await
            .unwrap();
        let number = PullRequestRepo::insert(
            pool,
            PullRequestId::new(),
            repository.id,
            NewPullRequest {
                title: "Add a thing",
                body: None,
                author_id: author,
                source: &PrRef {
                    repository_id: repository.id,
                    branch: "feature".to_string(),
                },
                target: "main",
                draft,
            },
        )
        .await
        .unwrap();
        (owner, number)
    }

    #[tokio::test]
    async fn request_review_writes_a_review_requested_event_and_is_idempotent() {
        let pool = edda_db::test_pool().await;
        let owner = user(&pool, "alice").await;
        let reviewer = user(&pool, "bob").await;
        let number = repo_with_pr(&pool, owner).await;

        let svc = service(&pool);
        svc.request_review(&ActorContext::User(owner), "alice", "demo", number, "bob")
            .await
            .unwrap();
        svc.request_review(&ActorContext::User(owner), "alice", "demo", number, "bob")
            .await
            .unwrap();

        let events = EventRepo::fetch_unprocessed(&pool, 50).await.unwrap();
        let requested: Vec<_> = events
            .iter()
            .filter(|r| matches!(r.event, DomainEvent::ReviewRequested { reviewer_id, .. } if reviewer_id == reviewer))
            .collect();
        assert_eq!(requested.len(), 1);
    }

    #[tokio::test]
    async fn draft_and_ready_transitions_move_between_open_and_draft() {
        let pool = edda_db::test_pool().await;
        let author = user(&pool, "contributor").await;
        let (owner, number) = repo_with_foreign_authored_pr(&pool, author, true).await;
        let svc = service(&pool);

        // The maintainer (write access) can take it out of draft.
        svc.mark_ready(&ActorContext::User(owner), "maintainer", "demo", number)
            .await
            .unwrap();
        // Not a draft any more.
        let err = svc
            .mark_ready(&ActorContext::User(owner), "maintainer", "demo", number)
            .await
            .unwrap_err();
        assert!(matches!(err, ServiceError::Conflict(_)));

        // The author (no write access) can convert their own PR back to a draft.
        svc.convert_to_draft(&ActorContext::User(author), "maintainer", "demo", number)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_fork_contributor_can_comment_on_and_close_their_own_pull_request() {
        let pool = edda_db::test_pool().await;
        let author = user(&pool, "contributor").await;
        let _bystander = user(&pool, "bob").await;
        let (_owner, number) = repo_with_foreign_authored_pr(&pool, author, false).await;

        // No write access to the target repo, but they authored the PR.
        service(&pool)
            .add_comment(
                &ActorContext::User(author),
                "maintainer",
                "demo",
                number,
                "thanks for the review",
                None,
            )
            .await
            .expect("the author may comment on their own PR");
        service(&pool)
            .close(&ActorContext::User(author), "maintainer", "demo", number)
            .await
            .expect("the author may close their own PR");
    }
}

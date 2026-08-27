//! `PullRequestService` — the merge sequence and the comment/`@mention`
//! fan-out. Both write their `DomainEvent` to the outbox in the same
//! transaction as their state change (see [`super`]).
//!
//! Phase 3 ports only these two methods (the ones that already emitted
//! events); open / review / request-review / update-branch / close /
//! reopen / draft↔ready move here in Phase 4 as their handlers do.

use std::sync::Arc;

use edda_auth::AuthorizationService;
use edda_db::{DbPool, EventRepo, PrCommentRepo, PrReviewRepo, PullRequestRepo};
use edda_domain::{
    ActorContext, DiffAnchor, DomainEvent, EventId, MentionSource, MergeStrategy, PrCommentId,
    PrState,
};
use edda_git::store::RepoStore;
use edda_git::{merge_branches, LockRegistry, MergeOutcome};

use super::{mentions, now_unix, ServiceError};

/// Constructed per request from `AppState`'s shared handles (Phase 4 moves
/// it into `AppState` itself). Cloning is cheap — `DbPool` and the `Arc`s
/// are handle clones.
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
        committer_name: &str,
        committer_email: &str,
    ) -> Result<MergeOutcome, ServiceError> {
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

        let identity = format!("{owner}/{name}");
        let lock = self.locks.lock_for(&identity);
        let _guard = lock.lock().await;

        let outcome = merge_branches(
            self.store.as_ref(),
            &identity,
            &pr.source.branch,
            &pr.target,
            committer_name,
            committer_email,
            &format!("Merge pull request #{number} from {}", pr.source.branch),
        )?;

        let merged_state = PrState::Merged {
            merged_at: now_unix(),
            merge_commit: outcome.merge_commit.clone(),
            strategy: MergeStrategy::Merge,
        };

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
        tx.commit().await?;

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
        let commenter = actor.user_id().ok_or(ServiceError::Unauthorized)?;
        let body = body.trim();
        if body.is_empty() {
            return Err(ServiceError::Validation(
                "a comment can't be empty".to_string(),
            ));
        }

        let repository = self.authz.repository_by_name(owner, name).await?;
        self.authz.check_write(actor, &repository).await?;
        let pr = PullRequestRepo::find_by_repository_and_number(&self.pool, repository.id, number)
            .await?
            .ok_or(ServiceError::NotFound)?;

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
}

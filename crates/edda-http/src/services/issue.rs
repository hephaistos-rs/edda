//! `IssueService` — Phase 3 ports only `add_comment`, the issue-side half
//! of the `@mention` fan-out that previously called
//! `mentions::dispatch_mentions` directly. Open / label / milestone /
//! assign / close / reopen move here in Phase 4.

use edda_auth::AuthorizationService;
use edda_db::{DbPool, EventRepo, IssueCommentRepo};
use edda_domain::{ActorContext, DomainEvent, EventId, IssueCommentId, MentionSource};

use super::{mentions, ServiceError};

#[derive(Clone)]
pub struct IssueService {
    pool: DbPool,
    authz: AuthorizationService,
}

impl IssueService {
    pub fn new(pool: DbPool, authz: AuthorizationService) -> Self {
        Self { pool, authz }
    }

    /// Post a comment on an issue. The insert and one `UserMentioned`
    /// event per resolved `@mention` commit together — same outbox
    /// guarantee as the pull-request path.
    pub async fn add_comment(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
        body: &str,
    ) -> Result<IssueCommentId, ServiceError> {
        let commenter = actor.user_id().ok_or(ServiceError::Unauthorized)?;
        let body = body.trim();
        if body.is_empty() {
            return Err(ServiceError::Validation(
                "a comment can't be empty".to_string(),
            ));
        }

        let repository = self.authz.repository_by_name(owner, name).await?;
        self.authz.check_write(actor, &repository).await?;
        let issue =
            edda_db::IssueRepo::find_by_repository_and_number(&self.pool, repository.id, number)
                .await?
                .ok_or(ServiceError::NotFound)?;

        let mentioned = mentions::resolve(&self.pool, body, commenter).await?;
        let source = MentionSource::IssueComment { issue_id: issue.id };

        let comment_id = IssueCommentId::new();
        let mut tx = self.pool.begin().await?;
        IssueCommentRepo::insert(&mut tx, comment_id, issue.id, commenter, body).await?;
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
    use edda_db::{EventRepo, IssueRepo, RepositoryRepo, UserRepo};
    use edda_domain::{DomainEvent, Repository, RepositoryId, RepositoryOwner, UserId, Visibility};

    async fn user(pool: &DbPool, name: &str) -> UserId {
        let id = UserId::new();
        UserRepo::insert(pool, id, name, &format!("{name}@example.com"), "x")
            .await
            .unwrap();
        id
    }

    fn service(pool: &DbPool) -> IssueService {
        IssueService::new(pool.clone(), AuthorizationService::new(pool.clone()))
    }

    #[tokio::test]
    async fn a_comment_and_its_mention_events_commit_together() {
        let pool = edda_db::test_pool().await;
        let author = user(&pool, "alice").await;
        let mentioned = user(&pool, "bob").await;
        let _bystander = user(&pool, "carol").await;

        let repository = Repository {
            id: RepositoryId::new(),
            owner: RepositoryOwner::User(author),
            name: "demo".to_string(),
            description: None,
            visibility: Visibility::Public,
            forked_from: None,
        };
        RepositoryRepo::insert_with_owner(&pool, &repository, author)
            .await
            .unwrap();
        let number = IssueRepo::insert(
            &pool,
            edda_domain::IssueId::new(),
            repository.id,
            "Bug",
            None,
            author,
        )
        .await
        .unwrap();

        service(&pool)
            .add_comment(
                &ActorContext::User(author),
                "alice",
                "demo",
                number,
                "hey @bob and @nobody, take a look",
            )
            .await
            .unwrap();

        let outbox = EventRepo::fetch_unprocessed(&pool, 50).await.unwrap();
        // One event: @bob resolves, @nobody doesn't, the author isn't
        // self-mentioned here anyway.
        assert_eq!(outbox.len(), 1);
        let DomainEvent::UserMentioned {
            mentioned_user_id,
            mentioned_by_user_id,
            ..
        } = outbox[0].event
        else {
            panic!("unexpected event: {:?}", outbox[0].event);
        };
        assert_eq!(mentioned_user_id, mentioned);
        assert_eq!(mentioned_by_user_id, author);
    }

    #[tokio::test]
    async fn an_empty_comment_is_rejected_before_any_write() {
        let pool = edda_db::test_pool().await;
        let author = user(&pool, "alice").await;
        let repository = Repository {
            id: RepositoryId::new(),
            owner: RepositoryOwner::User(author),
            name: "demo".to_string(),
            description: None,
            visibility: Visibility::Public,
            forked_from: None,
        };
        RepositoryRepo::insert_with_owner(&pool, &repository, author)
            .await
            .unwrap();
        let number = IssueRepo::insert(
            &pool,
            edda_domain::IssueId::new(),
            repository.id,
            "Bug",
            None,
            author,
        )
        .await
        .unwrap();

        let err = service(&pool)
            .add_comment(&ActorContext::User(author), "alice", "demo", number, "   ")
            .await
            .unwrap_err();
        assert!(matches!(err, ServiceError::Validation(_)));
        assert!(EventRepo::fetch_unprocessed(&pool, 50)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn a_writer_without_access_is_forbidden() {
        let pool = edda_db::test_pool().await;
        let owner = user(&pool, "alice").await;
        let outsider = user(&pool, "mallory").await;
        let repository = Repository {
            id: RepositoryId::new(),
            owner: RepositoryOwner::User(owner),
            name: "demo".to_string(),
            description: None,
            visibility: Visibility::Public,
            forked_from: None,
        };
        RepositoryRepo::insert_with_owner(&pool, &repository, owner)
            .await
            .unwrap();
        let number = IssueRepo::insert(
            &pool,
            edda_domain::IssueId::new(),
            repository.id,
            "Bug",
            None,
            owner,
        )
        .await
        .unwrap();

        let err = service(&pool)
            .add_comment(
                &ActorContext::User(outsider),
                "alice",
                "demo",
                number,
                "let me in",
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ServiceError::Forbidden | ServiceError::NotFound
        ));
    }
}

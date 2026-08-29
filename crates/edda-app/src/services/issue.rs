//! `IssueService` — open / comment / close / reopen, plus label and
//! milestone management. The comment path emits `UserMentioned` outbox
//! events in the same transaction as the insert.

use edda_auth::AuthorizationService;
use edda_db::{
    DbPool, EventRepo, IssueAssigneeRepo, IssueCommentRepo, IssueRepo, LabelRepo, MilestoneRepo,
    UserRepo,
};
use edda_domain::{
    ActorContext, CloseReason, DomainEvent, EventId, Issue, IssueCommentId, IssueState, LabelId,
    MentionSource, MilestoneId, Repository,
};

use super::{mentions, now_unix, ServiceError};
use crate::AppState;

/// What a caller supplies to open an issue.
pub struct NewIssueInput {
    pub title: String,
    pub body: Option<String>,
}

#[derive(Clone)]
pub struct IssueService {
    pool: DbPool,
    authz: AuthorizationService,
}

impl IssueService {
    pub fn new(pool: DbPool, authz: AuthorizationService) -> Self {
        Self { pool, authz }
    }

    #[must_use]
    pub fn from_state(state: &AppState) -> Self {
        Self::new(state.pool.clone(), state.authz.clone())
    }

    /// Open an issue — write access. Returns its number.
    pub async fn open(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        input: NewIssueInput,
    ) -> Result<i64, ServiceError> {
        let (repository, author_id) = self.write_checked(actor, owner, name).await?;
        if input.title.trim().is_empty() {
            return Err(ServiceError::Validation(
                "an issue needs a title".to_string(),
            ));
        }
        let number = IssueRepo::insert(
            &self.pool,
            edda_domain::IssueId::new(),
            repository.id,
            input.title.trim(),
            input.body.as_deref().filter(|b| !b.trim().is_empty()),
            author_id,
        )
        .await?;
        Ok(number)
    }

    /// Close an open issue — write access.
    pub async fn close(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
    ) -> Result<(), ServiceError> {
        let (repository, _) = self.write_checked(actor, owner, name).await?;
        let issue = self.load_issue(repository.id, number).await?;
        if !issue.state.is_open() {
            return Err(ServiceError::Conflict(
                "this issue is already closed".to_string(),
            ));
        }
        IssueRepo::update_state(
            &self.pool,
            issue.id,
            &IssueState::Closed {
                closed_at: now_unix(),
                reason: CloseReason::Completed,
            },
        )
        .await?;
        Ok(())
    }

    /// Reopen a closed issue — write access.
    pub async fn reopen(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
    ) -> Result<(), ServiceError> {
        let (repository, _) = self.write_checked(actor, owner, name).await?;
        let issue = self.load_issue(repository.id, number).await?;
        IssueRepo::update_state(&self.pool, issue.id, &IssueState::Open).await?;
        Ok(())
    }

    /// Create a repository label — write access.
    pub async fn create_label(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        label_name: &str,
        color: &str,
        description: Option<&str>,
    ) -> Result<(), ServiceError> {
        let (repository, _) = self.write_checked(actor, owner, name).await?;
        if label_name.trim().is_empty() {
            return Err(ServiceError::Validation("a label needs a name".to_string()));
        }
        LabelRepo::insert(
            &self.pool,
            LabelId::new(),
            repository.id,
            label_name.trim(),
            color,
            description.filter(|d| !d.trim().is_empty()),
        )
        .await?;
        Ok(())
    }

    /// Apply an existing repository label to an issue — write access.
    pub async fn apply_label(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
        label_id: LabelId,
    ) -> Result<(), ServiceError> {
        let (repository, _) = self.write_checked(actor, owner, name).await?;
        let issue = self.load_issue(repository.id, number).await?;
        let label = LabelRepo::list_for_repository(&self.pool, repository.id)
            .await?
            .into_iter()
            .find(|l| l.id == label_id)
            .ok_or(ServiceError::NotFound)?;
        LabelRepo::apply_to_issue(&self.pool, issue.id, &label).await?;
        Ok(())
    }

    /// Remove a label from an issue — write access.
    pub async fn remove_label(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
        label_id: LabelId,
    ) -> Result<(), ServiceError> {
        let (repository, _) = self.write_checked(actor, owner, name).await?;
        let issue = self.load_issue(repository.id, number).await?;
        LabelRepo::remove_from_issue(&self.pool, issue.id, label_id).await?;
        Ok(())
    }

    /// Create a milestone — write access.
    pub async fn create_milestone(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        title: &str,
        description: Option<&str>,
        due_on: Option<i64>,
    ) -> Result<(), ServiceError> {
        let (repository, _) = self.write_checked(actor, owner, name).await?;
        if title.trim().is_empty() {
            return Err(ServiceError::Validation(
                "a milestone needs a title".to_string(),
            ));
        }
        MilestoneRepo::insert(
            &self.pool,
            MilestoneId::new(),
            repository.id,
            title.trim(),
            description.filter(|d| !d.trim().is_empty()),
            due_on,
        )
        .await?;
        Ok(())
    }

    /// Assign a user to an issue — write access. Idempotent: assigning
    /// someone already assigned is a no-op (no second notification). Emits
    /// `IssueAssigned` in the same transaction as the junction insert.
    pub async fn assign(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
        assignee_username: &str,
    ) -> Result<(), ServiceError> {
        let (repository, actor_id) = self.write_checked(actor, owner, name).await?;
        let issue = self.load_issue(repository.id, number).await?;
        let assignee = UserRepo::find_by_username(&self.pool, assignee_username)
            .await?
            .ok_or(ServiceError::NotFound)?;

        let mut tx = self.pool.begin().await?;
        let newly_assigned =
            IssueAssigneeRepo::assign(&mut tx, issue.id, assignee.id, Some(actor_id)).await?;
        if newly_assigned {
            EventRepo::append(
                &mut tx,
                EventId::new(),
                &DomainEvent::IssueAssigned {
                    issue_id: issue.id,
                    repository_id: repository.id,
                    assignee_id: assignee.id,
                    assigned_by_id: actor_id,
                },
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Remove an assignee from an issue — write access.
    pub async fn unassign(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
        assignee_username: &str,
    ) -> Result<(), ServiceError> {
        let (repository, _) = self.write_checked(actor, owner, name).await?;
        let issue = self.load_issue(repository.id, number).await?;
        let assignee = UserRepo::find_by_username(&self.pool, assignee_username)
            .await?
            .ok_or(ServiceError::NotFound)?;
        IssueAssigneeRepo::unassign(&self.pool, issue.id, assignee.id).await?;
        Ok(())
    }

    /// Set (or clear, with `None`) an issue's milestone — write access.
    pub async fn set_milestone(
        &self,
        actor: &ActorContext,
        owner: &str,
        name: &str,
        number: i64,
        milestone_id: Option<MilestoneId>,
    ) -> Result<(), ServiceError> {
        let (repository, _) = self.write_checked(actor, owner, name).await?;
        let issue = self.load_issue(repository.id, number).await?;
        IssueRepo::set_milestone(&self.pool, issue.id, milestone_id).await?;
        Ok(())
    }

    async fn load_issue(
        &self,
        repository_id: edda_domain::RepositoryId,
        number: i64,
    ) -> Result<Issue, ServiceError> {
        IssueRepo::find_by_repository_and_number(&self.pool, repository_id, number)
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

    #[tokio::test]
    async fn assign_writes_the_junction_row_and_one_issue_assigned_event_then_is_idempotent() {
        let pool = edda_db::test_pool().await;
        let owner = user(&pool, "alice").await;
        let assignee = user(&pool, "bob").await;
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
        let issue_id = edda_domain::IssueId::new();
        let number = IssueRepo::insert(&pool, issue_id, repository.id, "Bug", None, owner)
            .await
            .unwrap();

        let svc = service(&pool);
        svc.assign(&ActorContext::User(owner), "alice", "demo", number, "bob")
            .await
            .unwrap();
        svc.assign(&ActorContext::User(owner), "alice", "demo", number, "bob")
            .await
            .unwrap();

        assert_eq!(
            edda_db::IssueAssigneeRepo::list_for_issue(&pool, issue_id)
                .await
                .unwrap(),
            vec![assignee]
        );
        let outbox = EventRepo::fetch_unprocessed(&pool, 50).await.unwrap();
        let assigned: Vec<_> = outbox
            .iter()
            .filter(|r| matches!(r.event, DomainEvent::IssueAssigned { assignee_id, .. } if assignee_id == assignee))
            .collect();
        assert_eq!(assigned.len(), 1, "one event for the first assignment only");
    }
}

//! `issue_assignees` persistence — the users assigned to an issue. A
//! composite-PK junction, the same shape as `issue_labels`.

use edda_domain::{IssueId, UserId};

use crate::{get_string, Backend, DbConn, DbError};

pub struct IssueAssigneeRepo;

impl IssueAssigneeRepo {
    /// Assigns `user_id` to the issue. `Ok(true)` if a new assignment was
    /// written, `Ok(false)` if they were already assigned.
    pub async fn assign<'c>(
        db: impl DbConn<'c>,
        issue_id: IssueId,
        user_id: UserId,
        assigned_by_id: Option<UserId>,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let now = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO issue_assignees (issue_id, user_id, assigned_by_id, assigned_at) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING"
            }
            Backend::Sqlite => {
                "INSERT OR IGNORE INTO issue_assignees (issue_id, user_id, assigned_by_id, assigned_at) \
                 VALUES (?, ?, ?, ?)"
            }
            Backend::MySql => {
                "INSERT IGNORE INTO issue_assignees (issue_id, user_id, assigned_by_id, assigned_at) \
                 VALUES (?, ?, ?, ?)"
            }
        };
        let result = sqlx::query(sql)
            .bind(issue_id.to_string())
            .bind(user_id.to_string())
            .bind(assigned_by_id.map(|id| id.to_string()))
            .bind(now)
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Removes an assignment. `Ok(true)` if a row was removed.
    pub async fn unassign<'c>(
        db: impl DbConn<'c>,
        issue_id: IssueId,
        user_id: UserId,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => "DELETE FROM issue_assignees WHERE issue_id = $1 AND user_id = $2",
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM issue_assignees WHERE issue_id = ? AND user_id = ?"
            }
        };
        let result = sqlx::query(sql)
            .bind(issue_id.to_string())
            .bind(user_id.to_string())
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// The assignees of one issue, oldest assignment first.
    pub async fn list_for_issue<'c>(
        db: impl DbConn<'c>,
        issue_id: IssueId,
    ) -> Result<Vec<UserId>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT user_id FROM issue_assignees WHERE issue_id = $1 ORDER BY assigned_at, user_id"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT user_id FROM issue_assignees WHERE issue_id = ? ORDER BY assigned_at, user_id"
            }
        };
        let rows = sqlx::query(sql)
            .bind(issue_id.to_string())
            .fetch_all(&mut *h.conn())
            .await?;
        rows.iter()
            .map(|row| {
                Ok(get_string(row, "user_id")?
                    .parse()
                    .expect("stored user id is a valid UUID"))
            })
            .collect()
    }

    /// The issue ids assigned to `user_id` (for an "assigned to me" view),
    /// newest assignment first.
    pub async fn list_issue_ids_for_user<'c>(
        db: impl DbConn<'c>,
        user_id: UserId,
    ) -> Result<Vec<IssueId>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT issue_id FROM issue_assignees WHERE user_id = $1 ORDER BY assigned_at DESC"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT issue_id FROM issue_assignees WHERE user_id = ? ORDER BY assigned_at DESC"
            }
        };
        let rows = sqlx::query(sql)
            .bind(user_id.to_string())
            .fetch_all(&mut *h.conn())
            .await?;
        rows.iter()
            .map(|row| {
                Ok(get_string(row, "issue_id")?
                    .parse()
                    .expect("stored issue id is a valid UUID"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DbPool, IssueRepo, RepositoryRepo, UserRepo};
    use edda_domain::{IssueId, Repository, RepositoryId, RepositoryOwner, UserId, Visibility};

    async fn user(pool: &DbPool, name: &str) -> UserId {
        let id = UserId::new();
        UserRepo::insert(pool, id, name, &format!("{name}@example.com"), "x")
            .await
            .unwrap();
        id
    }

    async fn issue(pool: &DbPool, owner: UserId) -> IssueId {
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
        let id = IssueId::new();
        IssueRepo::insert(pool, id, repository.id, "Bug", None, owner)
            .await
            .unwrap();
        id
    }

    #[tokio::test]
    async fn assign_is_idempotent_and_unassign_reverses_it() {
        let pool = crate::test_pool().await;
        let owner = user(&pool, "alice").await;
        let assignee = user(&pool, "bob").await;
        let issue_id = issue(&pool, owner).await;

        assert!(
            IssueAssigneeRepo::assign(&pool, issue_id, assignee, Some(owner))
                .await
                .unwrap()
        );
        assert!(
            !IssueAssigneeRepo::assign(&pool, issue_id, assignee, Some(owner))
                .await
                .unwrap()
        );

        assert_eq!(
            IssueAssigneeRepo::list_for_issue(&pool, issue_id)
                .await
                .unwrap(),
            vec![assignee]
        );
        assert_eq!(
            IssueAssigneeRepo::list_issue_ids_for_user(&pool, assignee)
                .await
                .unwrap(),
            vec![issue_id]
        );

        assert!(IssueAssigneeRepo::unassign(&pool, issue_id, assignee)
            .await
            .unwrap());
        assert!(IssueAssigneeRepo::list_for_issue(&pool, issue_id)
            .await
            .unwrap()
            .is_empty());
    }
}

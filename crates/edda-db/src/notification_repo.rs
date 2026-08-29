//! `notifications` persistence.

use edda_domain::{
    IssueId, Notification, NotificationId, NotificationKind, NotificationSubject, PullRequestId,
    ReleaseId, UserId,
};

use crate::{get_i64, get_opt_i64, get_string, Backend, DbConn, DbError};

fn subject_to_columns(subject: NotificationSubject) -> (&'static str, String) {
    (
        subject.subject_type_db_str(),
        subject.subject_id().to_string(),
    )
}

fn row_to_subject(subject_type: &str, subject_id: &str) -> NotificationSubject {
    match subject_type {
        "pull_request" => NotificationSubject::PullRequest(
            subject_id
                .parse::<PullRequestId>()
                .expect("stored pull request id is a valid UUID"),
        ),
        "issue" => NotificationSubject::Issue(
            subject_id
                .parse::<IssueId>()
                .expect("stored issue id is a valid UUID"),
        ),
        "release" => NotificationSubject::Release(
            subject_id
                .parse::<ReleaseId>()
                .expect("stored release id is a valid UUID"),
        ),
        other => unreachable!("unknown notification subject_type {other:?} in the database"),
    }
}

fn row_to_notification(
    id: String,
    user_id: String,
    kind: String,
    subject_type: String,
    subject_id: String,
    read_at: Option<i64>,
    created_at: i64,
) -> Notification {
    Notification {
        id: id.parse().expect("stored notification id is a valid UUID"),
        user_id: user_id.parse().expect("stored user id is a valid UUID"),
        kind: NotificationKind::from_db_str(&kind)
            .expect("stored notification kind is a known value"),
        subject: row_to_subject(&subject_type, &subject_id),
        read_at,
        created_at,
    }
}

const NOTIFICATION_COLUMNS: &str =
    "id, user_id, kind, subject_type, subject_id, read_at, created_at";

pub struct NotificationRepo;

impl NotificationRepo {
    /// Creates a notification unless an unread one already exists for the
    /// same `(user_id, kind, subject)` — the "notification creation checks
    /// for an existing un-superseded notification... before inserting a
    /// duplicate" idempotency rule. This is an application-level
    /// check-then-insert, not a DB-enforced uniqueness constraint: a
    /// duplicate notification is a UX nuisance (the same PR review-request
    /// shown twice), not a correctness or security defect, so the small
    /// race window between the check and the insert (two *different*
    /// triggering events landing at almost the same instant) is an
    /// accepted trade-off rather than something worth a MySQL generated-
    /// column uniqueness workaround for.
    pub async fn insert_if_new<'c>(
        db: impl DbConn<'c>,
        id: NotificationId,
        user_id: UserId,
        kind: NotificationKind,
        subject: NotificationSubject,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let (subject_type, subject_id) = subject_to_columns(subject);
        let existing_sql = match h.backend() {
            Backend::Postgres => {
                "SELECT 1 FROM notifications WHERE user_id = $1 AND kind = $2 AND subject_type = $3 AND subject_id = $4 AND read_at IS NULL"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT 1 FROM notifications WHERE user_id = ? AND kind = ? AND subject_type = ? AND subject_id = ? AND read_at IS NULL"
            }
        };
        let existing = sqlx::query(existing_sql)
            .bind(user_id.to_string())
            .bind(kind.as_db_str())
            .bind(subject_type)
            .bind(&subject_id)
            .fetch_optional(&mut *h.conn())
            .await?;
        if existing.is_some() {
            return Ok(false);
        }

        let created_at = crate::now_unix();
        let insert_sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO notifications (id, user_id, kind, subject_type, subject_id, created_at) VALUES ($1, $2, $3, $4, $5, $6)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO notifications (id, user_id, kind, subject_type, subject_id, created_at) VALUES (?, ?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(insert_sql)
            .bind(id.to_string())
            .bind(user_id.to_string())
            .bind(kind.as_db_str())
            .bind(subject_type)
            .bind(&subject_id)
            .bind(created_at)
            .execute(&mut *h.conn())
            .await?;
        Ok(true)
    }

    /// Newest first — the notification list/badge view.
    pub async fn list_for_user<'c>(
        db: impl DbConn<'c>,
        user_id: UserId,
    ) -> Result<Vec<Notification>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => format!(
                "SELECT {NOTIFICATION_COLUMNS} FROM notifications WHERE user_id = $1 ORDER BY created_at DESC"
            ),
            Backend::Sqlite | Backend::MySql => format!(
                "SELECT {NOTIFICATION_COLUMNS} FROM notifications WHERE user_id = ? ORDER BY created_at DESC"
            ),
        };
        let rows = sqlx::query(&sql)
            .bind(user_id.to_string())
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(row_to_notification(
                    get_string(&row, "id")?,
                    get_string(&row, "user_id")?,
                    get_string(&row, "kind")?,
                    get_string(&row, "subject_type")?,
                    get_string(&row, "subject_id")?,
                    get_opt_i64(&row, "read_at")?,
                    get_i64(&row, "created_at")?,
                ))
            })
            .collect()
    }

    pub async fn unread_count<'c>(db: impl DbConn<'c>, user_id: UserId) -> Result<i64, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT COUNT(*) AS n FROM notifications WHERE user_id = $1 AND read_at IS NULL"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT COUNT(*) AS n FROM notifications WHERE user_id = ? AND read_at IS NULL"
            }
        };
        let row = sqlx::query(sql)
            .bind(user_id.to_string())
            .fetch_one(&mut *h.conn())
            .await?;
        Ok(get_i64(&row, "n")?)
    }

    pub async fn mark_read<'c>(
        db: impl DbConn<'c>,
        user_id: UserId,
        id: NotificationId,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let read_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "UPDATE notifications SET read_at = $1 WHERE id = $2 AND user_id = $3 AND read_at IS NULL"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE notifications SET read_at = ? WHERE id = ? AND user_id = ? AND read_at IS NULL"
            }
        };
        let result = sqlx::query(sql)
            .bind(read_at)
            .bind(id.to_string())
            .bind(user_id.to_string())
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DbPool;

    async fn insert_user(pool: &DbPool, username: &str) -> UserId {
        let user_id = UserId::new();
        crate::UserRepo::insert(
            pool,
            user_id,
            username,
            &format!("{username}@example.com"),
            "x",
        )
        .await
        .unwrap();
        user_id
    }

    #[tokio::test]
    async fn inserting_the_same_unread_kind_and_subject_twice_is_a_no_op_the_second_time() {
        let pool = crate::test_pool().await;
        let user_id = insert_user(&pool, "alice").await;
        let subject = NotificationSubject::PullRequest(PullRequestId::new());

        let first = NotificationRepo::insert_if_new(
            &pool,
            NotificationId::new(),
            user_id,
            NotificationKind::Mention,
            subject,
        )
        .await
        .unwrap();
        assert!(first);

        let second = NotificationRepo::insert_if_new(
            &pool,
            NotificationId::new(),
            user_id,
            NotificationKind::Mention,
            subject,
        )
        .await
        .unwrap();
        assert!(!second);

        let list = NotificationRepo::list_for_user(&pool, user_id)
            .await
            .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(
            NotificationRepo::unread_count(&pool, user_id)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn a_read_notification_no_longer_blocks_a_fresh_duplicate() {
        let pool = crate::test_pool().await;
        let user_id = insert_user(&pool, "bob").await;
        let subject = NotificationSubject::PullRequest(PullRequestId::new());
        let id = NotificationId::new();

        NotificationRepo::insert_if_new(&pool, id, user_id, NotificationKind::Mention, subject)
            .await
            .unwrap();
        assert!(NotificationRepo::mark_read(&pool, user_id, id)
            .await
            .unwrap());
        assert_eq!(
            NotificationRepo::unread_count(&pool, user_id)
                .await
                .unwrap(),
            0
        );

        let again = NotificationRepo::insert_if_new(
            &pool,
            NotificationId::new(),
            user_id,
            NotificationKind::Mention,
            subject,
        )
        .await
        .unwrap();
        assert!(again);
        assert_eq!(
            NotificationRepo::unread_count(&pool, user_id)
                .await
                .unwrap(),
            1
        );
    }
}

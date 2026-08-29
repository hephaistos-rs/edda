//! `watches` persistence — a user's standing interest (`watching` /
//! `ignoring`) in a repository, issue, or pull request. Drives the
//! notification fan-out; the absence of a row means "default" (notified
//! only for direct involvement).

use edda_domain::{UserId, Watch, WatchId, WatchLevel, WatchSubject};

use crate::{get_i64, get_string, Backend, DbConn, DbError};

fn subject_columns(subject: WatchSubject) -> (&'static str, String) {
    (
        subject.subject_type_db_str(),
        subject.subject_id().to_string(),
    )
}

pub struct WatchRepo;

impl WatchRepo {
    /// Sets (or updates) a user's watch level for a subject.
    pub async fn set<'c>(
        db: impl DbConn<'c>,
        id: WatchId,
        user_id: UserId,
        subject: WatchSubject,
        level: WatchLevel,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let (subject_type, subject_id) = subject_columns(subject);
        let now = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO watches (id, user_id, subject_type, subject_id, level, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT (user_id, subject_type, subject_id) DO UPDATE SET level = $5"
            }
            Backend::Sqlite => {
                "INSERT INTO watches (id, user_id, subject_type, subject_id, level, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON CONFLICT (user_id, subject_type, subject_id) DO UPDATE SET level = excluded.level"
            }
            Backend::MySql => {
                "INSERT INTO watches (id, user_id, subject_type, subject_id, level, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE level = VALUES(level)"
            }
        };
        sqlx::query(sql)
            .bind(id.to_string())
            .bind(user_id.to_string())
            .bind(subject_type)
            .bind(&subject_id)
            .bind(level.as_db_str())
            .bind(now)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// Removes a user's watch row for a subject (back to the default).
    /// `Ok(true)` if a row was removed.
    pub async fn clear<'c>(
        db: impl DbConn<'c>,
        user_id: UserId,
        subject: WatchSubject,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let (subject_type, subject_id) = subject_columns(subject);
        let sql = match h.backend() {
            Backend::Postgres => {
                "DELETE FROM watches WHERE user_id = $1 AND subject_type = $2 AND subject_id = $3"
            }
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM watches WHERE user_id = ? AND subject_type = ? AND subject_id = ?"
            }
        };
        let result = sqlx::query(sql)
            .bind(user_id.to_string())
            .bind(subject_type)
            .bind(&subject_id)
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// One user's explicit watch level for a subject, or `None` for the
    /// default.
    pub async fn get<'c>(
        db: impl DbConn<'c>,
        user_id: UserId,
        subject: WatchSubject,
    ) -> Result<Option<WatchLevel>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let (subject_type, subject_id) = subject_columns(subject);
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT level FROM watches WHERE user_id = $1 AND subject_type = $2 AND subject_id = $3"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT level FROM watches WHERE user_id = ? AND subject_type = ? AND subject_id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(user_id.to_string())
            .bind(subject_type)
            .bind(&subject_id)
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(|row| {
            Ok(WatchLevel::from_db_str(&get_string(&row, "level")?)
                .expect("stored watch level is a known value"))
        })
        .transpose()
    }

    /// Everyone with an explicit watch row for a subject — both `watching`
    /// and `ignoring` (the caller filters). Used by the notification
    /// fan-out.
    pub async fn watchers_of<'c>(
        db: impl DbConn<'c>,
        subject: WatchSubject,
    ) -> Result<Vec<Watch>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let (subject_type, subject_id) = subject_columns(subject);
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, user_id, level, created_at FROM watches \
                 WHERE subject_type = $1 AND subject_id = $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, user_id, level, created_at FROM watches \
                 WHERE subject_type = ? AND subject_id = ?"
            }
        };
        let rows = sqlx::query(sql)
            .bind(subject_type)
            .bind(&subject_id)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.iter()
            .map(|row| {
                Ok(Watch {
                    id: get_string(row, "id")?
                        .parse()
                        .expect("stored watch id is a valid UUID"),
                    user_id: get_string(row, "user_id")?
                        .parse()
                        .expect("stored user id is a valid UUID"),
                    subject,
                    level: WatchLevel::from_db_str(&get_string(row, "level")?)
                        .expect("stored watch level is a known value"),
                    created_at: get_i64(row, "created_at")?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DbPool, UserRepo};
    use edda_domain::{RepositoryId, UserId, WatchSubject};

    async fn user(pool: &DbPool, name: &str) -> UserId {
        let id = UserId::new();
        UserRepo::insert(pool, id, name, &format!("{name}@example.com"), "x")
            .await
            .unwrap();
        id
    }

    #[tokio::test]
    async fn set_upserts_the_level_and_clear_removes_the_row() {
        let pool = crate::test_pool().await;
        let alice = user(&pool, "alice").await;
        let bob = user(&pool, "bob").await;
        let repo = WatchSubject::Repository(RepositoryId::new());

        WatchRepo::set(&pool, WatchId::new(), alice, repo, WatchLevel::Watching)
            .await
            .unwrap();
        WatchRepo::set(&pool, WatchId::new(), alice, repo, WatchLevel::Ignoring)
            .await
            .unwrap();
        WatchRepo::set(&pool, WatchId::new(), bob, repo, WatchLevel::Watching)
            .await
            .unwrap();

        assert_eq!(
            WatchRepo::get(&pool, alice, repo).await.unwrap(),
            Some(WatchLevel::Ignoring)
        );

        let watchers = WatchRepo::watchers_of(&pool, repo).await.unwrap();
        assert_eq!(watchers.len(), 2);

        assert!(WatchRepo::clear(&pool, alice, repo).await.unwrap());
        assert_eq!(WatchRepo::get(&pool, alice, repo).await.unwrap(), None);
        assert_eq!(WatchRepo::watchers_of(&pool, repo).await.unwrap().len(), 1);
    }
}

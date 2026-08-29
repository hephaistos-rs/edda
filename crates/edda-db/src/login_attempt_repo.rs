//! `login_attempts` persistence — the storage half of the login
//! brute-force throttle. The *policy* (when to lock, the backoff curve)
//! lives in `edda_auth::login_throttle`; this repo only counts failures
//! per `attempt_key` (`lower(email) || '|' || client_ip`) and records a
//! lock deadline.

use crate::{get_i64, get_opt_i64, get_string, Backend, DbConn, DbError};

#[derive(Debug, Clone)]
pub struct LoginAttempt {
    pub attempt_key: String,
    pub failure_count: i64,
    pub first_failed_at: i64,
    pub last_failed_at: i64,
    pub locked_until: Option<i64>,
}

pub struct LoginAttemptRepo;

impl LoginAttemptRepo {
    /// The current counter for `key`, or `None` if there's no failure on
    /// record (a clean account/IP pair).
    pub async fn current<'c>(
        db: impl DbConn<'c>,
        key: &str,
    ) -> Result<Option<LoginAttempt>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT attempt_key, failure_count, first_failed_at, last_failed_at, locked_until
                 FROM login_attempts WHERE attempt_key = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT attempt_key, failure_count, first_failed_at, last_failed_at, locked_until
                 FROM login_attempts WHERE attempt_key = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(key)
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(|row| {
            Ok(LoginAttempt {
                attempt_key: get_string(&row, "attempt_key")?,
                failure_count: get_i64(&row, "failure_count")?,
                first_failed_at: get_i64(&row, "first_failed_at")?,
                last_failed_at: get_i64(&row, "last_failed_at")?,
                locked_until: get_opt_i64(&row, "locked_until")?,
            })
        })
        .transpose()
    }

    /// Records one more failed attempt for `key` at `now`, creating the row
    /// if needed, and returns the updated counter.
    pub async fn record_failure<'c>(
        db: impl DbConn<'c>,
        key: &str,
        now: i64,
    ) -> Result<LoginAttempt, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO login_attempts (attempt_key, failure_count, first_failed_at, last_failed_at)
                 VALUES ($1, 1, $2, $2)
                 ON CONFLICT (attempt_key) DO UPDATE
                   SET failure_count = login_attempts.failure_count + 1, last_failed_at = $2"
            }
            Backend::Sqlite => {
                "INSERT INTO login_attempts (attempt_key, failure_count, first_failed_at, last_failed_at)
                 VALUES (?, 1, ?, ?)
                 ON CONFLICT (attempt_key) DO UPDATE
                   SET failure_count = failure_count + 1, last_failed_at = excluded.last_failed_at"
            }
            Backend::MySql => {
                "INSERT INTO login_attempts (attempt_key, failure_count, first_failed_at, last_failed_at)
                 VALUES (?, 1, ?, ?)
                 ON DUPLICATE KEY UPDATE
                   failure_count = failure_count + 1, last_failed_at = VALUES(last_failed_at)"
            }
        };
        match h.backend() {
            Backend::Postgres => {
                sqlx::query(sql)
                    .bind(key)
                    .bind(now)
                    .execute(&mut *h.conn())
                    .await?;
            }
            Backend::Sqlite | Backend::MySql => {
                sqlx::query(sql)
                    .bind(key)
                    .bind(now)
                    .bind(now)
                    .execute(&mut *h.conn())
                    .await?;
            }
        }
        Self::current(&mut h, key)
            .await?
            .ok_or(DbError::RowNotFound)
    }

    /// Sets (or clears, with `None`) the lock deadline for `key`.
    pub async fn set_locked_until<'c>(
        db: impl DbConn<'c>,
        key: &str,
        locked_until: Option<i64>,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "UPDATE login_attempts SET locked_until = $1 WHERE attempt_key = $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE login_attempts SET locked_until = ? WHERE attempt_key = ?"
            }
        };
        sqlx::query(sql)
            .bind(locked_until)
            .bind(key)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// Wipes the counter for `key` — called on a successful login.
    pub async fn clear<'c>(db: impl DbConn<'c>, key: &str) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => "DELETE FROM login_attempts WHERE attempt_key = $1",
            Backend::Sqlite | Backend::MySql => "DELETE FROM login_attempts WHERE attempt_key = ?",
        };
        sqlx::query(sql).bind(key).execute(&mut *h.conn()).await?;
        Ok(())
    }
}

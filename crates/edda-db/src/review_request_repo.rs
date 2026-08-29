//! `review_requests` persistence — an outstanding ask for one user to
//! review a pull request. Created from a CODEOWNERS match on push (Phase
//! 10) or manually (Phase 11); cleared when that reviewer submits a review
//! or the request is withdrawn.

use edda_domain::{PullRequestId, ReviewRequest, ReviewRequestId, UserId};

use crate::{get_i64, get_string, Backend, DbConn, DbError};

fn row_to_request(row: &sqlx::any::AnyRow) -> Result<ReviewRequest, DbError> {
    Ok(ReviewRequest {
        id: get_string(row, "id")?
            .parse()
            .expect("stored review request id is a valid UUID"),
        pull_request_id: get_string(row, "pull_request_id")?
            .parse()
            .expect("stored pull request id is a valid UUID"),
        reviewer_id: get_string(row, "reviewer_id")?
            .parse()
            .expect("stored user id is a valid UUID"),
        created_at: get_i64(row, "created_at")?,
    })
}

pub struct ReviewRequestRepo;

impl ReviewRequestRepo {
    /// Adds a review request. A repeat request for the same
    /// (pull request, reviewer) is a no-op — `Ok(false)` means "already
    /// requested", `Ok(true)` means a new row was written.
    pub async fn insert_if_new<'c>(
        db: impl DbConn<'c>,
        id: ReviewRequestId,
        pull_request_id: PullRequestId,
        reviewer_id: UserId,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let now = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO review_requests (id, pull_request_id, reviewer_id, created_at) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING"
            }
            Backend::Sqlite => {
                "INSERT OR IGNORE INTO review_requests (id, pull_request_id, reviewer_id, created_at) \
                 VALUES (?, ?, ?, ?)"
            }
            Backend::MySql => {
                "INSERT IGNORE INTO review_requests (id, pull_request_id, reviewer_id, created_at) \
                 VALUES (?, ?, ?, ?)"
            }
        };
        let result = sqlx::query(sql)
            .bind(id.to_string())
            .bind(pull_request_id.to_string())
            .bind(reviewer_id.to_string())
            .bind(now)
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list_for_pull_request<'c>(
        db: impl DbConn<'c>,
        pull_request_id: PullRequestId,
    ) -> Result<Vec<ReviewRequest>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, pull_request_id, reviewer_id, created_at FROM review_requests \
                 WHERE pull_request_id = $1 ORDER BY created_at"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, pull_request_id, reviewer_id, created_at FROM review_requests \
                 WHERE pull_request_id = ? ORDER BY created_at"
            }
        };
        let rows = sqlx::query(sql)
            .bind(pull_request_id.to_string())
            .fetch_all(&mut *h.conn())
            .await?;
        rows.iter().map(row_to_request).collect()
    }

    /// Removes the request for one reviewer on one PR (called when that
    /// reviewer submits a review, or a maintainer withdraws the request).
    /// `Ok(true)` if a row was removed.
    pub async fn delete<'c>(
        db: impl DbConn<'c>,
        pull_request_id: PullRequestId,
        reviewer_id: UserId,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "DELETE FROM review_requests WHERE pull_request_id = $1 AND reviewer_id = $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM review_requests WHERE pull_request_id = ? AND reviewer_id = ?"
            }
        };
        let result = sqlx::query(sql)
            .bind(pull_request_id.to_string())
            .bind(reviewer_id.to_string())
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

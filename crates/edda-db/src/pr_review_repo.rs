//! Pull-request review persistence. Append-only — see
//! `edda_domain::PrReview`'s doc comment for why a new review never
//! deletes an earlier one from the same reviewer.

use edda_domain::{PrReview, PrReviewId, PullRequestId, ReviewState, UserId};

use crate::{get_i64, get_opt_string, get_string, Backend, DbConn, DbError};

fn row_to_review(row: sqlx::any::AnyRow) -> Result<PrReview, DbError> {
    Ok(PrReview {
        id: get_string(&row, "id")?
            .parse()
            .expect("stored review id is a valid UUID"),
        pull_request_id: get_string(&row, "pull_request_id")?
            .parse()
            .expect("stored pull request id is a valid UUID"),
        reviewer_id: get_string(&row, "reviewer_id")?
            .parse()
            .expect("stored reviewer id is a valid UUID"),
        state: ReviewState::from_db_str(&get_string(&row, "state")?)
            .expect("stored pr_reviews.state is one of the CHECK'd values"),
        body: get_opt_string(&row, "body")?,
        created_at: get_i64(&row, "created_at")?,
    })
}

pub struct PrReviewRepo;

impl PrReviewRepo {
    pub async fn insert<'c>(
        db: impl DbConn<'c>,
        id: PrReviewId,
        pull_request_id: PullRequestId,
        reviewer_id: UserId,
        state: ReviewState,
        body: Option<&str>,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let pull_request_id_text = pull_request_id.to_string();
        let reviewer_id_text = reviewer_id.to_string();
        let created_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO pr_reviews (id, pull_request_id, reviewer_id, state, body, created_at) VALUES ($1, $2, $3, $4, $5, $6)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO pr_reviews (id, pull_request_id, reviewer_id, state, body, created_at) VALUES (?, ?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(sql)
            .bind(&id_text)
            .bind(&pull_request_id_text)
            .bind(&reviewer_id_text)
            .bind(state.as_db_str())
            .bind(body)
            .bind(created_at)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// Every review ever submitted on this pull request, oldest first —
    /// callers needing only the current verdict per reviewer reduce this
    /// via `edda_domain::latest_reviews`.
    pub async fn list_for_pull_request<'c>(
        db: impl DbConn<'c>,
        pull_request_id: PullRequestId,
    ) -> Result<Vec<PrReview>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let pull_request_id_text = pull_request_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, pull_request_id, reviewer_id, state, body, created_at FROM pr_reviews WHERE pull_request_id = $1 ORDER BY created_at"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, pull_request_id, reviewer_id, state, body, created_at FROM pr_reviews WHERE pull_request_id = ? ORDER BY created_at"
            }
        };
        let rows = sqlx::query(sql)
            .bind(&pull_request_id_text)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter().map(row_to_review).collect()
    }
}

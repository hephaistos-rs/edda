//! Issue persistence. Shares its per-repository numbering sequence with
//! `pull_requests` — see `RepoNumberRepo`.

use edda_domain::{CloseReason, Issue, IssueId, IssueState, MilestoneId, RepositoryId, UserId};

use crate::repo_number_repo::{NextNumberError, RepoNumberRepo};
use crate::{get_i64, get_opt_i64, get_opt_string, get_string, Backend, DbPool};

#[derive(Debug, thiserror::Error)]
pub enum InsertIssueError {
    #[error(transparent)]
    NextNumber(#[from] NextNumberError),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

const COLUMNS: &str = "id, repository_id, number, title, body, author_id, state, closed_at, close_reason, milestone_id, created_at";

fn row_to_issue(row: sqlx::any::AnyRow) -> Result<Issue, sqlx::Error> {
    let state_str = get_string(&row, "state")?;
    let state = match state_str.as_str() {
        "open" => IssueState::Open,
        "closed" => IssueState::Closed {
            closed_at: get_opt_i64(&row, "closed_at")?
                .expect("a closed issue always has closed_at"),
            reason: get_opt_string(&row, "close_reason")?
                .and_then(|s| CloseReason::from_db_str(&s))
                .expect("a closed issue always has a valid close_reason"),
        },
        other => unreachable!("unexpected issues.state value {other:?} — schema/domain drift"),
    };

    Ok(Issue {
        id: get_string(&row, "id")?
            .parse()
            .expect("stored issue id is a valid UUID"),
        repository_id: get_string(&row, "repository_id")?
            .parse()
            .expect("stored repository id is a valid UUID"),
        number: get_i64(&row, "number")?,
        title: get_string(&row, "title")?,
        body: get_opt_string(&row, "body")?,
        author_id: get_string(&row, "author_id")?
            .parse()
            .expect("stored author id is a valid UUID"),
        state,
        milestone_id: get_opt_string(&row, "milestone_id")?
            .map(|id| id.parse().expect("stored milestone id is a valid UUID")),
        created_at: get_i64(&row, "created_at")?,
    })
}

pub struct IssueRepo;

impl IssueRepo {
    pub async fn insert(
        pool: &DbPool,
        id: IssueId,
        repository_id: RepositoryId,
        title: &str,
        body: Option<&str>,
        author_id: UserId,
    ) -> Result<i64, InsertIssueError> {
        let number = RepoNumberRepo::next_number(pool, repository_id).await?;
        let id_text = id.to_string();
        let repository_id_text = repository_id.to_string();
        let author_id_text = author_id.to_string();
        let created_at = crate::now_unix();

        let sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO issues (id, repository_id, number, title, body, author_id, state, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'open', $7)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO issues (id, repository_id, number, title, body, author_id, state, created_at) VALUES (?, ?, ?, ?, ?, ?, 'open', ?)"
            }
        };
        sqlx::query(sql)
            .bind(&id_text)
            .bind(&repository_id_text)
            .bind(number)
            .bind(title)
            .bind(body)
            .bind(&author_id_text)
            .bind(created_at)
            .execute(&pool.any)
            .await?;
        Ok(number)
    }

    pub async fn find_by_id(pool: &DbPool, id: IssueId) -> Result<Option<Issue>, sqlx::Error> {
        let id_text = id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => format!("SELECT {COLUMNS} FROM issues WHERE id = $1"),
            Backend::Sqlite | Backend::MySql => {
                format!("SELECT {COLUMNS} FROM issues WHERE id = ?")
            }
        };
        let row = sqlx::query(&sql)
            .bind(&id_text)
            .fetch_optional(&pool.any)
            .await?;
        row.map(row_to_issue).transpose()
    }

    pub async fn find_by_repository_and_number(
        pool: &DbPool,
        repository_id: RepositoryId,
        number: i64,
    ) -> Result<Option<Issue>, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                format!("SELECT {COLUMNS} FROM issues WHERE repository_id = $1 AND number = $2")
            }
            Backend::Sqlite | Backend::MySql => {
                format!("SELECT {COLUMNS} FROM issues WHERE repository_id = ? AND number = ?")
            }
        };
        let row = sqlx::query(&sql)
            .bind(&repository_id_text)
            .bind(number)
            .fetch_optional(&pool.any)
            .await?;
        row.map(row_to_issue).transpose()
    }

    pub async fn list_for_repository(
        pool: &DbPool,
        repository_id: RepositoryId,
    ) -> Result<Vec<Issue>, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                format!(
                    "SELECT {COLUMNS} FROM issues WHERE repository_id = $1 ORDER BY number DESC"
                )
            }
            Backend::Sqlite | Backend::MySql => {
                format!("SELECT {COLUMNS} FROM issues WHERE repository_id = ? ORDER BY number DESC")
            }
        };
        let rows = sqlx::query(&sql)
            .bind(&repository_id_text)
            .fetch_all(&pool.any)
            .await?;
        rows.into_iter().map(row_to_issue).collect()
    }

    pub async fn update_state(
        pool: &DbPool,
        id: IssueId,
        state: &IssueState,
    ) -> Result<(), sqlx::Error> {
        let (state_str, closed_at, close_reason) = match state {
            IssueState::Open => ("open", None, None),
            IssueState::Closed { closed_at, reason } => {
                ("closed", Some(*closed_at), Some(reason.as_db_str()))
            }
        };
        let id_text = id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "UPDATE issues SET state = $1, closed_at = $2, close_reason = $3 WHERE id = $4"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE issues SET state = ?, closed_at = ?, close_reason = ? WHERE id = ?"
            }
        };
        sqlx::query(sql)
            .bind(state_str)
            .bind(closed_at)
            .bind(close_reason)
            .bind(&id_text)
            .execute(&pool.any)
            .await?;
        Ok(())
    }

    pub async fn set_milestone(
        pool: &DbPool,
        id: IssueId,
        milestone_id: Option<MilestoneId>,
    ) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        let milestone_id_text = milestone_id.map(|id| id.to_string());
        let sql = match pool.backend {
            Backend::Postgres => "UPDATE issues SET milestone_id = $1 WHERE id = $2",
            Backend::Sqlite | Backend::MySql => "UPDATE issues SET milestone_id = ? WHERE id = ?",
        };
        sqlx::query(sql)
            .bind(&milestone_id_text)
            .bind(&id_text)
            .execute(&pool.any)
            .await?;
        Ok(())
    }
}

use edda_domain::{IssueComment, IssueCommentId, IssueId, UserId};

use crate::{get_i64, get_string, Backend, DbPool};

fn row_to_comment(row: sqlx::any::AnyRow) -> Result<IssueComment, sqlx::Error> {
    Ok(IssueComment {
        id: get_string(&row, "id")?
            .parse()
            .expect("stored comment id is a valid UUID"),
        issue_id: get_string(&row, "issue_id")?
            .parse()
            .expect("stored issue id is a valid UUID"),
        author_id: get_string(&row, "author_id")?
            .parse()
            .expect("stored author id is a valid UUID"),
        body: get_string(&row, "body")?,
        created_at: get_i64(&row, "created_at")?,
    })
}

pub struct IssueCommentRepo;

impl IssueCommentRepo {
    pub async fn insert(
        pool: &DbPool,
        id: IssueCommentId,
        issue_id: IssueId,
        author_id: UserId,
        body: &str,
    ) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        let issue_id_text = issue_id.to_string();
        let author_id_text = author_id.to_string();
        let created_at = crate::now_unix();
        let sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO issue_comments (id, issue_id, author_id, body, created_at) VALUES ($1, $2, $3, $4, $5)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO issue_comments (id, issue_id, author_id, body, created_at) VALUES (?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(sql)
            .bind(&id_text)
            .bind(&issue_id_text)
            .bind(&author_id_text)
            .bind(body)
            .bind(created_at)
            .execute(&pool.any)
            .await?;
        Ok(())
    }

    pub async fn list_for_issue(
        pool: &DbPool,
        issue_id: IssueId,
    ) -> Result<Vec<IssueComment>, sqlx::Error> {
        let issue_id_text = issue_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT id, issue_id, author_id, body, created_at FROM issue_comments WHERE issue_id = $1 ORDER BY created_at"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, issue_id, author_id, body, created_at FROM issue_comments WHERE issue_id = ? ORDER BY created_at"
            }
        };
        let rows = sqlx::query(sql)
            .bind(&issue_id_text)
            .fetch_all(&pool.any)
            .await?;
        rows.into_iter().map(row_to_comment).collect()
    }
}

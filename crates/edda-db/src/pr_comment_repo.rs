//! Pull-request comment persistence — general and diff-anchored comments
//! in one table; see `edda_domain::PrComment`'s doc comment for why.

use edda_domain::{DiffAnchor, PrComment, PrCommentId, PullRequestId, UserId};

use crate::{get_i64, get_opt_i64, get_opt_string, get_string, Backend, DbPool};

fn row_to_comment(row: sqlx::any::AnyRow) -> Result<PrComment, sqlx::Error> {
    let anchor_file_path = get_opt_string(&row, "anchor_file_path")?;
    let anchor = match anchor_file_path {
        Some(file_path) => Some(DiffAnchor {
            file_path,
            line_range: (
                get_opt_i64(&row, "anchor_line_start")?
                    .expect("an anchored comment always has anchor_line_start")
                    as u32,
                get_opt_i64(&row, "anchor_line_end")?
                    .expect("an anchored comment always has anchor_line_end")
                    as u32,
            ),
            commit_sha: get_opt_string(&row, "anchor_commit_sha")?
                .expect("an anchored comment always has anchor_commit_sha"),
        }),
        None => None,
    };

    Ok(PrComment {
        id: get_string(&row, "id")?
            .parse()
            .expect("stored comment id is a valid UUID"),
        pull_request_id: get_string(&row, "pull_request_id")?
            .parse()
            .expect("stored pull request id is a valid UUID"),
        author_id: get_string(&row, "author_id")?
            .parse()
            .expect("stored author id is a valid UUID"),
        body: get_string(&row, "body")?,
        anchor,
        created_at: get_i64(&row, "created_at")?,
    })
}

const COLUMNS: &str = "id, pull_request_id, author_id, body, anchor_file_path, anchor_line_start, anchor_line_end, anchor_commit_sha, created_at";

pub struct PrCommentRepo;

impl PrCommentRepo {
    pub async fn insert(
        pool: &DbPool,
        id: PrCommentId,
        pull_request_id: PullRequestId,
        author_id: UserId,
        body: &str,
        anchor: Option<&DiffAnchor>,
    ) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        let pull_request_id_text = pull_request_id.to_string();
        let author_id_text = author_id.to_string();
        let created_at = crate::now_unix();
        let (file_path, line_start, line_end, commit_sha) = match anchor {
            Some(anchor) => (
                Some(anchor.file_path.as_str()),
                Some(anchor.line_range.0 as i64),
                Some(anchor.line_range.1 as i64),
                Some(anchor.commit_sha.as_str()),
            ),
            None => (None, None, None, None),
        };

        let sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO pr_comments (id, pull_request_id, author_id, body, anchor_file_path, anchor_line_start, anchor_line_end, anchor_commit_sha, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO pr_comments (id, pull_request_id, author_id, body, anchor_file_path, anchor_line_start, anchor_line_end, anchor_commit_sha, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(sql)
            .bind(&id_text)
            .bind(&pull_request_id_text)
            .bind(&author_id_text)
            .bind(body)
            .bind(file_path)
            .bind(line_start)
            .bind(line_end)
            .bind(commit_sha)
            .bind(created_at)
            .execute(&pool.any)
            .await?;
        Ok(())
    }

    pub async fn list_for_pull_request(
        pool: &DbPool,
        pull_request_id: PullRequestId,
    ) -> Result<Vec<PrComment>, sqlx::Error> {
        let pull_request_id_text = pull_request_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                format!("SELECT {COLUMNS} FROM pr_comments WHERE pull_request_id = $1 ORDER BY created_at")
            }
            Backend::Sqlite | Backend::MySql => {
                format!("SELECT {COLUMNS} FROM pr_comments WHERE pull_request_id = ? ORDER BY created_at")
            }
        };
        let rows = sqlx::query(&sql)
            .bind(&pull_request_id_text)
            .fetch_all(&pool.any)
            .await?;
        rows.into_iter().map(row_to_comment).collect()
    }
}

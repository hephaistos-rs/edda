//! `commit_statuses` persistence — one row per (repository, commit,
//! context). A repeat report for the same context overwrites its state;
//! `can_merge_pull_request` reads the set for a PR's head commit.

use edda_domain::{CommitStatus, CommitStatusId, CommitStatusState, RepositoryId};

use crate::{get_i64, get_opt_string, get_string, Backend, DbConn, DbError};

fn row_to_status(row: &sqlx::any::AnyRow) -> Result<CommitStatus, DbError> {
    Ok(CommitStatus {
        id: get_string(row, "id")?
            .parse()
            .expect("stored commit status id is a valid UUID"),
        repository_id: get_string(row, "repository_id")?
            .parse()
            .expect("stored repository id is a valid UUID"),
        commit_sha: get_string(row, "commit_sha")?,
        context: get_string(row, "context")?,
        state: CommitStatusState::from_db_str(&get_string(row, "state")?)
            .expect("stored commit_statuses.state is one of the CHECK-constrained values"),
        target_url: get_opt_string(row, "target_url")?,
        description: get_opt_string(row, "description")?,
        created_at: get_i64(row, "created_at")?,
        updated_at: get_i64(row, "updated_at")?,
    })
}

pub struct CommitStatusRepo;

impl CommitStatusRepo {
    /// Records (or updates, for a repeat `context`) an external status
    /// report. Returns the row id — the passed `id` on first report for
    /// that context, the existing row's id on a repeat.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert<'c>(
        db: impl DbConn<'c>,
        id: CommitStatusId,
        repository_id: RepositoryId,
        commit_sha: &str,
        context: &str,
        state: CommitStatusState,
        target_url: Option<&str>,
        description: Option<&str>,
    ) -> Result<CommitStatusId, DbError> {
        let mut h = crate::conn::open(db).await?;
        let repo_text = repository_id.to_string();
        let now = crate::now_unix();

        let find_sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id FROM commit_statuses \
                 WHERE repository_id = $1 AND commit_sha = $2 AND context = $3"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id FROM commit_statuses \
                 WHERE repository_id = ? AND commit_sha = ? AND context = ?"
            }
        };
        let existing = sqlx::query(find_sql)
            .bind(&repo_text)
            .bind(commit_sha)
            .bind(context)
            .fetch_optional(&mut *h.conn())
            .await?;

        if let Some(row) = existing {
            let existing_id: CommitStatusId = get_string(&row, "id")?
                .parse()
                .expect("stored commit status id is a valid UUID");
            let update_sql = match h.backend() {
                Backend::Postgres => {
                    "UPDATE commit_statuses SET state = $1, target_url = $2, description = $3, \
                     updated_at = $4 WHERE id = $5"
                }
                Backend::Sqlite | Backend::MySql => {
                    "UPDATE commit_statuses SET state = ?, target_url = ?, description = ?, \
                     updated_at = ? WHERE id = ?"
                }
            };
            sqlx::query(update_sql)
                .bind(state.as_db_str())
                .bind(target_url)
                .bind(description)
                .bind(now)
                .bind(existing_id.to_string())
                .execute(&mut *h.conn())
                .await?;
            return Ok(existing_id);
        }

        let insert_sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO commit_statuses \
                 (id, repository_id, commit_sha, context, state, target_url, description, \
                  created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO commit_statuses \
                 (id, repository_id, commit_sha, context, state, target_url, description, \
                  created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
            }
        };
        let mut q = sqlx::query(insert_sql)
            .bind(id.to_string())
            .bind(&repo_text)
            .bind(commit_sha)
            .bind(context)
            .bind(state.as_db_str())
            .bind(target_url)
            .bind(description)
            .bind(now);
        if h.backend() != Backend::Postgres {
            q = q.bind(now);
        }
        q.execute(&mut *h.conn()).await?;
        Ok(id)
    }

    /// Every recorded status for one commit, newest first.
    pub async fn list_for_commit<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
        commit_sha: &str,
    ) -> Result<Vec<CommitStatus>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, repository_id, commit_sha, context, state, target_url, description, \
                 created_at, updated_at FROM commit_statuses \
                 WHERE repository_id = $1 AND commit_sha = $2 ORDER BY updated_at DESC"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, repository_id, commit_sha, context, state, target_url, description, \
                 created_at, updated_at FROM commit_statuses \
                 WHERE repository_id = ? AND commit_sha = ? ORDER BY updated_at DESC"
            }
        };
        let rows = sqlx::query(sql)
            .bind(repository_id.to_string())
            .bind(commit_sha)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.iter().map(row_to_status).collect()
    }
}

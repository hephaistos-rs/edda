//! Pull-request persistence. `pull_requests.state`/`merged_at`/
//! `merge_commit`/`merge_strategy`/`closed_at`/`close_reason` together
//! encode `edda_domain::PrState`'s four variants — `row_to_pull_request`
//! is the one place that reconstructs the enum from those columns.

use edda_domain::{
    CloseReason, MergeStrategy, PrRef, PrState, PullRequest, PullRequestId, RepositoryId, UserId,
};

use crate::repo_number_repo::{NextNumberError, RepoNumberRepo};
use crate::{get_i64, get_opt_i64, get_opt_string, get_string, Backend, DbConn, DbError};

#[derive(Debug, thiserror::Error)]
pub enum InsertPullRequestError {
    #[error(transparent)]
    NextNumber(#[from] NextNumberError),
    #[error(transparent)]
    Db(#[from] DbError),
}

/// `(state, merged_at, merge_commit, merge_strategy, closed_at, close_reason)`.
type StateColumns = (
    &'static str,
    Option<i64>,
    Option<String>,
    Option<&'static str>,
    Option<i64>,
    Option<&'static str>,
);

fn state_columns(state: &PrState) -> StateColumns {
    match state {
        PrState::Open => ("open", None, None, None, None, None),
        PrState::Draft => ("draft", None, None, None, None, None),
        PrState::Merged {
            merged_at,
            merge_commit,
            strategy,
        } => (
            "merged",
            Some(*merged_at),
            Some(merge_commit.clone()),
            Some(strategy.as_db_str()),
            None,
            None,
        ),
        PrState::Closed { closed_at, reason } => (
            "closed",
            None,
            None,
            None,
            Some(*closed_at),
            Some(reason.as_db_str()),
        ),
    }
}

fn row_to_pull_request(row: sqlx::any::AnyRow) -> Result<PullRequest, DbError> {
    let state_str = get_string(&row, "state")?;
    let state = match state_str.as_str() {
        "open" => PrState::Open,
        "draft" => PrState::Draft,
        "merged" => PrState::Merged {
            merged_at: get_opt_i64(&row, "merged_at")?
                .expect("a merged pull request always has merged_at"),
            merge_commit: get_opt_string(&row, "merge_commit")?
                .expect("a merged pull request always has merge_commit"),
            strategy: get_opt_string(&row, "merge_strategy")?
                .and_then(|s| MergeStrategy::from_db_str(&s))
                .expect("a merged pull request always has a valid merge_strategy"),
        },
        "closed" => PrState::Closed {
            closed_at: get_opt_i64(&row, "closed_at")?
                .expect("a closed pull request always has closed_at"),
            reason: get_opt_string(&row, "close_reason")?
                .and_then(|s| CloseReason::from_db_str(&s))
                .expect("a closed pull request always has a valid close_reason"),
        },
        other => {
            unreachable!("unexpected pull_requests.state value {other:?} — schema/domain drift")
        }
    };

    Ok(PullRequest {
        id: get_string(&row, "id")?
            .parse()
            .expect("stored pull request id is a valid UUID"),
        repository_id: get_string(&row, "repository_id")?
            .parse()
            .expect("stored repository id is a valid UUID"),
        number: get_i64(&row, "number")?,
        title: get_string(&row, "title")?,
        body: get_opt_string(&row, "body")?,
        author_id: get_string(&row, "author_id")?
            .parse()
            .expect("stored author id is a valid UUID"),
        source: PrRef {
            repository_id: get_string(&row, "source_repository_id")?
                .parse()
                .expect("stored source repository id is a valid UUID"),
            branch: get_string(&row, "source_branch")?,
        },
        target: get_string(&row, "target_branch")?,
        state,
        created_at: get_i64(&row, "created_at")?,
    })
}

const COLUMNS: &str = "id, repository_id, number, title, body, author_id, source_repository_id, source_branch, target_branch, state, merged_at, merge_commit, merge_strategy, closed_at, close_reason, created_at";

/// The fields a caller supplies when opening a pull request — bundled
/// into one struct (rather than `PullRequestRepo::insert` taking each as
/// its own argument) purely to stay under clippy's argument-count lint;
/// `db`/`id`/`repository_id` stay top-level params, matching every
/// other repo method's `db`-then-`id` convention.
pub struct NewPullRequest<'a> {
    pub title: &'a str,
    pub body: Option<&'a str>,
    pub author_id: UserId,
    pub source: &'a PrRef,
    pub target: &'a str,
    pub draft: bool,
}

pub struct PullRequestRepo;

impl PullRequestRepo {
    /// Allocates the next number for `repository_id` and inserts a new,
    /// `Open` pull request. `new.source.repository_id` must equal
    /// `repository_id` — only same-repository pull requests are supported
    /// (see `edda_domain::pull_request`'s module doc comment);
    /// callers construct `source` from the same repository they're
    /// opening the PR in.
    pub async fn insert<'c>(
        db: impl DbConn<'c>,
        id: PullRequestId,
        repository_id: RepositoryId,
        new: NewPullRequest<'_>,
    ) -> Result<i64, InsertPullRequestError> {
        let mut h = crate::conn::open(db).await?;
        let NewPullRequest {
            title,
            body,
            author_id,
            source,
            target,
            draft,
        } = new;
        let number = RepoNumberRepo::next_number(&mut h, repository_id).await?;
        let id_text = id.to_string();
        let repository_id_text = repository_id.to_string();
        let author_id_text = author_id.to_string();
        let source_repository_id_text = source.repository_id.to_string();
        let state = if draft { "draft" } else { "open" };
        let created_at = crate::now_unix();

        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO pull_requests (id, repository_id, number, title, body, author_id, source_repository_id, source_branch, target_branch, state, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO pull_requests (id, repository_id, number, title, body, author_id, source_repository_id, source_branch, target_branch, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(sql)
            .bind(&id_text)
            .bind(&repository_id_text)
            .bind(number)
            .bind(title)
            .bind(body)
            .bind(&author_id_text)
            .bind(&source_repository_id_text)
            .bind(&source.branch)
            .bind(target)
            .bind(state)
            .bind(created_at)
            .execute(&mut *h.conn())
            .await
            .map_err(DbError::from)?;
        Ok(number)
    }

    pub async fn find_by_id<'c>(
        db: impl DbConn<'c>,
        id: PullRequestId,
    ) -> Result<Option<PullRequest>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => format!("SELECT {COLUMNS} FROM pull_requests WHERE id = $1"),
            Backend::Sqlite | Backend::MySql => {
                format!("SELECT {COLUMNS} FROM pull_requests WHERE id = ?")
            }
        };
        let row = sqlx::query(&sql)
            .bind(&id_text)
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(row_to_pull_request).transpose()
    }

    pub async fn find_by_repository_and_number<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
        number: i64,
    ) -> Result<Option<PullRequest>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let repository_id_text = repository_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                format!(
                    "SELECT {COLUMNS} FROM pull_requests WHERE repository_id = $1 AND number = $2"
                )
            }
            Backend::Sqlite | Backend::MySql => {
                format!(
                    "SELECT {COLUMNS} FROM pull_requests WHERE repository_id = ? AND number = ?"
                )
            }
        };
        let row = sqlx::query(&sql)
            .bind(&repository_id_text)
            .bind(number)
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(row_to_pull_request).transpose()
    }

    /// Every pull request in `repository_id`, most recently created first.
    pub async fn list_for_repository<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
    ) -> Result<Vec<PullRequest>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let repository_id_text = repository_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                format!("SELECT {COLUMNS} FROM pull_requests WHERE repository_id = $1 ORDER BY number DESC")
            }
            Backend::Sqlite | Backend::MySql => {
                format!("SELECT {COLUMNS} FROM pull_requests WHERE repository_id = ? ORDER BY number DESC")
            }
        };
        let rows = sqlx::query(&sql)
            .bind(&repository_id_text)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter().map(row_to_pull_request).collect()
    }

    /// Transitions a pull request to any of `PrState`'s four variants —
    /// the one place that writes `pull_requests.state` and its
    /// variant-specific columns. Callers are responsible for the
    /// transition being valid (this method does not check the *current*
    /// state); `edda-http`'s handlers only ever call this from a state
    /// they've already verified is `Open`/`Draft`.
    pub async fn update_state<'c>(
        db: impl DbConn<'c>,
        id: PullRequestId,
        state: &PrState,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let (state_str, merged_at, merge_commit, merge_strategy, closed_at, close_reason) =
            state_columns(state);
        let id_text = id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "UPDATE pull_requests SET state = $1, merged_at = $2, merge_commit = $3, merge_strategy = $4, closed_at = $5, close_reason = $6 WHERE id = $7"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE pull_requests SET state = ?, merged_at = ?, merge_commit = ?, merge_strategy = ?, closed_at = ?, close_reason = ? WHERE id = ?"
            }
        };
        sqlx::query(sql)
            .bind(state_str)
            .bind(merged_at)
            .bind(merge_commit)
            .bind(merge_strategy)
            .bind(closed_at)
            .bind(close_reason)
            .bind(&id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }
}

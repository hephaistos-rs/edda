//! Allocates the next pull-request/issue number for a repository —
//! `pull_requests.number` and `issues.number` share one sequence per
//! repository (see `edda_domain::PullRequest`'s doc comment), backed by
//! `repo_number_counters`.
//!
//! Allocation is a bounded compare-and-swap retry loop
//! (`UPDATE ... WHERE next_number = ?`), not `SELECT ... FOR UPDATE` (not
//! valid SQL on SQLite) or an `UPDATE ... RETURNING` (not reliably usable
//! through `sqlx::Any` on MySQL/MariaDB) — the same portable optimistic-
//! concurrency idiom `apply_ref_update` already uses for git ref updates.

use edda_domain::RepositoryId;

use crate::{Backend, DbPool};

const MAX_ATTEMPTS: u32 = 10;

#[derive(Debug, thiserror::Error)]
pub enum NextNumberError {
    #[error("could not allocate a pull-request/issue number after {0} attempts — high contention on this repository")]
    Contended(u32),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

pub struct RepoNumberRepo;

impl RepoNumberRepo {
    /// Returns the next number to use for a new pull request or issue in
    /// `repository_id`, incrementing the counter atomically. Lazily
    /// creates the counter row (starting at 1) the first time a given
    /// repository needs one, so repository creation itself doesn't need
    /// to know about this table.
    pub async fn next_number(
        pool: &DbPool,
        repository_id: RepositoryId,
    ) -> Result<i64, NextNumberError> {
        let repository_id_text = repository_id.to_string();
        Self::ensure_counter_row(pool, &repository_id_text).await?;

        for _ in 0..MAX_ATTEMPTS {
            let current = Self::read_current(pool, &repository_id_text).await?;
            if Self::try_advance(pool, &repository_id_text, current).await? {
                return Ok(current);
            }
            // Someone else's allocation won the race — retry with a fresh read.
        }
        Err(NextNumberError::Contended(MAX_ATTEMPTS))
    }

    async fn ensure_counter_row(pool: &DbPool, repository_id: &str) -> Result<(), sqlx::Error> {
        let sql = match pool.backend {
            Backend::Sqlite => {
                "INSERT INTO repo_number_counters (repository_id, next_number) VALUES (?, 1) ON CONFLICT (repository_id) DO NOTHING"
            }
            Backend::Postgres => {
                "INSERT INTO repo_number_counters (repository_id, next_number) VALUES ($1, 1) ON CONFLICT (repository_id) DO NOTHING"
            }
            Backend::MySql => {
                "INSERT IGNORE INTO repo_number_counters (repository_id, next_number) VALUES (?, 1)"
            }
        };
        sqlx::query(sql)
            .bind(repository_id)
            .execute(&pool.any)
            .await?;
        Ok(())
    }

    async fn read_current(pool: &DbPool, repository_id: &str) -> Result<i64, sqlx::Error> {
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT next_number FROM repo_number_counters WHERE repository_id = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT next_number FROM repo_number_counters WHERE repository_id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(repository_id)
            .fetch_one(&pool.any)
            .await?;
        crate::get_i64(&row, "next_number")
    }

    /// `true` if this call won the compare-and-swap (no concurrent
    /// allocation advanced the counter first).
    async fn try_advance(
        pool: &DbPool,
        repository_id: &str,
        expected_current: i64,
    ) -> Result<bool, sqlx::Error> {
        let sql = match pool.backend {
            Backend::Postgres => {
                "UPDATE repo_number_counters SET next_number = $1 WHERE repository_id = $2 AND next_number = $3"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE repo_number_counters SET next_number = ? WHERE repository_id = ? AND next_number = ?"
            }
        };
        let result = sqlx::query(sql)
            .bind(expected_current + 1)
            .bind(repository_id)
            .bind(expected_current)
            .execute(&pool.any)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edda_domain::UserId;

    async fn insert_repo(pool: &DbPool, username: &str) -> RepositoryId {
        let owner = UserId::new();
        crate::UserRepo::insert(
            pool,
            owner,
            username,
            &format!("{username}@example.com"),
            "x",
        )
        .await
        .unwrap();
        let repository = edda_domain::Repository {
            id: RepositoryId::new(),
            owner: edda_domain::RepositoryOwner::User(owner),
            name: "demo".to_string(),
            description: None,
            visibility: edda_domain::Visibility::Public,
            forked_from: None,
        };
        crate::RepositoryRepo::insert_with_owner(pool, &repository, owner)
            .await
            .unwrap();
        repository.id
    }

    #[tokio::test]
    async fn numbers_allocate_sequentially_starting_at_one() {
        let pool = crate::test_pool().await;
        let repository_id = insert_repo(&pool, "alice").await;

        assert_eq!(
            RepoNumberRepo::next_number(&pool, repository_id)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            RepoNumberRepo::next_number(&pool, repository_id)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            RepoNumberRepo::next_number(&pool, repository_id)
                .await
                .unwrap(),
            3
        );
    }

    #[tokio::test]
    async fn separate_repositories_have_independent_sequences() {
        let pool = crate::test_pool().await;
        let repo_a = insert_repo(&pool, "alice").await;
        let repo_b = insert_repo(&pool, "bob").await;

        assert_eq!(RepoNumberRepo::next_number(&pool, repo_a).await.unwrap(), 1);
        assert_eq!(RepoNumberRepo::next_number(&pool, repo_b).await.unwrap(), 1);
        assert_eq!(RepoNumberRepo::next_number(&pool, repo_a).await.unwrap(), 2);
    }
}

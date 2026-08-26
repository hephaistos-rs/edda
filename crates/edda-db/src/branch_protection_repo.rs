use edda_domain::{BranchProtectionRule, BranchProtectionRuleId, RepositoryId};

use crate::{get_i64, get_string, Backend, DbPool};

fn row_to_rule(row: sqlx::any::AnyRow) -> Result<BranchProtectionRule, sqlx::Error> {
    Ok(BranchProtectionRule {
        id: get_string(&row, "id")?
            .parse()
            .expect("stored branch protection rule id is a valid UUID"),
        repository_id: get_string(&row, "repository_id")?
            .parse()
            .expect("stored repository id is a valid UUID"),
        branch: get_string(&row, "branch")?,
        required_approvals: get_i64(&row, "required_approvals")?,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum InsertBranchProtectionError {
    #[error("branch \"{0}\" is already protected in this repository")]
    AlreadyExists(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

pub struct BranchProtectionRepo;

impl BranchProtectionRepo {
    pub async fn insert(
        pool: &DbPool,
        id: BranchProtectionRuleId,
        repository_id: RepositoryId,
        branch: &str,
        required_approvals: i64,
    ) -> Result<(), InsertBranchProtectionError> {
        let id_text = id.to_string();
        let repository_id_text = repository_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO branch_protection_rules (id, repository_id, branch, required_approvals) VALUES ($1, $2, $3, $4)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO branch_protection_rules (id, repository_id, branch, required_approvals) VALUES (?, ?, ?, ?)"
            }
        };
        let result = sqlx::query(sql)
            .bind(&id_text)
            .bind(&repository_id_text)
            .bind(branch)
            .bind(required_approvals)
            .execute(&pool.any)
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => Err(
                InsertBranchProtectionError::AlreadyExists(branch.to_string()),
            ),
            Err(err) => Err(InsertBranchProtectionError::Db(err)),
        }
    }

    pub async fn list_for_repository(
        pool: &DbPool,
        repository_id: RepositoryId,
    ) -> Result<Vec<BranchProtectionRule>, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT id, repository_id, branch, required_approvals FROM branch_protection_rules WHERE repository_id = $1 ORDER BY branch"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, repository_id, branch, required_approvals FROM branch_protection_rules WHERE repository_id = ? ORDER BY branch"
            }
        };
        let rows = sqlx::query(sql)
            .bind(&repository_id_text)
            .fetch_all(&pool.any)
            .await?;
        rows.into_iter().map(row_to_rule).collect()
    }

    pub async fn find_for_branch(
        pool: &DbPool,
        repository_id: RepositoryId,
        branch: &str,
    ) -> Result<Option<BranchProtectionRule>, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT id, repository_id, branch, required_approvals FROM branch_protection_rules WHERE repository_id = $1 AND branch = $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, repository_id, branch, required_approvals FROM branch_protection_rules WHERE repository_id = ? AND branch = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&repository_id_text)
            .bind(branch)
            .fetch_optional(&pool.any)
            .await?;
        row.map(row_to_rule).transpose()
    }

    pub async fn delete(
        pool: &DbPool,
        repository_id: RepositoryId,
        id: BranchProtectionRuleId,
    ) -> Result<bool, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let id_text = id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "DELETE FROM branch_protection_rules WHERE id = $1 AND repository_id = $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM branch_protection_rules WHERE id = ? AND repository_id = ?"
            }
        };
        let result = sqlx::query(sql)
            .bind(&id_text)
            .bind(&repository_id_text)
            .execute(&pool.any)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

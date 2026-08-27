use edda_domain::{BranchProtectionRule, BranchProtectionRuleId, RepositoryId};

use crate::{get_i64, get_string, Backend, DbConn, DbError};

fn row_to_rule(row: sqlx::any::AnyRow) -> Result<BranchProtectionRule, DbError> {
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
    Db(#[from] DbError),
}

pub struct BranchProtectionRepo;

impl BranchProtectionRepo {
    pub async fn insert<'c>(
        db: impl DbConn<'c>,
        id: BranchProtectionRuleId,
        repository_id: RepositoryId,
        branch: &str,
        required_approvals: i64,
    ) -> Result<(), InsertBranchProtectionError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let repository_id_text = repository_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO branch_protection_rules (id, repository_id, branch, required_approvals) VALUES ($1, $2, $3, $4)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO branch_protection_rules (id, repository_id, branch, required_approvals) VALUES (?, ?, ?, ?)"
            }
        };
        match sqlx::query(sql)
            .bind(&id_text)
            .bind(&repository_id_text)
            .bind(branch)
            .bind(required_approvals)
            .execute(&mut *h.conn())
            .await
            .map_err(DbError::from)
        {
            Ok(_) => Ok(()),
            Err(DbError::UniqueViolation) => Err(InsertBranchProtectionError::AlreadyExists(
                branch.to_string(),
            )),
            Err(err) => Err(InsertBranchProtectionError::Db(err)),
        }
    }

    pub async fn list_for_repository<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
    ) -> Result<Vec<BranchProtectionRule>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let repository_id_text = repository_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, repository_id, branch, required_approvals FROM branch_protection_rules WHERE repository_id = $1 ORDER BY branch"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, repository_id, branch, required_approvals FROM branch_protection_rules WHERE repository_id = ? ORDER BY branch"
            }
        };
        let rows = sqlx::query(sql)
            .bind(&repository_id_text)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter().map(row_to_rule).collect()
    }

    pub async fn find_for_branch<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
        branch: &str,
    ) -> Result<Option<BranchProtectionRule>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let repository_id_text = repository_id.to_string();
        let sql = match h.backend() {
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
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(row_to_rule).transpose()
    }

    pub async fn delete<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
        id: BranchProtectionRuleId,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let repository_id_text = repository_id.to_string();
        let id_text = id.to_string();
        let sql = match h.backend() {
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
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

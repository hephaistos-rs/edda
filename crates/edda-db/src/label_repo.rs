//! Label persistence, including the scoped-label mutual-exclusion rule:
//! applying a label unapplies any other label already applied that
//! shares its scope (`edda_domain::labels_to_unapply_for_scope` decides
//! *which*; `apply_to_issue` below is the one place that actually writes
//! that decision).

use edda_domain::{labels_to_unapply_for_scope, IssueId, Label, LabelId, RepositoryId};

use crate::{get_opt_i64, get_opt_string, get_string, Backend, DbConn, DbError};

fn row_to_label(row: sqlx::any::AnyRow) -> Result<Label, DbError> {
    Ok(Label {
        id: get_string(&row, "id")?
            .parse()
            .expect("stored label id is a valid UUID"),
        repository_id: get_string(&row, "repository_id")?
            .parse()
            .expect("stored repository id is a valid UUID"),
        name: get_string(&row, "name")?,
        color: get_string(&row, "color")?,
        description: get_opt_string(&row, "description")?,
        archived_at: get_opt_i64(&row, "archived_at")?,
    })
}

const COLUMNS: &str = "id, repository_id, name, color, description, archived_at";

#[derive(Debug, thiserror::Error)]
pub enum InsertLabelError {
    #[error("a label named \"{0}\" already exists in this repository")]
    AlreadyExists(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

pub struct LabelRepo;

impl LabelRepo {
    pub async fn insert<'c>(
        db: impl DbConn<'c>,
        id: LabelId,
        repository_id: RepositoryId,
        name: &str,
        color: &str,
        description: Option<&str>,
    ) -> Result<(), InsertLabelError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let repository_id_text = repository_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO labels (id, repository_id, name, color, description) VALUES ($1, $2, $3, $4, $5)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO labels (id, repository_id, name, color, description) VALUES (?, ?, ?, ?, ?)"
            }
        };
        match sqlx::query(sql)
            .bind(&id_text)
            .bind(&repository_id_text)
            .bind(name)
            .bind(color)
            .bind(description)
            .execute(&mut *h.conn())
            .await
            .map_err(DbError::from)
        {
            Ok(_) => Ok(()),
            Err(DbError::UniqueViolation) => Err(InsertLabelError::AlreadyExists(name.to_string())),
            Err(err) => Err(InsertLabelError::Db(err)),
        }
    }

    pub async fn list_for_repository<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
    ) -> Result<Vec<Label>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let repository_id_text = repository_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                format!("SELECT {COLUMNS} FROM labels WHERE repository_id = $1 ORDER BY name")
            }
            Backend::Sqlite | Backend::MySql => {
                format!("SELECT {COLUMNS} FROM labels WHERE repository_id = ? ORDER BY name")
            }
        };
        let rows = sqlx::query(&sql)
            .bind(&repository_id_text)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter().map(row_to_label).collect()
    }

    pub async fn list_for_issue<'c>(
        db: impl DbConn<'c>,
        issue_id: IssueId,
    ) -> Result<Vec<Label>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let issue_id_text = issue_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT l.id, l.repository_id, l.name, l.color, l.description, l.archived_at \
                 FROM labels l JOIN issue_labels il ON il.label_id = l.id \
                 WHERE il.issue_id = $1 ORDER BY l.name"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT l.id, l.repository_id, l.name, l.color, l.description, l.archived_at \
                 FROM labels l JOIN issue_labels il ON il.label_id = l.id \
                 WHERE il.issue_id = ? ORDER BY l.name"
            }
        };
        let rows = sqlx::query(sql)
            .bind(&issue_id_text)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter().map(row_to_label).collect()
    }

    /// Applies `label` to `issue_id`, first unapplying any other label
    /// already on the issue that shares `label`'s scope (at most one
    /// label per scope — see this module's doc comment). All in one
    /// transaction: a reader must never observe the issue holding two
    /// same-scope labels at once, even momentarily. Composes: when
    /// `db` is already a caller transaction this runs as a savepoint.
    pub async fn apply_to_issue<'c>(
        db: impl DbConn<'c>,
        issue_id: IssueId,
        label: &Label,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let backend = h.backend();
        let issue_id_text = issue_id.to_string();
        let mut tx = h.begin().await?;

        let currently_applied = {
            let sql = match backend {
                Backend::Postgres => {
                    "SELECT l.id, l.repository_id, l.name, l.color, l.description, l.archived_at \
                     FROM labels l JOIN issue_labels il ON il.label_id = l.id \
                     WHERE il.issue_id = $1"
                }
                Backend::Sqlite | Backend::MySql => {
                    "SELECT l.id, l.repository_id, l.name, l.color, l.description, l.archived_at \
                     FROM labels l JOIN issue_labels il ON il.label_id = l.id \
                     WHERE il.issue_id = ?"
                }
            };
            let rows = sqlx::query(sql)
                .bind(&issue_id_text)
                .fetch_all(&mut *tx)
                .await?;
            rows.into_iter()
                .map(row_to_label)
                .collect::<Result<Vec<_>, _>>()?
        };

        for stale in labels_to_unapply_for_scope(&currently_applied, label) {
            let stale_id_text = stale.id.to_string();
            let sql = match backend {
                Backend::Postgres => {
                    "DELETE FROM issue_labels WHERE issue_id = $1 AND label_id = $2"
                }
                Backend::Sqlite | Backend::MySql => {
                    "DELETE FROM issue_labels WHERE issue_id = ? AND label_id = ?"
                }
            };
            sqlx::query(sql)
                .bind(&issue_id_text)
                .bind(&stale_id_text)
                .execute(&mut *tx)
                .await?;
        }

        let label_id_text = label.id.to_string();
        let sql = match backend {
            Backend::Sqlite => {
                "INSERT INTO issue_labels (issue_id, label_id) VALUES (?, ?) ON CONFLICT (issue_id, label_id) DO NOTHING"
            }
            Backend::Postgres => {
                "INSERT INTO issue_labels (issue_id, label_id) VALUES ($1, $2) ON CONFLICT (issue_id, label_id) DO NOTHING"
            }
            Backend::MySql => "INSERT IGNORE INTO issue_labels (issue_id, label_id) VALUES (?, ?)",
        };
        sqlx::query(sql)
            .bind(&issue_id_text)
            .bind(&label_id_text)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn remove_from_issue<'c>(
        db: impl DbConn<'c>,
        issue_id: IssueId,
        label_id: LabelId,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let issue_id_text = issue_id.to_string();
        let label_id_text = label_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => "DELETE FROM issue_labels WHERE issue_id = $1 AND label_id = $2",
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM issue_labels WHERE issue_id = ? AND label_id = ?"
            }
        };
        sqlx::query(sql)
            .bind(&issue_id_text)
            .bind(&label_id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }
}

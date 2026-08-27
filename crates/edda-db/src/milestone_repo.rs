use edda_domain::{Milestone, MilestoneId, MilestoneState, RepositoryId};

use crate::{get_opt_i64, get_opt_string, get_string, Backend, DbConn, DbError};

fn row_to_milestone(row: sqlx::any::AnyRow) -> Result<Milestone, DbError> {
    Ok(Milestone {
        id: get_string(&row, "id")?
            .parse()
            .expect("stored milestone id is a valid UUID"),
        repository_id: get_string(&row, "repository_id")?
            .parse()
            .expect("stored repository id is a valid UUID"),
        title: get_string(&row, "title")?,
        description: get_opt_string(&row, "description")?,
        due_on: get_opt_i64(&row, "due_on")?,
        state: MilestoneState::from_db_str(&get_string(&row, "state")?)
            .expect("stored milestones.state is one of the CHECK'd values"),
    })
}

const COLUMNS: &str = "id, repository_id, title, description, due_on, state";

pub struct MilestoneRepo;

impl MilestoneRepo {
    pub async fn insert<'c>(
        db: impl DbConn<'c>,
        id: MilestoneId,
        repository_id: RepositoryId,
        title: &str,
        description: Option<&str>,
        due_on: Option<i64>,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let repository_id_text = repository_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO milestones (id, repository_id, title, description, due_on, state) VALUES ($1, $2, $3, $4, $5, 'open')"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO milestones (id, repository_id, title, description, due_on, state) VALUES (?, ?, ?, ?, ?, 'open')"
            }
        };
        sqlx::query(sql)
            .bind(&id_text)
            .bind(&repository_id_text)
            .bind(title)
            .bind(description)
            .bind(due_on)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    pub async fn list_for_repository<'c>(
        db: impl DbConn<'c>,
        repository_id: RepositoryId,
    ) -> Result<Vec<Milestone>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let repository_id_text = repository_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                format!("SELECT {COLUMNS} FROM milestones WHERE repository_id = $1 ORDER BY due_on IS NULL, due_on")
            }
            Backend::Sqlite | Backend::MySql => {
                format!("SELECT {COLUMNS} FROM milestones WHERE repository_id = ? ORDER BY due_on IS NULL, due_on")
            }
        };
        let rows = sqlx::query(&sql)
            .bind(&repository_id_text)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter().map(row_to_milestone).collect()
    }

    pub async fn update_state<'c>(
        db: impl DbConn<'c>,
        id: MilestoneId,
        state: MilestoneState,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => "UPDATE milestones SET state = $1 WHERE id = $2",
            Backend::Sqlite | Backend::MySql => "UPDATE milestones SET state = ? WHERE id = ?",
        };
        sqlx::query(sql)
            .bind(state.as_db_str())
            .bind(&id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }
}

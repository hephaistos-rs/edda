use edda_domain::{Milestone, MilestoneId, MilestoneState, RepositoryId};

use crate::{get_opt_i64, get_opt_string, get_string, Backend, DbPool};

fn row_to_milestone(row: sqlx::any::AnyRow) -> Result<Milestone, sqlx::Error> {
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
    pub async fn insert(
        pool: &DbPool,
        id: MilestoneId,
        repository_id: RepositoryId,
        title: &str,
        description: Option<&str>,
        due_on: Option<i64>,
    ) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        let repository_id_text = repository_id.to_string();
        let sql = match pool.backend {
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
            .execute(&pool.any)
            .await?;
        Ok(())
    }

    pub async fn list_for_repository(
        pool: &DbPool,
        repository_id: RepositoryId,
    ) -> Result<Vec<Milestone>, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                format!("SELECT {COLUMNS} FROM milestones WHERE repository_id = $1 ORDER BY due_on IS NULL, due_on")
            }
            Backend::Sqlite | Backend::MySql => {
                format!("SELECT {COLUMNS} FROM milestones WHERE repository_id = ? ORDER BY due_on IS NULL, due_on")
            }
        };
        let rows = sqlx::query(&sql)
            .bind(&repository_id_text)
            .fetch_all(&pool.any)
            .await?;
        rows.into_iter().map(row_to_milestone).collect()
    }

    pub async fn update_state(
        pool: &DbPool,
        id: MilestoneId,
        state: MilestoneState,
    ) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => "UPDATE milestones SET state = $1 WHERE id = $2",
            Backend::Sqlite | Backend::MySql => "UPDATE milestones SET state = ? WHERE id = ?",
        };
        sqlx::query(sql)
            .bind(state.as_db_str())
            .bind(&id_text)
            .execute(&pool.any)
            .await?;
        Ok(())
    }
}

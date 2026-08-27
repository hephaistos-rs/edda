use edda_domain::{Organization, OrganizationId, TeamId, TeamPermission, UserId};

use crate::{get_opt_string, get_string, Backend, DbPool};

#[derive(Debug, thiserror::Error)]
pub enum InsertOrganizationError {
    #[error("that name is already taken")]
    NameTaken,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

fn row_to_organization(id: String, name: String, display_name: Option<String>) -> Organization {
    Organization {
        id: id.parse().expect("stored organization id is a valid UUID"),
        name,
        display_name,
    }
}

fn row_to_organization_row(row: sqlx::any::AnyRow) -> Result<Organization, sqlx::Error> {
    Ok(row_to_organization(
        get_string(&row, "id")?,
        get_string(&row, "name")?,
        get_opt_string(&row, "display_name")?,
    ))
}

pub struct OrganizationRepo;

impl OrganizationRepo {
    /// Creates the organization and its default "Owners" team in one
    /// transaction, and adds `creating_user_id` as that team's first
    /// member — an organization is never left without at least one member
    /// able to administer it. This is what a repository created under the
    /// organization later grants its `Owner` role to (see
    /// `RepositoryRepo::insert_with_owner_team`); `AccessSubject` has no
    /// separate `Organization` variant, so the Owners team's id is the
    /// closest thing an organization has to its own identity for
    /// repository-ownership purposes.
    ///
    /// Callers are responsible for the cross-namespace uniqueness check
    /// against `users.username` (`edda-auth`'s organization-creation path
    /// does this before calling here — see that module's own doc comment
    /// for why this check can't live in a single database constraint).
    pub async fn insert(
        pool: &DbPool,
        id: OrganizationId,
        name: &str,
        display_name: Option<&str>,
        creating_user_id: UserId,
    ) -> Result<TeamId, InsertOrganizationError> {
        let id_text = id.to_string();
        let created_at = crate::now_unix();

        let mut tx = pool.any.begin().await?;

        let insert_org_sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO organizations (id, name, display_name, created_at) VALUES ($1, $2, $3, $4)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO organizations (id, name, display_name, created_at) VALUES (?, ?, ?, ?)"
            }
        };
        let result = sqlx::query(insert_org_sql)
            .bind(&id_text)
            .bind(name)
            .bind(display_name)
            .bind(created_at)
            .execute(&mut *tx)
            .await;
        match result {
            Ok(_) => {}
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                return Err(InsertOrganizationError::NameTaken);
            }
            Err(err) => return Err(err.into()),
        }

        let owners_team_id = TeamId::new();
        let owners_team_id_text = owners_team_id.to_string();
        let insert_team_sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO teams (id, organization_id, name, permission, created_at) VALUES ($1, $2, $3, $4, $5)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO teams (id, organization_id, name, permission, created_at) VALUES (?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(insert_team_sql)
            .bind(&owners_team_id_text)
            .bind(&id_text)
            .bind("Owners")
            .bind(TeamPermission::Admin.as_db_str())
            .bind(created_at)
            .execute(&mut *tx)
            .await?;

        let creating_user_id_text = creating_user_id.to_string();
        let insert_member_sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO team_members (team_id, user_id, added_at) VALUES ($1, $2, $3)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO team_members (team_id, user_id, added_at) VALUES (?, ?, ?)"
            }
        };
        sqlx::query(insert_member_sql)
            .bind(&owners_team_id_text)
            .bind(&creating_user_id_text)
            .bind(created_at)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(owners_team_id)
    }

    /// Case-insensitive — organizations share `users.username`'s global
    /// identifier namespace, so this uses the exact same collation
    /// approach per backend (`COLLATE NOCASE` on SQLite, `LOWER(...)` on
    /// PostgreSQL, the `name_lower` shadow column on MySQL/MariaDB).
    pub async fn find_by_name(
        pool: &DbPool,
        name: &str,
    ) -> Result<Option<Organization>, sqlx::Error> {
        let sql = match pool.backend {
            Backend::Sqlite => "SELECT id, name, display_name FROM organizations WHERE name = ?",
            Backend::Postgres => {
                "SELECT id, name, display_name FROM organizations WHERE LOWER(name) = LOWER($1)"
            }
            Backend::MySql => {
                "SELECT id, name, display_name FROM organizations WHERE name_lower = LOWER(?)"
            }
        };
        let row = sqlx::query(sql)
            .bind(name)
            .fetch_optional(&pool.any)
            .await?;
        row.map(row_to_organization_row).transpose()
    }

    pub async fn find_by_id(
        pool: &DbPool,
        id: OrganizationId,
    ) -> Result<Option<Organization>, sqlx::Error> {
        let id_text = id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => "SELECT id, name, display_name FROM organizations WHERE id = $1",
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, name, display_name FROM organizations WHERE id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&id_text)
            .fetch_optional(&pool.any)
            .await?;
        row.map(row_to_organization_row).transpose()
    }

    /// Every organization the given user belongs to at least one team of —
    /// used to render "your organizations" without a separate
    /// org-membership concept of its own (an organization's members *are*
    /// its teams' members, per this phase's model).
    pub async fn list_for_user(
        pool: &DbPool,
        user_id: UserId,
    ) -> Result<Vec<Organization>, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                r#"SELECT DISTINCT o.id, o.name, o.display_name
                   FROM organizations o
                   JOIN teams t ON t.organization_id = o.id
                   JOIN team_members m ON m.team_id = t.id
                   WHERE m.user_id = $1
                   ORDER BY o.name"#
            }
            Backend::Sqlite | Backend::MySql => {
                r#"SELECT DISTINCT o.id, o.name, o.display_name
                   FROM organizations o
                   JOIN teams t ON t.organization_id = o.id
                   JOIN team_members m ON m.team_id = t.id
                   WHERE m.user_id = ?
                   ORDER BY o.name"#
            }
        };
        let rows = sqlx::query(sql)
            .bind(&user_id_text)
            .fetch_all(&pool.any)
            .await?;
        rows.into_iter().map(row_to_organization_row).collect()
    }
}

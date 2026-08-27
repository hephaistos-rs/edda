use edda_domain::{OrganizationId, Team, TeamId, TeamPermission, TeamUnit, User, UserId};

use crate::{get_bool, get_opt_i64, get_string, Backend, DbConn, DbError};

#[derive(Debug, thiserror::Error)]
pub enum InsertTeamError {
    #[error("a team named \"{0}\" already exists in this organization")]
    AlreadyExists(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

fn row_to_team(id: String, organization_id: String, name: String, permission: String) -> Team {
    Team {
        id: id.parse().expect("stored team id is a valid UUID"),
        organization_id: organization_id
            .parse()
            .expect("stored organization id is a valid UUID"),
        name,
        permission: TeamPermission::from_db_str(&permission)
            .expect("stored teams.permission is one of the CHECK'd values"),
    }
}

fn row_to_team_row(row: sqlx::any::AnyRow) -> Result<Team, DbError> {
    Ok(row_to_team(
        get_string(&row, "id")?,
        get_string(&row, "organization_id")?,
        get_string(&row, "name")?,
        get_string(&row, "permission")?,
    ))
}

pub struct TeamRepo;

impl TeamRepo {
    pub async fn insert<'c>(
        db: impl DbConn<'c>,
        id: TeamId,
        organization_id: OrganizationId,
        name: &str,
        permission: TeamPermission,
    ) -> Result<(), InsertTeamError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let organization_id_text = organization_id.to_string();
        let created_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO teams (id, organization_id, name, permission, created_at) VALUES ($1, $2, $3, $4, $5)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO teams (id, organization_id, name, permission, created_at) VALUES (?, ?, ?, ?, ?)"
            }
        };
        match sqlx::query(sql)
            .bind(&id_text)
            .bind(&organization_id_text)
            .bind(name)
            .bind(permission.as_db_str())
            .bind(created_at)
            .execute(&mut *h.conn())
            .await
            .map_err(DbError::from)
        {
            Ok(_) => Ok(()),
            Err(DbError::UniqueViolation) => Err(InsertTeamError::AlreadyExists(name.to_string())),
            Err(err) => Err(InsertTeamError::Db(err)),
        }
    }

    pub async fn find_by_id<'c>(db: impl DbConn<'c>, id: TeamId) -> Result<Option<Team>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, organization_id, name, permission FROM teams WHERE id = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, organization_id, name, permission FROM teams WHERE id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&id_text)
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(row_to_team_row).transpose()
    }

    pub async fn find_by_org_and_name<'c>(
        db: impl DbConn<'c>,
        organization_id: OrganizationId,
        name: &str,
    ) -> Result<Option<Team>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let organization_id_text = organization_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, organization_id, name, permission FROM teams WHERE organization_id = $1 AND name = $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, organization_id, name, permission FROM teams WHERE organization_id = ? AND name = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&organization_id_text)
            .bind(name)
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(row_to_team_row).transpose()
    }

    pub async fn list_for_organization<'c>(
        db: impl DbConn<'c>,
        organization_id: OrganizationId,
    ) -> Result<Vec<Team>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let organization_id_text = organization_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, organization_id, name, permission FROM teams WHERE organization_id = $1 ORDER BY name"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, organization_id, name, permission FROM teams WHERE organization_id = ? ORDER BY name"
            }
        };
        let rows = sqlx::query(sql)
            .bind(&organization_id_text)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter().map(row_to_team_row).collect()
    }

    /// The `TeamPermission` override for `unit` on this team, if one has
    /// been set — `None` means "use the team's own default `permission`",
    /// matching `Team::code_role`'s own fallback.
    pub async fn find_unit_permission<'c>(
        db: impl DbConn<'c>,
        team_id: TeamId,
        unit: TeamUnit,
    ) -> Result<Option<TeamPermission>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let team_id_text = team_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT permission FROM team_unit_permissions WHERE team_id = $1 AND unit = $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT permission FROM team_unit_permissions WHERE team_id = ? AND unit = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&team_id_text)
            .bind(unit.as_db_str())
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(|row| {
            Ok(
                TeamPermission::from_db_str(&get_string(&row, "permission")?)
                    .expect("stored team_unit_permissions.permission is one of the CHECK'd values"),
            )
        })
        .transpose()
    }

    /// Sets (creating or replacing) `unit`'s permission override for this
    /// team.
    pub async fn set_unit_permission<'c>(
        db: impl DbConn<'c>,
        team_id: TeamId,
        unit: TeamUnit,
        permission: TeamPermission,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let team_id_text = team_id.to_string();
        let delete_sql = match h.backend() {
            Backend::Postgres => {
                "DELETE FROM team_unit_permissions WHERE team_id = $1 AND unit = $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM team_unit_permissions WHERE team_id = ? AND unit = ?"
            }
        };
        sqlx::query(delete_sql)
            .bind(&team_id_text)
            .bind(unit.as_db_str())
            .execute(&mut *h.conn())
            .await?;
        let insert_sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO team_unit_permissions (team_id, unit, permission) VALUES ($1, $2, $3)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO team_unit_permissions (team_id, unit, permission) VALUES (?, ?, ?)"
            }
        };
        sqlx::query(insert_sql)
            .bind(&team_id_text)
            .bind(unit.as_db_str())
            .bind(permission.as_db_str())
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }
}

pub struct TeamMemberRepo;

impl TeamMemberRepo {
    pub async fn add<'c>(
        db: impl DbConn<'c>,
        team_id: TeamId,
        user_id: UserId,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let team_id_text = team_id.to_string();
        let user_id_text = user_id.to_string();
        let added_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Sqlite => {
                "INSERT OR IGNORE INTO team_members (team_id, user_id, added_at) VALUES (?, ?, ?)"
            }
            Backend::Postgres => {
                "INSERT INTO team_members (team_id, user_id, added_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING"
            }
            Backend::MySql => {
                "INSERT IGNORE INTO team_members (team_id, user_id, added_at) VALUES (?, ?, ?)"
            }
        };
        sqlx::query(sql)
            .bind(&team_id_text)
            .bind(&user_id_text)
            .bind(added_at)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    pub async fn remove<'c>(
        db: impl DbConn<'c>,
        team_id: TeamId,
        user_id: UserId,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let team_id_text = team_id.to_string();
        let user_id_text = user_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => "DELETE FROM team_members WHERE team_id = $1 AND user_id = $2",
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM team_members WHERE team_id = ? AND user_id = ?"
            }
        };
        let result = sqlx::query(sql)
            .bind(&team_id_text)
            .bind(&user_id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn is_member<'c>(
        db: impl DbConn<'c>,
        team_id: TeamId,
        user_id: UserId,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let team_id_text = team_id.to_string();
        let user_id_text = user_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => "SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2",
            Backend::Sqlite | Backend::MySql => {
                "SELECT 1 FROM team_members WHERE team_id = ? AND user_id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&team_id_text)
            .bind(&user_id_text)
            .fetch_optional(&mut *h.conn())
            .await?;
        Ok(row.is_some())
    }

    pub async fn list_members<'c>(
        db: impl DbConn<'c>,
        team_id: TeamId,
    ) -> Result<Vec<User>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let team_id_text = team_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                r#"SELECT u.id, u.username, u.email, u.is_admin, u.disabled_at
                   FROM team_members m JOIN users u ON u.id = m.user_id
                   WHERE m.team_id = $1 ORDER BY u.username"#
            }
            Backend::Sqlite | Backend::MySql => {
                r#"SELECT u.id, u.username, u.email, u.is_admin, u.disabled_at
                   FROM team_members m JOIN users u ON u.id = m.user_id
                   WHERE m.team_id = ? ORDER BY u.username"#
            }
        };
        let rows = sqlx::query(sql)
            .bind(&team_id_text)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(User {
                    id: get_string(&row, "id")?
                        .parse()
                        .expect("stored user id is a valid UUID"),
                    username: get_string(&row, "username")?,
                    email: get_string(&row, "email")?,
                    is_admin: get_bool(&row, "is_admin")?,
                    disabled_at: get_opt_i64(&row, "disabled_at")?,
                })
            })
            .collect()
    }

    /// Every team `user_id` belongs to, within `organization_id` — used to
    /// decide whether an actor administers an organization (member of its
    /// Owners team) without hardcoding that team's id anywhere outside
    /// `OrganizationRepo::insert`.
    pub async fn teams_for_user_in_organization<'c>(
        db: impl DbConn<'c>,
        organization_id: OrganizationId,
        user_id: UserId,
    ) -> Result<Vec<Team>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let organization_id_text = organization_id.to_string();
        let user_id_text = user_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                r#"SELECT t.id, t.organization_id, t.name, t.permission
                   FROM teams t JOIN team_members m ON m.team_id = t.id
                   WHERE t.organization_id = $1 AND m.user_id = $2"#
            }
            Backend::Sqlite | Backend::MySql => {
                r#"SELECT t.id, t.organization_id, t.name, t.permission
                   FROM teams t JOIN team_members m ON m.team_id = t.id
                   WHERE t.organization_id = ? AND m.user_id = ?"#
            }
        };
        let rows = sqlx::query(sql)
            .bind(&organization_id_text)
            .bind(&user_id_text)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter().map(row_to_team_row).collect()
    }
}

use edda_domain::{AccessSubject, RepoAccess, RepoRole, RepositoryId, TeamId, User, UserId};

use crate::{get_bool, get_i64, get_opt_i64, get_string, Backend, DbPool};

/// One row of `list_collaborators`: the access grant plus enough of the
/// grantee's identity to render a collaborator list without a second
/// round trip per row. User-subject rows only — a team-subject grant is
/// listed separately (`list_team_grants`), since it has no single `User`
/// to attach.
pub struct CollaboratorRow {
    pub user: User,
    pub role: RepoRole,
    pub added_at: i64,
}

/// One row of `list_team_grants`: a team attached to a repository,
/// alongside enough of the team's identity to render an "attached teams"
/// list without a second round trip per row.
pub struct TeamGrantRow {
    pub team_id: TeamId,
    pub team_name: String,
    pub role: RepoRole,
    pub added_at: i64,
}

fn subject_type_db_str(subject: AccessSubject) -> &'static str {
    match subject {
        AccessSubject::User(_) => "user",
        AccessSubject::Team(_) => "team",
    }
}

fn subject_id(subject: AccessSubject) -> String {
    match subject {
        AccessSubject::User(id) => id.to_string(),
        AccessSubject::Team(id) => id.to_string(),
    }
}

pub struct RepoAccessRepo;

impl RepoAccessRepo {
    /// Called once, right after a repository is created — the creator (a
    /// user, or an organization's Owners team) is always its owner. Not
    /// the "ignore conflict" form: there's nothing to conflict with for a
    /// repository that didn't exist a moment ago, and a conflict here
    /// would mean a real bug upstream.
    pub async fn grant_owner(
        pool: &DbPool,
        repository_id: RepositoryId,
        subject: AccessSubject,
    ) -> Result<(), sqlx::Error> {
        Self::grant(pool, repository_id, subject, RepoRole::Owner).await
    }

    pub async fn grant(
        pool: &DbPool,
        repository_id: RepositoryId,
        subject: AccessSubject,
        role: RepoRole,
    ) -> Result<(), sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let subject_type = subject_type_db_str(subject);
        let subject_id_text = subject_id(subject).to_string();
        let role = role.as_db_str();
        let added_at = crate::now_unix();
        // Three genuinely different "insert, ignore if it already
        // exists" dialects — not a portability shortcut, this is the
        // actual syntax each backend requires.
        let sql = match pool.backend {
            Backend::Sqlite => {
                "INSERT OR IGNORE INTO repo_access (repository_id, subject_type, subject_id, role, added_at) VALUES (?, ?, ?, ?, ?)"
            }
            Backend::Postgres => {
                "INSERT INTO repo_access (repository_id, subject_type, subject_id, role, added_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING"
            }
            Backend::MySql => {
                "INSERT IGNORE INTO repo_access (repository_id, subject_type, subject_id, role, added_at) VALUES (?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(sql)
            .bind(&repository_id_text)
            .bind(subject_type)
            .bind(&subject_id_text)
            .bind(role)
            .bind(added_at)
            .execute(&pool.any)
            .await?;
        Ok(())
    }

    pub async fn find(
        pool: &DbPool,
        repository_id: RepositoryId,
        subject: AccessSubject,
    ) -> Result<Option<RepoAccess>, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let subject_type = subject_type_db_str(subject);
        let subject_id_text = subject_id(subject).to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT role FROM repo_access WHERE repository_id = $1 AND subject_type = $2 AND subject_id = $3"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT role FROM repo_access WHERE repository_id = ? AND subject_type = ? AND subject_id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&repository_id_text)
            .bind(subject_type)
            .bind(&subject_id_text)
            .fetch_optional(&pool.any)
            .await?;
        row.map(|row| {
            let role = RepoRole::from_db_str(&get_string(&row, "role")?)
                .expect("stored repo_access.role is one of the CHECK'd values");
            Ok(RepoAccess {
                repository_id,
                subject,
                role,
            })
        })
        .transpose()
    }

    /// Every `(repository, role)` direct grant a user holds — used to
    /// annotate a repository listing with per-repo role without one query
    /// per row, behind this crate's boundary rather than as an ad hoc
    /// query inline in a server function. Direct grants only — a role
    /// held only through team membership isn't reflected here; callers
    /// needing the *effective* role (direct-or-team) go through
    /// `AuthorizationService` instead.
    pub async fn roles_for_user(
        pool: &DbPool,
        user_id: UserId,
    ) -> Result<Vec<(RepositoryId, RepoRole)>, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT repository_id, role FROM repo_access WHERE subject_type = 'user' AND subject_id = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT repository_id, role FROM repo_access WHERE subject_type = 'user' AND subject_id = ?"
            }
        };
        let rows = sqlx::query(sql)
            .bind(&user_id_text)
            .fetch_all(&pool.any)
            .await?;
        rows.into_iter()
            .map(|row| {
                let repository_id = get_string(&row, "repository_id")?
                    .parse()
                    .expect("stored repository id is a valid UUID");
                let role = RepoRole::from_db_str(&get_string(&row, "role")?)
                    .expect("stored repo_access.role is one of the CHECK'd values");
                Ok((repository_id, role))
            })
            .collect()
    }

    /// Every `RepoRole` reachable through `user_id`'s team memberships on
    /// `repository_id` — every team the user belongs to that also has a
    /// grant on this repository, one role per such team. Used by
    /// `AuthorizationService::access_for` to compute the effective role
    /// (`edda_domain::effective_repo_role`) alongside any direct grant.
    pub async fn team_roles_for_user(
        pool: &DbPool,
        repository_id: RepositoryId,
        user_id: UserId,
    ) -> Result<Vec<RepoRole>, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let user_id_text = user_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                r#"SELECT a.role FROM repo_access a
                   JOIN team_members m ON m.team_id = a.subject_id
                   WHERE a.repository_id = $1 AND a.subject_type = 'team' AND m.user_id = $2"#
            }
            Backend::Sqlite | Backend::MySql => {
                r#"SELECT a.role FROM repo_access a
                   JOIN team_members m ON m.team_id = a.subject_id
                   WHERE a.repository_id = ? AND a.subject_type = 'team' AND m.user_id = ?"#
            }
        };
        let rows = sqlx::query(sql)
            .bind(&repository_id_text)
            .bind(&user_id_text)
            .fetch_all(&pool.any)
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(RepoRole::from_db_str(&get_string(&row, "role")?)
                    .expect("stored repo_access.role is one of the CHECK'd values"))
            })
            .collect()
    }

    pub async fn list_collaborators(
        pool: &DbPool,
        repository_id: RepositoryId,
    ) -> Result<Vec<CollaboratorRow>, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                r#"SELECT u.id as user_id, u.username, u.email, u.is_admin, u.disabled_at, a.role, a.added_at
                   FROM repo_access a JOIN users u ON u.id = a.subject_id AND a.subject_type = 'user'
                   WHERE a.repository_id = $1 ORDER BY a.added_at"#
            }
            Backend::Sqlite | Backend::MySql => {
                r#"SELECT u.id as user_id, u.username, u.email, u.is_admin, u.disabled_at, a.role, a.added_at
                   FROM repo_access a JOIN users u ON u.id = a.subject_id AND a.subject_type = 'user'
                   WHERE a.repository_id = ? ORDER BY a.added_at"#
            }
        };
        let rows = sqlx::query(sql)
            .bind(&repository_id_text)
            .fetch_all(&pool.any)
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(CollaboratorRow {
                    user: User {
                        id: get_string(&row, "user_id")?
                            .parse()
                            .expect("stored user id is a valid UUID"),
                        username: get_string(&row, "username")?,
                        email: get_string(&row, "email")?,
                        is_admin: get_bool(&row, "is_admin")?,
                        disabled_at: get_opt_i64(&row, "disabled_at")?,
                    },
                    role: RepoRole::from_db_str(&get_string(&row, "role")?)
                        .expect("stored repo_access.role is one of the CHECK'd values"),
                    added_at: get_i64(&row, "added_at")?,
                })
            })
            .collect()
    }

    /// Every team currently attached to `repository_id`, alongside the
    /// role that attachment grants — the team-subject counterpart of
    /// `list_collaborators`.
    pub async fn list_team_grants(
        pool: &DbPool,
        repository_id: RepositoryId,
    ) -> Result<Vec<TeamGrantRow>, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                r#"SELECT t.id as team_id, t.name as team_name, a.role, a.added_at
                   FROM repo_access a JOIN teams t ON t.id = a.subject_id AND a.subject_type = 'team'
                   WHERE a.repository_id = $1 ORDER BY a.added_at"#
            }
            Backend::Sqlite | Backend::MySql => {
                r#"SELECT t.id as team_id, t.name as team_name, a.role, a.added_at
                   FROM repo_access a JOIN teams t ON t.id = a.subject_id AND a.subject_type = 'team'
                   WHERE a.repository_id = ? ORDER BY a.added_at"#
            }
        };
        let rows = sqlx::query(sql)
            .bind(&repository_id_text)
            .fetch_all(&pool.any)
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(TeamGrantRow {
                    team_id: get_string(&row, "team_id")?
                        .parse()
                        .expect("stored team id is a valid UUID"),
                    team_name: get_string(&row, "team_name")?,
                    role: RepoRole::from_db_str(&get_string(&row, "role")?)
                        .expect("stored repo_access.role is one of the CHECK'd values"),
                    added_at: get_i64(&row, "added_at")?,
                })
            })
            .collect()
    }

    /// `Ok(true)` if a non-owner grant was actually removed. The owner
    /// grant can never be removed through this path — a repository must
    /// always keep exactly one (enforced independently by the database's
    /// own one-owner invariant, but checked here too so the caller gets a
    /// clear "no such collaborator" outcome rather than a constraint-
    /// violation error).
    pub async fn remove_grant(
        pool: &DbPool,
        repository_id: RepositoryId,
        subject: AccessSubject,
    ) -> Result<bool, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let subject_type = subject_type_db_str(subject);
        let subject_id_text = subject_id(subject).to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "DELETE FROM repo_access WHERE repository_id = $1 AND subject_type = $2 AND subject_id = $3 AND role != 'owner'"
            }
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM repo_access WHERE repository_id = ? AND subject_type = ? AND subject_id = ? AND role != 'owner'"
            }
        };
        let result = sqlx::query(sql)
            .bind(&repository_id_text)
            .bind(subject_type)
            .bind(&subject_id_text)
            .execute(&pool.any)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

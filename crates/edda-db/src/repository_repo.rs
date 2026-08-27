use edda_domain::{Repository, RepositoryId, RepositoryOwner, TeamId, UserId, Visibility};

use crate::{get_opt_string, get_string, Backend, DbConn, DbError};

#[derive(Debug, thiserror::Error)]
pub enum InsertRepositoryError {
    #[error("a repository named \"{0}\" already exists for this owner")]
    AlreadyExists(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

fn row_to_repository(
    id: String,
    owner_type: String,
    owner_id: String,
    name: String,
    description: Option<String>,
    visibility: String,
    forked_from: Option<String>,
) -> Repository {
    let owner = match owner_type.as_str() {
        "user" => RepositoryOwner::User(owner_id.parse().expect("stored owner id is a valid UUID")),
        "organization" => RepositoryOwner::Organization(
            owner_id.parse().expect("stored owner id is a valid UUID"),
        ),
        other => {
            unreachable!("unexpected repositories.owner_type value {other:?} — schema/domain drift")
        }
    };
    Repository {
        id: id.parse().expect("stored repository id is a valid UUID"),
        owner,
        name,
        description,
        visibility: Visibility::from_db_str(&visibility)
            .expect("stored repositories.visibility is one of the CHECK'd values"),
        forked_from: forked_from.map(|id| id.parse().expect("stored forked_from is a valid UUID")),
    }
}

pub struct RepositoryRepo;

impl RepositoryRepo {
    pub async fn insert<'c>(
        db: impl DbConn<'c>,
        repository: &Repository,
    ) -> Result<(), InsertRepositoryError> {
        let mut h = crate::conn::open(db).await?;
        let id = repository.id.to_string();
        let owner_type = repository.owner.owner_type_db_str();
        let owner_id = repository.owner.owner_id().to_string();
        let visibility = repository.visibility.as_db_str();
        let forked_from = repository.forked_from.map(|id| id.to_string());
        let created_at = crate::now_unix();

        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO repositories (id, owner_type, owner_id, name, description, visibility, forked_from, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO repositories (id, owner_type, owner_id, name, description, visibility, forked_from, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            }
        };
        match sqlx::query(sql)
            .bind(&id)
            .bind(owner_type)
            .bind(&owner_id)
            .bind(&repository.name)
            .bind(&repository.description)
            .bind(visibility)
            .bind(&forked_from)
            .bind(created_at)
            .execute(&mut *h.conn())
            .await
            .map_err(DbError::from)
        {
            Ok(_) => Ok(()),
            Err(DbError::UniqueViolation) => Err(InsertRepositoryError::AlreadyExists(
                repository.name.clone(),
            )),
            Err(err) => Err(InsertRepositoryError::Db(err)),
        }
    }

    /// Inserts the repository and grants its creator the `Owner` role
    /// atomically, inside one transaction. Calling `insert` and
    /// `RepoAccessRepo::grant_owner` as two separate top-level statements
    /// would let SQLite's single-writer serialization mask an atomicity
    /// gap that a server-grade backend's real MVCC concurrency would not
    /// (a reader could observe a repository that exists with zero access
    /// grants). Callers must go through this method rather than the two
    /// steps separately. When `db` is already a caller transaction this
    /// runs as a savepoint, so it composes.
    pub async fn insert_with_owner<'c>(
        db: impl DbConn<'c>,
        repository: &Repository,
        owner_user_id: UserId,
    ) -> Result<(), InsertRepositoryError> {
        let mut h = crate::conn::open(db).await?;
        let backend = h.backend();
        let id = repository.id.to_string();
        let owner_type = repository.owner.owner_type_db_str();
        let owner_id = repository.owner.owner_id().to_string();
        let visibility = repository.visibility.as_db_str();
        let forked_from = repository.forked_from.map(|id| id.to_string());
        let created_at = crate::now_unix();

        let mut tx = h.begin().await?;

        let insert_sql = match backend {
            Backend::Postgres => {
                "INSERT INTO repositories (id, owner_type, owner_id, name, description, visibility, forked_from, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO repositories (id, owner_type, owner_id, name, description, visibility, forked_from, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            }
        };
        match sqlx::query(insert_sql)
            .bind(&id)
            .bind(owner_type)
            .bind(&owner_id)
            .bind(&repository.name)
            .bind(&repository.description)
            .bind(visibility)
            .bind(&forked_from)
            .bind(created_at)
            .execute(&mut *tx)
            .await
            .map_err(DbError::from)
        {
            Ok(_) => {}
            Err(DbError::UniqueViolation) => {
                return Err(InsertRepositoryError::AlreadyExists(
                    repository.name.clone(),
                ));
            }
            Err(err) => return Err(InsertRepositoryError::Db(err)),
        }

        let owner_user_id_text = owner_user_id.to_string();
        let role = edda_domain::RepoRole::Owner.as_db_str();
        let granted_at = crate::now_unix();
        let grant_sql = match backend {
            Backend::Postgres => {
                "INSERT INTO repo_access (repository_id, subject_type, subject_id, role, added_at) VALUES ($1, 'user', $2, $3, $4)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO repo_access (repository_id, subject_type, subject_id, role, added_at) VALUES (?, 'user', ?, ?, ?)"
            }
        };
        sqlx::query(grant_sql)
            .bind(&id)
            .bind(&owner_user_id_text)
            .bind(role)
            .bind(granted_at)
            .execute(&mut *tx)
            .await
            .map_err(DbError::from)?;

        tx.commit().await.map_err(DbError::from)?;
        Ok(())
    }

    /// The organization-owned counterpart of `insert_with_owner`: grants
    /// the repository's mandatory `Owner` role to `owner_team_id` (an
    /// organization's Owners team, per `OrganizationRepo::insert`'s own
    /// doc comment) instead of to an individual user — `AccessSubject` has
    /// no separate `Organization` variant of its own, so an org-owned
    /// repository's owner grant is always a team grant.
    pub async fn insert_with_owner_team<'c>(
        db: impl DbConn<'c>,
        repository: &Repository,
        owner_team_id: TeamId,
    ) -> Result<(), InsertRepositoryError> {
        let mut h = crate::conn::open(db).await?;
        let backend = h.backend();
        let id = repository.id.to_string();
        let owner_type = repository.owner.owner_type_db_str();
        let owner_id = repository.owner.owner_id().to_string();
        let visibility = repository.visibility.as_db_str();
        let forked_from = repository.forked_from.map(|id| id.to_string());
        let created_at = crate::now_unix();

        let mut tx = h.begin().await?;

        let insert_sql = match backend {
            Backend::Postgres => {
                "INSERT INTO repositories (id, owner_type, owner_id, name, description, visibility, forked_from, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO repositories (id, owner_type, owner_id, name, description, visibility, forked_from, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            }
        };
        match sqlx::query(insert_sql)
            .bind(&id)
            .bind(owner_type)
            .bind(&owner_id)
            .bind(&repository.name)
            .bind(&repository.description)
            .bind(visibility)
            .bind(&forked_from)
            .bind(created_at)
            .execute(&mut *tx)
            .await
            .map_err(DbError::from)
        {
            Ok(_) => {}
            Err(DbError::UniqueViolation) => {
                return Err(InsertRepositoryError::AlreadyExists(
                    repository.name.clone(),
                ));
            }
            Err(err) => return Err(InsertRepositoryError::Db(err)),
        }

        let owner_team_id_text = owner_team_id.to_string();
        let role = edda_domain::RepoRole::Owner.as_db_str();
        let granted_at = crate::now_unix();
        let grant_sql = match backend {
            Backend::Postgres => {
                "INSERT INTO repo_access (repository_id, subject_type, subject_id, role, added_at) VALUES ($1, 'team', $2, $3, $4)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO repo_access (repository_id, subject_type, subject_id, role, added_at) VALUES (?, 'team', ?, ?, ?)"
            }
        };
        sqlx::query(grant_sql)
            .bind(&id)
            .bind(&owner_team_id_text)
            .bind(role)
            .bind(granted_at)
            .execute(&mut *tx)
            .await
            .map_err(DbError::from)?;

        tx.commit().await.map_err(DbError::from)?;
        Ok(())
    }

    pub async fn find_by_owner_and_name<'c>(
        db: impl DbConn<'c>,
        owner: RepositoryOwner,
        name: &str,
    ) -> Result<Option<Repository>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let owner_type = owner.owner_type_db_str();
        let owner_id = owner.owner_id().to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                r#"SELECT id, owner_type, owner_id, name, description, visibility, forked_from
                   FROM repositories WHERE owner_type = $1 AND owner_id = $2 AND name = $3"#
            }
            Backend::Sqlite | Backend::MySql => {
                r#"SELECT id, owner_type, owner_id, name, description, visibility, forked_from
                   FROM repositories WHERE owner_type = ? AND owner_id = ? AND name = ?"#
            }
        };
        let row = sqlx::query(sql)
            .bind(owner_type)
            .bind(&owner_id)
            .bind(name)
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(row_to_repository_row).transpose()
    }

    /// Resolves an `{owner}` URL/clone-path segment to whichever entity it
    /// names — a user or an organization. The two share one
    /// global identifier namespace (`edda-auth`'s signup and organization-
    /// creation paths both enforce that at write time), so this resolves
    /// unambiguously: at most one of the two lookups below can ever find a
    /// match.
    pub async fn resolve_owner<'c>(
        db: impl DbConn<'c>,
        owner_name: &str,
    ) -> Result<Option<RepositoryOwner>, DbError> {
        let mut h = crate::conn::open(db).await?;
        if let Some(user) = crate::user_repo::UserRepo::find_by_username(&mut h, owner_name).await?
        {
            return Ok(Some(RepositoryOwner::User(user.id)));
        }
        if let Some(org) =
            crate::organization_repo::OrganizationRepo::find_by_name(&mut h, owner_name).await?
        {
            return Ok(Some(RepositoryOwner::Organization(org.id)));
        }
        Ok(None)
    }

    /// Resolves the `{owner_username}/{repo_name}` form used in URLs and
    /// clone paths back to a `Repository` row.
    pub async fn find_by_owner_username_and_name<'c>(
        db: impl DbConn<'c>,
        owner_username: &str,
        name: &str,
    ) -> Result<Option<Repository>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let Some(owner) = Self::resolve_owner(&mut h, owner_username).await? else {
            return Ok(None);
        };
        Self::find_by_owner_and_name(&mut h, owner, name).await
    }

    pub async fn find_by_id<'c>(
        db: impl DbConn<'c>,
        id: RepositoryId,
    ) -> Result<Option<Repository>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, owner_type, owner_id, name, description, visibility, forked_from FROM repositories WHERE id = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, owner_type, owner_id, name, description, visibility, forked_from FROM repositories WHERE id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&id_text)
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(row_to_repository_row).transpose()
    }

    /// Every repository in the instance. `edda-http` filters this down to
    /// what the requesting actor may actually see (public repos plus any
    /// private repo they hold a grant on) — there is no per-owner or
    /// per-visibility variant yet because nothing needs one at the
    /// instance's current expected scale.
    pub async fn list_all<'c>(db: impl DbConn<'c>) -> Result<Vec<Repository>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let rows = sqlx::query(
            "SELECT id, owner_type, owner_id, name, description, visibility, forked_from FROM repositories ORDER BY owner_id, name",
        )
        .fetch_all(&mut *h.conn())
        .await?;
        rows.into_iter().map(row_to_repository_row).collect()
    }

    /// Every repository, alongside its owner's display name (a username or
    /// an organization name — exactly one `LEFT JOIN` below matches per
    /// row, since `owner_type` picks which) — the join `list_all`
    /// deliberately doesn't do (nothing else needs it): a repository
    /// listing DTO needs the `{owner}/{name}` display form, and resolving
    /// that per-row here avoids an N+1 owner-name lookup in `edda-web`'s
    /// `list_repos` server function.
    pub async fn list_all_with_owner_username<'c>(
        db: impl DbConn<'c>,
    ) -> Result<Vec<(Repository, String)>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let rows = sqlx::query(
            r#"SELECT r.id, r.owner_type, r.owner_id, r.name, r.description, r.visibility, r.forked_from,
                      COALESCE(u.username, o.name) as owner_username
               FROM repositories r
               LEFT JOIN users u ON u.id = r.owner_id AND r.owner_type = 'user'
               LEFT JOIN organizations o ON o.id = r.owner_id AND r.owner_type = 'organization'
               ORDER BY owner_username, r.name"#,
        )
        .fetch_all(&mut *h.conn())
        .await?;
        rows.into_iter()
            .map(|row| {
                let owner_username = get_string(&row, "owner_username")?;
                Ok((row_to_repository_row(row)?, owner_username))
            })
            .collect()
    }

    pub async fn update_description<'c>(
        db: impl DbConn<'c>,
        id: RepositoryId,
        description: Option<&str>,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => "UPDATE repositories SET description = $1 WHERE id = $2",
            Backend::Sqlite | Backend::MySql => {
                "UPDATE repositories SET description = ? WHERE id = ?"
            }
        };
        sqlx::query(sql)
            .bind(description)
            .bind(&id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    pub async fn update_visibility<'c>(
        db: impl DbConn<'c>,
        id: RepositoryId,
        visibility: Visibility,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let visibility = visibility.as_db_str();
        let sql = match h.backend() {
            Backend::Postgres => "UPDATE repositories SET visibility = $1 WHERE id = $2",
            Backend::Sqlite | Backend::MySql => {
                "UPDATE repositories SET visibility = ? WHERE id = ?"
            }
        };
        sqlx::query(sql)
            .bind(visibility)
            .bind(&id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    pub async fn delete<'c>(db: impl DbConn<'c>, id: RepositoryId) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => "DELETE FROM repositories WHERE id = $1",
            Backend::Sqlite | Backend::MySql => "DELETE FROM repositories WHERE id = ?",
        };
        sqlx::query(sql)
            .bind(&id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }
}

fn row_to_repository_row(row: sqlx::any::AnyRow) -> Result<Repository, DbError> {
    Ok(row_to_repository(
        get_string(&row, "id")?,
        get_string(&row, "owner_type")?,
        get_string(&row, "owner_id")?,
        get_string(&row, "name")?,
        get_opt_string(&row, "description")?,
        get_string(&row, "visibility")?,
        get_opt_string(&row, "forked_from")?,
    ))
}

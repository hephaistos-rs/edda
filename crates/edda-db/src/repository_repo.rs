use edda_domain::{Repository, RepositoryId, RepositoryOwner, UserId, Visibility};

use crate::{get_opt_string, get_string, Backend, DbPool};

#[derive(Debug, thiserror::Error)]
pub enum InsertRepositoryError {
    #[error("a repository named \"{0}\" already exists for this owner")]
    AlreadyExists(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

fn row_to_repository(
    id: String,
    owner_type: String,
    owner_id: String,
    name: String,
    description: Option<String>,
    visibility: String,
) -> Repository {
    let owner = match owner_type.as_str() {
        "user" => RepositoryOwner::User(owner_id.parse().expect("stored owner id is a valid UUID")),
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
    }
}

pub struct RepositoryRepo;

impl RepositoryRepo {
    pub async fn insert(
        pool: &DbPool,
        repository: &Repository,
    ) -> Result<(), InsertRepositoryError> {
        let id = repository.id.to_string();
        let owner_type = repository.owner.owner_type_db_str();
        let owner_id = repository.owner.owner_id().to_string();
        let visibility = repository.visibility.as_db_str();
        let created_at = crate::now_unix();

        let sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO repositories (id, owner_type, owner_id, name, description, visibility, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO repositories (id, owner_type, owner_id, name, description, visibility, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
            }
        };
        let result = sqlx::query(sql)
            .bind(&id)
            .bind(owner_type)
            .bind(&owner_id)
            .bind(&repository.name)
            .bind(&repository.description)
            .bind(visibility)
            .bind(created_at)
            .execute(&pool.any)
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => Err(
                InsertRepositoryError::AlreadyExists(repository.name.clone()),
            ),
            Err(err) => Err(InsertRepositoryError::Db(err)),
        }
    }

    /// Inserts the repository and grants its creator the `Owner` role
    /// atomically, inside one transaction — found missing at this
    /// crate's original call site during Phase 3's audit (plan.local.md
    /// §17 Phase 3): it used to call `insert` and `RepoAccessRepo::
    /// grant_owner` as two separate top-level statements, which SQLite's
    /// single-writer serialization happened to mask but a server-grade
    /// backend's real MVCC concurrency would not (a reader could observe
    /// a repository that exists with zero access grants). Callers that
    /// used to do both steps themselves should call this instead.
    pub async fn insert_with_owner(
        pool: &DbPool,
        repository: &Repository,
        owner_user_id: UserId,
    ) -> Result<(), InsertRepositoryError> {
        let id = repository.id.to_string();
        let owner_type = repository.owner.owner_type_db_str();
        let owner_id = repository.owner.owner_id().to_string();
        let visibility = repository.visibility.as_db_str();
        let created_at = crate::now_unix();

        let mut tx = pool.any.begin().await?;

        let insert_sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO repositories (id, owner_type, owner_id, name, description, visibility, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO repositories (id, owner_type, owner_id, name, description, visibility, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
            }
        };
        let result = sqlx::query(insert_sql)
            .bind(&id)
            .bind(owner_type)
            .bind(&owner_id)
            .bind(&repository.name)
            .bind(&repository.description)
            .bind(visibility)
            .bind(created_at)
            .execute(&mut *tx)
            .await;
        match result {
            Ok(_) => {}
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                return Err(InsertRepositoryError::AlreadyExists(
                    repository.name.clone(),
                ));
            }
            Err(err) => return Err(InsertRepositoryError::Db(err)),
        }

        let owner_user_id_text = owner_user_id.to_string();
        let role = edda_domain::RepoRole::Owner.as_db_str();
        let granted_at = crate::now_unix();
        let grant_sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO repo_access (repository_id, user_id, role, added_at) VALUES ($1, $2, $3, $4)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO repo_access (repository_id, user_id, role, added_at) VALUES (?, ?, ?, ?)"
            }
        };
        sqlx::query(grant_sql)
            .bind(&id)
            .bind(&owner_user_id_text)
            .bind(role)
            .bind(granted_at)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn find_by_owner_and_name(
        pool: &DbPool,
        owner: RepositoryOwner,
        name: &str,
    ) -> Result<Option<Repository>, sqlx::Error> {
        let owner_type = owner.owner_type_db_str();
        let owner_id = owner.owner_id().to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                r#"SELECT id, owner_type, owner_id, name, description, visibility
                   FROM repositories WHERE owner_type = $1 AND owner_id = $2 AND name = $3"#
            }
            Backend::Sqlite | Backend::MySql => {
                r#"SELECT id, owner_type, owner_id, name, description, visibility
                   FROM repositories WHERE owner_type = ? AND owner_id = ? AND name = ?"#
            }
        };
        let row = sqlx::query(sql)
            .bind(owner_type)
            .bind(&owner_id)
            .bind(name)
            .fetch_optional(&pool.any)
            .await?;
        row.map(row_to_repository_row).transpose()
    }

    /// Resolves the `{owner_username}/{repo_name}` form used in URLs and
    /// clone paths back to a `Repository` row — joins through `users`
    /// since only `User`-owned repositories exist until organizations
    /// land (plan.local.md §17 Phase 8).
    pub async fn find_by_owner_username_and_name(
        pool: &DbPool,
        owner_username: &str,
        name: &str,
    ) -> Result<Option<Repository>, sqlx::Error> {
        let sql = match pool.backend {
            Backend::Sqlite => {
                r#"SELECT r.id, r.owner_type, r.owner_id, r.name, r.description, r.visibility
                   FROM repositories r
                   JOIN users u ON u.id = r.owner_id AND r.owner_type = 'user'
                   WHERE u.username = ? AND r.name = ?"#
            }
            Backend::Postgres => {
                r#"SELECT r.id, r.owner_type, r.owner_id, r.name, r.description, r.visibility
                   FROM repositories r
                   JOIN users u ON u.id = r.owner_id AND r.owner_type = 'user'
                   WHERE LOWER(u.username) = LOWER($1) AND r.name = $2"#
            }
            // MariaDB rejects a direct functional index, so `users` has a
            // stored `username_lower` shadow column instead (see the
            // mysql migration's comment on `idx_users_username_ci`).
            Backend::MySql => {
                r#"SELECT r.id, r.owner_type, r.owner_id, r.name, r.description, r.visibility
                   FROM repositories r
                   JOIN users u ON u.id = r.owner_id AND r.owner_type = 'user'
                   WHERE u.username_lower = LOWER(?) AND r.name = ?"#
            }
        };
        let row = sqlx::query(sql)
            .bind(owner_username)
            .bind(name)
            .fetch_optional(&pool.any)
            .await?;
        row.map(row_to_repository_row).transpose()
    }

    pub async fn find_by_id(
        pool: &DbPool,
        id: RepositoryId,
    ) -> Result<Option<Repository>, sqlx::Error> {
        let id_text = id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT id, owner_type, owner_id, name, description, visibility FROM repositories WHERE id = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, owner_type, owner_id, name, description, visibility FROM repositories WHERE id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&id_text)
            .fetch_optional(&pool.any)
            .await?;
        row.map(row_to_repository_row).transpose()
    }

    /// Every repository in the instance. `edda-http` filters this down to
    /// what the requesting actor may actually see (public repos plus any
    /// private repo they hold a grant on) — there is no per-owner or
    /// per-visibility variant yet because nothing in Phase 1 needs one at
    /// the instance's current expected scale (plan.local.md §5.8).
    pub async fn list_all(pool: &DbPool) -> Result<Vec<Repository>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, owner_type, owner_id, name, description, visibility FROM repositories ORDER BY owner_id, name",
        )
        .fetch_all(&pool.any)
        .await?;
        rows.into_iter().map(row_to_repository_row).collect()
    }

    /// Every repository, alongside its owning user's username — the join
    /// `list_all` deliberately doesn't do (nothing else needs it): a
    /// repository listing DTO needs the `{owner}/{name}` display form, and
    /// resolving that per-row here avoids an N+1 username lookup in
    /// `edda-web`'s `list_repos` server function.
    pub async fn list_all_with_owner_username(
        pool: &DbPool,
    ) -> Result<Vec<(Repository, String)>, sqlx::Error> {
        let rows = sqlx::query(
            r#"SELECT r.id, r.owner_type, r.owner_id, r.name, r.description, r.visibility, u.username as owner_username
               FROM repositories r JOIN users u ON u.id = r.owner_id AND r.owner_type = 'user'
               ORDER BY u.username, r.name"#,
        )
        .fetch_all(&pool.any)
        .await?;
        rows.into_iter()
            .map(|row| {
                let owner_username = get_string(&row, "owner_username")?;
                Ok((row_to_repository_row(row)?, owner_username))
            })
            .collect()
    }

    pub async fn update_description(
        pool: &DbPool,
        id: RepositoryId,
        description: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => "UPDATE repositories SET description = $1 WHERE id = $2",
            Backend::Sqlite | Backend::MySql => {
                "UPDATE repositories SET description = ? WHERE id = ?"
            }
        };
        sqlx::query(sql)
            .bind(description)
            .bind(&id_text)
            .execute(&pool.any)
            .await?;
        Ok(())
    }

    pub async fn update_visibility(
        pool: &DbPool,
        id: RepositoryId,
        visibility: Visibility,
    ) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        let visibility = visibility.as_db_str();
        let sql = match pool.backend {
            Backend::Postgres => "UPDATE repositories SET visibility = $1 WHERE id = $2",
            Backend::Sqlite | Backend::MySql => {
                "UPDATE repositories SET visibility = ? WHERE id = ?"
            }
        };
        sqlx::query(sql)
            .bind(visibility)
            .bind(&id_text)
            .execute(&pool.any)
            .await?;
        Ok(())
    }

    pub async fn delete(pool: &DbPool, id: RepositoryId) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => "DELETE FROM repositories WHERE id = $1",
            Backend::Sqlite | Backend::MySql => "DELETE FROM repositories WHERE id = ?",
        };
        sqlx::query(sql).bind(&id_text).execute(&pool.any).await?;
        Ok(())
    }
}

fn row_to_repository_row(row: sqlx::any::AnyRow) -> Result<Repository, sqlx::Error> {
    Ok(row_to_repository(
        get_string(&row, "id")?,
        get_string(&row, "owner_type")?,
        get_string(&row, "owner_id")?,
        get_string(&row, "name")?,
        get_opt_string(&row, "description")?,
        get_string(&row, "visibility")?,
    ))
}

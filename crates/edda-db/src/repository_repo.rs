use edda_domain::{Repository, RepositoryId, RepositoryOwner, UserId, Visibility};

use crate::DbPool;

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
    #[cfg(feature = "sqlite")]
    pub async fn insert(
        pool: &DbPool,
        repository: &Repository,
    ) -> Result<(), InsertRepositoryError> {
        let id = repository.id.to_string();
        let owner_type = repository.owner.owner_type_db_str();
        let owner_id = repository.owner.owner_id().to_string();
        let visibility = repository.visibility.as_db_str();
        let created_at = crate::now_unix();

        let result = sqlx::query!(
            "INSERT INTO repositories (id, owner_type, owner_id, name, description, visibility, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            id,
            owner_type,
            owner_id,
            repository.name,
            repository.description,
            visibility,
            created_at,
        )
        .execute(pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => Err(
                InsertRepositoryError::AlreadyExists(repository.name.clone()),
            ),
            Err(err) => Err(InsertRepositoryError::Db(err)),
        }
    }

    #[cfg(feature = "postgres")]
    pub async fn insert(
        pool: &DbPool,
        repository: &Repository,
    ) -> Result<(), InsertRepositoryError> {
        let id = repository.id.to_string();
        let owner_type = repository.owner.owner_type_db_str();
        let owner_id = repository.owner.owner_id().to_string();
        let visibility = repository.visibility.as_db_str();
        let created_at = crate::now_unix();

        let result = sqlx::query!(
            "INSERT INTO repositories (id, owner_type, owner_id, name, description, visibility, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            id,
            owner_type,
            owner_id,
            repository.name,
            repository.description,
            visibility,
            created_at,
        )
        .execute(pool)
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
    /// crate's two call sites during Phase 3's audit (plan.local.md §17
    /// Phase 3): they used to call `insert` and `RepoAccessRepo::
    /// grant_owner` as two separate top-level statements, which SQLite's
    /// single-writer serialization happened to mask but PostgreSQL's real
    /// MVCC concurrency would not (a reader could observe a repository
    /// that exists with zero access grants). Callers that used to do
    /// both steps themselves should call this instead.
    #[cfg(feature = "sqlite")]
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

        let mut tx = pool.begin().await?;

        let result = sqlx::query!(
            "INSERT INTO repositories (id, owner_type, owner_id, name, description, visibility, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            id,
            owner_type,
            owner_id,
            repository.name,
            repository.description,
            visibility,
            created_at,
        )
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
        sqlx::query!(
            "INSERT INTO repo_access (repository_id, user_id, role, added_at) VALUES (?, ?, ?, ?)",
            id,
            owner_user_id_text,
            role,
            granted_at,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    #[cfg(feature = "postgres")]
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

        let mut tx = pool.begin().await?;

        let result = sqlx::query!(
            "INSERT INTO repositories (id, owner_type, owner_id, name, description, visibility, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            id,
            owner_type,
            owner_id,
            repository.name,
            repository.description,
            visibility,
            created_at,
        )
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
        sqlx::query!(
            "INSERT INTO repo_access (repository_id, user_id, role, added_at) VALUES ($1, $2, $3, $4)",
            id,
            owner_user_id_text,
            role,
            granted_at,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    pub async fn find_by_owner_and_name(
        pool: &DbPool,
        owner: RepositoryOwner,
        name: &str,
    ) -> Result<Option<Repository>, sqlx::Error> {
        let owner_type = owner.owner_type_db_str();
        let owner_id = owner.owner_id().to_string();
        let row = sqlx::query!(
            r#"SELECT id, owner_type, owner_id, name, description, visibility
               FROM repositories WHERE owner_type = ? AND owner_id = ? AND name = ?"#,
            owner_type,
            owner_id,
            name,
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| {
            row_to_repository(
                row.id,
                row.owner_type,
                row.owner_id,
                row.name,
                row.description,
                row.visibility,
            )
        }))
    }

    #[cfg(feature = "postgres")]
    pub async fn find_by_owner_and_name(
        pool: &DbPool,
        owner: RepositoryOwner,
        name: &str,
    ) -> Result<Option<Repository>, sqlx::Error> {
        let owner_type = owner.owner_type_db_str();
        let owner_id = owner.owner_id().to_string();
        let row = sqlx::query!(
            r#"SELECT id, owner_type, owner_id, name, description, visibility
               FROM repositories WHERE owner_type = $1 AND owner_id = $2 AND name = $3"#,
            owner_type,
            owner_id,
            name,
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| {
            row_to_repository(
                row.id,
                row.owner_type,
                row.owner_id,
                row.name,
                row.description,
                row.visibility,
            )
        }))
    }

    /// Resolves the `{owner_username}/{repo_name}` form used in URLs and
    /// clone paths back to a `Repository` row — joins through `users`
    /// since only `User`-owned repositories exist until organizations
    /// land (plan.local.md §17 Phase 8).
    #[cfg(feature = "sqlite")]
    pub async fn find_by_owner_username_and_name(
        pool: &DbPool,
        owner_username: &str,
        name: &str,
    ) -> Result<Option<Repository>, sqlx::Error> {
        let row = sqlx::query!(
            r#"SELECT r.id, r.owner_type, r.owner_id, r.name, r.description, r.visibility
               FROM repositories r
               JOIN users u ON u.id = r.owner_id AND r.owner_type = 'user'
               WHERE u.username = ? AND r.name = ?"#,
            owner_username,
            name,
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| {
            row_to_repository(
                row.id,
                row.owner_type,
                row.owner_id,
                row.name,
                row.description,
                row.visibility,
            )
        }))
    }

    #[cfg(feature = "postgres")]
    pub async fn find_by_owner_username_and_name(
        pool: &DbPool,
        owner_username: &str,
        name: &str,
    ) -> Result<Option<Repository>, sqlx::Error> {
        let row = sqlx::query!(
            r#"SELECT r.id, r.owner_type, r.owner_id, r.name, r.description, r.visibility
               FROM repositories r
               JOIN users u ON u.id = r.owner_id AND r.owner_type = 'user'
               WHERE LOWER(u.username) = LOWER($1) AND r.name = $2"#,
            owner_username,
            name,
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| {
            row_to_repository(
                row.id,
                row.owner_type,
                row.owner_id,
                row.name,
                row.description,
                row.visibility,
            )
        }))
    }

    #[cfg(feature = "sqlite")]
    pub async fn find_by_id(
        pool: &DbPool,
        id: RepositoryId,
    ) -> Result<Option<Repository>, sqlx::Error> {
        let id_text = id.to_string();
        let row = sqlx::query!(r#"SELECT id, owner_type, owner_id, name, description, visibility FROM repositories WHERE id = ?"#, id_text)
            .fetch_optional(pool)
            .await?;
        Ok(row.map(|row| {
            row_to_repository(
                row.id,
                row.owner_type,
                row.owner_id,
                row.name,
                row.description,
                row.visibility,
            )
        }))
    }

    #[cfg(feature = "postgres")]
    pub async fn find_by_id(
        pool: &DbPool,
        id: RepositoryId,
    ) -> Result<Option<Repository>, sqlx::Error> {
        let id_text = id.to_string();
        let row = sqlx::query!(r#"SELECT id, owner_type, owner_id, name, description, visibility FROM repositories WHERE id = $1"#, id_text)
            .fetch_optional(pool)
            .await?;
        Ok(row.map(|row| {
            row_to_repository(
                row.id,
                row.owner_type,
                row.owner_id,
                row.name,
                row.description,
                row.visibility,
            )
        }))
    }

    /// Every repository in the instance. `edda-http` filters this down to
    /// what the requesting actor may actually see (public repos plus any
    /// private repo they hold a grant on) — there is no per-owner or
    /// per-visibility variant yet because nothing in Phase 1 needs one at
    /// the instance's current expected scale (plan.local.md §5.8).
    // The trailing `-- sqlite`/`-- postgres` comment below is inert SQL —
    // it exists only so this query's text differs from its
    // otherwise-byte-identical `postgres` counterpart. Both backends
    // support this query verbatim (no placeholders, plain ANSI SQL), but
    // `sqlx`'s offline `.sqlx` cache is keyed by the query text's hash and
    // tags each cached entry with the one backend it was checked
    // against — two backends sharing one hash would mean whichever
    // backend's `cargo sqlx prepare` ran last silently overwrites the
    // other's cache entry (found while regenerating the offline cache
    // for both backends, plan.local.md §17 Phase 3).
    #[cfg(feature = "sqlite")]
    pub async fn list_all(pool: &DbPool) -> Result<Vec<Repository>, sqlx::Error> {
        let rows = sqlx::query!(r#"SELECT id, owner_type, owner_id, name, description, visibility FROM repositories ORDER BY owner_id, name -- sqlite"#)
            .fetch_all(pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                row_to_repository(
                    row.id,
                    row.owner_type,
                    row.owner_id,
                    row.name,
                    row.description,
                    row.visibility,
                )
            })
            .collect())
    }

    #[cfg(feature = "postgres")]
    pub async fn list_all(pool: &DbPool) -> Result<Vec<Repository>, sqlx::Error> {
        let rows = sqlx::query!(r#"SELECT id, owner_type, owner_id, name, description, visibility FROM repositories ORDER BY owner_id, name -- postgres"#)
            .fetch_all(pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                row_to_repository(
                    row.id,
                    row.owner_type,
                    row.owner_id,
                    row.name,
                    row.description,
                    row.visibility,
                )
            })
            .collect())
    }

    /// Every repository, alongside its owning user's username — the join
    /// `list_all` deliberately doesn't do (nothing else needs it): a
    /// repository listing DTO needs the `{owner}/{name}` display form, and
    /// resolving that per-row here avoids an N+1 username lookup in
    /// `edda-web`'s `list_repos` server function.
    // See `list_all`'s comment just above for why these two otherwise-
    // identical queries carry a distinguishing trailing SQL comment.
    #[cfg(feature = "sqlite")]
    pub async fn list_all_with_owner_username(
        pool: &DbPool,
    ) -> Result<Vec<(Repository, String)>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"SELECT r.id, r.owner_type, r.owner_id, r.name, r.description, r.visibility, u.username as owner_username
               FROM repositories r JOIN users u ON u.id = r.owner_id AND r.owner_type = 'user'
               ORDER BY u.username, r.name -- sqlite"#
        )
        .fetch_all(pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                (
                    row_to_repository(
                        row.id,
                        row.owner_type,
                        row.owner_id,
                        row.name,
                        row.description,
                        row.visibility,
                    ),
                    row.owner_username,
                )
            })
            .collect())
    }

    #[cfg(feature = "postgres")]
    pub async fn list_all_with_owner_username(
        pool: &DbPool,
    ) -> Result<Vec<(Repository, String)>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"SELECT r.id, r.owner_type, r.owner_id, r.name, r.description, r.visibility, u.username as owner_username
               FROM repositories r JOIN users u ON u.id = r.owner_id AND r.owner_type = 'user'
               ORDER BY u.username, r.name -- postgres"#
        )
        .fetch_all(pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                (
                    row_to_repository(
                        row.id,
                        row.owner_type,
                        row.owner_id,
                        row.name,
                        row.description,
                        row.visibility,
                    ),
                    row.owner_username,
                )
            })
            .collect())
    }

    #[cfg(feature = "sqlite")]
    pub async fn update_description(
        pool: &DbPool,
        id: RepositoryId,
        description: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        sqlx::query!(
            "UPDATE repositories SET description = ? WHERE id = ?",
            description,
            id_text
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    #[cfg(feature = "postgres")]
    pub async fn update_description(
        pool: &DbPool,
        id: RepositoryId,
        description: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        sqlx::query!(
            "UPDATE repositories SET description = $1 WHERE id = $2",
            description,
            id_text
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    pub async fn update_visibility(
        pool: &DbPool,
        id: RepositoryId,
        visibility: Visibility,
    ) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        let visibility = visibility.as_db_str();
        sqlx::query!(
            "UPDATE repositories SET visibility = ? WHERE id = ?",
            visibility,
            id_text
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    #[cfg(feature = "postgres")]
    pub async fn update_visibility(
        pool: &DbPool,
        id: RepositoryId,
        visibility: Visibility,
    ) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        let visibility = visibility.as_db_str();
        sqlx::query!(
            "UPDATE repositories SET visibility = $1 WHERE id = $2",
            visibility,
            id_text
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    pub async fn delete(pool: &DbPool, id: RepositoryId) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        sqlx::query!("DELETE FROM repositories WHERE id = ?", id_text)
            .execute(pool)
            .await?;
        Ok(())
    }

    #[cfg(feature = "postgres")]
    pub async fn delete(pool: &DbPool, id: RepositoryId) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        sqlx::query!("DELETE FROM repositories WHERE id = $1", id_text)
            .execute(pool)
            .await?;
        Ok(())
    }
}

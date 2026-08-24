use edda_domain::{Repository, RepositoryId, RepositoryOwner, Visibility};
use sqlx::SqlitePool;

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
        pool: &SqlitePool,
        repository: &Repository,
    ) -> Result<(), InsertRepositoryError> {
        let id = repository.id.to_string();
        let owner_type = repository.owner.owner_type_db_str();
        let owner_id = repository.owner.owner_id().to_string();
        let visibility = repository.visibility.as_db_str();

        let result = sqlx::query!(
            "INSERT INTO repositories (id, owner_type, owner_id, name, description, visibility) VALUES (?, ?, ?, ?, ?, ?)",
            id,
            owner_type,
            owner_id,
            repository.name,
            repository.description,
            visibility,
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

    pub async fn find_by_owner_and_name(
        pool: &SqlitePool,
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

    /// Resolves the `{owner_username}/{repo_name}` form used in URLs and
    /// clone paths back to a `Repository` row — joins through `users`
    /// since only `User`-owned repositories exist until organizations
    /// land (plan.local.md §17 Phase 7).
    pub async fn find_by_owner_username_and_name(
        pool: &SqlitePool,
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

    pub async fn find_by_id(
        pool: &SqlitePool,
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

    /// Every repository in the instance. `edda-http` filters this down to
    /// what the requesting actor may actually see (public repos plus any
    /// private repo they hold a grant on) — there is no per-owner or
    /// per-visibility variant yet because nothing in Phase 1 needs one at
    /// the instance's current expected scale (plan.local.md §5.8).
    pub async fn list_all(pool: &SqlitePool) -> Result<Vec<Repository>, sqlx::Error> {
        let rows = sqlx::query!(r#"SELECT id, owner_type, owner_id, name, description, visibility FROM repositories ORDER BY owner_id, name"#)
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
    pub async fn list_all_with_owner_username(
        pool: &SqlitePool,
    ) -> Result<Vec<(Repository, String)>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"SELECT r.id, r.owner_type, r.owner_id, r.name, r.description, r.visibility, u.username as owner_username
               FROM repositories r JOIN users u ON u.id = r.owner_id AND r.owner_type = 'user'
               ORDER BY u.username, r.name"#
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

    pub async fn update_description(
        pool: &SqlitePool,
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

    pub async fn update_visibility(
        pool: &SqlitePool,
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

    pub async fn delete(pool: &SqlitePool, id: RepositoryId) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        sqlx::query!("DELETE FROM repositories WHERE id = ?", id_text)
            .execute(pool)
            .await?;
        Ok(())
    }
}

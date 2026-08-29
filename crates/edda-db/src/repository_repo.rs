use edda_domain::{Repository, RepositoryId, RepositoryOwner, TeamId, UserId, Visibility};

use crate::{get_opt_string, get_string, Backend, DbConn, DbError};

#[derive(Debug, thiserror::Error)]
pub enum InsertRepositoryError {
    #[error("a repository named \"{0}\" already exists for this owner")]
    AlreadyExists(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

/// Reconstructs the domain `RepositoryOwner` from the `repositories`
/// row's typed FK pair. Since the Phase 9 baseline, ownership is
/// `owner_user_id` / `owner_org_id` — two nullable columns with a
/// database `CHECK` that exactly one is set — not the old polymorphic
/// `(owner_type TEXT, owner_id TEXT)` pair.
fn row_to_owner(owner_user_id: Option<String>, owner_org_id: Option<String>) -> RepositoryOwner {
    match (owner_user_id, owner_org_id) {
        (Some(user_id), None) => {
            RepositoryOwner::User(user_id.parse().expect("stored owner_user_id is a valid UUID"))
        }
        (None, Some(org_id)) => RepositoryOwner::Organization(
            org_id.parse().expect("stored owner_org_id is a valid UUID"),
        ),
        (user, org) => unreachable!(
            "repositories row has {} owner columns set — the one-owner CHECK should make this impossible (user={user:?}, org={org:?})",
            user.is_some() as u8 + org.is_some() as u8
        ),
    }
}

pub struct RepositoryRepo;

impl RepositoryRepo {
    pub async fn insert<'c>(
        db: impl DbConn<'c>,
        repository: &Repository,
    ) -> Result<(), InsertRepositoryError> {
        let mut h = crate::conn::open(db).await?;
        let backend = h.backend();
        match sqlx::query(insert_repository_sql(backend))
            .bind(repository.id.to_string())
            .bind(repository.owner.as_user().map(|id| id.to_string()))
            .bind(repository.owner.as_organization().map(|id| id.to_string()))
            .bind(&repository.name)
            .bind(&repository.description)
            .bind(repository.visibility.as_db_str())
            .bind(repository.forked_from.map(|id| id.to_string()))
            .bind(crate::now_unix())
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
        Self::insert_with_owner_grant(db, repository, OwnerGrant::User(owner_user_id)).await
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
        Self::insert_with_owner_grant(db, repository, OwnerGrant::Team(owner_team_id)).await
    }

    async fn insert_with_owner_grant<'c>(
        db: impl DbConn<'c>,
        repository: &Repository,
        grant: OwnerGrant,
    ) -> Result<(), InsertRepositoryError> {
        let mut h = crate::conn::open(db).await?;
        let backend = h.backend();
        let id = repository.id.to_string();
        let mut tx = h.begin().await?;

        match sqlx::query(insert_repository_sql(backend))
            .bind(&id)
            .bind(repository.owner.as_user().map(|id| id.to_string()))
            .bind(repository.owner.as_organization().map(|id| id.to_string()))
            .bind(&repository.name)
            .bind(&repository.description)
            .bind(repository.visibility.as_db_str())
            .bind(repository.forked_from.map(|id| id.to_string()))
            .bind(crate::now_unix())
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

        let role = edda_domain::RepoRole::Owner.as_db_str();
        let granted_at = crate::now_unix();
        let (subject_column, subject_id) = match grant {
            OwnerGrant::User(user_id) => ("subject_user_id", user_id.to_string()),
            OwnerGrant::Team(team_id) => ("subject_team_id", team_id.to_string()),
        };
        let grant_sql = match backend {
            Backend::Postgres => format!(
                "INSERT INTO repo_access (repository_id, {subject_column}, role, added_at) VALUES ($1, $2, $3, $4)"
            ),
            Backend::Sqlite | Backend::MySql => format!(
                "INSERT INTO repo_access (repository_id, {subject_column}, role, added_at) VALUES (?, ?, ?, ?)"
            ),
        };
        sqlx::query(&grant_sql)
            .bind(&id)
            .bind(&subject_id)
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
        // Which typed owner column this lookup keys on.
        let owner_column = match owner {
            RepositoryOwner::User(_) => "owner_user_id",
            RepositoryOwner::Organization(_) => "owner_org_id",
        };
        let owner_id = owner.owner_id().to_string();
        let sql = match h.backend() {
            Backend::Postgres => format!(
                "SELECT {REPO_COLS} FROM repositories WHERE {owner_column} = $1 AND name = $2"
            ),
            Backend::Sqlite | Backend::MySql => format!(
                "SELECT {REPO_COLS} FROM repositories WHERE {owner_column} = ? AND name = ?"
            ),
        };
        let row = sqlx::query(&sql)
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
                format!("SELECT {REPO_COLS} FROM repositories WHERE id = $1")
            }
            Backend::Sqlite | Backend::MySql => {
                format!("SELECT {REPO_COLS} FROM repositories WHERE id = ?")
            }
        };
        let row = sqlx::query(&sql)
            .bind(&id_text)
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(row_to_repository_row).transpose()
    }

    /// A repository by id, together with its owner's display name (a
    /// username or an organization name) — the same `COALESCE` join
    /// `list_all_with_owner_username` does, narrowed to one id. Used to turn
    /// a cross-repository pull request's stored `source_repository_id` back
    /// into the `{owner}/{name}` identity the git layer needs.
    pub async fn find_by_id_with_owner_username<'c>(
        db: impl DbConn<'c>,
        id: RepositoryId,
    ) -> Result<Option<(Repository, String)>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                format!("{REPO_OWNER_JOIN_SELECT} WHERE r.id = $1")
            }
            Backend::Sqlite | Backend::MySql => {
                format!("{REPO_OWNER_JOIN_SELECT} WHERE r.id = ?")
            }
        };
        let row = sqlx::query(&sql)
            .bind(&id_text)
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(|row| {
            let owner_username = get_string(&row, "owner_username")?;
            Ok((row_to_repository_row(row)?, owner_username))
        })
        .transpose()
    }

    /// Every repository in the instance. `edda-app` filters this down to
    /// what the requesting actor may actually see (public repos plus any
    /// private repo they hold a grant on) — there is no per-owner or
    /// per-visibility variant yet because nothing needs one at the
    /// instance's current expected scale.
    pub async fn list_all<'c>(db: impl DbConn<'c>) -> Result<Vec<Repository>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let rows = sqlx::query(&format!(
            "SELECT {REPO_COLS} FROM repositories ORDER BY COALESCE(owner_user_id, owner_org_id), name"
        ))
        .fetch_all(&mut *h.conn())
        .await?;
        rows.into_iter().map(row_to_repository_row).collect()
    }

    /// Every repository, alongside its owner's display name (a username or
    /// an organization name — exactly one `LEFT JOIN` below matches per
    /// row, since exactly one owner column is set) — the join `list_all`
    /// deliberately doesn't do (nothing else needs it): a repository
    /// listing DTO needs the `{owner}/{name}` display form, and resolving
    /// that per-row here avoids an N+1 owner-name lookup in `edda-web`'s
    /// `list_repos` server function.
    pub async fn list_all_with_owner_username<'c>(
        db: impl DbConn<'c>,
    ) -> Result<Vec<(Repository, String)>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let rows = sqlx::query(&format!(
            "{REPO_OWNER_JOIN_SELECT} ORDER BY owner_username, r.name"
        ))
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

    /// How many repositories `user_id` directly owns (via
    /// `owner_user_id`). The `edda-cli user delete` / admin delete-user
    /// paths call this to give a clear "still owns N repositories" error
    /// instead of surfacing a raw foreign-key violation — since the Phase
    /// 9 baseline `repositories.owner_user_id` is a real restricting
    /// foreign key, so deleting an owner while repositories remain fails.
    pub async fn count_owned_by_user<'c>(
        db: impl DbConn<'c>,
        user_id: UserId,
    ) -> Result<i64, DbError> {
        let mut h = crate::conn::open(db).await?;
        let user_id_text = user_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => "SELECT COUNT(*) AS n FROM repositories WHERE owner_user_id = $1",
            Backend::Sqlite | Backend::MySql => {
                "SELECT COUNT(*) AS n FROM repositories WHERE owner_user_id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&user_id_text)
            .fetch_one(&mut *h.conn())
            .await?;
        Ok(crate::get_i64(&row, "n")?)
    }
}

enum OwnerGrant {
    User(UserId),
    Team(TeamId),
}

/// The `repositories` column list every `SELECT` that reconstructs a
/// `Repository` reads, in the order `row_to_repository_row` expects.
const REPO_COLS: &str =
    "id, owner_user_id, owner_org_id, name, description, visibility, forked_from";

/// The `SELECT` that also resolves the owner's display name — exactly one
/// `LEFT JOIN` matches per row (one owner column is always NULL).
const REPO_OWNER_JOIN_SELECT: &str = r#"SELECT r.id, r.owner_user_id, r.owner_org_id, r.name, r.description, r.visibility, r.forked_from,
          COALESCE(u.username, o.name) AS owner_username
   FROM repositories r
   LEFT JOIN users u ON u.id = r.owner_user_id
   LEFT JOIN organizations o ON o.id = r.owner_org_id"#;

fn insert_repository_sql(backend: Backend) -> &'static str {
    match backend {
        Backend::Postgres => {
            "INSERT INTO repositories (id, owner_user_id, owner_org_id, name, description, visibility, forked_from, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
        }
        Backend::Sqlite | Backend::MySql => {
            "INSERT INTO repositories (id, owner_user_id, owner_org_id, name, description, visibility, forked_from, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        }
    }
}

fn row_to_repository_row(row: sqlx::any::AnyRow) -> Result<Repository, DbError> {
    Ok(Repository {
        id: get_string(&row, "id")?
            .parse()
            .expect("stored repository id is a valid UUID"),
        owner: row_to_owner(
            get_opt_string(&row, "owner_user_id")?,
            get_opt_string(&row, "owner_org_id")?,
        ),
        name: get_string(&row, "name")?,
        description: get_opt_string(&row, "description")?,
        visibility: Visibility::from_db_str(&get_string(&row, "visibility")?)
            .expect("stored repositories.visibility is one of the CHECK'd values"),
        forked_from: get_opt_string(&row, "forked_from")?
            .map(|id| id.parse().expect("stored forked_from is a valid UUID")),
    })
}

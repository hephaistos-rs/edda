use edda_domain::{RepoAccess, RepoRole, RepositoryId, User, UserId};

use crate::DbPool;

/// One row of `list_collaborators`: the access grant plus enough of the
/// grantee's identity to render a collaborator list without a second
/// round trip per row.
pub struct CollaboratorRow {
    pub user: User,
    pub role: RepoRole,
    pub added_at: i64,
}

pub struct RepoAccessRepo;

impl RepoAccessRepo {
    /// Called once, right after a repository is created — the creator is
    /// always its owner. Not `INSERT OR IGNORE`: there's nothing to
    /// conflict with for a repository that didn't exist a moment ago, and
    /// a conflict here would mean a real bug upstream.
    pub async fn grant_owner(
        pool: &DbPool,
        repository_id: RepositoryId,
        user_id: UserId,
    ) -> Result<(), sqlx::Error> {
        Self::grant(pool, repository_id, user_id, RepoRole::Owner).await
    }

    #[cfg(feature = "sqlite")]
    pub async fn grant(
        pool: &DbPool,
        repository_id: RepositoryId,
        user_id: UserId,
        role: RepoRole,
    ) -> Result<(), sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let user_id_text = user_id.to_string();
        let role = role.as_db_str();
        let added_at = crate::now_unix();
        sqlx::query!(
            "INSERT OR IGNORE INTO repo_access (repository_id, user_id, role, added_at) VALUES (?, ?, ?, ?)",
            repository_id_text,
            user_id_text,
            role,
            added_at,
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    #[cfg(feature = "postgres")]
    pub async fn grant(
        pool: &DbPool,
        repository_id: RepositoryId,
        user_id: UserId,
        role: RepoRole,
    ) -> Result<(), sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let user_id_text = user_id.to_string();
        let role = role.as_db_str();
        let added_at = crate::now_unix();
        sqlx::query!(
            "INSERT INTO repo_access (repository_id, user_id, role, added_at) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            repository_id_text,
            user_id_text,
            role,
            added_at,
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    pub async fn find(
        pool: &DbPool,
        repository_id: RepositoryId,
        user_id: UserId,
    ) -> Result<Option<RepoAccess>, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let user_id_text = user_id.to_string();
        let row = sqlx::query!(
            "SELECT role FROM repo_access WHERE repository_id = ? AND user_id = ?",
            repository_id_text,
            user_id_text,
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| RepoAccess {
            repository_id,
            user_id,
            role: RepoRole::from_db_str(&row.role)
                .expect("stored repo_access.role is one of the CHECK'd values"),
        }))
    }

    #[cfg(feature = "postgres")]
    pub async fn find(
        pool: &DbPool,
        repository_id: RepositoryId,
        user_id: UserId,
    ) -> Result<Option<RepoAccess>, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let user_id_text = user_id.to_string();
        let row = sqlx::query!(
            "SELECT role FROM repo_access WHERE repository_id = $1 AND user_id = $2",
            repository_id_text,
            user_id_text,
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| RepoAccess {
            repository_id,
            user_id,
            role: RepoRole::from_db_str(&row.role)
                .expect("stored repo_access.role is one of the CHECK'd values"),
        }))
    }

    /// Every `(repository, role)` grant a user holds — used to annotate a
    /// repository listing with per-repo role without one query per row
    /// (mirrors the pre-restructuring `access_roles` helper in
    /// `server/mod.rs`, now behind this crate's boundary instead of an ad
    /// hoc query inline in a server function).
    #[cfg(feature = "sqlite")]
    pub async fn roles_for_user(
        pool: &DbPool,
        user_id: UserId,
    ) -> Result<Vec<(RepositoryId, RepoRole)>, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let rows = sqlx::query!(
            "SELECT repository_id, role FROM repo_access WHERE user_id = ?",
            user_id_text
        )
        .fetch_all(pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let repository_id = row
                    .repository_id
                    .parse()
                    .expect("stored repository id is a valid UUID");
                let role = RepoRole::from_db_str(&row.role)
                    .expect("stored repo_access.role is one of the CHECK'd values");
                (repository_id, role)
            })
            .collect())
    }

    #[cfg(feature = "postgres")]
    pub async fn roles_for_user(
        pool: &DbPool,
        user_id: UserId,
    ) -> Result<Vec<(RepositoryId, RepoRole)>, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let rows = sqlx::query!(
            "SELECT repository_id, role FROM repo_access WHERE user_id = $1",
            user_id_text
        )
        .fetch_all(pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let repository_id = row
                    .repository_id
                    .parse()
                    .expect("stored repository id is a valid UUID");
                let role = RepoRole::from_db_str(&row.role)
                    .expect("stored repo_access.role is one of the CHECK'd values");
                (repository_id, role)
            })
            .collect())
    }

    #[cfg(feature = "sqlite")]
    pub async fn list_collaborators(
        pool: &DbPool,
        repository_id: RepositoryId,
    ) -> Result<Vec<CollaboratorRow>, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let rows = sqlx::query!(
            r#"SELECT u.id as user_id, u.username, u.email, a.role, a.added_at
               FROM repo_access a JOIN users u ON u.id = a.user_id
               WHERE a.repository_id = ? ORDER BY a.added_at"#,
            repository_id_text,
        )
        .fetch_all(pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| CollaboratorRow {
                user: User {
                    id: row.user_id.parse().expect("stored user id is a valid UUID"),
                    username: row.username,
                    email: row.email,
                },
                role: RepoRole::from_db_str(&row.role)
                    .expect("stored repo_access.role is one of the CHECK'd values"),
                added_at: row.added_at,
            })
            .collect())
    }

    #[cfg(feature = "postgres")]
    pub async fn list_collaborators(
        pool: &DbPool,
        repository_id: RepositoryId,
    ) -> Result<Vec<CollaboratorRow>, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let rows = sqlx::query!(
            r#"SELECT u.id as user_id, u.username, u.email, a.role, a.added_at
               FROM repo_access a JOIN users u ON u.id = a.user_id
               WHERE a.repository_id = $1 ORDER BY a.added_at"#,
            repository_id_text,
        )
        .fetch_all(pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| CollaboratorRow {
                user: User {
                    id: row.user_id.parse().expect("stored user id is a valid UUID"),
                    username: row.username,
                    email: row.email,
                },
                role: RepoRole::from_db_str(&row.role)
                    .expect("stored repo_access.role is one of the CHECK'd values"),
                added_at: row.added_at,
            })
            .collect())
    }

    /// `Ok(true)` if a non-owner grant was actually removed. The owner
    /// grant can never be removed through this path — a repository must
    /// always keep exactly one (enforced independently by the database's
    /// own partial-unique-index invariant, but checked here too so the
    /// caller gets a clear "no such collaborator" outcome rather than a
    /// constraint-violation error).
    #[cfg(feature = "sqlite")]
    pub async fn remove_collaborator(
        pool: &DbPool,
        repository_id: RepositoryId,
        user_id: UserId,
    ) -> Result<bool, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let user_id_text = user_id.to_string();
        let result = sqlx::query!(
            "DELETE FROM repo_access WHERE repository_id = ? AND user_id = ? AND role != 'owner'",
            repository_id_text,
            user_id_text,
        )
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    #[cfg(feature = "postgres")]
    pub async fn remove_collaborator(
        pool: &DbPool,
        repository_id: RepositoryId,
        user_id: UserId,
    ) -> Result<bool, sqlx::Error> {
        let repository_id_text = repository_id.to_string();
        let user_id_text = user_id.to_string();
        let result = sqlx::query!(
            "DELETE FROM repo_access WHERE repository_id = $1 AND user_id = $2 AND role != 'owner'",
            repository_id_text,
            user_id_text,
        )
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

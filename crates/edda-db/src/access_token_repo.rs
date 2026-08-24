use edda_domain::{AccessToken, AccessTokenId, RepositoryScope, User, UserId};

use crate::DbPool;

fn scope_to_json(scope: &RepositoryScope) -> String {
    serde_json::to_string(scope).expect("RepositoryScope always serializes")
}

fn scope_from_json(json: &str) -> RepositoryScope {
    serde_json::from_str(json)
        .expect("stored access_tokens.repository_scope is valid JSON written by this crate")
}

pub struct AccessTokenRepo;

impl AccessTokenRepo {
    #[cfg(feature = "sqlite")]
    pub async fn insert(
        pool: &DbPool,
        id: AccessTokenId,
        user_id: UserId,
        name: &str,
        token_hash: &str,
        repository_scope: &RepositoryScope,
    ) -> Result<i64, sqlx::Error> {
        let id_text = id.to_string();
        let user_id_text = user_id.to_string();
        let scope_json = scope_to_json(repository_scope);
        let created_at = crate::now_unix();
        sqlx::query!(
            "INSERT INTO access_tokens (id, user_id, name, token_hash, repository_scope, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            id_text,
            user_id_text,
            name,
            token_hash,
            scope_json,
            created_at,
        )
        .execute(pool)
        .await?;
        Ok(created_at)
    }

    #[cfg(feature = "postgres")]
    pub async fn insert(
        pool: &DbPool,
        id: AccessTokenId,
        user_id: UserId,
        name: &str,
        token_hash: &str,
        repository_scope: &RepositoryScope,
    ) -> Result<i64, sqlx::Error> {
        let id_text = id.to_string();
        let user_id_text = user_id.to_string();
        let scope_json = scope_to_json(repository_scope);
        let created_at = crate::now_unix();
        sqlx::query!(
            "INSERT INTO access_tokens (id, user_id, name, token_hash, repository_scope, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
            id_text,
            user_id_text,
            name,
            token_hash,
            scope_json,
            created_at,
        )
        .execute(pool)
        .await?;
        Ok(created_at)
    }

    #[cfg(feature = "sqlite")]
    pub async fn list_for_user(
        pool: &DbPool,
        user_id: UserId,
    ) -> Result<Vec<AccessToken>, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let rows = sqlx::query!(
            "SELECT id, name, repository_scope, created_at, last_used_at FROM access_tokens WHERE user_id = ? ORDER BY created_at DESC",
            user_id_text,
        )
        .fetch_all(pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| AccessToken {
                id: row
                    .id
                    .parse()
                    .expect("stored access token id is a valid UUID"),
                user_id,
                name: row.name,
                repository_scope: scope_from_json(&row.repository_scope),
                created_at: row.created_at,
                last_used_at: row.last_used_at,
            })
            .collect())
    }

    #[cfg(feature = "postgres")]
    pub async fn list_for_user(
        pool: &DbPool,
        user_id: UserId,
    ) -> Result<Vec<AccessToken>, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let rows = sqlx::query!(
            "SELECT id, name, repository_scope, created_at, last_used_at FROM access_tokens WHERE user_id = $1 ORDER BY created_at DESC",
            user_id_text,
        )
        .fetch_all(pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| AccessToken {
                id: row
                    .id
                    .parse()
                    .expect("stored access token id is a valid UUID"),
                user_id,
                name: row.name,
                repository_scope: scope_from_json(&row.repository_scope),
                created_at: row.created_at,
                last_used_at: row.last_used_at,
            })
            .collect())
    }

    /// `Ok(true)` if a token owned by `user_id` was revoked — deliberately
    /// scoped to that owner, so revoking someone else's token by guessing
    /// its id looks identical to "no such token."
    #[cfg(feature = "sqlite")]
    pub async fn revoke(
        pool: &DbPool,
        user_id: UserId,
        token_id: AccessTokenId,
    ) -> Result<bool, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let token_id_text = token_id.to_string();
        let result = sqlx::query!(
            "DELETE FROM access_tokens WHERE id = ? AND user_id = ?",
            token_id_text,
            user_id_text
        )
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    #[cfg(feature = "postgres")]
    pub async fn revoke(
        pool: &DbPool,
        user_id: UserId,
        token_id: AccessTokenId,
    ) -> Result<bool, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let token_id_text = token_id.to_string();
        let result = sqlx::query!(
            "DELETE FROM access_tokens WHERE id = $1 AND user_id = $2",
            token_id_text,
            user_id_text
        )
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Resolves a raw token's hash to the user it belongs to and the
    /// token's own scope. Also best-effort records `last_used_at` — a
    /// failure to record that shouldn't fail the authentication it's just
    /// accounting for.
    #[cfg(feature = "sqlite")]
    pub async fn find_by_hash(
        pool: &DbPool,
        token_hash: &str,
    ) -> Result<Option<(User, RepositoryScope)>, sqlx::Error> {
        let row = sqlx::query!(
            r#"SELECT u.id as user_id, u.username, u.email, t.repository_scope
               FROM access_tokens t JOIN users u ON u.id = t.user_id
               WHERE t.token_hash = ?"#,
            token_hash,
        )
        .fetch_optional(pool)
        .await?;
        let Some(row) = row else { return Ok(None) };

        let last_used_at = crate::now_unix();
        let _ = sqlx::query!(
            "UPDATE access_tokens SET last_used_at = ? WHERE token_hash = ?",
            last_used_at,
            token_hash
        )
        .execute(pool)
        .await;

        let user = User {
            id: row.user_id.parse().expect("stored user id is a valid UUID"),
            username: row.username,
            email: row.email,
        };
        Ok(Some((user, scope_from_json(&row.repository_scope))))
    }

    #[cfg(feature = "postgres")]
    pub async fn find_by_hash(
        pool: &DbPool,
        token_hash: &str,
    ) -> Result<Option<(User, RepositoryScope)>, sqlx::Error> {
        let row = sqlx::query!(
            r#"SELECT u.id as user_id, u.username, u.email, t.repository_scope
               FROM access_tokens t JOIN users u ON u.id = t.user_id
               WHERE t.token_hash = $1"#,
            token_hash,
        )
        .fetch_optional(pool)
        .await?;
        let Some(row) = row else { return Ok(None) };

        let last_used_at = crate::now_unix();
        let _ = sqlx::query!(
            "UPDATE access_tokens SET last_used_at = $1 WHERE token_hash = $2",
            last_used_at,
            token_hash
        )
        .execute(pool)
        .await;

        let user = User {
            id: row.user_id.parse().expect("stored user id is a valid UUID"),
            username: row.username,
            email: row.email,
        };
        Ok(Some((user, scope_from_json(&row.repository_scope))))
    }
}

use edda_domain::{AccessToken, AccessTokenId, RepositoryScope, User, UserId};

use crate::{get_bool, get_i64, get_opt_i64, get_string, Backend, DbPool};

fn scope_to_json(scope: &RepositoryScope) -> String {
    serde_json::to_string(scope).expect("RepositoryScope always serializes")
}

fn scope_from_json(json: &str) -> RepositoryScope {
    serde_json::from_str(json)
        .expect("stored access_tokens.repository_scope is valid JSON written by this crate")
}

pub struct AccessTokenRepo;

impl AccessTokenRepo {
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
        let sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO access_tokens (id, user_id, name, token_hash, repository_scope, created_at) VALUES ($1, $2, $3, $4, $5, $6)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO access_tokens (id, user_id, name, token_hash, repository_scope, created_at) VALUES (?, ?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(sql)
            .bind(&id_text)
            .bind(&user_id_text)
            .bind(name)
            .bind(token_hash)
            .bind(&scope_json)
            .bind(created_at)
            .execute(&pool.any)
            .await?;
        Ok(created_at)
    }

    pub async fn list_for_user(
        pool: &DbPool,
        user_id: UserId,
    ) -> Result<Vec<AccessToken>, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT id, name, repository_scope, created_at, last_used_at FROM access_tokens WHERE user_id = $1 ORDER BY created_at DESC"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, name, repository_scope, created_at, last_used_at FROM access_tokens WHERE user_id = ? ORDER BY created_at DESC"
            }
        };
        let rows = sqlx::query(sql)
            .bind(&user_id_text)
            .fetch_all(&pool.any)
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(AccessToken {
                    id: get_string(&row, "id")?
                        .parse()
                        .expect("stored access token id is a valid UUID"),
                    user_id,
                    name: get_string(&row, "name")?,
                    repository_scope: scope_from_json(&get_string(&row, "repository_scope")?),
                    created_at: get_i64(&row, "created_at")?,
                    last_used_at: get_opt_i64(&row, "last_used_at")?,
                })
            })
            .collect()
    }

    /// `Ok(true)` if a token owned by `user_id` was revoked — deliberately
    /// scoped to that owner, so revoking someone else's token by guessing
    /// its id looks identical to "no such token."
    pub async fn revoke(
        pool: &DbPool,
        user_id: UserId,
        token_id: AccessTokenId,
    ) -> Result<bool, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let token_id_text = token_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => "DELETE FROM access_tokens WHERE id = $1 AND user_id = $2",
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM access_tokens WHERE id = ? AND user_id = ?"
            }
        };
        let result = sqlx::query(sql)
            .bind(&token_id_text)
            .bind(&user_id_text)
            .execute(&pool.any)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Resolves a raw token's hash to the user it belongs to and the
    /// token's own scope. Also best-effort records `last_used_at` — a
    /// failure to record that shouldn't fail the authentication it's just
    /// accounting for.
    pub async fn find_by_hash(
        pool: &DbPool,
        token_hash: &str,
    ) -> Result<Option<(User, RepositoryScope)>, sqlx::Error> {
        let select_sql = match pool.backend {
            Backend::Postgres => {
                r#"SELECT u.id as user_id, u.username, u.email, u.is_admin, u.disabled_at, t.repository_scope
                   FROM access_tokens t JOIN users u ON u.id = t.user_id
                   WHERE t.token_hash = $1"#
            }
            Backend::Sqlite | Backend::MySql => {
                r#"SELECT u.id as user_id, u.username, u.email, u.is_admin, u.disabled_at, t.repository_scope
                   FROM access_tokens t JOIN users u ON u.id = t.user_id
                   WHERE t.token_hash = ?"#
            }
        };
        let row = sqlx::query(select_sql)
            .bind(token_hash)
            .fetch_optional(&pool.any)
            .await?;
        let Some(row) = row else { return Ok(None) };

        let last_used_at = crate::now_unix();
        let update_sql = match pool.backend {
            Backend::Postgres => "UPDATE access_tokens SET last_used_at = $1 WHERE token_hash = $2",
            Backend::Sqlite | Backend::MySql => {
                "UPDATE access_tokens SET last_used_at = ? WHERE token_hash = ?"
            }
        };
        let _ = sqlx::query(update_sql)
            .bind(last_used_at)
            .bind(token_hash)
            .execute(&pool.any)
            .await;

        let user = User {
            id: get_string(&row, "user_id")?
                .parse()
                .expect("stored user id is a valid UUID"),
            username: get_string(&row, "username")?,
            email: get_string(&row, "email")?,
            is_admin: get_bool(&row, "is_admin")?,
            disabled_at: get_opt_i64(&row, "disabled_at")?,
        };
        Ok(Some((
            user,
            scope_from_json(&get_string(&row, "repository_scope")?),
        )))
    }
}

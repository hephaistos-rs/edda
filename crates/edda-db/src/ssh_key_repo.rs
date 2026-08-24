use edda_domain::{SshKey, SshKeyId, User, UserId};

use crate::DbPool;

#[derive(Debug, thiserror::Error)]
pub enum InsertSshKeyError {
    #[error("that key is already registered")]
    FingerprintTaken,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

fn row_to_ssh_key(
    id: String,
    user_id: UserId,
    fingerprint: String,
    public_key: String,
    title: String,
    created_at: i64,
    last_used_at: Option<i64>,
) -> SshKey {
    SshKey {
        id: id.parse().expect("stored ssh key id is a valid UUID"),
        user_id,
        fingerprint,
        public_key,
        title,
        created_at,
        last_used_at,
    }
}

pub struct SshKeyRepo;

impl SshKeyRepo {
    #[cfg(feature = "sqlite")]
    pub async fn insert(
        pool: &DbPool,
        id: SshKeyId,
        user_id: UserId,
        fingerprint: &str,
        public_key: &str,
        title: &str,
    ) -> Result<i64, InsertSshKeyError> {
        let id_text = id.to_string();
        let user_id_text = user_id.to_string();
        let created_at = crate::now_unix();
        let result = sqlx::query!(
            "INSERT INTO ssh_keys (id, user_id, fingerprint, public_key, title, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            id_text,
            user_id_text,
            fingerprint,
            public_key,
            title,
            created_at,
        )
        .execute(pool)
        .await;

        match result {
            Ok(_) => Ok(created_at),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                Err(InsertSshKeyError::FingerprintTaken)
            }
            Err(err) => Err(InsertSshKeyError::Db(err)),
        }
    }

    #[cfg(feature = "postgres")]
    pub async fn insert(
        pool: &DbPool,
        id: SshKeyId,
        user_id: UserId,
        fingerprint: &str,
        public_key: &str,
        title: &str,
    ) -> Result<i64, InsertSshKeyError> {
        let id_text = id.to_string();
        let user_id_text = user_id.to_string();
        let created_at = crate::now_unix();
        let result = sqlx::query!(
            "INSERT INTO ssh_keys (id, user_id, fingerprint, public_key, title, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
            id_text,
            user_id_text,
            fingerprint,
            public_key,
            title,
            created_at,
        )
        .execute(pool)
        .await;

        match result {
            Ok(_) => Ok(created_at),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                Err(InsertSshKeyError::FingerprintTaken)
            }
            Err(err) => Err(InsertSshKeyError::Db(err)),
        }
    }

    #[cfg(feature = "sqlite")]
    pub async fn list_for_user(pool: &DbPool, user_id: UserId) -> Result<Vec<SshKey>, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let rows = sqlx::query!(
            "SELECT id, fingerprint, public_key, title, created_at, last_used_at FROM ssh_keys WHERE user_id = ? ORDER BY created_at DESC",
            user_id_text,
        )
        .fetch_all(pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                row_to_ssh_key(
                    row.id,
                    user_id,
                    row.fingerprint,
                    row.public_key,
                    row.title,
                    row.created_at,
                    row.last_used_at,
                )
            })
            .collect())
    }

    #[cfg(feature = "postgres")]
    pub async fn list_for_user(pool: &DbPool, user_id: UserId) -> Result<Vec<SshKey>, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let rows = sqlx::query!(
            "SELECT id, fingerprint, public_key, title, created_at, last_used_at FROM ssh_keys WHERE user_id = $1 ORDER BY created_at DESC",
            user_id_text,
        )
        .fetch_all(pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                row_to_ssh_key(
                    row.id,
                    user_id,
                    row.fingerprint,
                    row.public_key,
                    row.title,
                    row.created_at,
                    row.last_used_at,
                )
            })
            .collect())
    }

    /// `Ok(true)` if a key owned by `user_id` was revoked — deliberately
    /// scoped to that owner, so revoking someone else's key by guessing
    /// its id looks identical to "no such key" (mirrors
    /// `AccessTokenRepo::revoke`'s exact reasoning).
    #[cfg(feature = "sqlite")]
    pub async fn revoke(
        pool: &DbPool,
        user_id: UserId,
        key_id: SshKeyId,
    ) -> Result<bool, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let key_id_text = key_id.to_string();
        let result = sqlx::query!(
            "DELETE FROM ssh_keys WHERE id = ? AND user_id = ?",
            key_id_text,
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
        key_id: SshKeyId,
    ) -> Result<bool, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let key_id_text = key_id.to_string();
        let result = sqlx::query!(
            "DELETE FROM ssh_keys WHERE id = $1 AND user_id = $2",
            key_id_text,
            user_id_text
        )
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Resolves a public key's fingerprint to the user it belongs to —
    /// the entire SSH-authentication lookup. Also best-effort records
    /// `last_used_at`, same reasoning as `AccessTokenRepo::find_by_hash`.
    #[cfg(feature = "sqlite")]
    pub async fn find_by_fingerprint(
        pool: &DbPool,
        fingerprint: &str,
    ) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query!(
            r#"SELECT u.id as user_id, u.username, u.email
               FROM ssh_keys k JOIN users u ON u.id = k.user_id
               WHERE k.fingerprint = ?"#,
            fingerprint,
        )
        .fetch_optional(pool)
        .await?;
        let Some(row) = row else { return Ok(None) };

        let last_used_at = crate::now_unix();
        let _ = sqlx::query!(
            "UPDATE ssh_keys SET last_used_at = ? WHERE fingerprint = ?",
            last_used_at,
            fingerprint
        )
        .execute(pool)
        .await;

        Ok(Some(User {
            id: row.user_id.parse().expect("stored user id is a valid UUID"),
            username: row.username,
            email: row.email,
        }))
    }

    #[cfg(feature = "postgres")]
    pub async fn find_by_fingerprint(
        pool: &DbPool,
        fingerprint: &str,
    ) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query!(
            r#"SELECT u.id as user_id, u.username, u.email
               FROM ssh_keys k JOIN users u ON u.id = k.user_id
               WHERE k.fingerprint = $1"#,
            fingerprint,
        )
        .fetch_optional(pool)
        .await?;
        let Some(row) = row else { return Ok(None) };

        let last_used_at = crate::now_unix();
        let _ = sqlx::query!(
            "UPDATE ssh_keys SET last_used_at = $1 WHERE fingerprint = $2",
            last_used_at,
            fingerprint
        )
        .execute(pool)
        .await;

        Ok(Some(User {
            id: row.user_id.parse().expect("stored user id is a valid UUID"),
            username: row.username,
            email: row.email,
        }))
    }
}

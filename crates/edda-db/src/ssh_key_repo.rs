use edda_domain::{SshKey, SshKeyId, User, UserId};
use sqlx::SqlitePool;

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
    pub async fn insert(
        pool: &SqlitePool,
        id: SshKeyId,
        user_id: UserId,
        fingerprint: &str,
        public_key: &str,
        title: &str,
    ) -> Result<i64, InsertSshKeyError> {
        let id_text = id.to_string();
        let user_id_text = user_id.to_string();
        let result = sqlx::query!(
            "INSERT INTO ssh_keys (id, user_id, fingerprint, public_key, title) VALUES (?, ?, ?, ?, ?) RETURNING created_at",
            id_text,
            user_id_text,
            fingerprint,
            public_key,
            title,
        )
        .fetch_one(pool)
        .await;

        match result {
            Ok(row) => Ok(row.created_at),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                Err(InsertSshKeyError::FingerprintTaken)
            }
            Err(err) => Err(InsertSshKeyError::Db(err)),
        }
    }

    pub async fn list_for_user(
        pool: &SqlitePool,
        user_id: UserId,
    ) -> Result<Vec<SshKey>, sqlx::Error> {
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

    /// `Ok(true)` if a key owned by `user_id` was revoked — deliberately
    /// scoped to that owner, so revoking someone else's key by guessing
    /// its id looks identical to "no such key" (mirrors
    /// `AccessTokenRepo::revoke`'s exact reasoning).
    pub async fn revoke(
        pool: &SqlitePool,
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

    /// Resolves a public key's fingerprint to the user it belongs to —
    /// the entire SSH-authentication lookup. Also best-effort records
    /// `last_used_at`, same reasoning as `AccessTokenRepo::find_by_hash`.
    pub async fn find_by_fingerprint(
        pool: &SqlitePool,
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

        let _ = sqlx::query!(
            "UPDATE ssh_keys SET last_used_at = unixepoch() WHERE fingerprint = ?",
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

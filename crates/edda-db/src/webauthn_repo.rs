//! WebAuthn/passkey credential storage. `passkey_json` is `webauthn-rs`'s
//! own serialized `Passkey` — this crate never interprets it, only
//! round-trips the bytes `edda-auth::webauthn` hands it.

use edda_domain::{UserId, WebauthnCredentialId};

use crate::{get_i64, get_opt_i64, get_string, Backend, DbPool};

pub struct WebauthnCredentialRow {
    pub id: WebauthnCredentialId,
    pub user_id: UserId,
    pub label: String,
    pub passkey_json: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

fn row_to_credential(row: sqlx::any::AnyRow) -> Result<WebauthnCredentialRow, sqlx::Error> {
    Ok(WebauthnCredentialRow {
        id: get_string(&row, "id")?
            .parse()
            .expect("stored webauthn credential id is a valid UUID"),
        user_id: get_string(&row, "user_id")?
            .parse()
            .expect("stored user id is a valid UUID"),
        label: get_string(&row, "label")?,
        passkey_json: get_string(&row, "passkey_json")?,
        created_at: get_i64(&row, "created_at")?,
        last_used_at: get_opt_i64(&row, "last_used_at")?,
    })
}

pub struct WebauthnRepo;

impl WebauthnRepo {
    pub async fn insert(
        pool: &DbPool,
        id: WebauthnCredentialId,
        user_id: UserId,
        label: &str,
        passkey_json: &str,
    ) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        let user_id_text = user_id.to_string();
        let created_at = crate::now_unix();
        let sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO webauthn_credentials (id, user_id, label, passkey_json, created_at) VALUES ($1, $2, $3, $4, $5)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO webauthn_credentials (id, user_id, label, passkey_json, created_at) VALUES (?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(sql)
            .bind(&id_text)
            .bind(&user_id_text)
            .bind(label)
            .bind(passkey_json)
            .bind(created_at)
            .execute(&pool.any)
            .await?;
        Ok(())
    }

    pub async fn list_for_user(
        pool: &DbPool,
        user_id: UserId,
    ) -> Result<Vec<WebauthnCredentialRow>, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT id, user_id, label, passkey_json, created_at, last_used_at FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, user_id, label, passkey_json, created_at, last_used_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at"
            }
        };
        let rows = sqlx::query(sql)
            .bind(&user_id_text)
            .fetch_all(&pool.any)
            .await?;
        rows.into_iter().map(row_to_credential).collect()
    }

    pub async fn update_passkey(
        pool: &DbPool,
        id: WebauthnCredentialId,
        passkey_json: &str,
    ) -> Result<(), sqlx::Error> {
        let id_text = id.to_string();
        let last_used_at = crate::now_unix();
        let sql = match pool.backend {
            Backend::Postgres => {
                "UPDATE webauthn_credentials SET passkey_json = $1, last_used_at = $2 WHERE id = $3"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE webauthn_credentials SET passkey_json = ?, last_used_at = ? WHERE id = ?"
            }
        };
        sqlx::query(sql)
            .bind(passkey_json)
            .bind(last_used_at)
            .bind(&id_text)
            .execute(&pool.any)
            .await?;
        Ok(())
    }

    /// Scoped to `user_id` — see `SshKeyRepo::revoke`'s identical
    /// reasoning for why.
    pub async fn delete(
        pool: &DbPool,
        user_id: UserId,
        id: WebauthnCredentialId,
    ) -> Result<bool, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let id_text = id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => "DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2",
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?"
            }
        };
        let result = sqlx::query(sql)
            .bind(&id_text)
            .bind(&user_id_text)
            .execute(&pool.any)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

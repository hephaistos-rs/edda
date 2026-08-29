//! Support for `edda-cli secrets rotate`: enumerate every stored
//! `secret_ciphertext` (TOTP shared secrets + webhook signing secrets) and
//! write each back re-encrypted. The re-encryption itself is
//! `edda_auth::secret_box`'s job — this module only moves opaque bytes in
//! and out, the same "never interprets the ciphertext" stance the
//! `totp_repo` / `webhook_repo` modules take.

use crate::{get_bytes, get_string, Backend, DbConn, DbError};

/// One encrypted-at-rest blob, tagged with which table it came from so the
/// CLI can report progress and write it back to the right place.
pub struct StoredSecret {
    /// `"totp"` (keyed by `totp_secrets.user_id`) or `"webhook"` (keyed by
    /// `webhooks.id`).
    pub kind: &'static str,
    pub id: String,
    pub ciphertext: Vec<u8>,
}

pub struct SecretRotationRepo;

impl SecretRotationRepo {
    /// Every `secret_ciphertext` currently stored, across both tables.
    pub async fn load_all<'c>(db: impl DbConn<'c>) -> Result<Vec<StoredSecret>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let mut out = Vec::new();
        for row in sqlx::query("SELECT user_id, secret_ciphertext FROM totp_secrets")
            .fetch_all(&mut *h.conn())
            .await?
        {
            out.push(StoredSecret {
                kind: "totp",
                id: get_string(&row, "user_id")?,
                ciphertext: get_bytes(&row, "secret_ciphertext")?,
            });
        }
        for row in sqlx::query("SELECT id, secret_ciphertext FROM webhooks")
            .fetch_all(&mut *h.conn())
            .await?
        {
            out.push(StoredSecret {
                kind: "webhook",
                id: get_string(&row, "id")?,
                ciphertext: get_bytes(&row, "secret_ciphertext")?,
            });
        }
        Ok(out)
    }

    /// Writes `ciphertext` back to the row `secret` came from.
    pub async fn store<'c>(
        db: impl DbConn<'c>,
        secret: &StoredSecret,
        ciphertext: &[u8],
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let (pg, other) = match secret.kind {
            "totp" => (
                "UPDATE totp_secrets SET secret_ciphertext = $1 WHERE user_id = $2",
                "UPDATE totp_secrets SET secret_ciphertext = ? WHERE user_id = ?",
            ),
            _ => (
                "UPDATE webhooks SET secret_ciphertext = $1 WHERE id = $2",
                "UPDATE webhooks SET secret_ciphertext = ? WHERE id = ?",
            ),
        };
        let sql = match h.backend() {
            Backend::Postgres => pg,
            Backend::Sqlite | Backend::MySql => other,
        };
        sqlx::query(sql)
            .bind(ciphertext)
            .bind(&secret.id)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }
}

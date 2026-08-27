//! TOTP secret and recovery-code storage. This crate never encrypts or
//! decrypts anything — `secret_ciphertext` is opaque bytes as far as this
//! module is concerned; `edda-auth`'s `secret_box` module is the only code
//! that understands its contents. Recovery codes are hashed the same way
//! access tokens are (SHA-256, high-entropy, generated server-side).

use edda_domain::{TotpRecoveryCodeId, UserId};

use crate::{get_bytes, get_opt_i64, Backend, DbConn, DbError};

pub struct TotpRepo;

impl TotpRepo {
    /// Starts (or restarts, if a prior enrollment was never activated)
    /// enrollment: stores the encrypted secret with `activated_at` unset.
    /// Does not affect login until `activate` is called — see
    /// `edda_auth::totp`'s enrollment flow.
    pub async fn upsert_secret<'c>(
        db: impl DbConn<'c>,
        user_id: UserId,
        secret_ciphertext: &[u8],
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let user_id_text = user_id.to_string();
        let created_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO totp_secrets (user_id, secret_ciphertext, created_at, activated_at)
                 VALUES ($1, $2, $3, NULL)
                 ON CONFLICT (user_id) DO UPDATE SET secret_ciphertext = EXCLUDED.secret_ciphertext, created_at = EXCLUDED.created_at, activated_at = NULL"
            }
            Backend::Sqlite => {
                "INSERT INTO totp_secrets (user_id, secret_ciphertext, created_at, activated_at)
                 VALUES (?, ?, ?, NULL)
                 ON CONFLICT (user_id) DO UPDATE SET secret_ciphertext = excluded.secret_ciphertext, created_at = excluded.created_at, activated_at = NULL"
            }
            Backend::MySql => {
                "INSERT INTO totp_secrets (user_id, secret_ciphertext, created_at, activated_at)
                 VALUES (?, ?, ?, NULL)
                 ON DUPLICATE KEY UPDATE secret_ciphertext = VALUES(secret_ciphertext), created_at = VALUES(created_at), activated_at = NULL"
            }
        };
        sqlx::query(sql)
            .bind(&user_id_text)
            .bind(secret_ciphertext)
            .bind(created_at)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// The raw ciphertext plus whether enrollment has been activated —
    /// `edda_auth::totp` decrypts and interprets this; this repo never
    /// does.
    pub async fn find_by_user<'c>(
        db: impl DbConn<'c>,
        user_id: UserId,
    ) -> Result<Option<(Vec<u8>, Option<i64>)>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let user_id_text = user_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT secret_ciphertext, activated_at FROM totp_secrets WHERE user_id = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT secret_ciphertext, activated_at FROM totp_secrets WHERE user_id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&user_id_text)
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(|row| {
            Ok((
                get_bytes(&row, "secret_ciphertext")?,
                get_opt_i64(&row, "activated_at")?,
            ))
        })
        .transpose()
    }

    /// Whether `user_id` has an *activated* TOTP credential — the one
    /// question the login flow actually needs answered before deciding
    /// whether to challenge for a second factor.
    pub async fn is_activated<'c>(db: impl DbConn<'c>, user_id: UserId) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        Ok(matches!(
            Self::find_by_user(&mut h, user_id).await?,
            Some((_, Some(_)))
        ))
    }

    pub async fn activate<'c>(db: impl DbConn<'c>, user_id: UserId) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let user_id_text = user_id.to_string();
        let activated_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => "UPDATE totp_secrets SET activated_at = $1 WHERE user_id = $2",
            Backend::Sqlite | Backend::MySql => {
                "UPDATE totp_secrets SET activated_at = ? WHERE user_id = ?"
            }
        };
        sqlx::query(sql)
            .bind(activated_at)
            .bind(&user_id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// Disables 2FA entirely: drops the secret and every recovery code.
    pub async fn delete<'c>(db: impl DbConn<'c>, user_id: UserId) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let user_id_text = user_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => "DELETE FROM totp_secrets WHERE user_id = $1",
            Backend::Sqlite | Backend::MySql => "DELETE FROM totp_secrets WHERE user_id = ?",
        };
        sqlx::query(sql)
            .bind(&user_id_text)
            .execute(&mut *h.conn())
            .await?;
        let sql = match h.backend() {
            Backend::Postgres => "DELETE FROM totp_recovery_codes WHERE user_id = $1",
            Backend::Sqlite | Backend::MySql => "DELETE FROM totp_recovery_codes WHERE user_id = ?",
        };
        sqlx::query(sql)
            .bind(&user_id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// Replaces every existing recovery code with a fresh batch — called
    /// once, right after activation, and again if the user regenerates
    /// codes. Old codes are invalidated by deletion, not left dangling.
    pub async fn replace_recovery_codes<'c>(
        db: impl DbConn<'c>,
        user_id: UserId,
        code_hashes: &[String],
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let user_id_text = user_id.to_string();
        let delete_sql = match h.backend() {
            Backend::Postgres => "DELETE FROM totp_recovery_codes WHERE user_id = $1",
            Backend::Sqlite | Backend::MySql => "DELETE FROM totp_recovery_codes WHERE user_id = ?",
        };
        sqlx::query(delete_sql)
            .bind(&user_id_text)
            .execute(&mut *h.conn())
            .await?;

        let insert_sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO totp_recovery_codes (id, user_id, code_hash, created_at) VALUES ($1, $2, $3, $4)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO totp_recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)"
            }
        };
        let created_at = crate::now_unix();
        for code_hash in code_hashes {
            let id = TotpRecoveryCodeId::new().to_string();
            sqlx::query(insert_sql)
                .bind(&id)
                .bind(&user_id_text)
                .bind(code_hash)
                .bind(created_at)
                .execute(&mut *h.conn())
                .await?;
        }
        Ok(())
    }

    /// Consumes a recovery code if it exists, belongs to `user_id`, and
    /// hasn't been used before — `Ok(true)` means the code was valid and
    /// is now spent; a code is never accepted twice.
    pub async fn consume_recovery_code<'c>(
        db: impl DbConn<'c>,
        user_id: UserId,
        code_hash: &str,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let user_id_text = user_id.to_string();
        let used_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "UPDATE totp_recovery_codes SET used_at = $1 WHERE user_id = $2 AND code_hash = $3 AND used_at IS NULL"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE totp_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL"
            }
        };
        let result = sqlx::query(sql)
            .bind(used_at)
            .bind(&user_id_text)
            .bind(code_hash)
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

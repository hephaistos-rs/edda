//! `email_verification_tokens` persistence (Phase 9). The table comes
//! from the `0001_baseline` migration; the request/consume flow that
//! uses it is `edda_auth::email_verification`. `token_hash` is a fast
//! SHA-256 digest, not a slow hash — the token is a 32-byte random
//! value with 256 bits of entropy (same reasoning as
//! `PasswordResetTokenRepo`).

use edda_domain::{EmailVerificationTokenId, UserId};

use crate::{get_string, Backend, DbConn, DbError};

pub struct EmailVerificationTokenRepo;

impl EmailVerificationTokenRepo {
    pub async fn insert<'c>(
        db: impl DbConn<'c>,
        id: EmailVerificationTokenId,
        user_id: UserId,
        token_hash: &str,
        expires_at: i64,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let created_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO email_verification_tokens (id, user_id, token_hash, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO email_verification_tokens (id, user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(sql)
            .bind(id.to_string())
            .bind(user_id.to_string())
            .bind(token_hash)
            .bind(created_at)
            .bind(expires_at)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// A still-usable (unused, unexpired) token by its hash — `None` for
    /// an unknown, consumed, or expired hash, all indistinguishable to the
    /// caller (a verification link either works or it doesn't).
    pub async fn find_valid_by_hash<'c>(
        db: impl DbConn<'c>,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<(EmailVerificationTokenId, UserId)>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, user_id FROM email_verification_tokens WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, user_id FROM email_verification_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(token_hash)
            .bind(now)
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(|row| {
            Ok((
                get_string(&row, "id")?
                    .parse()
                    .expect("stored email verification token id is a valid UUID"),
                get_string(&row, "user_id")?
                    .parse()
                    .expect("stored user id is a valid UUID"),
            ))
        })
        .transpose()
    }

    pub async fn mark_used<'c>(
        db: impl DbConn<'c>,
        id: EmailVerificationTokenId,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let used_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "UPDATE email_verification_tokens SET used_at = $1 WHERE id = $2 AND used_at IS NULL"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE email_verification_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL"
            }
        };
        let result = sqlx::query(sql)
            .bind(used_at)
            .bind(id.to_string())
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Supersedes every still-outstanding verification token for
    /// `user_id` — called when a fresh link is issued (only one active at
    /// a time).
    pub async fn invalidate_all_for_user<'c>(
        db: impl DbConn<'c>,
        user_id: UserId,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let used_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "UPDATE email_verification_tokens SET used_at = $1 WHERE user_id = $2 AND used_at IS NULL"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE email_verification_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL"
            }
        };
        sqlx::query(sql)
            .bind(used_at)
            .bind(user_id.to_string())
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }
}

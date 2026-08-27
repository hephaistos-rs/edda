//! `password_reset_tokens` persistence — the table comes from the
//! `auth_hardening` migration; the request/consume flow that uses it is
//! `edda_auth::password_reset`. `token_hash` is a fast SHA-256 digest,
//! not a slow hash — same reasoning as `AccessToken`'s token hash (a
//! 32-byte random token already has 256 bits of entropy).

use edda_domain::{PasswordResetTokenId, UserId};

use crate::{get_string, Backend, DbPool};

pub struct PasswordResetTokenRepo;

impl PasswordResetTokenRepo {
    pub async fn insert(
        pool: &DbPool,
        id: PasswordResetTokenId,
        user_id: UserId,
        token_hash: &str,
        expires_at: i64,
    ) -> Result<(), sqlx::Error> {
        let created_at = crate::now_unix();
        let sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO password_reset_tokens (id, user_id, token_hash, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO password_reset_tokens (id, user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(sql)
            .bind(id.to_string())
            .bind(user_id.to_string())
            .bind(token_hash)
            .bind(created_at)
            .bind(expires_at)
            .execute(&pool.any)
            .await?;
        Ok(())
    }

    /// A still-usable (unused, unexpired) token by its hash — `None` for
    /// an unknown hash, an already-consumed one, or one past
    /// `expires_at`, all indistinguishable to the caller (a reset link
    /// either works or it doesn't; which of those three reasons doesn't
    /// change the response).
    pub async fn find_valid_by_hash(
        pool: &DbPool,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<(PasswordResetTokenId, UserId)>, sqlx::Error> {
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT id, user_id FROM password_reset_tokens WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, user_id FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(token_hash)
            .bind(now)
            .fetch_optional(&pool.any)
            .await?;
        row.map(|row| {
            Ok((
                get_string(&row, "id")?
                    .parse()
                    .expect("stored password reset token id is a valid UUID"),
                get_string(&row, "user_id")?
                    .parse()
                    .expect("stored user id is a valid UUID"),
            ))
        })
        .transpose()
    }

    pub async fn mark_used(pool: &DbPool, id: PasswordResetTokenId) -> Result<bool, sqlx::Error> {
        let used_at = crate::now_unix();
        let sql = match pool.backend {
            Backend::Postgres => {
                "UPDATE password_reset_tokens SET used_at = $1 WHERE id = $2 AND used_at IS NULL"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE password_reset_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL"
            }
        };
        let result = sqlx::query(sql)
            .bind(used_at)
            .bind(id.to_string())
            .execute(&pool.any)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Marks every still-outstanding token for `user_id` as used — called
    /// both when a fresh reset is requested (only one active token per
    /// user at a time) and when 2FA enrollment completes: a reset link
    /// issued before 2FA was enabled must not bypass the second factor the
    /// account now requires.
    pub async fn invalidate_all_for_user(
        pool: &DbPool,
        user_id: UserId,
    ) -> Result<(), sqlx::Error> {
        let used_at = crate::now_unix();
        let sql = match pool.backend {
            Backend::Postgres => {
                "UPDATE password_reset_tokens SET used_at = $1 WHERE user_id = $2 AND used_at IS NULL"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL"
            }
        };
        sqlx::query(sql)
            .bind(used_at)
            .bind(user_id.to_string())
            .execute(&pool.any)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_freshly_issued_token_is_valid_and_single_use() {
        let pool = crate::test_pool().await;
        let user_id = UserId::new();
        crate::UserRepo::insert(&pool, user_id, "alice", "alice@example.com", "x")
            .await
            .unwrap();
        let id = PasswordResetTokenId::new();
        PasswordResetTokenRepo::insert(&pool, id, user_id, "somehash", 1_000_000_000)
            .await
            .unwrap();

        let found = PasswordResetTokenRepo::find_valid_by_hash(&pool, "somehash", 0)
            .await
            .unwrap();
        assert_eq!(found, Some((id, user_id)));

        assert!(PasswordResetTokenRepo::mark_used(&pool, id).await.unwrap());
        assert_eq!(
            PasswordResetTokenRepo::find_valid_by_hash(&pool, "somehash", 0)
                .await
                .unwrap(),
            None
        );
        // Already used — a second `mark_used` reports no row updated.
        assert!(!PasswordResetTokenRepo::mark_used(&pool, id).await.unwrap());
    }

    #[tokio::test]
    async fn an_expired_token_is_not_valid() {
        let pool = crate::test_pool().await;
        let user_id = UserId::new();
        crate::UserRepo::insert(&pool, user_id, "bob", "bob@example.com", "x")
            .await
            .unwrap();
        PasswordResetTokenRepo::insert(&pool, PasswordResetTokenId::new(), user_id, "h", 100)
            .await
            .unwrap();

        assert_eq!(
            PasswordResetTokenRepo::find_valid_by_hash(&pool, "h", 200)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn invalidate_all_supersedes_every_outstanding_token_for_that_user() {
        let pool = crate::test_pool().await;
        let user_id = UserId::new();
        crate::UserRepo::insert(&pool, user_id, "carol", "carol@example.com", "x")
            .await
            .unwrap();
        PasswordResetTokenRepo::insert(
            &pool,
            PasswordResetTokenId::new(),
            user_id,
            "h1",
            1_000_000_000,
        )
        .await
        .unwrap();
        PasswordResetTokenRepo::insert(
            &pool,
            PasswordResetTokenId::new(),
            user_id,
            "h2",
            1_000_000_000,
        )
        .await
        .unwrap();

        PasswordResetTokenRepo::invalidate_all_for_user(&pool, user_id)
            .await
            .unwrap();

        assert_eq!(
            PasswordResetTokenRepo::find_valid_by_hash(&pool, "h1", 0)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            PasswordResetTokenRepo::find_valid_by_hash(&pool, "h2", 0)
                .await
                .unwrap(),
            None
        );
    }
}

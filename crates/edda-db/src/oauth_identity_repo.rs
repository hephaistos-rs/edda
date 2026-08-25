//! Linked external OAuth/OIDC identities. Looked up exclusively by
//! `(provider, subject_id)` — never by email, matching the account-linking
//! policy documented at the `edda-auth` module that calls this repo: an
//! email match alone is never sufficient to attach an external identity to
//! an existing account.

use edda_domain::{OAuthIdentity, OAuthIdentityId, UserId};

use crate::{get_i64, get_string, Backend, DbPool};

pub struct OAuthIdentityRepo;

impl OAuthIdentityRepo {
    pub async fn insert(
        pool: &DbPool,
        id: OAuthIdentityId,
        user_id: UserId,
        provider: &str,
        subject_id: &str,
    ) -> Result<i64, sqlx::Error> {
        let id_text = id.to_string();
        let user_id_text = user_id.to_string();
        let created_at = crate::now_unix();
        let sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO oauth_identities (id, user_id, provider, subject_id, created_at) VALUES ($1, $2, $3, $4, $5)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO oauth_identities (id, user_id, provider, subject_id, created_at) VALUES (?, ?, ?, ?, ?)"
            }
        };
        sqlx::query(sql)
            .bind(&id_text)
            .bind(&user_id_text)
            .bind(provider)
            .bind(subject_id)
            .bind(created_at)
            .execute(&pool.any)
            .await?;
        Ok(created_at)
    }

    /// The lookup a returning OAuth login resolves through — the only way
    /// this repo ever resolves an identity to a user.
    pub async fn find_by_provider_subject(
        pool: &DbPool,
        provider: &str,
        subject_id: &str,
    ) -> Result<Option<OAuthIdentity>, sqlx::Error> {
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT id, user_id, provider, subject_id, created_at FROM oauth_identities WHERE provider = $1 AND subject_id = $2"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, user_id, provider, subject_id, created_at FROM oauth_identities WHERE provider = ? AND subject_id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(provider)
            .bind(subject_id)
            .fetch_optional(&pool.any)
            .await?;
        row.map(row_to_identity).transpose()
    }

    pub async fn list_for_user(
        pool: &DbPool,
        user_id: UserId,
    ) -> Result<Vec<OAuthIdentity>, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT id, user_id, provider, subject_id, created_at FROM oauth_identities WHERE user_id = $1 ORDER BY created_at DESC"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, user_id, provider, subject_id, created_at FROM oauth_identities WHERE user_id = ? ORDER BY created_at DESC"
            }
        };
        let rows = sqlx::query(sql)
            .bind(&user_id_text)
            .fetch_all(&pool.any)
            .await?;
        rows.into_iter().map(row_to_identity).collect()
    }

    /// Unlinks a provider identity from `user_id` — scoped to that owner
    /// the same way `SshKeyRepo::revoke`/`AccessTokenRepo::revoke` are, so
    /// unlinking someone else's identity by guessing its id looks
    /// identical to "no such identity."
    pub async fn delete(
        pool: &DbPool,
        user_id: UserId,
        id: OAuthIdentityId,
    ) -> Result<bool, sqlx::Error> {
        let user_id_text = user_id.to_string();
        let id_text = id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => "DELETE FROM oauth_identities WHERE id = $1 AND user_id = $2",
            Backend::Sqlite | Backend::MySql => {
                "DELETE FROM oauth_identities WHERE id = ? AND user_id = ?"
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

fn row_to_identity(row: sqlx::any::AnyRow) -> Result<OAuthIdentity, sqlx::Error> {
    Ok(OAuthIdentity {
        id: get_string(&row, "id")?
            .parse()
            .expect("stored oauth identity id is a valid UUID"),
        user_id: get_string(&row, "user_id")?
            .parse()
            .expect("stored user id is a valid UUID"),
        provider: get_string(&row, "provider")?,
        subject_id: get_string(&row, "subject_id")?,
        created_at: get_i64(&row, "created_at")?,
    })
}

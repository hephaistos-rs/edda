use edda_domain::{SshKey, SshKeyId, User, UserId};

use crate::{get_bool, get_i64, get_opt_i64, get_string, Backend, DbConn, DbError};

#[derive(Debug, thiserror::Error)]
pub enum InsertSshKeyError {
    #[error("that key is already registered")]
    FingerprintTaken,
    #[error(transparent)]
    Db(#[from] DbError),
}

pub struct SshKeyRepo;

impl SshKeyRepo {
    pub async fn insert<'c>(
        db: impl DbConn<'c>,
        id: SshKeyId,
        user_id: UserId,
        fingerprint: &str,
        public_key: &str,
        title: &str,
    ) -> Result<i64, InsertSshKeyError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let user_id_text = user_id.to_string();
        let created_at = crate::now_unix();
        let sql = match h.backend() {
            Backend::Postgres => {
                "INSERT INTO ssh_keys (id, user_id, fingerprint, public_key, title, created_at) VALUES ($1, $2, $3, $4, $5, $6)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO ssh_keys (id, user_id, fingerprint, public_key, title, created_at) VALUES (?, ?, ?, ?, ?, ?)"
            }
        };
        match sqlx::query(sql)
            .bind(&id_text)
            .bind(&user_id_text)
            .bind(fingerprint)
            .bind(public_key)
            .bind(title)
            .bind(created_at)
            .execute(&mut *h.conn())
            .await
            .map_err(DbError::from)
        {
            Ok(_) => Ok(created_at),
            Err(DbError::UniqueViolation) => Err(InsertSshKeyError::FingerprintTaken),
            Err(err) => Err(InsertSshKeyError::Db(err)),
        }
    }

    pub async fn list_for_user<'c>(
        db: impl DbConn<'c>,
        user_id: UserId,
    ) -> Result<Vec<SshKey>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let user_id_text = user_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, fingerprint, public_key, title, created_at, last_used_at FROM ssh_keys WHERE user_id = $1 ORDER BY created_at DESC"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, fingerprint, public_key, title, created_at, last_used_at FROM ssh_keys WHERE user_id = ? ORDER BY created_at DESC"
            }
        };
        let rows = sqlx::query(sql)
            .bind(&user_id_text)
            .fetch_all(&mut *h.conn())
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(SshKey {
                    id: get_string(&row, "id")?
                        .parse()
                        .expect("stored ssh key id is a valid UUID"),
                    user_id,
                    fingerprint: get_string(&row, "fingerprint")?,
                    public_key: get_string(&row, "public_key")?,
                    title: get_string(&row, "title")?,
                    created_at: get_i64(&row, "created_at")?,
                    last_used_at: get_opt_i64(&row, "last_used_at")?,
                })
            })
            .collect()
    }

    /// `Ok(true)` if a key owned by `user_id` was revoked — deliberately
    /// scoped to that owner, so revoking someone else's key by guessing
    /// its id looks identical to "no such key" (mirrors
    /// `AccessTokenRepo::revoke`'s exact reasoning).
    pub async fn revoke<'c>(
        db: impl DbConn<'c>,
        user_id: UserId,
        key_id: SshKeyId,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let user_id_text = user_id.to_string();
        let key_id_text = key_id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => "DELETE FROM ssh_keys WHERE id = $1 AND user_id = $2",
            Backend::Sqlite | Backend::MySql => "DELETE FROM ssh_keys WHERE id = ? AND user_id = ?",
        };
        let result = sqlx::query(sql)
            .bind(&key_id_text)
            .bind(&user_id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Resolves a public key's fingerprint to the user it belongs to —
    /// the entire SSH-authentication lookup. Also best-effort records
    /// `last_used_at`, same reasoning as `AccessTokenRepo::find_by_hash`.
    pub async fn find_by_fingerprint<'c>(
        db: impl DbConn<'c>,
        fingerprint: &str,
    ) -> Result<Option<User>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let select_sql = match h.backend() {
            Backend::Postgres => {
                r#"SELECT u.id as user_id, u.username, u.email, u.is_admin, u.disabled_at
                   FROM ssh_keys k JOIN users u ON u.id = k.user_id
                   WHERE k.fingerprint = $1"#
            }
            Backend::Sqlite | Backend::MySql => {
                r#"SELECT u.id as user_id, u.username, u.email, u.is_admin, u.disabled_at
                   FROM ssh_keys k JOIN users u ON u.id = k.user_id
                   WHERE k.fingerprint = ?"#
            }
        };
        let row = sqlx::query(select_sql)
            .bind(fingerprint)
            .fetch_optional(&mut *h.conn())
            .await?;
        let Some(row) = row else { return Ok(None) };

        let last_used_at = crate::now_unix();
        let update_sql = match h.backend() {
            Backend::Postgres => "UPDATE ssh_keys SET last_used_at = $1 WHERE fingerprint = $2",
            Backend::Sqlite | Backend::MySql => {
                "UPDATE ssh_keys SET last_used_at = ? WHERE fingerprint = ?"
            }
        };
        let _ = sqlx::query(update_sql)
            .bind(last_used_at)
            .bind(fingerprint)
            .execute(&mut *h.conn())
            .await;

        Ok(Some(User {
            id: get_string(&row, "user_id")?
                .parse()
                .expect("stored user id is a valid UUID"),
            username: get_string(&row, "username")?,
            email: get_string(&row, "email")?,
            is_admin: get_bool(&row, "is_admin")?,
            disabled_at: get_opt_i64(&row, "disabled_at")?,
        }))
    }
}

use edda_domain::{User, UserId};

use crate::{get_bool, get_opt_i64, get_string, Backend, DbPool};

/// A `users` row including its password hash — only ever handed to
/// `edda-auth`'s authentication path, never returned from anywhere a
/// plain `edda_domain::User` would do (see that type's own doc comment
/// for why the domain entity itself excludes this field).
pub struct UserRow {
    pub user: User,
    pub password_hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum InsertUserError {
    #[error("that username is already taken")]
    UsernameTaken,
    #[error("that email is already registered")]
    EmailTaken,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

#[allow(clippy::too_many_arguments)]
fn row_to_user_row(
    id: String,
    username: String,
    email: String,
    is_admin: bool,
    disabled_at: Option<i64>,
    password_hash: String,
) -> UserRow {
    UserRow {
        user: User {
            id: id.parse().expect("stored user id is a valid UUID"),
            username,
            email,
            is_admin,
            disabled_at,
        },
        password_hash,
    }
}

fn row_to_user(
    id: String,
    username: String,
    email: String,
    is_admin: bool,
    disabled_at: Option<i64>,
) -> User {
    User {
        id: id.parse().expect("stored user id is a valid UUID"),
        username,
        email,
        is_admin,
        disabled_at,
    }
}

pub struct UserRepo;

impl UserRepo {
    pub async fn insert(
        pool: &DbPool,
        id: UserId,
        username: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<(), InsertUserError> {
        let id_text = id.to_string();
        let created_at = crate::now_unix();
        let sql = match pool.backend {
            Backend::Postgres => {
                "INSERT INTO users (id, username, email, password_hash, created_at) VALUES ($1, $2, $3, $4, $5)"
            }
            Backend::Sqlite | Backend::MySql => {
                "INSERT INTO users (id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)"
            }
        };
        let result = sqlx::query(sql)
            .bind(&id_text)
            .bind(username)
            .bind(email)
            .bind(password_hash)
            .bind(created_at)
            .execute(&pool.any)
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                // Which column conflicted: SQLite/MySQL report it in the
                // error message text (SQLite as `table.column`, MySQL as
                // the violated key/index name — reliable on the MariaDB
                // 10.6+/MySQL 8.0.19+ this targets, which name the key in
                // the message rather than an ordinal position the way
                // very old MySQL releases did); PostgreSQL exposes the
                // constraint name structurally via `.constraint()`.
                let msg = db_err.message();
                let is_username_conflict = match pool.backend {
                    Backend::Postgres => db_err.constraint() == Some("idx_users_username_ci"),
                    Backend::Sqlite => msg.contains("users.username"),
                    Backend::MySql => msg.contains("idx_users_username_ci"),
                };
                if is_username_conflict {
                    Err(InsertUserError::UsernameTaken)
                } else {
                    Err(InsertUserError::EmailTaken)
                }
            }
            Err(err) => Err(InsertUserError::Db(err)),
        }
    }

    pub async fn find_by_email(pool: &DbPool, email: &str) -> Result<Option<UserRow>, sqlx::Error> {
        // Case-insensitive lookup: SQLite's `email` column is declared
        // `COLLATE NOCASE`, so a plain `=` already compares
        // case-insensitively there; PostgreSQL/MySQL compare on
        // `LOWER(...)` against the matching functional index instead.
        let sql = match pool.backend {
            Backend::Sqlite => {
                "SELECT id, username, email, is_admin, disabled_at, password_hash FROM users WHERE email = ?"
            }
            Backend::Postgres => {
                "SELECT id, username, email, is_admin, disabled_at, password_hash FROM users WHERE LOWER(email) = LOWER($1)"
            }
            // MariaDB rejects a direct functional index (see the mysql
            // migration's comment), so this backend compares against the
            // stored `email_lower` shadow column instead.
            Backend::MySql => {
                "SELECT id, username, email, is_admin, disabled_at, password_hash FROM users WHERE email_lower = LOWER(?)"
            }
        };
        let row = sqlx::query(sql)
            .bind(email)
            .fetch_optional(&pool.any)
            .await?;
        row.map(|row| {
            Ok(row_to_user_row(
                get_string(&row, "id")?,
                get_string(&row, "username")?,
                get_string(&row, "email")?,
                get_bool(&row, "is_admin")?,
                get_opt_i64(&row, "disabled_at")?,
                get_string(&row, "password_hash")?,
            ))
        })
        .transpose()
    }

    pub async fn find_by_id(pool: &DbPool, id: UserId) -> Result<Option<UserRow>, sqlx::Error> {
        let id_text = id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => {
                "SELECT id, username, email, is_admin, disabled_at, password_hash FROM users WHERE id = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, username, email, is_admin, disabled_at, password_hash FROM users WHERE id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&id_text)
            .fetch_optional(&pool.any)
            .await?;
        row.map(|row| {
            Ok(row_to_user_row(
                get_string(&row, "id")?,
                get_string(&row, "username")?,
                get_string(&row, "email")?,
                get_bool(&row, "is_admin")?,
                get_opt_i64(&row, "disabled_at")?,
                get_string(&row, "password_hash")?,
            ))
        })
        .transpose()
    }

    pub async fn find_by_username(
        pool: &DbPool,
        username: &str,
    ) -> Result<Option<User>, sqlx::Error> {
        let sql = match pool.backend {
            Backend::Sqlite => {
                "SELECT id, username, email, is_admin, disabled_at FROM users WHERE username = ?"
            }
            Backend::Postgres => {
                "SELECT id, username, email, is_admin, disabled_at FROM users WHERE LOWER(username) = LOWER($1)"
            }
            Backend::MySql => {
                "SELECT id, username, email, is_admin, disabled_at FROM users WHERE username_lower = LOWER(?)"
            }
        };
        let row = sqlx::query(sql)
            .bind(username)
            .fetch_optional(&pool.any)
            .await?;
        row.map(|row| {
            Ok(row_to_user(
                get_string(&row, "id")?,
                get_string(&row, "username")?,
                get_string(&row, "email")?,
                get_bool(&row, "is_admin")?,
                get_opt_i64(&row, "disabled_at")?,
            ))
        })
        .transpose()
    }

    /// Lists every account, newest first — the raw material for
    /// `edda-cli user list` and the admin user-management page. Not
    /// paginated: this targets solo developers and small teams, where an
    /// unpaginated list is still a reasonable size; revisit if that scale
    /// assumption changes.
    pub async fn list_all(pool: &DbPool) -> Result<Vec<User>, sqlx::Error> {
        let sql = "SELECT id, username, email, is_admin, disabled_at FROM users ORDER BY id DESC";
        let rows = sqlx::query(sql).fetch_all(&pool.any).await?;
        rows.into_iter()
            .map(|row| {
                Ok(row_to_user(
                    get_string(&row, "id")?,
                    get_string(&row, "username")?,
                    get_string(&row, "email")?,
                    get_bool(&row, "is_admin")?,
                    get_opt_i64(&row, "disabled_at")?,
                ))
            })
            .collect()
    }

    /// Sets or clears the instance-admin flag. Returns `Ok(true)` if a row
    /// was actually updated (an unknown `id` is `Ok(false)`, not an
    /// error — callers that need "no such user" as a distinct case check
    /// the return value).
    pub async fn set_admin(pool: &DbPool, id: UserId, is_admin: bool) -> Result<bool, sqlx::Error> {
        let id_text = id.to_string();
        let flag = if is_admin { 1i64 } else { 0i64 };
        let sql = match pool.backend {
            Backend::Postgres => "UPDATE users SET is_admin = $1 WHERE id = $2",
            Backend::Sqlite | Backend::MySql => "UPDATE users SET is_admin = ? WHERE id = ?",
        };
        let result = sqlx::query(sql)
            .bind(flag)
            .bind(&id_text)
            .execute(&pool.any)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Disables (or re-enables, passing `disabled = false`) an account.
    /// Does not touch existing sessions — see `User::disabled_at`'s doc
    /// comment for why that's a deliberate, not accidental, omission.
    pub async fn set_disabled(
        pool: &DbPool,
        id: UserId,
        disabled: bool,
    ) -> Result<bool, sqlx::Error> {
        let id_text = id.to_string();
        let disabled_at = if disabled {
            Some(crate::now_unix())
        } else {
            None
        };
        let sql = match pool.backend {
            Backend::Postgres => "UPDATE users SET disabled_at = $1 WHERE id = $2",
            Backend::Sqlite | Backend::MySql => "UPDATE users SET disabled_at = ? WHERE id = ?",
        };
        let result = sqlx::query(sql)
            .bind(disabled_at)
            .bind(&id_text)
            .execute(&pool.any)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Permanently deletes an account and everything that cascades from it
    /// (access tokens, SSH keys, OAuth identities, TOTP/WebAuthn
    /// credentials, repo-access grants — every FK referencing `users(id)`
    /// in this crate's migrations is `ON DELETE CASCADE`). Does **not**
    /// delete repositories the account owns — an owned repository has no
    /// `ON DELETE CASCADE` from `users` (ownership transfer/deletion is a
    /// deliberate, separate operation, not a side effect of removing the
    /// account), so those rows are left in place; `edda-cli user delete`
    /// surfaces that as an explicit warning rather than silently orphaning
    /// them.
    pub async fn delete(pool: &DbPool, id: UserId) -> Result<bool, sqlx::Error> {
        let id_text = id.to_string();
        let sql = match pool.backend {
            Backend::Postgres => "DELETE FROM users WHERE id = $1",
            Backend::Sqlite | Backend::MySql => "DELETE FROM users WHERE id = ?",
        };
        let result = sqlx::query(sql).bind(&id_text).execute(&pool.any).await?;
        Ok(result.rows_affected() > 0)
    }
}

use edda_domain::{User, UserId};

use crate::{get_bool, get_opt_i64, get_string, Backend, DbConn, DbError};

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
    Db(#[from] DbError),
}

/// The account-lifecycle timestamps the authentication and push/create
/// gates consult — see [`UserRepo::account_status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountStatus {
    /// Set once an admin disables the account (`NULL` = enabled).
    pub disabled_at: Option<i64>,
    /// Set once the account's email address is confirmed, or immediately
    /// at signup when the policy doesn't require verification.
    pub email_verified_at: Option<i64>,
    /// Set once the account is active — immediately for `Open`/`Closed`
    /// registration, on admin approval for `Approval`.
    pub approved_at: Option<i64>,
}

impl AccountStatus {
    pub fn is_disabled(&self) -> bool {
        self.disabled_at.is_some()
    }
    pub fn is_email_verified(&self) -> bool {
        self.email_verified_at.is_some()
    }
    pub fn is_approved(&self) -> bool {
        self.approved_at.is_some()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeleteUserError {
    /// The account still directly owns one or more repositories. Since the
    /// Phase 9 baseline `repositories.owner_user_id` restricts deletes,
    /// those repositories must be transferred or deleted first.
    #[error(
        "this account still owns {count} repositor{plural} — transfer or delete {them} first",
        plural = if *count == 1 { "y" } else { "ies" },
        them = if *count == 1 { "it" } else { "them" },
    )]
    OwnsRepositories { count: i64 },
    #[error(transparent)]
    Db(#[from] DbError),
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
    pub async fn insert<'c>(
        db: impl DbConn<'c>,
        id: UserId,
        username: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<(), InsertUserError> {
        let mut h = crate::conn::open(db).await?;
        let backend = h.backend();
        let id_text = id.to_string();
        let created_at = crate::now_unix();
        let sql = match backend {
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
            .execute(&mut *h.conn())
            .await;

        match result {
            Ok(_) => Ok(()),
            // Matched against the raw `sqlx::Error` (allowed inside
            // `edda-db`) rather than `DbError::UniqueViolation`, because
            // deciding *which* unique index conflicted needs the driver's
            // own message / constraint name — detail `DbError` doesn't
            // carry.
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                // Which column conflicted: SQLite/MySQL report it in the
                // error message text (SQLite as `table.column`, MySQL as
                // the violated key/index name — reliable on the MariaDB
                // 10.6+/MySQL 8.0.19+ this targets, which name the key in
                // the message rather than an ordinal position the way
                // very old MySQL releases did); PostgreSQL exposes the
                // constraint name structurally via `.constraint()`.
                let msg = db_err.message();
                let is_username_conflict = match backend {
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
            Err(err) => Err(InsertUserError::Db(err.into())),
        }
    }

    pub async fn find_by_email<'c>(
        db: impl DbConn<'c>,
        email: &str,
    ) -> Result<Option<UserRow>, DbError> {
        let mut h = crate::conn::open(db).await?;
        // Case-insensitive lookup: SQLite's `email` column is declared
        // `COLLATE NOCASE`, so a plain `=` already compares
        // case-insensitively there; PostgreSQL/MySQL compare on
        // `LOWER(...)` against the matching functional index instead.
        let sql = match h.backend() {
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
            .fetch_optional(&mut *h.conn())
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

    pub async fn find_by_id<'c>(
        db: impl DbConn<'c>,
        id: UserId,
    ) -> Result<Option<UserRow>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT id, username, email, is_admin, disabled_at, password_hash FROM users WHERE id = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT id, username, email, is_admin, disabled_at, password_hash FROM users WHERE id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&id_text)
            .fetch_optional(&mut *h.conn())
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

    pub async fn find_by_username<'c>(
        db: impl DbConn<'c>,
        username: &str,
    ) -> Result<Option<User>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = match h.backend() {
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
            .fetch_optional(&mut *h.conn())
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
    pub async fn list_all<'c>(db: impl DbConn<'c>) -> Result<Vec<User>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let sql = "SELECT id, username, email, is_admin, disabled_at FROM users ORDER BY id DESC";
        let rows = sqlx::query(sql).fetch_all(&mut *h.conn()).await?;
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
    pub async fn set_admin<'c>(
        db: impl DbConn<'c>,
        id: UserId,
        is_admin: bool,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let flag = if is_admin { 1i64 } else { 0i64 };
        let sql = match h.backend() {
            Backend::Postgres => "UPDATE users SET is_admin = $1 WHERE id = $2",
            Backend::Sqlite | Backend::MySql => "UPDATE users SET is_admin = ? WHERE id = ?",
        };
        let result = sqlx::query(sql)
            .bind(flag)
            .bind(&id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Disables (or re-enables, passing `disabled = false`) an account.
    /// Does not touch existing sessions — see `User::disabled_at`'s doc
    /// comment for why that's a deliberate, not accidental, omission.
    pub async fn set_disabled<'c>(
        db: impl DbConn<'c>,
        id: UserId,
        disabled: bool,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let disabled_at = if disabled {
            Some(crate::now_unix())
        } else {
            None
        };
        let sql = match h.backend() {
            Backend::Postgres => "UPDATE users SET disabled_at = $1 WHERE id = $2",
            Backend::Sqlite | Backend::MySql => "UPDATE users SET disabled_at = ? WHERE id = ?",
        };
        let result = sqlx::query(sql)
            .bind(disabled_at)
            .bind(&id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Permanently deletes an account and everything that cascades from it
    /// (access tokens, SSH keys, OAuth identities, TOTP/WebAuthn
    /// credentials, repo-access grants — every FK referencing `users(id)`
    /// in the baseline schema is `ON DELETE CASCADE`). Does **not** delete
    /// repositories the account owns: since the Phase 9 baseline
    /// `repositories.owner_user_id` is a real *restricting* foreign key,
    /// so an account that still owns repositories cannot be deleted at
    /// all. This method makes that a clear typed error
    /// (`DeleteUserError::OwnsRepositories`) rather than a raw foreign-key
    /// violation — ownership transfer or repository deletion is a
    /// deliberate, separate operation.
    pub async fn delete<'c>(db: impl DbConn<'c>, id: UserId) -> Result<bool, DeleteUserError> {
        let mut h = crate::conn::open(db).await?;

        let owned = crate::RepositoryRepo::count_owned_by_user(&mut h, id).await?;
        if owned > 0 {
            return Err(DeleteUserError::OwnsRepositories { count: owned });
        }

        let id_text = id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => "DELETE FROM users WHERE id = $1",
            Backend::Sqlite | Backend::MySql => "DELETE FROM users WHERE id = ?",
        };
        let result = sqlx::query(sql)
            .bind(&id_text)
            .execute(&mut *h.conn())
            .await
            .map_err(DbError::from)?;
        Ok(result.rows_affected() > 0)
    }

    /// Whether `id` wants email delivery of a notification, in addition to
    /// the in-app one Edda always creates — the per-user opt-out toggled
    /// from the settings page. Deliberately not a field on the core
    /// `User` entity (that type is constructed as a struct literal across
    /// many already-stable call sites in this workspace — auth fixtures,
    /// tests — and this preference is only ever read by one narrow
    /// consumer, the notification job handler, so a dedicated query avoids
    /// widening `User` for a field almost nothing else needs). An unknown
    /// `id` defaults to `true` (the column's own default) rather than
    /// erroring — the caller (a job handler acting on a
    /// `DomainEvent::UserMentioned` for a user id resolved moments
    /// earlier) has already established the account exists.
    pub async fn email_notifications_enabled<'c>(
        db: impl DbConn<'c>,
        id: UserId,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => "SELECT email_notifications_enabled FROM users WHERE id = $1",
            Backend::Sqlite | Backend::MySql => {
                "SELECT email_notifications_enabled FROM users WHERE id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&id_text)
            .fetch_optional(&mut *h.conn())
            .await?;
        match row {
            Some(row) => Ok(get_bool(&row, "email_notifications_enabled")?),
            None => Ok(true),
        }
    }

    /// Overwrites the stored password hash — used by the password-reset
    /// consume flow (`edda_auth::password_reset::consume`). Session
    /// invalidation on password change is automatic, not something this
    /// call has to do itself: `axum_login`'s `SessionUser::
    /// session_auth_hash` is derived from the stored hash, so any session
    /// established under the old hash simply stops matching on its next
    /// check — the same mechanism a settings-page password change would
    /// rely on.
    pub async fn update_password_hash<'c>(
        db: impl DbConn<'c>,
        id: UserId,
        password_hash: &str,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => "UPDATE users SET password_hash = $1 WHERE id = $2",
            Backend::Sqlite | Backend::MySql => "UPDATE users SET password_hash = ? WHERE id = ?",
        };
        let result = sqlx::query(sql)
            .bind(password_hash)
            .bind(&id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// The three lifecycle timestamps the auth path checks — kept off the
    /// core `User` entity for the same reason `email_notifications_enabled`
    /// is (that type is a struct literal at many stable call sites; these
    /// fields have exactly two consumers, the login gate and the
    /// push/create gate). `None` for an unknown id.
    pub async fn account_status<'c>(
        db: impl DbConn<'c>,
        id: UserId,
    ) -> Result<Option<AccountStatus>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "SELECT disabled_at, email_verified_at, approved_at FROM users WHERE id = $1"
            }
            Backend::Sqlite | Backend::MySql => {
                "SELECT disabled_at, email_verified_at, approved_at FROM users WHERE id = ?"
            }
        };
        let row = sqlx::query(sql)
            .bind(&id_text)
            .fetch_optional(&mut *h.conn())
            .await?;
        row.map(|row| {
            Ok(AccountStatus {
                disabled_at: get_opt_i64(&row, "disabled_at")?,
                email_verified_at: get_opt_i64(&row, "email_verified_at")?,
                approved_at: get_opt_i64(&row, "approved_at")?,
            })
        })
        .transpose()
    }

    /// Stamps `approved_at` / `email_verified_at` right after signup,
    /// according to the active `RegistrationPolicy`. `None` leaves the
    /// column NULL (pending). One statement rather than widening `insert`
    /// (which has many stable call sites).
    pub async fn stamp_signup_status<'c>(
        db: impl DbConn<'c>,
        id: UserId,
        approved_at: Option<i64>,
        email_verified_at: Option<i64>,
    ) -> Result<(), DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "UPDATE users SET approved_at = $1, email_verified_at = $2 WHERE id = $3"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE users SET approved_at = ?, email_verified_at = ? WHERE id = ?"
            }
        };
        sqlx::query(sql)
            .bind(approved_at)
            .bind(email_verified_at)
            .bind(&id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(())
    }

    /// Marks the account's email confirmed (`email_verification::consume`).
    /// `Ok(false)` if there was nothing to do (unknown id, or already
    /// verified).
    pub async fn mark_email_verified<'c>(db: impl DbConn<'c>, id: UserId) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let now = crate::now_unix();
        let id_text = id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "UPDATE users SET email_verified_at = $1 WHERE id = $2 AND email_verified_at IS NULL"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE users SET email_verified_at = ? WHERE id = ? AND email_verified_at IS NULL"
            }
        };
        let result = sqlx::query(sql)
            .bind(now)
            .bind(&id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Admin approval-queue action: activates a pending account.
    /// `Ok(false)` for an unknown id or one already approved.
    pub async fn approve<'c>(db: impl DbConn<'c>, id: UserId) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let now = crate::now_unix();
        let id_text = id.to_string();
        let sql = match h.backend() {
            Backend::Postgres => {
                "UPDATE users SET approved_at = $1 WHERE id = $2 AND approved_at IS NULL"
            }
            Backend::Sqlite | Backend::MySql => {
                "UPDATE users SET approved_at = ? WHERE id = ? AND approved_at IS NULL"
            }
        };
        let result = sqlx::query(sql)
            .bind(now)
            .bind(&id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Every account still awaiting admin approval, newest first — the
    /// admin approval queue.
    pub async fn list_pending_approval<'c>(db: impl DbConn<'c>) -> Result<Vec<User>, DbError> {
        let mut h = crate::conn::open(db).await?;
        let rows = sqlx::query(
            "SELECT id, username, email, is_admin, disabled_at FROM users \
             WHERE approved_at IS NULL ORDER BY id DESC",
        )
        .fetch_all(&mut *h.conn())
        .await?;
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

    pub async fn set_email_notifications_enabled<'c>(
        db: impl DbConn<'c>,
        id: UserId,
        enabled: bool,
    ) -> Result<bool, DbError> {
        let mut h = crate::conn::open(db).await?;
        let id_text = id.to_string();
        let flag = if enabled { 1i64 } else { 0i64 };
        let sql = match h.backend() {
            Backend::Postgres => "UPDATE users SET email_notifications_enabled = $1 WHERE id = $2",
            Backend::Sqlite | Backend::MySql => {
                "UPDATE users SET email_notifications_enabled = ? WHERE id = ?"
            }
        };
        let result = sqlx::query(sql)
            .bind(flag)
            .bind(&id_text)
            .execute(&mut *h.conn())
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

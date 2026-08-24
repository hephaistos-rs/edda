use edda_domain::{User, UserId};

use crate::DbPool;

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

fn row_to_user_row(id: String, username: String, email: String, password_hash: String) -> UserRow {
    UserRow {
        user: User {
            id: id.parse().expect("stored user id is a valid UUID"),
            username,
            email,
        },
        password_hash,
    }
}

pub struct UserRepo;

impl UserRepo {
    #[cfg(feature = "sqlite")]
    pub async fn insert(
        pool: &DbPool,
        id: UserId,
        username: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<(), InsertUserError> {
        let id_text = id.to_string();
        let created_at = crate::now_unix();
        let result = sqlx::query!(
            "INSERT INTO users (id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            id_text,
            username,
            email,
            password_hash,
            created_at,
        )
        .execute(pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                if db_err.message().contains("users.username") {
                    Err(InsertUserError::UsernameTaken)
                } else {
                    Err(InsertUserError::EmailTaken)
                }
            }
            Err(err) => Err(InsertUserError::Db(err)),
        }
    }

    // PostgreSQL: `?` becomes `$n`; case-insensitive uniqueness is
    // enforced by an index on `LOWER(...)` rather than a `COLLATE NOCASE`
    // column (plan.local.md §17 Phase 3), so the violated-column check
    // reads the constraint/index name PostgreSQL reports instead of
    // sniffing SQLite's error message text.
    #[cfg(feature = "postgres")]
    pub async fn insert(
        pool: &DbPool,
        id: UserId,
        username: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<(), InsertUserError> {
        let id_text = id.to_string();
        let created_at = crate::now_unix();
        let result = sqlx::query!(
            "INSERT INTO users (id, username, email, password_hash, created_at) VALUES ($1, $2, $3, $4, $5)",
            id_text,
            username,
            email,
            password_hash,
            created_at,
        )
        .execute(pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                match db_err.constraint() {
                    Some("idx_users_username_ci") => Err(InsertUserError::UsernameTaken),
                    _ => Err(InsertUserError::EmailTaken),
                }
            }
            Err(err) => Err(InsertUserError::Db(err)),
        }
    }

    #[cfg(feature = "sqlite")]
    pub async fn find_by_email(pool: &DbPool, email: &str) -> Result<Option<UserRow>, sqlx::Error> {
        let row = sqlx::query!(
            r#"SELECT id, username, email, password_hash FROM users WHERE email = ?"#,
            email
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| row_to_user_row(row.id, row.username, row.email, row.password_hash)))
    }

    #[cfg(feature = "postgres")]
    pub async fn find_by_email(pool: &DbPool, email: &str) -> Result<Option<UserRow>, sqlx::Error> {
        let row = sqlx::query!(
            r#"SELECT id, username, email, password_hash FROM users WHERE LOWER(email) = LOWER($1)"#,
            email
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| row_to_user_row(row.id, row.username, row.email, row.password_hash)))
    }

    #[cfg(feature = "sqlite")]
    pub async fn find_by_id(pool: &DbPool, id: UserId) -> Result<Option<UserRow>, sqlx::Error> {
        let id_text = id.to_string();
        let row = sqlx::query!(
            r#"SELECT id, username, email, password_hash FROM users WHERE id = ?"#,
            id_text
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| row_to_user_row(row.id, row.username, row.email, row.password_hash)))
    }

    #[cfg(feature = "postgres")]
    pub async fn find_by_id(pool: &DbPool, id: UserId) -> Result<Option<UserRow>, sqlx::Error> {
        let id_text = id.to_string();
        let row = sqlx::query!(
            r#"SELECT id, username, email, password_hash FROM users WHERE id = $1"#,
            id_text
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| row_to_user_row(row.id, row.username, row.email, row.password_hash)))
    }

    #[cfg(feature = "sqlite")]
    pub async fn find_by_username(
        pool: &DbPool,
        username: &str,
    ) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query!(
            r#"SELECT id, username, email FROM users WHERE username = ?"#,
            username
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| User {
            id: row.id.parse().expect("stored user id is a valid UUID"),
            username: row.username,
            email: row.email,
        }))
    }

    #[cfg(feature = "postgres")]
    pub async fn find_by_username(
        pool: &DbPool,
        username: &str,
    ) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query!(
            r#"SELECT id, username, email FROM users WHERE LOWER(username) = LOWER($1)"#,
            username
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| User {
            id: row.id.parse().expect("stored user id is a valid UUID"),
            username: row.username,
            email: row.email,
        }))
    }
}

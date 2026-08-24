use edda_domain::{User, UserId};
use sqlx::SqlitePool;

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
    pub async fn insert(
        pool: &SqlitePool,
        id: UserId,
        username: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<(), InsertUserError> {
        let id_text = id.to_string();
        let result = sqlx::query!(
            "INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)",
            id_text,
            username,
            email,
            password_hash,
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

    pub async fn find_by_email(
        pool: &SqlitePool,
        email: &str,
    ) -> Result<Option<UserRow>, sqlx::Error> {
        let row = sqlx::query!(
            r#"SELECT id, username, email, password_hash FROM users WHERE email = ?"#,
            email
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| row_to_user_row(row.id, row.username, row.email, row.password_hash)))
    }

    pub async fn find_by_id(pool: &SqlitePool, id: UserId) -> Result<Option<UserRow>, sqlx::Error> {
        let id_text = id.to_string();
        let row = sqlx::query!(
            r#"SELECT id, username, email, password_hash FROM users WHERE id = ?"#,
            id_text
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| row_to_user_row(row.id, row.username, row.email, row.password_hash)))
    }

    pub async fn find_by_username(
        pool: &SqlitePool,
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
}

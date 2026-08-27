//! `edda-db`'s own error type. `sqlx::Error` is an internal detail of this
//! crate and never crosses its API boundary (plan.local.md §5.1 — enforced
//! by the `sqlx::` boundary grep): every repository method returns
//! `Result<_, DbError>` (or a small operation-specific enum that wraps
//! `DbError`), so no other crate needs to depend on `sqlx` to name a
//! database failure.

/// A database failure, with the three constraint-violation classes every
/// backend reports pulled out as named variants so callers can branch on
/// them (`insert` -> "already exists") without pattern-matching a
/// `sqlx::Error`.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// A `UNIQUE` / primary-key constraint was violated.
    #[error("a record with those values already exists")]
    UniqueViolation,
    /// A `FOREIGN KEY` constraint was violated (referenced row missing, or
    /// a referenced row still has children on delete).
    #[error("that operation refers to a record that does not exist")]
    ForeignKeyViolation,
    /// A `CHECK` constraint was violated.
    #[error("that value is not allowed here")]
    CheckViolation,
    /// A query that required exactly one row found none — `sqlx`'s
    /// `RowNotFound`, surfaced for the few call sites that treat it as a
    /// distinct outcome rather than folding it into `Option`.
    #[error("no matching record")]
    RowNotFound,
    /// Anything else: connection loss, a protocol error, a migration
    /// failure, a type-decode mismatch. The underlying `sqlx::Error` is
    /// kept as the source for logging but is not nameable outside this
    /// crate.
    #[error("database error: {0}")]
    Other(#[source] sqlx::Error),
}

impl From<sqlx::Error> for DbError {
    fn from(err: sqlx::Error) -> Self {
        match &err {
            sqlx::Error::RowNotFound => DbError::RowNotFound,
            sqlx::Error::Database(db) if db.is_unique_violation() => DbError::UniqueViolation,
            sqlx::Error::Database(db) if db.is_foreign_key_violation() => {
                DbError::ForeignKeyViolation
            }
            sqlx::Error::Database(db) if db.is_check_violation() => DbError::CheckViolation,
            _ => DbError::Other(err),
        }
    }
}

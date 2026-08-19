use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;

/// Same convention as `EDDA_DATA_DIR` for repos: configurable, defaults to
/// `./data` for local dev. The database file lives alongside `repos/`.
fn db_path() -> std::path::PathBuf {
    let data_dir = std::env::var("EDDA_DATA_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| "./data".into());
    data_dir.join("edda.db")
}

/// Opens the SQLite pool, creating the database file (and its parent
/// directory) on first run, and applying any migrations that haven't run
/// yet. Safe to call more than once per process — pool creation is cheap
/// and idempotent, matching how the rest of this app re-opens state
/// per-request rather than caching a single global handle.
pub async fn pool() -> Result<SqlitePool, sqlx::Error> {
    let path = db_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(sqlx::Error::Io)?;
    }

    // Default (rollback-journal) mode lets one writer starve every other
    // connection in the pool, including reads — and every authenticated
    // request touches the sessions table, so this is on the hot path for
    // concurrent traffic, not just heavy writes. WAL lets readers and the
    // writer proceed together; busy_timeout makes a connection that still
    // loses a write race retry for a bit instead of failing outright.
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new().connect_with(options).await?;

    crate::migrations::run(&pool).await?;

    Ok(pool)
}

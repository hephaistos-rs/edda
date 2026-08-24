//! Persistence: pool setup, embedded migrations, and one narrow
//! repository struct per aggregate. This is the only crate in the
//! workspace that contains `sqlx::query!` — see this crate's `Cargo.toml`
//! doc comment and plan.local.md §3.3/§16 (smell S3).

pub mod access_token_repo;
pub mod repo_access_repo;
pub mod repository_repo;
pub mod ssh_key_repo;
pub mod user_repo;

#[cfg(test)]
mod tests;

pub use access_token_repo::AccessTokenRepo;
pub use repo_access_repo::RepoAccessRepo;
pub use repository_repo::RepositoryRepo;
pub use ssh_key_repo::SshKeyRepo;
pub use user_repo::UserRepo;

use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;

/// Same convention as `EDDA_DATA_DIR` for repo storage (`edda-git`):
/// configurable, defaults to `./data` for local dev. The database file
/// lives alongside the git store's `repos/` directory.
fn db_path() -> std::path::PathBuf {
    let data_dir = std::env::var("EDDA_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| "./data".into());
    data_dir.join("edda.db")
}

/// Opens the SQLite pool, creating the database file (and its parent
/// directory) on first run, and applying any migrations that haven't run
/// yet. Safe to call more than once per process — pool creation is cheap
/// and idempotent.
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

    run_migrations(&pool).await?;

    Ok(pool)
}

/// An in-memory, fully migrated database — for tests only, in this crate
/// and in every other crate that wants to test against real (if
/// ephemeral) SQL rather than a mock. Never touches `EDDA_DATA_DIR`.
pub async fn test_pool() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite pool");
    run_migrations(&pool)
        .await
        .expect("apply migrations to in-memory pool");
    pool
}

async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // Path is relative to this crate's own `Cargo.toml` (`CARGO_MANIFEST_DIR`,
    // what `sqlx::migrate!` resolves against) — kept at the workspace root
    // rather than nested under this crate so `sqlx`/`sqlx-cli` commands run
    // from the repo root (the common case) find it without extra flags.
    sqlx::migrate!("../../migrations")
        .run(pool)
        .await
        .map_err(|err| sqlx::Error::Migrate(Box::new(err)))
}

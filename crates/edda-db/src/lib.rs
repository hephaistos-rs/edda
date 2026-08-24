//! Persistence: pool setup, embedded migrations, and one narrow
//! repository struct per aggregate. This is the only crate in the
//! workspace that contains `sqlx::query!` — see this crate's `Cargo.toml`
//! doc comment and plan.local.md §3.3/§16 (smell S3).
//!
//! Exactly one of this crate's `sqlite`/`postgres` Cargo features is
//! compiled in at a time (plan.local.md §17 Phase 3) — `sqlx::query!`
//! cannot compile-time-check one query against two backends in the same
//! build, so backend selection is a build-time choice, not a runtime
//! one. `DbPool` is whichever concrete pool type that feature selects; it
//! is the only backend-specific type this crate exposes, and nothing
//! outside this crate should ever name `SqlitePool`/`PgPool` directly.

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

#[cfg(all(feature = "sqlite", feature = "postgres"))]
compile_error!(
    "edda-db's `sqlite` and `postgres` features are mutually exclusive — \
     sqlx::query! can only be compile-time-checked against one backend at \
     a time (plan.local.md §17 Phase 3). Build with exactly one enabled."
);
#[cfg(not(any(feature = "sqlite", feature = "postgres")))]
compile_error!("edda-db needs exactly one of its `sqlite`/`postgres` features enabled.");

#[cfg(feature = "sqlite")]
pub type DbPool = sqlx::SqlitePool;
#[cfg(feature = "postgres")]
pub type DbPool = sqlx::PgPool;

/// The current unix-seconds timestamp, computed once in application code
/// and bound as an ordinary query parameter everywhere a row needs to
/// record "now" — deliberately not a SQL-side `unixepoch()`/`now()` call,
/// so every INSERT/UPDATE that touches a timestamp behaves identically on
/// both backends without depending on which database's clock function
/// ran (plan.local.md §17 Phase 3). Each migration still declares a
/// native per-backend column `DEFAULT` as a safety net, but application
/// code never relies on it firing.
pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs() as i64
}

/// Opens the configured backend's pool and applies any migrations that
/// haven't run yet. Safe to call more than once per process — pool
/// creation is cheap and idempotent.
#[cfg(feature = "sqlite")]
pub async fn pool() -> Result<DbPool, sqlx::Error> {
    use std::time::Duration;

    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

    // Same convention as `EDDA_DATA_DIR` for repo storage (`edda-git`):
    // configurable, defaults to `./data` for local dev. The database file
    // lives alongside the git store's `repos/` directory.
    let data_dir = std::env::var("EDDA_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| "./data".into());
    let path = data_dir.join("edda.db");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(sqlx::Error::Io)?;
    }

    // Default (rollback-journal) mode lets one writer starve every other
    // connection in the pool, including reads — and every authenticated
    // request touches the sessions table, so this is on the hot path for
    // concurrent traffic, not just heavy writes. WAL lets readers and the
    // writer proceed together; busy_timeout makes a connection that still
    // loses a write race retry for a bit instead of failing outright.
    // `foreign_keys(true)`: raw SQLite defaults this off, but sqlx's own
    // `SqliteConnectOptions::default()` already turns it on (verified
    // against `sqlx-sqlite`'s source, 2026-08-25) — stated explicitly
    // here anyway so this crate's `ON DELETE CASCADE` reliance (relied on
    // by the cascade-delete tests) doesn't silently depend on a default
    // that isn't spelled out anywhere in this file.
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new().connect_with(options).await?;

    run_migrations(&pool).await?;
    Ok(pool)
}

/// PostgreSQL has no local zero-config default the way SQLite does — a
/// `postgres`-featured build always requires `EDDA_DATABASE_URL`.
/// Rejected with a clear startup error (not a panic: this is trusted
/// local operator configuration, not attacker-controlled network input,
/// but it still deserves a message that says what's wrong).
#[cfg(feature = "postgres")]
pub async fn pool() -> Result<DbPool, sqlx::Error> {
    use sqlx::postgres::PgPoolOptions;

    let url = std::env::var("EDDA_DATABASE_URL").map_err(|_| {
        sqlx::Error::Configuration(
            "EDDA_DATABASE_URL is required — this build of edda-db was compiled with the \
             `postgres` feature, which has no local default the way `sqlite` does"
                .into(),
        )
    })?;
    if !(url.starts_with("postgres:") || url.starts_with("postgresql:")) {
        return Err(sqlx::Error::Configuration(
            "EDDA_DATABASE_URL is not a postgres:// URL, but this build of edda-db was \
             compiled with the `postgres` feature"
                .into(),
        ));
    }

    let pool = PgPoolOptions::new().connect(&url).await?;
    run_migrations(&pool).await?;
    Ok(pool)
}

/// An in-memory, fully migrated database — for tests only, in this crate
/// and in every other crate that wants to test against real (if
/// ephemeral) SQL rather than a mock. Never touches `EDDA_DATA_DIR`.
#[cfg(feature = "sqlite")]
pub async fn test_pool() -> DbPool {
    use sqlx::sqlite::SqliteConnectOptions;

    let options = "sqlite::memory:"
        .parse::<SqliteConnectOptions>()
        .expect("in-memory sqlite URL always parses")
        .foreign_keys(true);
    let pool = sqlx::SqlitePool::connect_with(options)
        .await
        .expect("in-memory sqlite pool");
    run_migrations(&pool)
        .await
        .expect("apply migrations to in-memory pool");
    pool
}

/// PostgreSQL has no in-memory mode — this connects to
/// `EDDA_TEST_POSTGRES_URL` (defaulting to the local dev instance
/// `compose.db.yml` defines at the workspace root) and creates+migrates a
/// fresh, uniquely-named database per call, so concurrent test runs stay
/// isolated the same way the SQLite in-memory pool isolates them for
/// free. The per-test database is deliberately not dropped afterward —
/// disposable local/CI Postgres instances get thrown away between runs
/// anyway, and dropping adds a failure mode for no real benefit.
#[cfg(feature = "postgres")]
pub async fn test_pool() -> DbPool {
    use sqlx::postgres::PgPoolOptions;

    let admin_url = std::env::var("EDDA_TEST_POSTGRES_URL")
        .unwrap_or_else(|_| "postgres://edda:edda@localhost:5432/eddadb".to_string());
    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .expect("connect to the test postgres instance (see compose.db.yml)");

    // Not user input — generated from a clock reading plus a
    // process-local atomic counter, not injectable. The counter matters:
    // `cargo test` runs tests on multiple threads, and a nanosecond clock
    // reading alone collided in practice between two tests started in
    // the same tick (found running this suite against real PostgreSQL,
    // plan.local.md §17 Phase 3) — Windows' clock resolution isn't fine
    // enough to rely on the timestamp being unique by itself.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let db_name = format!(
        "edda_test_{}_{}",
        now_unix_nanos_hex(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    sqlx::query(&format!(r#"CREATE DATABASE "{db_name}""#))
        .execute(&admin_pool)
        .await
        .expect("create a fresh per-test postgres database");

    let base = admin_url
        .rsplit_once('/')
        .map(|(base, _)| base)
        .unwrap_or(&admin_url);
    let test_url = format!("{base}/{db_name}");

    let pool = PgPoolOptions::new()
        .connect(&test_url)
        .await
        .expect("connect to the freshly created test database");
    run_migrations(&pool)
        .await
        .expect("apply migrations to the fresh postgres test database");
    pool
}

#[cfg(feature = "postgres")]
fn now_unix_nanos_hex() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_nanos();
    format!("{nanos:x}")
}

/// Path is relative to this crate's own `Cargo.toml` (`CARGO_MANIFEST_DIR`,
/// what `sqlx::migrate!` resolves against) — kept at the workspace root
/// rather than nested under this crate so `sqlx`/`sqlx-cli` commands run
/// from the repo root (the common case) find it without extra flags.
/// One directory per backend (Phase 3) — dialect differences (`STRICT`,
/// collation, native types) mean the two chains are independent, not a
/// shared template.
#[cfg(feature = "sqlite")]
async fn run_migrations(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::migrate!("../../migrations/sqlite")
        .run(pool)
        .await
        .map_err(|err| sqlx::Error::Migrate(Box::new(err)))
}

#[cfg(feature = "postgres")]
async fn run_migrations(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::migrate!("../../migrations/postgres")
        .run(pool)
        .await
        .map_err(|err| sqlx::Error::Migrate(Box::new(err)))
}

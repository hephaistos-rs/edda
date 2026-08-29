//! `up` → `down` → `up` on the Phase 9 baseline migration (plan.local.md
//! §12.1 "Migrations" validation). Runs against SQLite by default and
//! against `EDDA_TEST_DATABASE_URL` when it names a Postgres or MySQL
//! server, so CI exercises the `down` file on every backend.

use sqlx::migrate::Migrator;

static SQLITE: Migrator = sqlx::migrate!("../../migrations/sqlite");
static POSTGRES: Migrator = sqlx::migrate!("../../migrations/postgres");
static MYSQL: Migrator = sqlx::migrate!("../../migrations/mysql");

#[tokio::test]
async fn the_baseline_migration_reverses_and_reapplies_cleanly() {
    sqlx::any::install_default_drivers();

    let url =
        std::env::var("EDDA_TEST_DATABASE_URL").unwrap_or_else(|_| "sqlite::memory:".to_string());

    let (migrator, pool) = if url.starts_with("sqlite:") {
        // An in-memory SQLite database is per-connection — pin the pool to
        // one connection so `run`/`undo`/`SELECT` all see the same schema.
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        (&SQLITE, pool)
    } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
        (&POSTGRES, fresh_pg_or_mysql(&url).await)
    } else if url.starts_with("mysql:") || url.starts_with("mariadb:") {
        (&MYSQL, fresh_pg_or_mysql(&url).await)
    } else {
        panic!("unrecognized EDDA_TEST_DATABASE_URL scheme: {url}");
    };

    migrator.run(&pool).await.expect("initial up");
    // `undo` to version 0 = run every `.down.sql` newest-first. There is
    // only the one baseline migration, so this drops the whole schema.
    migrator.undo(&pool, 0).await.expect("down");
    migrator.run(&pool).await.expect("re-up after down");

    // The schema is really back: a table from the baseline is queryable
    // again.
    sqlx::query("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .expect("users table exists after re-up");
}

/// Postgres/MySQL have no in-memory mode — create a throwaway database on
/// the target server (never dropped; disposable CI instances get wiped
/// between runs).
async fn fresh_pg_or_mysql(admin_url: &str) -> sqlx::AnyPool {
    let admin = sqlx::AnyPool::connect(admin_url).await.unwrap();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    // `edda_test_` prefix so the CI / compose grant (`ALL ON
    // `edda_test_%`.*`) covers this throwaway database.
    let db = format!("edda_test_roundtrip_{nanos:x}");
    let quoted = if admin_url.starts_with("mysql:") || admin_url.starts_with("mariadb:") {
        format!("CREATE DATABASE `{db}`")
    } else {
        format!(r#"CREATE DATABASE "{db}""#)
    };
    sqlx::query(&quoted).execute(&admin).await.unwrap();
    let base = admin_url
        .rsplit_once('/')
        .map(|(b, _)| b)
        .unwrap_or(admin_url);
    sqlx::AnyPool::connect(&format!("{base}/{db}"))
        .await
        .unwrap()
}

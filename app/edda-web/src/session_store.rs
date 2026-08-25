//! `tower-sessions-sqlx-store`'s `SqliteStore`/`PostgresStore`/`MySqlStore`
//! each need a *concrete* typed pool (`sqlx::SqlitePool`/`PgPool`/
//! `MySqlPool`) — none of them support `sqlx::AnyPool`, which is what
//! `edda_db::DbPool` deliberately erases to for backend-agnostic runtime
//! selection (plan.local.md §17 Phase 3, revised 2026-08-25). Session
//! storage is the one place in the composition root that still needs to
//! know which concrete backend is active: this module opens a second,
//! small connection using the *same* `EDDA_DATABASE_URL` (typed this
//! time), and wraps whichever store that produces behind one type so the
//! rest of `main.rs` doesn't need to branch on backend again.
//!
//! This is not a hand-rolled session-persistence reimplementation — the
//! actual storage logic (schema, encoding, cleanup) is entirely
//! `tower-sessions-sqlx-store`'s; this enum only dispatches to it.

use tower_sessions::session::{Id, Record};
use tower_sessions::session_store::Result as StoreResult;
use tower_sessions::SessionStore;

#[derive(Clone)]
pub enum AnySessionStore {
    Sqlite(tower_sessions_sqlx_store::SqliteStore),
    Postgres(tower_sessions_sqlx_store::PostgresStore),
    MySql(tower_sessions_sqlx_store::MySqlStore),
}

impl std::fmt::Debug for AnySessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Sqlite(_) => "Sqlite",
            Self::Postgres(_) => "Postgres",
            Self::MySql(_) => "MySql",
        };
        write!(f, "AnySessionStore::{name}")
    }
}

/// Opens the typed session-store connection matching `pool`'s backend,
/// re-reading `EDDA_DATABASE_URL`/`EDDA_DATA_DIR` exactly the way
/// `edda_db::pool()` did to connect the `AnyPool` in the first place, and
/// runs that store's own migration.
pub async fn connect(pool: &edda_db::DbPool) -> Result<AnySessionStore, sqlx::Error> {
    let url_env = std::env::var("EDDA_DATABASE_URL").ok();
    let store = match pool.backend() {
        edda_db::Backend::Sqlite => {
            let url = match url_env {
                Some(url) => url,
                None => {
                    let data_dir = std::env::var("EDDA_DATA_DIR")
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|_| "./data".into());
                    format!("sqlite://{}?mode=rwc", data_dir.join("edda.db").display())
                }
            };
            let sqlite_pool = sqlx::SqlitePool::connect(&url).await?;
            AnySessionStore::Sqlite(tower_sessions_sqlx_store::SqliteStore::new(sqlite_pool))
        }
        edda_db::Backend::Postgres => {
            let url = url_env.expect("EDDA_DATABASE_URL is required for the postgres backend");
            let pg_pool = sqlx::PgPool::connect(&url).await?;
            AnySessionStore::Postgres(tower_sessions_sqlx_store::PostgresStore::new(pg_pool))
        }
        edda_db::Backend::MySql => {
            let url = url_env.expect("EDDA_DATABASE_URL is required for the mysql backend");
            let mysql_pool = sqlx::MySqlPool::connect(&url).await?;
            AnySessionStore::MySql(tower_sessions_sqlx_store::MySqlStore::new(mysql_pool))
        }
    };

    match &store {
        AnySessionStore::Sqlite(s) => s.migrate().await?,
        AnySessionStore::Postgres(s) => s.migrate().await?,
        AnySessionStore::MySql(s) => s.migrate().await?,
    }

    Ok(store)
}

// `tower_sessions::SessionStore` is defined with `#[async_trait]` (boxes
// each method's future with a specific elided-lifetime shape), so the
// impl needs the same macro — a plain `async fn` impl doesn't satisfy
// the trait's lifetime bounds (found via `cargo check`, not assumed).
#[async_trait::async_trait]
impl SessionStore for AnySessionStore {
    async fn create(&self, record: &mut Record) -> StoreResult<()> {
        match self {
            Self::Sqlite(s) => s.create(record).await,
            Self::Postgres(s) => s.create(record).await,
            Self::MySql(s) => s.create(record).await,
        }
    }

    async fn save(&self, record: &Record) -> StoreResult<()> {
        match self {
            Self::Sqlite(s) => s.save(record).await,
            Self::Postgres(s) => s.save(record).await,
            Self::MySql(s) => s.save(record).await,
        }
    }

    async fn load(&self, session_id: &Id) -> StoreResult<Option<Record>> {
        match self {
            Self::Sqlite(s) => s.load(session_id).await,
            Self::Postgres(s) => s.load(session_id).await,
            Self::MySql(s) => s.load(session_id).await,
        }
    }

    async fn delete(&self, session_id: &Id) -> StoreResult<()> {
        match self {
            Self::Sqlite(s) => s.delete(session_id).await,
            Self::Postgres(s) => s.delete(session_id).await,
            Self::MySql(s) => s.delete(session_id).await,
        }
    }
}

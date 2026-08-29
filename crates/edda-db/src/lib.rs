//! Persistence: pool setup, embedded migrations, and one narrow
//! repository struct per aggregate. This is the only crate in the
//! workspace that issues SQL — see this crate's `Cargo.toml` doc comment.
//!
//! Backend (SQLite/PostgreSQL/MySQL-MariaDB) is a **runtime** choice, not
//! a build-time one: `DbPool` wraps `sqlx::AnyPool`, and every query is issued as a
//! runtime-checked `sqlx::query`/`query_as` call rather than the
//! compile-time-checked `sqlx::query!` macro — `sqlx::Any` cannot use
//! that macro (it has no single fixed schema to check against at build
//! time). This is a deliberate, disclosed trade-off: Edda ships one
//! binary that connects to whichever backend `EDDA_DATABASE_URL` names,
//! matching Forgejo's own `DB_TYPE=`-in-config model, at the cost of the
//! compiler no longer catching a query/column mismatch — the same
//! behavioral test suite running against all three backends is what
//! stands in for that now (see `tests.rs`).

mod conn;
mod error;

pub mod access_token_repo;
pub mod audit_event_repo;
pub mod branch_protection_repo;
pub mod commit_status_repo;
pub mod deploy_key_repo;
pub mod email_verification_token_repo;
pub mod event_repo;
pub mod issue_comment_repo;
pub mod issue_repo;
pub mod job_repo;
pub mod label_repo;
pub mod lfs_repo;
pub mod login_attempt_repo;
pub mod milestone_repo;
pub mod notification_repo;
pub mod oauth_identity_repo;
pub mod organization_repo;
pub mod password_reset_token_repo;
pub mod pr_comment_repo;
pub mod pr_review_repo;
pub mod pull_request_repo;
pub mod release_repo;
pub mod repo_access_repo;
pub mod repo_number_repo;
pub mod repo_size_repo;
pub mod repository_repo;
pub mod review_request_repo;
pub mod secret_rotation;
pub mod ssh_key_repo;
pub mod team_repo;
pub mod totp_repo;
pub mod user_repo;
pub mod webauthn_repo;
pub mod webhook_repo;

#[cfg(test)]
mod tests;

pub use conn::{DbConn, DbTx, Handle};
pub use error::DbError;

pub use access_token_repo::AccessTokenRepo;
pub use audit_event_repo::{AuditEvent, AuditEventRepo};
pub use branch_protection_repo::{BranchProtectionRepo, BranchProtectionSettings};
pub use commit_status_repo::CommitStatusRepo;
pub use deploy_key_repo::DeployKeyRepo;
pub use email_verification_token_repo::EmailVerificationTokenRepo;
pub use event_repo::{EventRecord, EventRepo};
pub use issue_comment_repo::IssueCommentRepo;
pub use issue_repo::IssueRepo;
pub use job_repo::JobRepo;
pub use label_repo::LabelRepo;
pub use lfs_repo::{CreateLockError, LfsRepo};
pub use login_attempt_repo::{LoginAttempt, LoginAttemptRepo};
pub use milestone_repo::MilestoneRepo;
pub use notification_repo::NotificationRepo;
pub use oauth_identity_repo::OAuthIdentityRepo;
pub use organization_repo::{InsertOrganizationError, OrganizationRepo};
pub use password_reset_token_repo::PasswordResetTokenRepo;
pub use pr_comment_repo::PrCommentRepo;
pub use pr_review_repo::PrReviewRepo;
pub use pull_request_repo::{NewPullRequest, PullRequestRepo};
pub use release_repo::{InsertReleaseError, NewRelease, ReleaseAssetRepo, ReleaseRepo};
pub use repo_access_repo::{CollaboratorRow, RepoAccessRepo, TeamGrantRow};
pub use repo_number_repo::RepoNumberRepo;
pub use repo_size_repo::RepoSizeRepo;
pub use repository_repo::RepositoryRepo;
pub use review_request_repo::ReviewRequestRepo;
pub use secret_rotation::{SecretRotationRepo, StoredSecret};
pub use ssh_key_repo::SshKeyRepo;
pub use team_repo::{InsertTeamError, TeamMemberRepo, TeamRepo};
pub use totp_repo::TotpRepo;
pub use user_repo::{AccountStatus, DeleteUserError, UserRepo};
pub use webauthn_repo::WebauthnRepo;
pub use webhook_repo::{WebhookDeliveryRepo, WebhookRepo};

use sqlx::any::{AnyPoolOptions, AnyRow};
use sqlx::Row;

/// Which SQL dialect the connected database speaks. `sqlx::any::AnyKind`
/// exists but is `#[deprecated = "not used or returned by any API"]` and
/// unreachable from a live `AnyPool`/`AnyConnection` — this crate needs
/// its own tag, decided once (from the connection URL's scheme) and
/// carried alongside the pool, rather than rediscovered per query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Sqlite,
    Postgres,
    MySql,
}

impl Backend {
    fn from_url(url: &str) -> Result<Self, sqlx::Error> {
        if url.starts_with("sqlite:") {
            Ok(Backend::Sqlite)
        } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            Ok(Backend::Postgres)
        } else if url.starts_with("mysql:") || url.starts_with("mariadb:") {
            Ok(Backend::MySql)
        } else {
            Err(sqlx::Error::Configuration(
                format!("EDDA_DATABASE_URL {url:?} has an unrecognized scheme — expected sqlite:, postgres:/postgresql:, or mysql:/mariadb:")
                    .into(),
            ))
        }
    }
}

/// The persistence handle every other crate holds — deliberately opaque
/// about *which* backend is behind it, even though `any` (an `AnyPool`,
/// itself already backend-erased — no crate needs `SqlitePool`/`PgPool`/
/// `MySqlPool` to use it) is reachable for the rare direct-SQL case
/// (`edda-app`'s `/healthz` check). `backend` stays crate-private: it's
/// what this crate's own repository functions match on to pick the right
/// SQL text, not something a caller outside `edda-db` should ever branch
/// on.
#[derive(Clone)]
pub struct DbPool {
    pub any: sqlx::AnyPool,
    pub(crate) backend: Backend,
}

impl DbPool {
    /// Which backend is behind this pool — needed by the composition
    /// root (`edda-web`'s `main.rs`) to pick a matching
    /// `tower-sessions-sqlx-store` type, since that crate needs a
    /// concrete typed pool `AnyPool` can't provide (see `edda-web`'s
    /// `session_store` module). Not meant for SQL-dialect branching
    /// outside this crate — that stays entirely inside `edda-db`.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Opens a transaction. Thread the returned `DbTx` as `&mut tx`
    /// through several repository methods and then `commit` — the way an
    /// application service makes a multi-aggregate operation atomic.
    /// Dropping without committing rolls back.
    pub async fn begin(&self) -> Result<DbTx, DbError> {
        let inner = self.any.begin().await.map_err(DbError::from)?;
        Ok(DbTx {
            inner,
            backend: self.backend,
        })
    }
}

/// Tunables for the connection pool, surfaced from `Settings` by the
/// composition root. `Default` matches what a small single-instance
/// deployment wants; a busy PostgreSQL/MySQL instance raises
/// `max_connections`.
#[derive(Debug, Clone, Copy)]
pub struct PoolOptions {
    /// Upper bound on connections held open at once.
    pub max_connections: u32,
    /// How long `acquire` waits for a free connection before erroring.
    pub acquire_timeout: std::time::Duration,
}

impl Default for PoolOptions {
    fn default() -> Self {
        Self {
            max_connections: 10,
            acquire_timeout: std::time::Duration::from_secs(30),
        }
    }
}

/// The current unix-seconds timestamp, computed once in application code
/// and bound as an ordinary query parameter everywhere a row needs to
/// record "now" — deliberately not a SQL-side `unixepoch()`/`now()` call,
/// so every INSERT/UPDATE that touches a timestamp behaves identically on
/// every backend without depending on which database's clock function
/// ran. Each migration still declares a native per-backend column
/// `DEFAULT` as a safety net, but application code never relies on it
/// firing.
pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs() as i64
}

/// Reads a `TEXT`/`VARCHAR` column as a `String` regardless of backend —
/// `AnyRow` decodes through each driver's own type system, but a plain
/// `String` target works identically on all three.
pub(crate) fn get_string(row: &AnyRow, column: &str) -> Result<String, sqlx::Error> {
    row.try_get(column)
}

pub(crate) fn get_opt_string(row: &AnyRow, column: &str) -> Result<Option<String>, sqlx::Error> {
    row.try_get(column)
}

pub(crate) fn get_i64(row: &AnyRow, column: &str) -> Result<i64, sqlx::Error> {
    row.try_get(column)
}

pub(crate) fn get_opt_i64(row: &AnyRow, column: &str) -> Result<Option<i64>, sqlx::Error> {
    row.try_get(column)
}

/// Reads an `INTEGER 0/1` flag column as a `bool` — see the admin/disable
/// migration's comment for why these flags are `INTEGER`, not a native
/// `BOOLEAN`, on every backend.
pub(crate) fn get_bool(row: &AnyRow, column: &str) -> Result<bool, sqlx::Error> {
    Ok(get_i64(row, column)? != 0)
}

/// Reads a `BLOB`/`BYTEA` column as raw bytes regardless of backend.
pub(crate) fn get_bytes(row: &AnyRow, column: &str) -> Result<Vec<u8>, sqlx::Error> {
    row.try_get(column)
}

/// The effective connection URL for a given deployment: `configured` (from
/// `EDDA_DATABASE_URL`) verbatim when set, otherwise a local SQLite file
/// under `data_dir` — the zero-config default. Pure; the caller (the
/// composition root or `edda-cli`, the only places that read env) decides
/// where `configured`/`data_dir` come from.
///
/// `sqlite:` (opaque form), not `sqlite://` (authority form): the latter
/// parses the first path segment as a URL host, so an absolute path
/// (`C:\...` -> host `C`) or any Windows separator (`\`) makes it
/// malformed. The opaque form takes the remainder verbatim as a filename,
/// so absolute/relative and either separator all work.
pub fn effective_url(configured: Option<&str>, data_dir: &std::path::Path) -> String {
    match configured {
        Some(url) => url.to_string(),
        None => format!("sqlite:{}?mode=rwc", data_dir.join("edda.db").display()),
    }
}

/// Opens the pool for `url` and applies any migrations that haven't run
/// yet. Safe to call more than once per process — pool creation is cheap
/// and idempotent. The caller is responsible for the data directory
/// existing (`edda_app::config` / `edda-cli` create it at startup); a
/// file-backed SQLite URL under a missing directory fails here with a
/// clear IO error rather than silently creating a tree.
///
/// Networked PostgreSQL/MySQL connect over TLS when the URL asks for it:
/// `sqlx::Any` hands `url` straight to the concrete driver, which reads
/// `?sslmode=`/`?ssl-mode=` (and `?sslrootcert=<path>` for a private CA)
/// on its own — no `Any`-level TLS configuration is needed or possible
/// here. The `rustls`/`ring` stack that backs it is pulled in by this
/// crate's `sqlx` `tls-rustls-ring` feature.
pub async fn pool(url: &str, options: PoolOptions) -> Result<DbPool, DbError> {
    sqlx::any::install_default_drivers();
    connect_and_migrate(url, options)
        .await
        .map_err(DbError::from)
}

/// A cheap `SELECT 1` against the pool — the `/healthz` liveness probe.
/// Replaces `edda-app` reaching into the pool to issue that query
/// itself (which needed a direct `sqlx` dependency there).
pub async fn health(pool: &DbPool) -> Result<(), DbError> {
    sqlx::query("SELECT 1")
        .execute(&pool.any)
        .await
        .map(|_| ())
        .map_err(DbError::from)
}

/// `PRAGMA optimize` on SQLite — cheap, recommended to run periodically
/// so the query planner keeps up-to-date statistics. A no-op on
/// PostgreSQL/MySQL (they maintain statistics automatically). Wired to a
/// scheduled job in Phase 12; exposed now so that job has something to
/// call.
pub async fn optimize(pool: &DbPool) -> Result<(), DbError> {
    if pool.backend == Backend::Sqlite {
        sqlx::query("PRAGMA optimize")
            .execute(&pool.any)
            .await
            .map_err(DbError::from)?;
    }
    Ok(())
}

/// Shared by `pool()` and `test_pool()` — connects, applies this
/// backend's own SQLite tuning (WAL/foreign-keys/busy-timeout have no
/// generic `Any`-level equivalent, so they're applied as plain `PRAGMA`
/// statements after connecting rather than through a typed
/// `SqliteConnectOptions` builder), then runs migrations.
async fn connect_and_migrate(url: &str, options: PoolOptions) -> Result<DbPool, sqlx::Error> {
    let backend = Backend::from_url(url)?;

    let mut pool_options = AnyPoolOptions::new()
        .max_connections(options.max_connections)
        .acquire_timeout(options.acquire_timeout);
    // An in-memory SQLite database is per-connection, not shared, unless
    // every query goes through the exact same connection — a pool with
    // more than one connection would silently hand later queries an
    // empty database (found running this crate's own tests through
    // `AnyPool`, which doesn't special-case `:memory:` the way sqlx's
    // typed `SqlitePool` used to).
    if backend == Backend::Sqlite && url.contains(":memory:") {
        pool_options = pool_options.max_connections(1);
    }
    let any = pool_options.connect(url).await?;

    if backend == Backend::Sqlite {
        // Default (rollback-journal) mode lets one writer starve every
        // other connection in the pool, including reads — and every
        // authenticated request touches the sessions table, so this is
        // on the hot path for concurrent traffic, not just heavy writes.
        // WAL lets readers and the writer proceed together. `foreign_keys
        // = ON`: SQLite defaults this off at the C-library level (sqlx's
        // typed `SqliteConnectOptions` used to turn it on by default;
        // going through `Any` loses that default, so it's set explicitly
        // here instead).
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&any)
            .await?;
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&any)
            .await?;
        sqlx::query("PRAGMA busy_timeout = 5000")
            .execute(&any)
            .await?;
    }

    let pool = DbPool { any, backend };
    run_migrations(&pool).await?;
    Ok(pool)
}

/// A fresh, fully migrated database for tests. Defaults to an in-memory
/// SQLite database (fast, no external service) — set
/// `EDDA_TEST_DATABASE_URL` to run the exact same test suite against a
/// real PostgreSQL or MySQL/MariaDB instance instead (see
/// `compose.db.yml` at the workspace root for both). Never touches
/// `EDDA_DATA_DIR`/`EDDA_DATABASE_URL`'s production defaults.
pub async fn test_pool() -> DbPool {
    sqlx::any::install_default_drivers();

    match std::env::var("EDDA_TEST_DATABASE_URL") {
        Ok(url) => {
            let backend = Backend::from_url(&url).expect("EDDA_TEST_DATABASE_URL is valid");
            match backend {
                Backend::Sqlite => connect_and_migrate(&url, PoolOptions::default())
                    .await
                    .expect("connect and migrate the configured sqlite test database"),
                Backend::Postgres | Backend::MySql => fresh_server_test_database(&url, backend)
                    .await
                    .expect("create and migrate a fresh per-test database"),
            }
        }
        Err(_) => connect_and_migrate("sqlite::memory:", PoolOptions::default())
            .await
            .expect("in-memory sqlite pool"),
    }
}

/// PostgreSQL/MySQL have no in-memory mode — this connects to the
/// server named by `admin_url` and creates+migrates a fresh,
/// uniquely-named database per call, so concurrent test runs stay
/// isolated the same way the SQLite in-memory pool isolates them for
/// free. The per-test database is deliberately not dropped afterward —
/// disposable local/CI instances get thrown away between runs anyway,
/// and dropping adds a failure mode for no real benefit.
async fn fresh_server_test_database(
    admin_url: &str,
    backend: Backend,
) -> Result<DbPool, sqlx::Error> {
    let admin_any = AnyPoolOptions::new()
        .max_connections(1)
        .connect(admin_url)
        .await?;

    // Not user input — a clock reading plus a process-local atomic
    // counter, not injectable. The counter matters: `cargo test` runs on
    // multiple threads, and a nanosecond clock reading alone collided in
    // practice between two tests started in the same tick.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_nanos();
    let db_name = format!(
        "edda_test_{nanos:x}_{}",
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );

    let create_stmt = match backend {
        // MySQL/MariaDB use backtick identifier quoting; PostgreSQL uses
        // double quotes.
        Backend::MySql => format!("CREATE DATABASE `{db_name}`"),
        Backend::Postgres => format!(r#"CREATE DATABASE "{db_name}""#),
        Backend::Sqlite => unreachable!("callers only reach here for Postgres/MySql"),
    };
    sqlx::query(&create_stmt).execute(&admin_any).await?;

    let base = admin_url
        .rsplit_once('/')
        .map(|(base, _)| base)
        .unwrap_or(admin_url);
    let test_url = format!("{base}/{db_name}");
    connect_and_migrate(&test_url, PoolOptions::default()).await
}

/// Path is relative to this crate's own `Cargo.toml` (`CARGO_MANIFEST_DIR`,
/// what `sqlx::migrate!` resolves against) — kept at the workspace root
/// rather than nested under this crate so `sqlx`/`sqlx-cli` commands run
/// from the repo root (the common case) find it without extra flags. One
/// directory per backend — dialect differences (case-insensitive
/// uniqueness, the one-owner-per-repo partial-index equivalent, column
/// width limits) mean the three chains are independent, not a shared
/// template; all three are embedded at compile time and the right one is
/// selected at runtime by `pool.backend`.
async fn run_migrations(pool: &DbPool) -> Result<(), sqlx::Error> {
    static SQLITE: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations/sqlite");
    static POSTGRES: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations/postgres");
    static MYSQL: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations/mysql");

    match pool.backend {
        // A couple of SQLite migrations rebuild a table other tables
        // reference via foreign key (SQLite has no `ALTER TABLE` support
        // for widening a `CHECK` constraint in place — see the
        // `organization_repository_owner` / `team_repo_access` migrations'
        // own comments for the documented table-rebuild procedure this
        // requires). `PRAGMA foreign_keys` is a no-op once a transaction
        // is already open, so it can't be toggled from inside a
        // migration's own `.sql` file — this dedicates one connection to
        // the whole migration run, disables enforcement on it *before*
        // `sqlx::migrate`'s own per-file transactions begin, and restores
        // it before the connection goes back to the pool. Safe to do
        // unconditionally on every startup, not just when a rebuild
        // migration is pending: a run with nothing new to apply is a
        // no-op either way, and no other connection in the pool is
        // affected (each SQLite connection tracks this setting
        // independently).
        Backend::Sqlite => {
            let mut conn = pool.any.acquire().await?;
            sqlx::query("PRAGMA foreign_keys = OFF")
                .execute(&mut *conn)
                .await?;
            let result = SQLITE.run(&mut *conn).await;
            sqlx::query("PRAGMA foreign_keys = ON")
                .execute(&mut *conn)
                .await?;
            result.map_err(|err| sqlx::Error::Migrate(Box::new(err)))?;
        }
        Backend::Postgres => POSTGRES
            .run(&pool.any)
            .await
            .map_err(|err| sqlx::Error::Migrate(Box::new(err)))?,
        Backend::MySql => MYSQL
            .run(&pool.any)
            .await
            .map_err(|err| sqlx::Error::Migrate(Box::new(err)))?,
    }
    Ok(())
}

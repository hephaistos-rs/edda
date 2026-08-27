//! The handle a repository method runs against.
//!
//! Before Phase 2 every method took `&DbPool`, so a caller could never
//! wrap several of them in one transaction. They now take
//! `impl DbConn<'_>`, which is implemented for:
//!
//! - `&DbPool` — the standalone case; checks a connection out of the pool
//!   for the duration of the call.
//! - `&mut DbTx` — a transaction opened by `DbPool::begin`; the method
//!   runs on that transaction's connection, so an application service can
//!   compose N repo calls into one atomic unit.
//! - `&mut Handle` — lets one repo method call another while holding the
//!   same connection/transaction (e.g. `RepositoryRepo::resolve_owner`).
//!
//! `sqlx` stays entirely behind this trait; `DbConn`, `Handle`, and
//! `DbTx` are the only database handles the rest of the workspace sees.

use crate::{Backend, DbError};

mod sealed {
    pub trait Sealed {}
    impl Sealed for &crate::DbPool {}
    impl Sealed for &mut super::DbTx {}
    impl Sealed for &mut super::Handle<'_> {}
}

/// Something a repository method can issue SQL against — see the module
/// docs. Sealed: the three implementors above are the whole set.
#[allow(private_bounds)]
pub trait DbConn<'c>: sealed::Sealed + Send + Sized {
    #[doc(hidden)]
    fn backend(&self) -> Backend;
    #[doc(hidden)]
    fn source(self) -> Source<'c>;
}

/// Opaque wrapper around "pool or live connection", produced by
/// `DbConn::source` and consumed by `open`.
#[doc(hidden)]
pub enum Source<'c> {
    Pool(&'c sqlx::AnyPool),
    Conn(&'c mut sqlx::AnyConnection),
}

impl<'c> DbConn<'c> for &'c crate::DbPool {
    fn backend(&self) -> Backend {
        crate::DbPool::backend(self)
    }
    fn source(self) -> Source<'c> {
        Source::Pool(&self.any)
    }
}

impl<'c> DbConn<'c> for &'c mut DbTx {
    fn backend(&self) -> Backend {
        self.backend
    }
    fn source(self) -> Source<'c> {
        Source::Conn(&mut self.inner)
    }
}

impl<'c, 'h: 'c> DbConn<'c> for &'c mut Handle<'h> {
    fn backend(&self) -> Backend {
        self.backend
    }
    fn source(self) -> Source<'c> {
        Source::Conn(self.conn())
    }
}

/// A live connection acquired for the span of one repository method, plus
/// the backend tag that method needs to pick its SQL dialect. Either a
/// connection checked out of the pool, or a borrow of the caller's
/// transaction — the method's body does not care which.
pub struct Handle<'c> {
    backend: Backend,
    inner: HandleInner<'c>,
}

enum HandleInner<'c> {
    Pooled(sqlx::pool::PoolConnection<sqlx::Any>),
    Borrowed(&'c mut sqlx::AnyConnection),
}

impl Handle<'_> {
    /// The connected backend — repository methods match on this to choose
    /// between `$1` (PostgreSQL) and `?` (SQLite/MySQL) placeholder style.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// The underlying connection, to hand to `sqlx::query(..).execute(..)`
    /// and friends. Reborrow (`&mut *handle.conn()`) at each call site so
    /// the method can issue more than one statement.
    pub(crate) fn conn(&mut self) -> &mut sqlx::AnyConnection {
        match &mut self.inner {
            HandleInner::Pooled(conn) => conn,
            HandleInner::Borrowed(conn) => conn,
        }
    }

    /// Begins a transaction on this handle for the methods that need
    /// several writes to land atomically on their own. When the handle is
    /// already inside a caller's transaction this issues a `SAVEPOINT`, so
    /// the method stays atomic whether it was called standalone or
    /// composed.
    pub(crate) async fn begin(&mut self) -> Result<sqlx::Transaction<'_, sqlx::Any>, DbError> {
        sqlx::Connection::begin(self.conn())
            .await
            .map_err(DbError::from)
    }
}

/// Resolve an `impl DbConn` to a `Handle` — the first line of essentially
/// every repository method:
///
/// ```ignore
/// pub async fn find<'c>(db: impl DbConn<'c>, id: Id) -> Result<T, DbError> {
///     let mut h = crate::conn::open(db).await?;
///     let sql = match h.backend() { Backend::Postgres => "..$1..", _ => "..?.." };
///     let row = sqlx::query(sql).bind(..).fetch_optional(&mut *h.conn()).await?;
///     ..
/// }
/// ```
pub async fn open<'c>(db: impl DbConn<'c>) -> Result<Handle<'c>, DbError> {
    let backend = db.backend();
    let inner = match db.source() {
        Source::Pool(pool) => HandleInner::Pooled(pool.acquire().await.map_err(DbError::from)?),
        Source::Conn(conn) => HandleInner::Borrowed(conn),
    };
    Ok(Handle { backend, inner })
}

/// A database transaction, opened by [`crate::DbPool::begin`]. Carries the
/// backend tag alongside the `sqlx` transaction so it can be passed as
/// `&mut tx` to the now-generic repository methods; an application service
/// threads one of these through several repo calls and then `commit`s.
/// Dropping without `commit` rolls back.
pub struct DbTx {
    pub(crate) inner: sqlx::Transaction<'static, sqlx::Any>,
    pub(crate) backend: Backend,
}

impl DbTx {
    /// The connected backend (same value as the originating pool's).
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Commit every write made through this transaction.
    pub async fn commit(self) -> Result<(), DbError> {
        self.inner.commit().await.map_err(DbError::from)
    }

    /// Discard every write made through this transaction. Equivalent to
    /// dropping it, but explicit and `await`able.
    pub async fn rollback(self) -> Result<(), DbError> {
        self.inner.rollback().await.map_err(DbError::from)
    }
}

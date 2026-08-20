use sqlx::SqlitePool;

/// Runs every migration in `migrations/` (project root) that hasn't run yet
/// against this pool, then backfills any account created before the
/// `username` column existed. Safe to call on every startup — sqlx tracks
/// what's already applied, and `backfill_usernames` is itself a no-op once
/// every row has a username (see its doc comment for why that backfill runs
/// here as plain Rust rather than as another `.sql` migration).
pub async fn run(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::migrate!().run(pool).await.map_err(|err| sqlx::Error::Migrate(Box::new(err)))?;
    crate::auth::backfill_usernames(pool).await?;
    Ok(())
}

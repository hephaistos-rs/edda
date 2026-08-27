//! Phase 2: a networked PostgreSQL/MySQL connection must be able to run
//! over TLS.
//!
//! `edda_db::pool` hands the connection URL to the concrete driver
//! verbatim (`sqlx::Any` does no rewriting), and the driver parses
//! `?sslmode=` / `?ssl-mode=` (and `?sslrootcert=`) itself — so TLS needs
//! no `Any`-level plumbing, only the `tls-rustls-ring` feature this crate
//! enables. This test proves that end to end against a real TLS-enabled
//! server.
//!
//! It is opt-in: set `EDDA_TEST_TLS_DATABASE_URL` to a URL that *demands*
//! TLS, e.g.
//!
//! ```text
//! EDDA_TEST_TLS_DATABASE_URL='postgres://edda:edda@localhost:5433/eddadb?sslmode=require'
//! ```
//!
//! `compose.db-tls.yml` at the workspace root brings up exactly such a
//! server (a self-signed Postgres on :5433). With the variable unset the
//! test is a no-op pass, so a plain `cargo test` and CI stay green without
//! the extra container.

#[tokio::test]
async fn a_tls_required_url_connects_and_is_usable() {
    let Ok(url) = std::env::var("EDDA_TEST_TLS_DATABASE_URL") else {
        eprintln!(
            "skipping: set EDDA_TEST_TLS_DATABASE_URL (see compose.db-tls.yml) to exercise \
             the pg/mysql-over-TLS path"
        );
        return;
    };

    let pool = edda_db::pool(&url, edda_db::PoolOptions::default())
        .await
        .unwrap_or_else(|err| panic!("TLS connect to {url:?} failed: {err}"));

    edda_db::health(&pool)
        .await
        .expect("a trivial query over the TLS connection");
}

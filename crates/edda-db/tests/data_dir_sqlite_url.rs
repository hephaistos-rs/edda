//! Regression test: `edda_db::effective_url` + `pool` must build a usable
//! SQLite URL from a data directory regardless of the directory's shape —
//! an absolute path and the platform-native separator included.
//!
//! The zero-config default path used to format the URL as
//! `sqlite://<data_dir>/edda.db`, where `sqlite://` makes the URL parser
//! read the first path segment as an authority/host. On Windows that meant
//! an absolute data dir (`C:\...`) put the drive letter in the host
//! position ("unable to open database file"), and any backslash separator
//! produced "invalid domain character" — the server panicked at startup
//! for essentially every real deployment path, and only a forward-slash
//! *relative* data dir happened to work. This exercises the fixed
//! `sqlite:` opaque form against exactly that input.
//!
//! Since Phase 1 the resolution takes explicit parameters (no `std::env`),
//! so this no longer touches process-global state.

use std::path::{Path, PathBuf};

fn unique_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "edda-db-datadir-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// Resolves the zero-config SQLite URL for `data_dir`, opens a pool, and
/// proves it's actually usable — not merely constructed.
async fn assert_pool_works_with_data_dir(data_dir: &str) {
    // The data dir is the caller's responsibility (`edda_db::pool` no
    // longer touches the filesystem) — `edda_http::config` / `edda-cli`
    // create it at startup; here the test does.
    std::fs::create_dir_all(data_dir).expect("create the test data dir");

    let url = edda_db::effective_url(None, Path::new(data_dir));
    assert!(
        url.starts_with("sqlite:"),
        "expected a sqlite: URL, got {url:?}"
    );

    let pool = edda_db::pool(&url).await.unwrap_or_else(|err| {
        panic!("pool() failed for data_dir={data_dir:?} (url {url:?}): {err}")
    });

    sqlx::query("SELECT 1")
        .execute(&pool.any)
        .await
        .expect("run a trivial query against the opened pool");

    assert!(
        Path::new(data_dir).join("edda.db").exists(),
        "expected edda.db under {data_dir:?}"
    );

    let _ = std::fs::remove_dir_all(data_dir);
}

#[tokio::test]
async fn pool_opens_from_data_dir_regardless_of_path_shape() {
    // An absolute path with the platform-native separator — on Windows the
    // `C:\...\` shape that used to make startup panic.
    let native = unique_dir("native");
    assert!(
        native.is_absolute(),
        "temp_dir() should yield an absolute path"
    );
    assert_pool_works_with_data_dir(native.to_str().expect("utf-8 temp path")).await;

    // The same absolute location written with forward slashes — `sqlite://`
    // mishandled this too (drive letter as host); the opaque `sqlite:` form
    // must accept either separator.
    let forward = unique_dir("fwd")
        .to_str()
        .expect("utf-8 temp path")
        .replace('\\', "/");
    assert_pool_works_with_data_dir(&forward).await;
}

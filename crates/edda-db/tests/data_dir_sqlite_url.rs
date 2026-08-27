//! Regression test: `edda_db::pool()` must build a usable SQLite URL from
//! `EDDA_DATA_DIR` regardless of the directory's shape — an absolute path
//! and the platform-native separator included.
//!
//! The zero-config default path used to format the URL as
//! `sqlite://<data_dir>/edda.db`, where `sqlite://` makes the URL parser
//! read the first path segment as an authority/host. On Windows that meant
//! an absolute `EDDA_DATA_DIR` (`C:\...`) put the drive letter in the host
//! position ("unable to open database file"), and any backslash separator
//! produced "invalid domain character" — the server panicked at startup
//! for essentially every real deployment path, and only a forward-slash
//! *relative* `EDDA_DATA_DIR` happened to work. This exercises the fixed
//! `sqlite:` opaque form against exactly that input.
//!
//! One test, run cases sequentially: `pool()` reads process-global env, so
//! the cases must not interleave. This file is its own test binary, so
//! there is no contention with the rest of the suite.

struct EnvGuard {
    database_url: Option<String>,
    data_dir: Option<String>,
}

impl EnvGuard {
    fn capture() -> Self {
        Self {
            database_url: std::env::var("EDDA_DATABASE_URL").ok(),
            data_dir: std::env::var("EDDA_DATA_DIR").ok(),
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        restore("EDDA_DATABASE_URL", self.database_url.as_deref());
        restore("EDDA_DATA_DIR", self.data_dir.as_deref());
    }
}

fn restore(key: &str, value: Option<&str>) {
    match value {
        Some(v) => std::env::set_var(key, v),
        None => std::env::remove_var(key),
    }
}

fn unique_dir(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "edda-db-datadir-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// Points `EDDA_DATA_DIR` at `data_dir` (with `EDDA_DATABASE_URL` unset, to
/// force the SQLite zero-config path), opens a pool, and proves it's
/// actually usable — not merely constructed.
async fn assert_pool_works_with_data_dir(data_dir: &str) {
    std::fs::create_dir_all(data_dir).expect("create the test data dir");

    std::env::remove_var("EDDA_DATABASE_URL");
    std::env::set_var("EDDA_DATA_DIR", data_dir);

    let pool = edda_db::pool()
        .await
        .unwrap_or_else(|err| panic!("pool() failed for EDDA_DATA_DIR={data_dir:?}: {err}"));

    sqlx::query("SELECT 1")
        .execute(&pool.any)
        .await
        .expect("run a trivial query against the opened pool");

    assert!(
        std::path::Path::new(data_dir).join("edda.db").exists(),
        "expected edda.db under {data_dir:?}"
    );

    let _ = std::fs::remove_dir_all(data_dir);
}

#[tokio::test]
async fn pool_opens_from_data_dir_regardless_of_path_shape() {
    let _restore = EnvGuard::capture();

    // An absolute path with the platform-native separator — on Windows the
    // `C:\...\` shape that used to make `pool()` panic at startup.
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

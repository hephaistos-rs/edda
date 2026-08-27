//! Proves `edda-cli user disable` actually blocks that account's *next*
//! login — not just that the database row changed. Runs the real
//! compiled `edda-cli` binary as a subprocess (the same "drive the real
//! artifact, not a reimplementation of it" approach already used for the
//! git-lfs CLI round-trip test) against a real file-backed SQLite
//! database — an in-memory database can't be shared across the two
//! separate OS processes (this test and the `edda-cli` subprocess) the
//! way it can within one process's connection pool.

use std::process::Command;

use axum_login::AuthnBackend;
use edda_auth::{Backend, Credentials};

fn run_cli(db_url: &str, args: &[&str]) {
    let output = Command::new(env!("CARGO_BIN_EXE_edda-cli"))
        .args(args)
        .env("EDDA_DATABASE_URL", db_url)
        .output()
        .expect("failed to run edda-cli");
    assert!(
        output.status.success(),
        "edda-cli {args:?} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn disabling_a_user_via_the_cli_blocks_their_next_login() {
    let db_path = std::env::temp_dir().join(format!(
        "edda-cli-disable-test-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_file(&db_path);
    // `sqlite://` (two slashes) plus a Windows absolute path starting with
    // a drive letter parses the drive letter as a URL host, not a path —
    // three slashes are needed so the whole thing is treated as a path.
    let db_url = format!(
        "sqlite:///{}?mode=rwc",
        db_path.to_str().unwrap().replace('\\', "/")
    );

    let pool = edda_db::pool(&db_url, edda_db::PoolOptions::default())
        .await
        .expect("connect and migrate test database");

    let password = "correct horse battery staple";
    let password_hash = edda_auth::password::hash_password(password).unwrap();
    edda_db::UserRepo::insert(
        &pool,
        edda_domain::UserId::new(),
        "alice",
        "alice@example.com",
        &password_hash,
    )
    .await
    .expect("insert test user");

    let backend = Backend::new(pool.clone());
    let creds = Credentials {
        email: "alice@example.com".to_string(),
        password: password.to_string(),
    };

    // Before disabling: login succeeds.
    let session_user = backend
        .authenticate(creds.clone())
        .await
        .expect("authenticate call succeeds")
        .expect("correct credentials log in before the account is disabled");
    assert_eq!(session_user.user.username, "alice");

    // Run the real, compiled `edda-cli` binary to disable the account.
    run_cli(&db_url, &["user", "disable", "alice"]);

    // After disabling: the exact same credentials no longer authenticate —
    // this is the actual login path (`AuthnBackend::authenticate`), not a
    // direct inspection of the `disabled_at` column.
    let result = backend
        .authenticate(creds)
        .await
        .expect("authenticate call succeeds even when it returns no user");
    assert!(
        result.is_none(),
        "a disabled account must not be able to log in"
    );

    let _ = std::fs::remove_file(&db_path);
}

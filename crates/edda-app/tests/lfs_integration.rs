//! Exercises the LFS batch/upload/download surface (`crates/edda-app/src/
//! lfs/mod.rs`) against a real `git`/`git-lfs` CLI talking to this crate's
//! actual router over a real TCP socket — not a mocked HTTP layer: a
//! `git-lfs`-CLI-managed push/pull of a tracked large file must round-trip
//! correctly against a running instance, mirroring the same "test against
//! the real client" philosophy the git smart-HTTP bridge itself was
//! validated with.
//!
//! Skips (rather than failing) if `git`/`git-lfs` aren't on `PATH` — this
//! test needs binaries this crate's own `cargo test` can't install.

use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use edda_app::{router, AppState};
use edda_auth::{tokens, AuthorizationService, Backend};
use edda_db::RepositoryRepo;
use edda_domain::{Repository, RepositoryId, RepositoryOwner, UserId, Visibility};
use edda_git::store::{LocalFsStore, RepoStore};
use edda_git::LockRegistry;

fn tool_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn run(cwd: &Path, program: &str, args: &[&str]) {
    let output = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .env("GIT_AUTHOR_NAME", "ci")
        .env("GIT_AUTHOR_EMAIL", "ci@example.com")
        .env("GIT_COMMITTER_NAME", "ci")
        .env("GIT_COMMITTER_EMAIL", "ci@example.com")
        .output()
        .unwrap_or_else(|err| panic!("failed to run {program} {args:?}: {err}"));
    assert!(
        output.status.success(),
        "{program} {args:?} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// `router()` itself applies no session/auth middleware — the composition
/// root (`edda-web`'s `main.rs`) does that, wrapping it in an
/// `axum_login::AuthManagerLayer` built from a real session store, which
/// is what the `AuthSession<Backend>` extractor every handler in this
/// crate uses actually needs present to resolve at all. This test needs
/// the same layer for the same reason, even though it never exercises
/// session-cookie auth (only the personal-access-token path) — a fresh,
/// throwaway in-memory SQLite session store is enough; it doesn't need to
/// match the `AppState`'s own configured backend, since sessions and
/// application data are two unrelated concerns.
async fn spawn_server(state: AppState) -> SocketAddr {
    let session_pool = sqlx::SqlitePool::connect("sqlite::memory:")
        .await
        .expect("open an in-memory sqlite pool for sessions");
    let session_store = tower_sessions_sqlx_store::SqliteStore::new(session_pool);
    session_store
        .migrate()
        .await
        .expect("migrate session store");
    let session_layer = tower_sessions::SessionManagerLayer::new(session_store);
    let backend = state.backend.clone();
    let auth_layer = axum_login::AuthManagerLayerBuilder::new(backend, session_layer).build();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("resolve bound address");
    let app = router(state).layer(auth_layer);
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    addr
}

// Multi-thread, not the default current-thread runtime: this test makes
// several *blocking* `Command::output()` calls (real `git`/`git-lfs`
// subprocesses) from the test's own async fn body. On a current-thread
// runtime those calls monopolize the only worker thread, starving the
// `tokio::spawn`ed server task of any chance to accept or answer a
// connection — indistinguishable from the server hanging. Found by
// probing with `curl` directly: the TCP handshake completed (proving the
// listener was reachable) but zero response bytes ever arrived.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_lfs_cli_round_trips_a_tracked_file_through_a_real_server() {
    if !tool_available("git") || !tool_available("git-lfs") {
        eprintln!("skipping: git/git-lfs not found on PATH");
        return;
    }

    let pool = edda_db::test_pool().await;

    let store_root = std::env::temp_dir().join(format!(
        "edda-app-lfs-it-store-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&store_root);
    let store: Arc<dyn RepoStore> = Arc::new(LocalFsStore::new(store_root.clone()));
    let locks = Arc::new(LockRegistry::new());

    let user_id = UserId::new();
    edda_db::UserRepo::insert(&pool, user_id, "alice", "alice@example.com", "unused")
        .await
        .expect("insert user");
    let (raw_token, _) = tokens::create(&pool, user_id, "ci")
        .await
        .expect("create access token");

    edda_git::create_repo(store.as_ref(), &locks, "alice/demo")
        .await
        .expect("initialize bare repo");
    let repository = Repository {
        id: RepositoryId::new(),
        owner: RepositoryOwner::User(user_id),
        name: "demo".to_string(),
        description: None,
        visibility: Visibility::Public,
        forked_from: None,
    };
    RepositoryRepo::insert_with_owner(&pool, &repository, user_id)
        .await
        .expect("insert repository row");

    let state = AppState {
        pool: pool.clone(),
        store,
        locks,
        authz: AuthorizationService::new(pool.clone()),
        backend: Backend::new(pool.clone()),
        config: Default::default(),
    };
    let addr = spawn_server(state).await;
    let remote = format!("http://ci:{raw_token}@{addr}/alice/demo.git");

    let work_dir = std::env::temp_dir().join(format!(
        "edda-app-lfs-it-work-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&work_dir);
    std::fs::create_dir_all(&work_dir).expect("create work dir");

    run(&work_dir, "git", &["clone", &remote, "repo"]);
    let repo_dir = work_dir.join("repo");
    run(&repo_dir, "git", &["lfs", "install", "--local"]);
    run(&repo_dir, "git", &["lfs", "track", "*.bin"]);
    run(&repo_dir, "git", &["add", ".gitattributes"]);

    let asset_bytes: Vec<u8> = (0..50_000u32).map(|n| (n % 256) as u8).collect();
    std::fs::write(repo_dir.join("asset.bin"), &asset_bytes).expect("write asset");
    run(&repo_dir, "git", &["add", "asset.bin"]);
    run(&repo_dir, "git", &["commit", "-m", "add a tracked asset"]);
    run(
        &repo_dir,
        "git",
        &["push", "origin", "HEAD:refs/heads/main"],
    );

    run(&work_dir, "git", &["clone", &remote, "repo2"]);
    let downloaded = std::fs::read(work_dir.join("repo2").join("asset.bin")).expect("read asset");
    assert_eq!(
        downloaded, asset_bytes,
        "downloaded LFS content must match what was pushed"
    );

    let _ = std::fs::remove_dir_all(&work_dir);
    let _ = std::fs::remove_dir_all(&store_root);
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Drives the LFS batch → PUT object-transfer flow directly (no `git-lfs`
/// CLI) against a server configured with a low `EDDA_LFS_MAX_OBJECT_BYTES`:
/// an object under the ceiling uploads (200), one over it is refused
/// mid-transfer with 413 and never reaches disk.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_lfs_upload_over_the_configured_object_ceiling_is_refused() {
    let pool = edda_db::test_pool().await;
    let store_root = std::env::temp_dir().join(format!(
        "edda-app-lfs-cap-store-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&store_root);
    let store: Arc<dyn RepoStore> = Arc::new(LocalFsStore::new(store_root.clone()));
    let locks = Arc::new(LockRegistry::new());

    let user_id = UserId::new();
    edda_db::UserRepo::insert(&pool, user_id, "alice", "alice@example.com", "unused")
        .await
        .expect("insert user");
    let (raw_token, _) = tokens::create(&pool, user_id, "ci")
        .await
        .expect("create access token");

    edda_git::create_repo(store.as_ref(), &locks, "alice/demo")
        .await
        .expect("initialize bare repo");
    let repository = Repository {
        id: RepositoryId::new(),
        owner: RepositoryOwner::User(user_id),
        name: "demo".to_string(),
        description: None,
        visibility: Visibility::Public,
        forked_from: None,
    };
    RepositoryRepo::insert_with_owner(&pool, &repository, user_id)
        .await
        .expect("insert repository row");

    let state = AppState {
        pool: pool.clone(),
        store,
        locks,
        authz: AuthorizationService::new(pool.clone()),
        backend: Backend::new(pool.clone()),
        config: edda_app::RuntimeConfig {
            git_limits: edda_app::config::GitLimits {
                max_pack_bytes: 2 * 1024 * 1024 * 1024,
                max_lfs_object_bytes: 64 * 1024,
            },
            ..Default::default()
        },
    };
    let addr = spawn_server(state).await;
    let base = format!("http://{addr}");
    let auth = format!(
        "Basic {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("ci:{raw_token}")
        )
    );
    let client = reqwest::Client::new();

    // Ask for an upload action, then PUT the object at the returned href.
    async fn upload(
        client: &reqwest::Client,
        base: &str,
        auth: &str,
        body: Vec<u8>,
    ) -> reqwest::StatusCode {
        let oid = sha256_hex(&body);
        let batch: serde_json::Value = client
            .post(format!("{base}/alice/demo.git/info/lfs/objects/batch"))
            .header("Authorization", auth)
            .header("Content-Type", "application/vnd.git-lfs+json")
            .body(
                serde_json::json!({
                    "operation": "upload",
                    "objects": [{ "oid": oid, "size": body.len() }],
                })
                .to_string(),
            )
            .send()
            .await
            .expect("batch request")
            .json()
            .await
            .expect("batch json");

        let action = &batch["objects"][0]["actions"]["upload"];
        let href = action["href"].as_str().expect("an upload href");
        let token = action["header"]["Authorization"]
            .as_str()
            .expect("an upload bearer header");

        client
            .put(href)
            .header("Authorization", token)
            .body(body)
            .send()
            .await
            .expect("put object")
            .status()
    }

    // Under the ceiling: accepted.
    let small = vec![7u8; 1024];
    assert_eq!(
        upload(&client, &base, &auth, small).await,
        reqwest::StatusCode::OK
    );

    // Over the ceiling: refused with 413, and nothing lands on disk.
    let big = vec![9u8; 256 * 1024];
    let big_oid = sha256_hex(&big);
    assert_eq!(
        upload(&client, &base, &auth, big).await,
        reqwest::StatusCode::PAYLOAD_TOO_LARGE
    );
    let leaked = LocalFsStore::new(store_root.clone()).lfs_object_path("alice/demo", &big_oid);
    assert!(
        !leaked.exists(),
        "the rejected LFS object must not have been written"
    );

    let _ = std::fs::remove_dir_all(&store_root);
}

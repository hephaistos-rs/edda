//! H1 baseline (plan.local.md §2 / Phase 0 exit criteria).
//!
//! The git smart-HTTP handlers currently take the whole request body as
//! `axum::body::Bytes`, so axum's default `DefaultBodyLimit` (~2 MiB) caps
//! every push. A pack larger than that is rejected before `edda-git` ever
//! sees it — the `Bytes` extractor fails the request (the `git` client
//! surfaces it as `RPC failed; HTTP 400`).
//!
//! This test pushes a deliberately-incompressible ~4 MiB blob and asserts
//! the push **succeeds** and the object is retrievable server-side — the
//! behaviour Phase 6 delivers by switching the receive path to a streaming
//! body with an explicit, mid-stream `EDDA_GIT_MAX_PACK_BYTES` cap and
//! `DefaultBodyLimit::disable()` on the git/LFS routes.
//!
//! It fails today, so it is `#[ignore]`d. Phase 6 removes the `#[ignore]`
//! line (and nothing else) once the streaming receive path lands.

use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use edda_auth::{tokens, AuthorizationService, Backend};
use edda_db::RepositoryRepo;
use edda_domain::{Repository, RepositoryId, RepositoryOwner, UserId, Visibility};
use edda_git::store::{LocalFsStore, RepoStore};
use edda_git::LockRegistry;
use edda_http::{router, AppState};

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

fn temp_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "edda-http-pack-size-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// ~`len` bytes a deflate pass cannot meaningfully shrink, so the pack
/// stays over axum's 2 MiB default body limit. A plain xorshift keeps this
/// dependency-free and deterministic.
fn incompressible_bytes(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "H1 baseline: >2 MiB push is rejected by axum's default body limit until Phase 6 streams the receive body. Un-ignore in Phase 6."]
async fn a_push_larger_than_the_default_body_limit_succeeds() {
    if !tool_available("git") {
        eprintln!("skipping: git not found on PATH");
        return;
    }

    let pool = edda_db::test_pool().await;
    let store_root = temp_dir("store");
    let store: Arc<dyn RepoStore> = Arc::new(LocalFsStore::new(store_root.clone()));
    let locks = Arc::new(LockRegistry::new());

    let alice_id = UserId::new();
    edda_db::UserRepo::insert(&pool, alice_id, "alice", "alice@example.com", "unused")
        .await
        .expect("insert alice");
    let (alice_token, _) = tokens::create(&pool, alice_id, "ci")
        .await
        .expect("create alice token");

    edda_git::create_repo(store.as_ref(), &locks, "alice/demo")
        .await
        .expect("initialize bare repo");
    let repository = Repository {
        id: RepositoryId::new(),
        owner: RepositoryOwner::User(alice_id),
        name: "demo".to_string(),
        description: None,
        visibility: Visibility::Public,
        forked_from: None,
    };
    RepositoryRepo::insert_with_owner(&pool, &repository, alice_id)
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

    let work_dir = temp_dir("work");
    std::fs::create_dir_all(&work_dir).expect("create work dir");
    let remote = format!("http://ci:{alice_token}@{addr}/alice/demo.git");

    run(&work_dir, "git", &["clone", &remote, "repo"]);
    let repo_dir = work_dir.join("repo");
    std::fs::write(
        repo_dir.join("big.bin"),
        incompressible_bytes(4 * 1024 * 1024),
    )
    .expect("write the large blob");
    run(&repo_dir, "git", &["add", "big.bin"]);
    run(
        &repo_dir,
        "git",
        &["commit", "-m", "add a 4 MiB incompressible blob"],
    );

    let push = Command::new("git")
        .args(["push", "origin", "HEAD:refs/heads/main"])
        .current_dir(&repo_dir)
        .env("GIT_AUTHOR_NAME", "ci")
        .env("GIT_AUTHOR_EMAIL", "ci@example.com")
        .env("GIT_COMMITTER_NAME", "ci")
        .env("GIT_COMMITTER_EMAIL", "ci@example.com")
        .output()
        .expect("run git push");
    assert!(
        push.status.success(),
        "a >2 MiB push should be accepted once the receive body streams:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&push.stdout),
        String::from_utf8_lossy(&push.stderr),
    );

    // Server-side confirmation: a fresh clone gets the blob back intact.
    run(&work_dir, "git", &["clone", &remote, "verify"]);
    let round_tripped = std::fs::read(work_dir.join("verify").join("big.bin"))
        .expect("the pushed blob is retrievable after a re-clone");
    assert_eq!(round_tripped.len(), 4 * 1024 * 1024);

    let _ = std::fs::remove_dir_all(&work_dir);
    let _ = std::fs::remove_dir_all(&store_root);
}

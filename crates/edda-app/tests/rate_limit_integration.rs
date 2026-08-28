//! Sustained-request-rate test against the public API: limits engage
//! correctly without false-positiving on legitimate git-over-HTTP clone
//! traffic. Two things proven together, against one real server:
//! rapid-fire requests against a rate-limited
//! `/api/v1/` endpoint eventually get a real `429 Too Many Requests`, and
//! a real `git clone` over HTTP — several of them, well past the request
//! count that tripped the limiter above — keeps succeeding throughout,
//! because the git smart-HTTP bridge is deliberately exempt
//! (`edda_app::rate_limit`'s own doc comment explains why).

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
        "edda-app-rate-limit-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sustained_requests_trip_the_limiter_but_never_a_real_git_clone() {
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
        // A deliberately tiny budget — this test only needs to *observe*
        // the limiter engaging, not exercise its production-sized default.
        config: edda_app::RuntimeConfig {
            rate_limit: edda_app::config::RateLimitConfig {
                per_second: 1,
                burst: 3,
            },
            ..Default::default()
        },
    };
    let addr = spawn_server(state).await;
    let base = format!("http://{addr}");
    let work_dir = temp_dir("work");
    std::fs::create_dir_all(&work_dir).expect("create work dir");

    // Give the repo real content — an empty repo's clone never issues the
    // upload-pack POST at all (nothing to want), which would leave half of
    // the git-over-HTTP protocol untested below.
    let alice_remote = format!("http://ci:{alice_token}@{addr}/alice/demo.git");
    run(&work_dir, "git", &["clone", &alice_remote, "seed-repo"]);
    let seed_repo_dir = work_dir.join("seed-repo");
    std::fs::write(seed_repo_dir.join("README.md"), b"# Demo\n").expect("write file");
    run(&seed_repo_dir, "git", &["add", "README.md"]);
    run(&seed_repo_dir, "git", &["commit", "-m", "seed commit"]);
    run(
        &seed_repo_dir,
        "git",
        &["push", "origin", "HEAD:refs/heads/main"],
    );

    // Sustained rapid-fire requests against a rate-limited `/api/v1/`
    // endpoint (public, no credentials needed — the limiter runs ahead of
    // any authorization check, keyed on the request itself). With a burst
    // of 3, replenishing one per second, the 4th request within the same
    // second must be rejected.
    let client = reqwest::Client::new();
    let mut saw_429 = false;
    for _ in 0..20 {
        let response = client
            .get(format!("{base}/api/v1/repos/alice/demo"))
            .send()
            .await
            .expect("send request");
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            break;
        }
    }
    assert!(
        saw_429,
        "expected the rate limiter to reject at least one of 20 rapid-fire \
         /api/v1/ requests given a burst size of 3"
    );

    // A real `git clone`, repeated well past that same burst size (each
    // clone issues at least two HTTP requests: `GET .../info/refs` and
    // `POST .../git-upload-pack`, so 6 clones is at least 12 requests,
    // four times the budget that just rejected `/api/v1/` traffic) must
    // still succeed every time — the git smart-HTTP bridge is exempt.
    for i in 0..6 {
        let dest = format!("clone-{i}");
        run(&work_dir, "git", &["clone", &alice_remote, &dest]);
        let log_output = Command::new("git")
            .args(["log", "-1", "--format=%s", "HEAD"])
            .current_dir(work_dir.join(&dest))
            .output()
            .expect("read cloned log");
        let summary = String::from_utf8_lossy(&log_output.stdout);
        assert!(
            summary.contains("seed commit"),
            "clone {i} did not land the seeded commit, got: {summary}"
        );
    }

    let _ = std::fs::remove_dir_all(&work_dir);
    let _ = std::fs::remove_dir_all(&store_root);
}

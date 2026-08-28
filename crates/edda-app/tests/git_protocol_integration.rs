//! Phase 7 protocol/tooling surface, end-to-end against the real
//! `edda_app::router` over HTTP with a real `git` CLI:
//!
//!   * a `git clone` negotiates `side-band-64k` (the server now advertises
//!     it) and the server's channel-2 progress line reaches the client as
//!     `remote:` output — no framing regression for a real client;
//!   * a lightweight tag pushed to the server is advertised (`ls-remote`
//!     lists `refs/tags/*`);
//!   * `GET /api/v1/repos/{o}/{r}/archive?format=zip` streams a valid zip;
//!   * `GET /api/v1/repos/{o}/{r}/blame?path=…` returns per-line blame.

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

fn git(cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_AUTHOR_NAME", "ci")
        .env("GIT_AUTHOR_EMAIL", "ci@example.com")
        .env("GIT_COMMITTER_NAME", "ci")
        .env("GIT_COMMITTER_EMAIL", "ci@example.com")
        .output()
        .unwrap_or_else(|err| panic!("failed to run git {args:?}: {err}"))
}

fn run(cwd: &Path, args: &[&str]) {
    let output = git(cwd, args);
    assert!(
        output.status.success(),
        "git {args:?} failed:\nstdout: {}\nstderr: {}",
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
        "edda-app-git-proto-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn commit_file(repo: &Path, name: &str, body: &str, message: &str) {
    std::fs::write(repo.join(name), body).expect("write file");
    run(repo, &["add", name]);
    run(repo, &["commit", "-m", message]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn side_band_progress_tags_archive_and_blame_all_work_end_to_end() {
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
    let (token, _) = tokens::create(&pool, alice_id, "ci")
        .await
        .expect("create token");

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
    let remote = format!("http://ci:{token}@{addr}/alice/demo.git");

    // Seed: two commits on `main`, plus a lightweight tag, all pushed.
    run(&work_dir, &["clone", &remote, "seed"]);
    let seed = work_dir.join("seed");
    commit_file(&seed, "a.txt", "one\ntwo\nthree\n", "first");
    run(&seed, &["push", "origin", "HEAD:refs/heads/main"]);
    commit_file(&seed, "a.txt", "one\nTWO\nthree\n", "second");
    run(&seed, &["push", "origin", "HEAD:refs/heads/main"]);
    run(&seed, &["tag", "v1"]);
    run(&seed, &["push", "origin", "v1"]);

    // The tag is advertised.
    let ls = git(&work_dir, &["ls-remote", "--tags", &remote]);
    assert!(
        String::from_utf8_lossy(&ls.stdout).contains("refs/tags/v1"),
        "server must advertise the pushed tag:\n{}",
        String::from_utf8_lossy(&ls.stdout)
    );

    // A fresh clone: real `git` negotiates side-band-64k, and the server's
    // channel-2 line surfaces as `remote:` output. `--progress` forces the
    // sideband messages to be shown even without a tty.
    let clone = git(&work_dir, &["clone", "--progress", &remote, "fresh"]);
    assert!(clone.status.success(), "clone failed");
    let clone_err = String::from_utf8_lossy(&clone.stderr);
    assert!(
        clone_err.contains("remote:"),
        "expected side-band `remote:` progress on clone, got:\n{clone_err}"
    );
    // The clone checked out the tag and both commits. (Normalize EOLs —
    // `git` on Windows checks out with CRLF by default.)
    let fresh = work_dir.join("fresh");
    assert_eq!(
        std::fs::read_to_string(fresh.join("a.txt"))
            .unwrap()
            .replace("\r\n", "\n"),
        "one\nTWO\nthree\n"
    );
    let tags = git(&fresh, &["tag", "--list"]);
    assert!(String::from_utf8_lossy(&tags.stdout).contains("v1"));

    // The `/api/v1` archive route streams a valid zip.
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");
    let archive = client
        .get(format!("{base}/api/v1/repos/alice/demo/archive"))
        .query(&[("format", "zip"), ("rev", "main")])
        .send()
        .await
        .expect("archive request");
    assert_eq!(archive.status(), reqwest::StatusCode::OK);
    assert_eq!(
        archive
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/zip")
    );
    let zip = archive.bytes().await.expect("archive bytes");
    assert_eq!(&zip[..2], b"PK", "zip magic");

    // The `/api/v1` blame route attributes line 2 to the second commit.
    let blame: serde_json::Value = client
        .get(format!("{base}/api/v1/repos/alice/demo/blame"))
        .query(&[("path", "a.txt")])
        .send()
        .await
        .expect("blame request")
        .json()
        .await
        .expect("blame json");
    let lines = blame["lines"].as_array().expect("lines array");
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[1].as_str(), Some("TWO"));
    let hunks = blame["hunks"].as_array().expect("hunks array");
    let total: u64 = hunks
        .iter()
        .map(|h| h["line_count"].as_u64().unwrap_or(0))
        .sum();
    assert_eq!(total, 3, "hunks cover every line exactly once");

    let _ = std::fs::remove_dir_all(&work_dir);
    let _ = std::fs::remove_dir_all(&store_root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_depth_one_clone_gets_a_shallow_repository() {
    if !tool_available("git") {
        eprintln!("skipping: git not found on PATH");
        return;
    }

    let pool = edda_db::test_pool().await;
    let store_root = temp_dir("shallow-store");
    let store: Arc<dyn RepoStore> = Arc::new(LocalFsStore::new(store_root.clone()));
    let locks = Arc::new(LockRegistry::new());

    let alice_id = UserId::new();
    edda_db::UserRepo::insert(&pool, alice_id, "alice", "alice@example.com", "unused")
        .await
        .expect("insert alice");
    let (token, _) = tokens::create(&pool, alice_id, "ci")
        .await
        .expect("create token");

    edda_git::create_repo(store.as_ref(), &locks, "alice/deep")
        .await
        .expect("initialize bare repo");
    let repository = Repository {
        id: RepositoryId::new(),
        owner: RepositoryOwner::User(alice_id),
        name: "deep".to_string(),
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

    let work_dir = temp_dir("shallow-work");
    std::fs::create_dir_all(&work_dir).expect("create work dir");
    let remote = format!("http://ci:{token}@{addr}/alice/deep.git");

    // A four-commit history.
    run(&work_dir, &["clone", &remote, "seed"]);
    let seed = work_dir.join("seed");
    for n in 1..=4 {
        commit_file(
            &seed,
            "log.txt",
            &format!("entry {n}\n"),
            &format!("commit {n}"),
        );
    }
    run(&seed, &["push", "origin", "HEAD:refs/heads/main"]);

    // `--depth 1`: the clone succeeds, is marked shallow, and holds exactly
    // one commit. This exercises git's two-request stateless shallow dance
    // (a first request with no `done` learns the boundary; the second
    // fetches the pack).
    let clone = git(&work_dir, &["clone", "--depth", "1", &remote, "shallow"]);
    assert!(
        clone.status.success(),
        "shallow clone failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&clone.stdout),
        String::from_utf8_lossy(&clone.stderr),
    );
    let shallow = work_dir.join("shallow");
    assert!(
        shallow.join(".git/shallow").exists(),
        "a --depth clone must write .git/shallow"
    );
    let count = git(&shallow, &["rev-list", "--count", "HEAD"]);
    assert_eq!(
        String::from_utf8_lossy(&count.stdout).trim(),
        "1",
        "depth-1 clone should hold exactly one commit"
    );
    // The working tree is complete at that one commit.
    assert_eq!(
        std::fs::read_to_string(shallow.join("log.txt"))
            .unwrap()
            .replace("\r\n", "\n"),
        "entry 4\n"
    );
    // `git fsck` is happy with the shallow boundary.
    let fsck = git(&shallow, &["fsck", "--no-dangling"]);
    assert!(
        fsck.status.success(),
        "fsck on the shallow clone failed:\n{}",
        String::from_utf8_lossy(&fsck.stderr)
    );

    let _ = std::fs::remove_dir_all(&work_dir);
    let _ = std::fs::remove_dir_all(&store_root);
}

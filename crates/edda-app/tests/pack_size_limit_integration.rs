//! H1 (plan.local.md §2 / Phase 0 exit criteria, closed in Phase 6).
//!
//! Before Phase 6 the git smart-HTTP handlers took the request body as
//! `axum::body::Bytes`, so axum's ~2 MiB `DefaultBodyLimit` capped every
//! push and a larger pack was rejected as `RPC failed; HTTP 400` before
//! `edda-git` saw it. Phase 6 disables `DefaultBodyLimit` on the git
//! routes and enforces Edda's own `EDDA_GIT_MAX_PACK_BYTES` ceiling
//! (`git_http::read_body_capped`) instead.
//!
//! The first test pushes a deliberately-incompressible ~4 MiB blob and
//! asserts the push **succeeds** and the object is retrievable
//! server-side — the behaviour Phase 6 delivers by disabling axum's
//! `DefaultBodyLimit` on the git routes and enforcing Edda's own,
//! git-aware `EDDA_GIT_MAX_PACK_BYTES` ceiling instead.
//!
//! The second test sets that ceiling very low and confirms a push over it
//! is rejected with `413` and leaves the bare repo's object store
//! byte-identical to before (no ref created, no objects written).

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
        "edda-app-pack-size-it-{label}-{}-{}",
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

    // No `http.postBuffer` override here on purpose: at 4 MiB the pack
    // exceeds git's 1 MiB default `postBuffer`, so `git` streams it with a
    // chunked body and first sends a 4-byte RPC *probe* — exercising both
    // the disabled `DefaultBodyLimit` and the probe's benign-200 handling.
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

/// Names of the immediate children of a bare repo's `objects/` directory
/// that indicate real object data was written — anything other than the
/// always-present empty `info/` and `pack/` scaffolding.
fn object_store_contents(repo_git_dir: &Path) -> Vec<String> {
    let objects = repo_git_dir.join("objects");
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&objects) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            match name.as_str() {
                "info" => {}
                "pack" => {
                    if std::fs::read_dir(entry.path())
                        .map(|mut d| d.next().is_some())
                        .unwrap_or(false)
                    {
                        found.push("pack/*".to_string());
                    }
                }
                _ => found.push(name),
            }
        }
    }
    found.sort();
    found
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_over_the_configured_pack_ceiling_is_rejected_and_writes_nothing() {
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

    let repo_git_dir = LocalFsStore::new(store_root.clone()).repo_dir("alice/demo");
    let before = object_store_contents(&repo_git_dir);

    // A 256 KiB ceiling — well under the ~1 MiB incompressible blob below.
    let state = AppState {
        pool: pool.clone(),
        store,
        locks,
        authz: AuthorizationService::new(pool.clone()),
        backend: Backend::new(pool.clone()),
        config: edda_app::RuntimeConfig {
            git_limits: edda_app::config::GitLimits {
                max_pack_bytes: 256 * 1024,
                max_lfs_object_bytes: 4 * 1024 * 1024 * 1024,
                max_repo_size_bytes: None,
                max_user_repos: None,
            },
            ..Default::default()
        },
    };
    let addr = spawn_server(state).await;

    let work_dir = temp_dir("work");
    std::fs::create_dir_all(&work_dir).expect("create work dir");
    let remote = format!("http://ci:{alice_token}@{addr}/alice/demo.git");

    run(&work_dir, "git", &["clone", &remote, "repo"]);
    let repo_dir = work_dir.join("repo");
    std::fs::write(repo_dir.join("big.bin"), incompressible_bytes(1024 * 1024))
        .expect("write the large blob");
    run(&repo_dir, "git", &["add", "big.bin"]);
    run(&repo_dir, "git", &["commit", "-m", "over the ceiling"]);

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
        !push.status.success(),
        "a push whose pack exceeds EDDA_GIT_MAX_PACK_BYTES must be rejected:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&push.stdout),
        String::from_utf8_lossy(&push.stderr),
    );

    // The server advertises no branch, and its object store is byte-for-byte
    // what `git init --bare` left — nothing from the rejected push leaked in.
    let ls_remote = Command::new("git")
        .args(["ls-remote", &remote])
        .output()
        .expect("run git ls-remote");
    assert!(
        String::from_utf8_lossy(&ls_remote.stdout).trim().is_empty(),
        "the rejected push must not have created any ref: {}",
        String::from_utf8_lossy(&ls_remote.stdout),
    );
    assert_eq!(
        object_store_contents(&repo_git_dir),
        before,
        "the rejected push must leave the object store byte-identical"
    );

    let _ = std::fs::remove_dir_all(&work_dir);
    let _ = std::fs::remove_dir_all(&store_root);
}

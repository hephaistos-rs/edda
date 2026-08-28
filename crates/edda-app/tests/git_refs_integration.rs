//! Integration test for Phase 6's ref layer: after `git pack-refs --all`
//! collapses a repo's loose refs into `packed-refs`, the server's
//! compare-and-swap must still read the *effective* ref value (H6). The
//! old hand-rolled `apply_ref_update` read `refs/heads/<b>` as a plain
//! file, so a packed ref looked like `0000…` — every fast-forward push
//! was then wrongly rejected, and a create-shaped push silently
//! overwrote history.
//!
//! Drives a real `git` CLI over the real `edda_app::router` HTTP path,
//! and asserts, all *after* `pack-refs`:
//!   * a fast-forward push still succeeds,
//!   * a non-fast-forward push is still rejected (CAS against the packed
//!     value),
//!   * a branch create and a branch delete both work,
//!   * a reflog entry exists on the server for the updated branch.

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
        "edda-app-git-refs-it-{label}-{}-{}",
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

fn remote_branch_tip(work_dir: &Path, remote: &str, branch: &str) -> Option<String> {
    let out = git(
        work_dir,
        &["ls-remote", remote, &format!("refs/heads/{branch}")],
    );
    let text = String::from_utf8_lossy(&out.stdout);
    text.split_whitespace().next().map(str::to_string)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packed_refs_do_not_break_compare_and_swap() {
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

    let bare_dir = LocalFsStore::new(store_root.clone()).repo_dir("alice/demo");

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

    // Seed: commit A on `main`, plus a `feature` branch, then push both.
    run(&work_dir, &["clone", &remote, "seed"]);
    let seed = work_dir.join("seed");
    commit_file(&seed, "a.txt", "A\n", "A");
    run(&seed, &["push", "origin", "HEAD:refs/heads/main"]);
    run(&seed, &["branch", "feature"]);
    run(&seed, &["push", "origin", "feature"]);
    // Fast-forward commit B on `main`.
    commit_file(&seed, "b.txt", "B\n", "B");
    run(&seed, &["push", "origin", "HEAD:refs/heads/main"]);
    let tip_b = remote_branch_tip(&work_dir, &remote, "main").expect("main has a tip");

    // A second clone taken now — its idea of `main` (B) is about to go
    // stale, which is what the server-side CAS check exists to catch.
    run(&work_dir, &["clone", &remote, "stale"]);
    let stale = work_dir.join("stale");

    // Collapse every loose ref into packed-refs — the exact operation the
    // old CAS was blind to (it read `refs/heads/main` as a plain file and
    // saw `0000…` once the file was gone).
    run(&bare_dir, &["pack-refs", "--all"]);
    assert!(
        !bare_dir.join("refs/heads/main").exists(),
        "pack-refs should have removed the loose ref file"
    );

    // (1) A fast-forward push AFTER pack-refs still succeeds — the server
    // now has to read the packed value to accept it.
    let ff = work_dir.join("ff");
    run(&work_dir, &["clone", &remote, "ff"]);
    commit_file(&ff, "c.txt", "C\n", "C (fast-forward)");
    run(&ff, &["push", "origin", "HEAD:refs/heads/main"]);
    let tip_c = remote_branch_tip(&work_dir, &remote, "main").expect("main advanced");
    assert_ne!(tip_c, tip_b, "the fast-forward push should have moved main");

    // (2) The stale clone tries a push that is a fast-forward *from its own
    // view* (child of B) but stale on the server (now at C). The server's
    // compare-and-swap must reject it, and `main` must not move.
    commit_file(&stale, "stale.txt", "stale\n", "X (stale fast-forward)");
    let push = git(&stale, &["push", "origin", "HEAD:refs/heads/main"]);
    assert!(
        !push.status.success(),
        "a stale (server-side non-fast-forward) push must be rejected:\n{}",
        String::from_utf8_lossy(&push.stderr)
    );
    assert_eq!(
        remote_branch_tip(&work_dir, &remote, "main").as_deref(),
        Some(tip_c.as_str()),
        "the rejected push must not have moved main"
    );

    // (3) Create a brand-new branch after pack-refs.
    run(&ff, &["push", "origin", "HEAD:refs/heads/topic"]);
    assert!(
        remote_branch_tip(&work_dir, &remote, "topic").is_some(),
        "the new branch should exist on the server"
    );

    // (4) Delete the packed `feature` branch.
    run(&ff, &["push", "origin", ":refs/heads/feature"]);
    assert!(
        remote_branch_tip(&work_dir, &remote, "feature").is_none(),
        "the deleted branch should be gone"
    );

    // (5) A reflog was written for `main` on the server.
    let reflog = std::fs::read_to_string(bare_dir.join("logs/refs/heads/main"))
        .expect("a reflog for main exists on the server");
    assert!(
        reflog.lines().count() >= 2,
        "expected multiple reflog entries for main, got:\n{reflog}"
    );

    let _ = std::fs::remove_dir_all(&work_dir);
    let _ = std::fs::remove_dir_all(&store_root);
}

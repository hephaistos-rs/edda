//! Phase 6 exit-criteria test: "a branch-protection rule with
//! `required_approvals: 1` actually blocks a direct push to the
//! protected branch by a non-admin collaborator (verified by an
//! integration test attempting exactly that push and asserting
//! rejection)." Exercises the real git-over-HTTP push path (`edda_http::
//! router`) against a real `git` CLI, the same "test against the real
//! client" approach `lfs_integration.rs` already established — branch
//! protection is enforced inside `edda_git::protocol::apply_receive_pack`
//! itself, so this has to go through a real `git push`, not a direct
//! function call, to prove the wire-level rejection actually reaches the
//! client.

use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use edda_auth::{tokens, AuthorizationService, Backend};
use edda_db::{BranchProtectionRepo, RepoAccessRepo, RepositoryRepo};
use edda_domain::{
    AccessSubject, BranchProtectionRuleId, RepoRole, Repository, RepositoryId, RepositoryOwner,
    UserId, Visibility,
};
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

/// Same reasoning as `lfs_integration.rs`'s identical helper: a session/
/// auth layer is needed for the `AuthSession<Backend>` extractor to
/// resolve at all, even though this test only ever uses PAT auth.
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
        "edda-http-branch-protection-it-{label}-{}-{}",
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
async fn a_protected_branch_rejects_a_direct_push_from_a_non_admin_collaborator() {
    if !tool_available("git") {
        eprintln!("skipping: git not found on PATH");
        return;
    }

    let pool = edda_db::test_pool().await;
    let store_root = temp_dir("store");
    let store: Arc<dyn RepoStore> = Arc::new(LocalFsStore::new(store_root.clone()));
    let locks = Arc::new(LockRegistry::new());

    // Alice owns the repo (Admin+, exempt from the direct-push block);
    // Bob is a Write-level collaborator (not exempt).
    let alice_id = UserId::new();
    edda_db::UserRepo::insert(&pool, alice_id, "alice", "alice@example.com", "unused")
        .await
        .expect("insert alice");
    let (alice_token, _) = tokens::create(&pool, alice_id, "ci")
        .await
        .expect("create alice token");

    let bob_id = UserId::new();
    edda_db::UserRepo::insert(&pool, bob_id, "bob", "bob@example.com", "unused")
        .await
        .expect("insert bob");
    let (bob_token, _) = tokens::create(&pool, bob_id, "ci")
        .await
        .expect("create bob token");

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
    RepoAccessRepo::grant(
        &pool,
        repository.id,
        AccessSubject::User(bob_id),
        RepoRole::Write,
    )
    .await
    .expect("grant bob write access");

    // Protect `main`, requiring 1 approval — its mere existence is what
    // blocks a direct push (see `edda_domain::branch_protection`'s
    // module doc comment).
    BranchProtectionRepo::insert(
        &pool,
        BranchProtectionRuleId::new(),
        repository.id,
        "main",
        1,
    )
    .await
    .expect("insert branch protection rule");

    let state = AppState {
        pool: pool.clone(),
        store,
        locks,
        authz: AuthorizationService::new(pool.clone()),
        backend: Backend::new(pool.clone()),
    };
    let addr = spawn_server(state).await;

    let work_dir = temp_dir("work");
    std::fs::create_dir_all(&work_dir).expect("create work dir");

    // Alice (owner/admin) can push `main` directly despite the rule.
    let alice_remote = format!("http://ci:{alice_token}@{addr}/alice/demo.git");
    run(&work_dir, "git", &["clone", &alice_remote, "alice-repo"]);
    let alice_repo_dir = work_dir.join("alice-repo");
    std::fs::write(alice_repo_dir.join("README.md"), b"# Demo\n").expect("write file");
    run(&alice_repo_dir, "git", &["add", "README.md"]);
    run(&alice_repo_dir, "git", &["commit", "-m", "initial commit"]);
    run(
        &alice_repo_dir,
        "git",
        &["push", "origin", "HEAD:refs/heads/main"],
    );

    // Bob (Write, non-admin) cannot — the push must fail, and `main`
    // must still point at alice's commit afterward.
    let bob_remote = format!("http://ci:{bob_token}@{addr}/alice/demo.git");
    run(&work_dir, "git", &["clone", &bob_remote, "bob-repo"]);
    let bob_repo_dir = work_dir.join("bob-repo");
    std::fs::write(bob_repo_dir.join("bob.txt"), b"bob was here\n").expect("write file");
    run(&bob_repo_dir, "git", &["add", "bob.txt"]);
    run(
        &bob_repo_dir,
        "git",
        &["commit", "-m", "sneak in a direct push"],
    );

    let push_output = Command::new("git")
        .args(["push", "origin", "HEAD:refs/heads/main"])
        .current_dir(&bob_repo_dir)
        .env("GIT_AUTHOR_NAME", "ci")
        .env("GIT_AUTHOR_EMAIL", "ci@example.com")
        .env("GIT_COMMITTER_NAME", "ci")
        .env("GIT_COMMITTER_EMAIL", "ci@example.com")
        .output()
        .expect("run git push");
    assert!(
        !push_output.status.success(),
        "bob's direct push to the protected branch should have been rejected, but succeeded"
    );
    let stderr = String::from_utf8_lossy(&push_output.stderr);
    assert!(
        stderr.contains("protected")
            || stderr.contains("rejected")
            || stderr.contains("[remote rejected]"),
        "expected a protected-branch rejection message, got: {stderr}"
    );

    // Confirm at the git level, not just the client's exit code: `main`
    // still points at alice's commit, not bob's.
    run(&work_dir, "git", &["clone", &alice_remote, "verify-repo"]);
    let log_output = Command::new("git")
        .args(["log", "-1", "--format=%s", "origin/main"])
        .current_dir(work_dir.join("verify-repo"))
        .output()
        .expect("read remote log");
    let last_summary = String::from_utf8_lossy(&log_output.stdout);
    assert!(
        last_summary.contains("initial commit"),
        "expected `main` to still be alice's commit, got: {last_summary}"
    );

    let _ = std::fs::remove_dir_all(&work_dir);
    let _ = std::fs::remove_dir_all(&store_root);
}

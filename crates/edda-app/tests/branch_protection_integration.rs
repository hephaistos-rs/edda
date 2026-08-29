//! Integration test: a branch-protection rule with `required_approvals: 1`
//! blocks a direct push to the protected branch by a non-admin
//! collaborator. Exercises the real git-over-HTTP push path
//! (`edda_app::router`) against a real `git` CLI, the same "test against
//! the real client" approach `lfs_integration.rs` uses — branch
//! protection is enforced inside `edda_git::protocol::apply_receive_pack`
//! itself, so this has to go through a real `git push`, not a direct
//! function call, to prove the wire-level rejection actually reaches the
//! client.

use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use edda_app::{router, AppState};
use edda_auth::{tokens, AuthorizationService, Backend};
use edda_db::{BranchProtectionRepo, RepoAccessRepo, RepositoryRepo};
use edda_domain::{
    AccessSubject, BranchProtectionRuleId, RepoRole, Repository, RepositoryId, RepositoryOwner,
    UserId, Visibility,
};
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
        "edda-app-branch-protection-it-{label}-{}-{}",
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
    BranchProtectionRepo::upsert_by_pattern(
        &pool,
        BranchProtectionRuleId::new(),
        repository.id,
        "main",
        &edda_db::BranchProtectionSettings {
            required_approvals: 1,
            ..Default::default()
        },
    )
    .await
    .expect("insert branch protection rule");

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

/// A glob pattern (`release/*`) blocks a non-allowlisted collaborator's
/// direct push to any matched branch; adding them to the rule's push
/// allowlist lets the same push through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_glob_pattern_blocks_matched_branches_unless_the_pusher_is_allowlisted() {
    if !tool_available("git") {
        eprintln!("skipping: git not found on PATH");
        return;
    }

    let pool = edda_db::test_pool().await;
    let store_root = temp_dir("glob-store");
    let store: Arc<dyn RepoStore> = Arc::new(LocalFsStore::new(store_root.clone()));
    let locks = Arc::new(LockRegistry::new());

    let alice_id = UserId::new();
    edda_db::UserRepo::insert(&pool, alice_id, "alice", "alice@example.com", "unused")
        .await
        .unwrap();
    let (alice_token, _) = tokens::create(&pool, alice_id, "ci").await.unwrap();
    let bob_id = UserId::new();
    edda_db::UserRepo::insert(&pool, bob_id, "bob", "bob@example.com", "unused")
        .await
        .unwrap();
    let (bob_token, _) = tokens::create(&pool, bob_id, "ci").await.unwrap();

    edda_git::create_repo(store.as_ref(), &locks, "alice/demo")
        .await
        .unwrap();
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
        .unwrap();
    RepoAccessRepo::grant(
        &pool,
        repository.id,
        AccessSubject::User(bob_id),
        RepoRole::Write,
    )
    .await
    .unwrap();

    let rule_id = BranchProtectionRepo::upsert_by_pattern(
        &pool,
        BranchProtectionRuleId::new(),
        repository.id,
        "release/*",
        &edda_db::BranchProtectionSettings::default(),
    )
    .await
    .unwrap();

    let state = AppState {
        pool: pool.clone(),
        store,
        locks,
        authz: AuthorizationService::new(pool.clone()),
        backend: Backend::new(pool.clone()),
        config: Default::default(),
    };
    let addr = spawn_server(state).await;

    let work_dir = temp_dir("glob-work");
    std::fs::create_dir_all(&work_dir).unwrap();

    // Alice seeds `main`.
    let alice_remote = format!("http://ci:{alice_token}@{addr}/alice/demo.git");
    run(&work_dir, "git", &["clone", &alice_remote, "alice-repo"]);
    let alice_repo_dir = work_dir.join("alice-repo");
    std::fs::write(alice_repo_dir.join("README.md"), b"# Demo\n").unwrap();
    run(&alice_repo_dir, "git", &["add", "README.md"]);
    run(&alice_repo_dir, "git", &["commit", "-m", "initial commit"]);
    run(
        &alice_repo_dir,
        "git",
        &["push", "origin", "HEAD:refs/heads/main"],
    );

    // Bob (Write) tries to push a branch matching `release/*` — rejected.
    let bob_remote = format!("http://ci:{bob_token}@{addr}/alice/demo.git");
    run(&work_dir, "git", &["clone", &bob_remote, "bob-repo"]);
    let bob_repo_dir = work_dir.join("bob-repo");
    std::fs::write(bob_repo_dir.join("r.txt"), b"cut a release\n").unwrap();
    run(&bob_repo_dir, "git", &["add", "r.txt"]);
    run(&bob_repo_dir, "git", &["commit", "-m", "release prep"]);

    let blocked = Command::new("git")
        .args(["push", "origin", "HEAD:refs/heads/release/2.0"])
        .current_dir(&bob_repo_dir)
        .output()
        .unwrap();
    assert!(
        !blocked.status.success(),
        "bob's push to release/2.0 should be blocked by the release/* rule"
    );

    // Allowlist bob on the rule — now the same push lands.
    BranchProtectionRepo::replace_allowlist(&pool, rule_id, &[AccessSubject::User(bob_id)])
        .await
        .unwrap();
    run(
        &bob_repo_dir,
        "git",
        &["push", "origin", "HEAD:refs/heads/release/2.0"],
    );

    let _ = std::fs::remove_dir_all(&work_dir);
    let _ = std::fs::remove_dir_all(&store_root);
}

/// A push that would take the repository past `EDDA_MAX_REPO_SIZE_BYTES`
/// is rejected by the receive hook with a size-limit message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_over_the_repository_size_quota_is_rejected() {
    if !tool_available("git") {
        eprintln!("skipping: git not found on PATH");
        return;
    }

    let pool = edda_db::test_pool().await;
    let store_root = temp_dir("quota-store");
    let store: Arc<dyn RepoStore> = Arc::new(LocalFsStore::new(store_root.clone()));
    let locks = Arc::new(LockRegistry::new());

    let alice_id = UserId::new();
    edda_db::UserRepo::insert(&pool, alice_id, "alice", "alice@example.com", "unused")
        .await
        .unwrap();
    let (alice_token, _) = tokens::create(&pool, alice_id, "ci").await.unwrap();

    edda_git::create_repo(store.as_ref(), &locks, "alice/demo")
        .await
        .unwrap();
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
        .unwrap();
    // The repo is already recorded as sitting on the limit.
    edda_db::RepoSizeRepo::upsert(&pool, repository.id, 4_096, 0)
        .await
        .unwrap();

    let config = edda_app::RuntimeConfig {
        git_limits: edda_app::config::GitLimits {
            max_repo_size_bytes: Some(4_096),
            ..Default::default()
        },
        ..Default::default()
    };
    let state = AppState {
        pool: pool.clone(),
        store,
        locks,
        authz: AuthorizationService::new(pool.clone()),
        backend: Backend::new(pool.clone()),
        config,
    };
    let addr = spawn_server(state).await;

    let work_dir = temp_dir("quota-work");
    std::fs::create_dir_all(&work_dir).unwrap();
    let remote = format!("http://ci:{alice_token}@{addr}/alice/demo.git");
    run(&work_dir, "git", &["clone", &remote, "repo"]);
    let repo_dir = work_dir.join("repo");
    std::fs::write(repo_dir.join("big.txt"), vec![b'x'; 8_192]).unwrap();
    run(&repo_dir, "git", &["add", "big.txt"]);
    run(&repo_dir, "git", &["commit", "-m", "over the quota"]);

    let push = Command::new("git")
        .args(["push", "origin", "HEAD:refs/heads/main"])
        .current_dir(&repo_dir)
        .output()
        .unwrap();
    assert!(
        !push.status.success(),
        "a push past the size quota should be rejected"
    );
    let stderr = String::from_utf8_lossy(&push.stderr);
    assert!(
        stderr.contains("limit") || stderr.contains("rejected"),
        "expected a size-limit rejection, got: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&work_dir);
    let _ = std::fs::remove_dir_all(&store_root);
}

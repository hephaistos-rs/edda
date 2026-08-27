//! Integration test: a team with `Write` on the `Code` unit grants its
//! members push access to every repo the team is attached to — verified
//! with a team-member identity that has no *direct* `RepoAccess` grant.
//! Exercises the real git-over-HTTP push path (`edda_http::router`)
//! against a real `git` CLI, the same approach
//! `branch_protection_integration.rs` uses — proving the authorization
//! decision is reachable end-to-end, not just correct in isolation at the
//! `AuthorizationService` layer.

use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use edda_auth::{tokens, AuthorizationService, Backend};
use edda_db::{OrganizationRepo, RepoAccessRepo, RepositoryRepo, TeamMemberRepo, TeamRepo};
use edda_domain::{
    AccessSubject, OrganizationId, RepoRole, Repository, RepositoryId, RepositoryOwner, TeamId,
    TeamPermission, TeamUnit, UserId, Visibility,
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
        "edda-http-org-team-it-{label}-{}-{}",
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
async fn a_team_members_push_access_comes_from_team_attachment_alone() {
    if !tool_available("git") {
        eprintln!("skipping: git not found on PATH");
        return;
    }

    let pool = edda_db::test_pool().await;
    let store_root = temp_dir("store");
    let store: Arc<dyn RepoStore> = Arc::new(LocalFsStore::new(store_root.clone()));
    let locks = Arc::new(LockRegistry::new());

    // Alice creates the organization and the repository — she is the
    // Owners team's sole member so far.
    let alice_id = UserId::new();
    edda_db::UserRepo::insert(&pool, alice_id, "alice", "alice@example.com", "unused")
        .await
        .expect("insert alice");

    // Bob is a member of "developers", a non-Owners team with Write on the
    // Code unit — and holds no direct `RepoAccess` grant of his own on
    // this repository at any point in this test.
    let bob_id = UserId::new();
    edda_db::UserRepo::insert(&pool, bob_id, "bob", "bob@example.com", "unused")
        .await
        .expect("insert bob");
    let (bob_token, _) = tokens::create(&pool, bob_id, "ci")
        .await
        .expect("create bob token");

    // Carol belongs to the organization's Owners team (through no
    // developers-team membership) — used as the negative control: an org
    // member who isn't on the attached team must still be rejected.
    let carol_id = UserId::new();
    edda_db::UserRepo::insert(&pool, carol_id, "carol", "carol@example.com", "unused")
        .await
        .expect("insert carol");
    let (carol_token, _) = tokens::create(&pool, carol_id, "ci")
        .await
        .expect("create carol token");

    let org_id = OrganizationId::new();
    let owners_team_id = OrganizationRepo::insert(&pool, org_id, "acme", None, alice_id)
        .await
        .expect("create organization");

    let developers_team_id = TeamId::new();
    TeamRepo::insert(
        &pool,
        developers_team_id,
        org_id,
        "developers",
        TeamPermission::Write,
    )
    .await
    .expect("create developers team");
    TeamMemberRepo::add(&pool, developers_team_id, bob_id)
        .await
        .expect("add bob to developers");
    // Carol belongs to the organization (a member of its Owners team) but
    // not to developers, and the Owners team is never attached to this
    // repository — organization membership alone must not imply access.
    TeamMemberRepo::add(&pool, owners_team_id, carol_id)
        .await
        .expect("add carol to the org's Owners team, but not developers");

    let developers_team = TeamRepo::find_by_id(&pool, developers_team_id)
        .await
        .expect("look up developers team")
        .expect("developers team exists");
    let code_override = TeamRepo::find_unit_permission(&pool, developers_team_id, TeamUnit::Code)
        .await
        .expect("look up code unit override");
    let attached_role = developers_team
        .code_role(code_override)
        .expect("developers team has Code access configured");
    assert_eq!(attached_role, RepoRole::Write);

    edda_git::create_repo(store.as_ref(), &locks, "alice/widgets")
        .await
        .expect("initialize bare repo");
    let repository = Repository {
        id: RepositoryId::new(),
        owner: RepositoryOwner::User(alice_id),
        name: "widgets".to_string(),
        description: None,
        visibility: Visibility::Public,
        forked_from: None,
    };
    RepositoryRepo::insert_with_owner(&pool, &repository, alice_id)
        .await
        .expect("insert repository row");

    // The attachment itself: the developers team is granted the role its
    // Code-unit permission currently resolves to.
    RepoAccessRepo::grant(
        &pool,
        repository.id,
        AccessSubject::Team(developers_team_id),
        attached_role,
    )
    .await
    .expect("attach developers team to the repository");

    // Confirm, at the persistence layer, that neither bob nor carol has a
    // direct grant on this repository — their only path to any access is
    // through team membership.
    assert!(
        RepoAccessRepo::find(&pool, repository.id, AccessSubject::User(bob_id))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        RepoAccessRepo::find(&pool, repository.id, AccessSubject::User(carol_id))
            .await
            .unwrap()
            .is_none()
    );

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

    // Bob — a developers-team member with no direct grant — can clone and
    // push.
    let bob_remote = format!("http://ci:{bob_token}@{addr}/alice/widgets.git");
    run(&work_dir, "git", &["clone", &bob_remote, "bob-repo"]);
    let bob_repo_dir = work_dir.join("bob-repo");
    std::fs::write(bob_repo_dir.join("bob.txt"), b"bob was here\n").expect("write file");
    run(&bob_repo_dir, "git", &["add", "bob.txt"]);
    run(
        &bob_repo_dir,
        "git",
        &["commit", "-m", "bob pushes via his team"],
    );
    run(
        &bob_repo_dir,
        "git",
        &["push", "origin", "HEAD:refs/heads/main"],
    );

    // Carol — same organization, but not a member of the attached team —
    // still cannot push. This is the negative control proving the grant
    // really is team-scoped, not organization-wide.
    let carol_remote = format!("http://ci:{carol_token}@{addr}/alice/widgets.git");
    run(&work_dir, "git", &["clone", &carol_remote, "carol-repo"]);
    let carol_repo_dir = work_dir.join("carol-repo");
    std::fs::write(carol_repo_dir.join("carol.txt"), b"carol was here\n").expect("write file");
    run(&carol_repo_dir, "git", &["add", "carol.txt"]);
    run(
        &carol_repo_dir,
        "git",
        &["commit", "-m", "carol tries to push without team access"],
    );
    let carol_push = Command::new("git")
        .args(["push", "origin", "HEAD:refs/heads/main"])
        .current_dir(&carol_repo_dir)
        .env("GIT_AUTHOR_NAME", "ci")
        .env("GIT_AUTHOR_EMAIL", "ci@example.com")
        .env("GIT_COMMITTER_NAME", "ci")
        .env("GIT_COMMITTER_EMAIL", "ci@example.com")
        .output()
        .expect("run git push");
    assert!(
        !carol_push.status.success(),
        "carol's push should have been rejected — she isn't a member of the attached team"
    );

    // Confirm at the git level that bob's push actually landed.
    let log_output = Command::new("git")
        .args(["log", "-1", "--format=%s", "HEAD"])
        .current_dir(&bob_repo_dir)
        .output()
        .expect("read local log");
    let last_summary = String::from_utf8_lossy(&log_output.stdout);
    assert!(
        last_summary.contains("bob pushes via his team"),
        "expected bob's commit to be HEAD locally, got: {last_summary}"
    );

    let _ = std::fs::remove_dir_all(&work_dir);
    let _ = std::fs::remove_dir_all(&store_root);
}

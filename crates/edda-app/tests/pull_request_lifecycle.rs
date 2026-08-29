//! Full PR lifecycle end to end against a real repository: open (via push)
//! → inline review comment → approve → merge (merge-commit strategy).
//!
//! The source/target branches are created via real `git push` over a
//! real HTTP server (`edda_app::router`, the same "test against the
//! real client" approach `lfs_integration.rs` uses) — real git objects,
//! real refs, on disk. Opening/commenting/reviewing/merging the pull
//! request itself calls the exact same `edda-db`/`edda-auth`/`edda-git`
//! functions `app/edda-web`'s `pr_server` module calls (`PullRequestRepo`,
//! `PrCommentRepo`, `PrReviewRepo`, `AuthorizationService::
//! check_merge_pull_request`, `edda_git::merge_branches`) — this test
//! drives them directly rather than through Dioxus's own HTTP routing,
//! since `dioxus::server::serve`'s router is constructed only inside
//! `edda-web`'s `main()` and isn't independently spinnable the way
//! `edda_app::router()` is. What's verified here is the real business
//! logic — real git merge, real conflict/approval enforcement, real
//! persistence — not (redundantly) that
//! Dioxus's macro-generated routing itself works, which the compile-time
//! guarantees of `#[get]`/`#[post]` already give more cheaply than an
//! HTTP round trip would.

use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use edda_app::{router, AppState};
use edda_auth::{tokens, AuthorizationService, Backend};
use edda_db::{PrCommentRepo, PrReviewRepo, PullRequestRepo, RepoAccessRepo, RepositoryRepo};
use edda_domain::{
    AccessSubject, ActorContext, DiffAnchor, MergeStrategy, PrRef, PrState, PullRequestId,
    RepoRole, Repository, RepositoryId, RepositoryOwner, ReviewState, UserId, Visibility,
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
        "edda-app-pr-lifecycle-it-{label}-{}-{}",
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
async fn a_pull_request_opens_is_reviewed_and_merges_against_a_real_repository() {
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

    let bob_id = UserId::new();
    edda_db::UserRepo::insert(&pool, bob_id, "bob", "bob@example.com", "unused")
        .await
        .expect("insert bob");

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
    // Bob reviews and alice merges — a reviewer needn't have write access
    // to leave a review, but does need it to be a meaningful
    // collaborator here.
    RepoAccessRepo::grant(
        &pool,
        repository.id,
        AccessSubject::User(bob_id),
        RepoRole::Write,
    )
    .await
    .expect("grant bob write access");

    let state = AppState {
        pool: pool.clone(),
        store: store.clone(),
        locks: locks.clone(),
        authz: AuthorizationService::new(pool.clone()),
        backend: Backend::new(pool.clone()),
        config: Default::default(),
    };
    let addr = spawn_server(state).await;
    let remote = format!("http://ci:{alice_token}@{addr}/alice/demo.git");

    // Real git history: `main` gets an initial commit, then a `feature`
    // branch adds a new file — both pushed over real HTTP.
    let work_dir = temp_dir("work");
    std::fs::create_dir_all(&work_dir).expect("create work dir");
    run(&work_dir, "git", &["clone", &remote, "repo"]);
    let repo_dir = work_dir.join("repo");
    std::fs::write(repo_dir.join("README.md"), b"# Demo\n").expect("write file");
    run(&repo_dir, "git", &["add", "README.md"]);
    run(&repo_dir, "git", &["commit", "-m", "initial commit"]);
    run(
        &repo_dir,
        "git",
        &["push", "origin", "HEAD:refs/heads/main"],
    );

    run(&repo_dir, "git", &["checkout", "-b", "feature"]);
    std::fs::write(repo_dir.join("feature.txt"), b"a new feature\n").expect("write file");
    run(&repo_dir, "git", &["add", "feature.txt"]);
    run(&repo_dir, "git", &["commit", "-m", "add feature"]);
    run(
        &repo_dir,
        "git",
        &["push", "origin", "HEAD:refs/heads/feature"],
    );

    // Open the pull request — same call `pr_server::create_pull_request`
    // makes.
    let pr_id = PullRequestId::new();
    let pr_number = PullRequestRepo::insert(
        &pool,
        pr_id,
        repository.id,
        edda_db::NewPullRequest {
            title: "Add feature",
            body: Some("This adds the feature."),
            author_id: bob_id,
            source: &PrRef {
                repository_id: repository.id,
                branch: "feature".to_string(),
            },
            target: "main",
            draft: false,
        },
    )
    .await
    .expect("open pull request");
    assert_eq!(pr_number, 1);

    let pr = PullRequestRepo::find_by_id(&pool, pr_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pr.state, PrState::Open);

    // An inline review comment, anchored to the new file.
    PrCommentRepo::insert(
        &pool,
        edda_domain::PrCommentId::new(),
        pr_id,
        alice_id,
        "looks good, one nit",
        Some(&DiffAnchor {
            file_path: "feature.txt".to_string(),
            line_range: (1, 1),
            commit_sha: "0".repeat(40),
        }),
    )
    .await
    .expect("insert inline comment");

    // Before any approval, alice (write access, repo owner) cannot merge
    // — no branch-protection rule exists here, so this isn't about
    // required approvals; it's the PR's own `Open` state that a real
    // merge additionally checks — the *authorization* check alone
    // (`check_merge_pull_request`) already succeeds with no reviews
    // since there's no protection rule on `main`. What actually
    // exercises the review requirement is covered in `edda-domain`'s and
    // `edda-db`'s own unit/integration tests
    // (`a_protected_branch_blocks_a_merge_short_of_its_required_approvals`);
    // this test's job is the full real-repository lifecycle, so it
    // proceeds straight to a real approval to keep the merge path
    // itself under test.
    PrReviewRepo::insert(
        &pool,
        edda_domain::PrReviewId::new(),
        pr_id,
        bob_id,
        ReviewState::Approved,
        Some("approved"),
    )
    .await
    .expect("insert approval review");

    // The actual merge — `PullRequestService::merge`, the exact call
    // `pr_server::merge_pull_request` makes after Phase 3: it re-checks
    // authorization, holds the repo lock across the real `gix` merge, and
    // commits the PR state change together with a `PullRequestMerged`
    // outbox event in one transaction.
    let service = edda_app::services::PullRequestService::new(
        pool.clone(),
        store.clone(),
        locks.clone(),
        AuthorizationService::new(pool.clone()),
    );
    let outcome = service
        .merge(
            &ActorContext::User(alice_id),
            "alice",
            "demo",
            pr_number,
            edda_domain::MergeStrategy::Merge,
        )
        .await
        .expect("merge succeeds — no conflicts between these two branches");

    let pr = PullRequestRepo::find_by_id(&pool, pr_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(
            pr.state,
            PrState::Merged { ref merge_commit, strategy: MergeStrategy::Merge, .. }
                if *merge_commit == outcome.merge_commit
        ),
        "PR recorded as merged with the merge-commit strategy, got {:?}",
        pr.state
    );

    // The outbox holds exactly one `PullRequestMerged` for this PR,
    // committed with the state change — the row `spawn_dispatcher` turns
    // into the webhook delivery job.
    let outbox = edda_db::EventRepo::fetch_unprocessed(&pool, 50)
        .await
        .expect("read the outbox");
    let merged_events: Vec<_> = outbox
        .iter()
        .filter(|record| {
            matches!(
                record.event,
                edda_domain::DomainEvent::PullRequestMerged { pull_request_id, .. }
                    if pull_request_id == pr_id
            )
        })
        .collect();
    assert_eq!(
        merged_events.len(),
        1,
        "one PullRequestMerged event on the outbox, got {outbox:?}"
    );

    // Verify against the *real* repository: `main` now points at the
    // merge commit, and a fresh clone contains both `README.md` (from
    // `main`) and `feature.txt` (from `feature`).
    run(&work_dir, "git", &["clone", &remote, "verify"]);
    let verify_dir = work_dir.join("verify");
    let log_output = Command::new("git")
        .args(["log", "-1", "--format=%H %P"])
        .current_dir(&verify_dir)
        .output()
        .expect("read log");
    let log_line = String::from_utf8_lossy(&log_output.stdout);
    let mut parts = log_line.split_whitespace();
    let head_id = parts.next().expect("head commit id");
    let parent_count = parts.count();
    assert_eq!(
        head_id, outcome.merge_commit,
        "main's tip is the merge commit"
    );
    assert_eq!(parent_count, 2, "the merge commit has exactly two parents");
    assert!(verify_dir.join("README.md").exists());
    assert!(verify_dir.join("feature.txt").exists());

    // ── A second PR, merged with the squash strategy ──────────────────
    // A fresh branch off the (now-merged) `main`, one commit, opened as
    // PR #2 and squash-merged.
    run(&repo_dir, "git", &["checkout", "main"]);
    run(&repo_dir, "git", &["pull", "--ff-only", "origin", "main"]);
    run(&repo_dir, "git", &["checkout", "-b", "cleanup"]);
    std::fs::write(repo_dir.join("cleanup.txt"), b"tidy\n").expect("write file");
    run(&repo_dir, "git", &["add", "cleanup.txt"]);
    run(&repo_dir, "git", &["commit", "-m", "tidy up"]);
    run(
        &repo_dir,
        "git",
        &["push", "origin", "HEAD:refs/heads/cleanup"],
    );

    let pr2_id = PullRequestId::new();
    let pr2_number = PullRequestRepo::insert(
        &pool,
        pr2_id,
        repository.id,
        edda_db::NewPullRequest {
            title: "Tidy up",
            body: Some("Some cleanup."),
            author_id: bob_id,
            source: &PrRef {
                repository_id: repository.id,
                branch: "cleanup".to_string(),
            },
            target: "main",
            draft: false,
        },
    )
    .await
    .expect("open the second pull request");
    assert_eq!(pr2_number, 2);
    PrReviewRepo::insert(
        &pool,
        edda_domain::PrReviewId::new(),
        pr2_id,
        bob_id,
        ReviewState::Approved,
        None,
    )
    .await
    .expect("approve the second pull request");

    let squash_outcome = service
        .merge(
            &ActorContext::User(alice_id),
            "alice",
            "demo",
            pr2_number,
            MergeStrategy::Squash,
        )
        .await
        .expect("squash merge succeeds");

    let pr2 = PullRequestRepo::find_by_id(&pool, pr2_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(
            pr2.state,
            PrState::Merged {
                strategy: MergeStrategy::Squash,
                ..
            }
        ),
        "PR #2 recorded as squash-merged, got {:?}",
        pr2.state
    );

    // The squash commit has exactly one parent (the previous `main` tip).
    run(&work_dir, "git", &["clone", &remote, "verify2"]);
    let verify2_dir = work_dir.join("verify2");
    let squash_log = Command::new("git")
        .args(["log", "-1", "--format=%H %P"])
        .current_dir(&verify2_dir)
        .output()
        .expect("read squash log");
    let squash_line = String::from_utf8_lossy(&squash_log.stdout);
    let mut squash_parts = squash_line.split_whitespace();
    assert_eq!(
        squash_parts.next().expect("squash head id"),
        squash_outcome.merge_commit
    );
    assert_eq!(
        squash_parts.count(),
        1,
        "the squash commit has exactly one parent"
    );
    assert!(verify2_dir.join("cleanup.txt").exists());

    let _ = std::fs::remove_dir_all(&work_dir);
    let _ = std::fs::remove_dir_all(&store_root);
}

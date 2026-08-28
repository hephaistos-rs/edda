//! Phase 5, vertical slice A (H4): the contributor + maintainer path for a
//! **fork-sourced** pull request, driven end to end through `/api/v1`
//! against a real database and the real `git` CLI over HTTP.
//!
//! fork upstream → push a branch to the fork → open a cross-repo PR
//! against upstream → maintainer reviews (approve) → maintainer merges →
//! upstream's `main` is a real two-parent merge commit containing both
//! sides, and the fork is byte-for-byte unchanged. A `PullRequestMerged`
//! event lands on the transactional outbox (the row `spawn_dispatcher`
//! turns into the webhook job; the delivery mechanics + HMAC signature +
//! redirect refusal are covered by `crates/edda/src/jobs.rs`'s own tests).

use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use edda_app::{router, AppState};
use edda_auth::{tokens, AuthorizationService, Backend};
use edda_db::{EventRepo, RepositoryRepo, UserRepo};
use edda_domain::{DomainEvent, Repository, RepositoryId, RepositoryOwner, UserId, Visibility};
use edda_git::store::{LocalFsStore, RepoStore};
use edda_git::LockRegistry;
use serde_json::json;

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

fn git_log_oneline(dir: &Path, revspec: &str) -> String {
    let out = Command::new("git")
        .args(["log", "--format=%s", revspec])
        .current_dir(dir)
        .output()
        .expect("git log");
    assert!(out.status.success(), "git log {revspec} failed in {dir:?}");
    String::from_utf8_lossy(&out.stdout).into_owned()
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
        "edda-app-fork-slice-it-{label}-{}-{}",
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
async fn a_fork_pull_request_is_reviewed_and_merged_upstream_leaving_the_fork_untouched() {
    if !tool_available("git") {
        eprintln!("skipping: git not found on PATH");
        return;
    }

    let pool = edda_db::test_pool().await;
    let store_root = temp_dir("store");
    let store: Arc<dyn RepoStore> = Arc::new(LocalFsStore::new(store_root.clone()));
    let locks = Arc::new(LockRegistry::new());

    let maintainer = UserId::new();
    UserRepo::insert(&pool, maintainer, "maintainer", "maint@example.com", "x")
        .await
        .unwrap();
    let (maintainer_token, _) = tokens::create(&pool, maintainer, "ci").await.unwrap();

    let contributor = UserId::new();
    UserRepo::insert(
        &pool,
        contributor,
        "contributor",
        "contrib@example.com",
        "x",
    )
    .await
    .unwrap();
    let (contributor_token, _) = tokens::create(&pool, contributor, "ci").await.unwrap();

    // Upstream repository (owned by the maintainer).
    edda_git::create_repo(store.as_ref(), &locks, "maintainer/proj")
        .await
        .unwrap();
    let upstream = Repository {
        id: RepositoryId::new(),
        owner: RepositoryOwner::User(maintainer),
        name: "proj".to_string(),
        description: None,
        visibility: Visibility::Public,
        forked_from: None,
    };
    RepositoryRepo::insert_with_owner(&pool, &upstream, maintainer)
        .await
        .unwrap();

    let state = AppState {
        pool: pool.clone(),
        store: store.clone(),
        locks: locks.clone(),
        authz: AuthorizationService::new(pool.clone()),
        backend: Backend::new(pool.clone()),
        config: Default::default(),
    };
    let addr = spawn_server(state).await;
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // ── Maintainer seeds `main` on upstream over real HTTP. ──────────────
    let work = temp_dir("work");
    std::fs::create_dir_all(&work).unwrap();
    let upstream_remote = format!("http://ci:{maintainer_token}@{addr}/maintainer/proj.git");
    run(&work, "git", &["clone", &upstream_remote, "up"]);
    let up_dir = work.join("up");
    std::fs::write(up_dir.join("README.md"), b"# proj\n").unwrap();
    run(&up_dir, "git", &["add", "README.md"]);
    run(&up_dir, "git", &["commit", "-m", "initial commit"]);
    run(&up_dir, "git", &["push", "origin", "HEAD:refs/heads/main"]);

    // ── Contributor forks upstream via /api/v1. ──────────────────────────
    let fork_resp = client
        .post(format!("{base}/api/v1/repos/maintainer/proj/fork"))
        .bearer_auth(&contributor_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        fork_resp.status(),
        200,
        "fork: {}",
        fork_resp.text().await.unwrap()
    );
    let forked: serde_json::Value = client
        .get(format!("{base}/api/v1/repos/contributor/proj"))
        .bearer_auth(&contributor_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(forked["owner"], "contributor");

    // ── Contributor pushes a `feature` branch to their fork. ─────────────
    let fork_remote = format!("http://ci:{contributor_token}@{addr}/contributor/proj.git");
    run(&work, "git", &["clone", &fork_remote, "fork"]);
    let fork_dir = work.join("fork");
    run(&fork_dir, "git", &["checkout", "-b", "feature"]);
    std::fs::write(fork_dir.join("feature.txt"), b"a contribution\n").unwrap();
    run(&fork_dir, "git", &["add", "feature.txt"]);
    run(&fork_dir, "git", &["commit", "-m", "add feature"]);
    run(
        &fork_dir,
        "git",
        &["push", "origin", "HEAD:refs/heads/feature"],
    );

    // ── Contributor opens a cross-repo PR against upstream. ──────────────
    let open_resp = client
        .post(format!("{base}/api/v1/repos/maintainer/proj/pulls"))
        .bearer_auth(&contributor_token)
        .json(&json!({
            "title": "Add a feature",
            "source_owner": "contributor",
            "source_branch": "feature",
            "target_branch": "main",
        }))
        .send()
        .await
        .unwrap();
    let open_status = open_resp.status();
    let open_body = open_resp.text().await.unwrap();
    assert_eq!(open_status, 200, "open PR failed: {open_body}");
    let open: serde_json::Value = serde_json::from_str(&open_body).unwrap();
    let number = open["number"].as_i64().expect("PR number");

    // Detail reports it as cross-repo, attributed to the fork's owner.
    let detail: serde_json::Value = client
        .get(format!(
            "{base}/api/v1/repos/maintainer/proj/pulls/{number}"
        ))
        .bearer_auth(&maintainer_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["pull_request"]["is_cross_repo"], true);
    assert_eq!(detail["pull_request"]["source_owner"], "contributor");
    assert_eq!(detail["pull_request"]["source_branch"], "feature");

    // The PR diff resolves across the fork boundary (the interim import).
    let diff: serde_json::Value = client
        .get(format!(
            "{base}/api/v1/repos/maintainer/proj/pulls/{number}/diff"
        ))
        .bearer_auth(&maintainer_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let files: Vec<String> = diff
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["new_path"].as_str().map(str::to_string))
        .collect();
    assert!(
        files.iter().any(|p| p == "feature.txt"),
        "PR diff shows the added file, got {files:?}"
    );

    // ── Maintainer approves, then merges. ───────────────────────────────
    let review = client
        .post(format!(
            "{base}/api/v1/repos/maintainer/proj/pulls/{number}/reviews"
        ))
        .bearer_auth(&maintainer_token)
        .json(&json!({ "state": "approved" }))
        .send()
        .await
        .unwrap();
    assert_eq!(review.status(), 200);

    let merged: serde_json::Value = client
        .post(format!(
            "{base}/api/v1/repos/maintainer/proj/pulls/{number}/merge"
        ))
        .bearer_auth(&maintainer_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let merge_commit = merged["merge_commit"].as_str().expect("merge commit id");

    // ── Upstream `main` is the merge commit: two parents, both files. ────
    run(&work, "git", &["clone", &upstream_remote, "verify"]);
    let verify = work.join("verify");
    let head_line = {
        let out = Command::new("git")
            .args(["log", "-1", "--format=%H %P"])
            .current_dir(&verify)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    let mut parts = head_line.split_whitespace();
    assert_eq!(parts.next().unwrap(), merge_commit, "main tip is the merge");
    assert_eq!(parts.count(), 2, "the merge commit has two parents");
    assert!(verify.join("README.md").exists());
    assert!(verify.join("feature.txt").exists());

    // ── The fork is untouched. ──────────────────────────────────────────
    run(&work, "git", &["clone", &fork_remote, "fork-after"]);
    let fork_after = work.join("fork-after");
    // Its default branch (`main`) still has exactly the one seeded commit
    // and no `feature.txt`.
    let fork_main_log = git_log_oneline(&fork_after, "origin/main");
    assert_eq!(
        fork_main_log.lines().count(),
        1,
        "fork main untouched: {fork_main_log:?}"
    );
    assert!(!fork_after.join("feature.txt").exists());
    // `feature` still points exactly where the contributor left it — no
    // merge commit, no history rewrite.
    let fork_feature_after = git_log_oneline(&fork_after, "origin/feature");
    assert_eq!(fork_feature_after.lines().next().unwrap(), "add feature");
    assert_eq!(
        fork_feature_after.lines().count(),
        2,
        "fork `feature` is still exactly its two commits: {fork_feature_after:?}"
    );
    assert!(
        !fork_feature_after.contains("Merge pull request"),
        "the fork gained no merge commit"
    );

    // ── The merge is on the outbox as a PullRequestMerged event. ─────────
    let outbox = EventRepo::fetch_unprocessed(&pool, 50).await.unwrap();
    let merged_events = outbox
        .iter()
        .filter(|record| {
            matches!(
                record.event,
                DomainEvent::PullRequestMerged { repository_id, .. }
                    if repository_id == upstream.id
            )
        })
        .count();
    assert_eq!(merged_events, 1, "one PullRequestMerged on the outbox");

    let _ = std::fs::remove_dir_all(&work);
    let _ = std::fs::remove_dir_all(&store_root);
}

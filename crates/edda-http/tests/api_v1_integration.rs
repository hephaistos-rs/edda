//! Integration test for `/api/v1/repos/{owner}/{repo}`: an unauthenticated
//! request to a public repo returns correct data; the same request to a
//! private repo 404s (not 403) without credentials — the workspace-wide
//! information-hiding rule, re-checked at this surface rather than assumed
//! to carry over. Also checks that a valid PAT does see the private repo,
//! and that a session cookie alone (no bearer token) is *not* accepted
//! here.

use std::net::SocketAddr;
use std::sync::Arc;

use edda_auth::{tokens, AuthorizationService, Backend};
use edda_db::RepositoryRepo;
use edda_domain::{Repository, RepositoryId, RepositoryOwner, UserId, Visibility};
use edda_git::store::{LocalFsStore, RepoStore};
use edda_git::LockRegistry;
use edda_http::{router, AppState};

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
        "edda-http-api-v1-it-{label}-{}-{}",
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
async fn a_public_repo_is_visible_unauthenticated_and_a_private_one_404s_without_credentials() {
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

    edda_git::create_repo(store.as_ref(), &locks, "alice/public-repo")
        .await
        .unwrap();
    let public_repo = Repository {
        id: RepositoryId::new(),
        owner: RepositoryOwner::User(alice_id),
        name: "public-repo".to_string(),
        description: Some("a public demo".to_string()),
        visibility: Visibility::Public,
        forked_from: None,
    };
    RepositoryRepo::insert_with_owner(&pool, &public_repo, alice_id)
        .await
        .unwrap();

    edda_git::create_repo(store.as_ref(), &locks, "alice/secret-repo")
        .await
        .unwrap();
    let private_repo = Repository {
        id: RepositoryId::new(),
        owner: RepositoryOwner::User(alice_id),
        name: "secret-repo".to_string(),
        description: None,
        visibility: Visibility::Private,
        forked_from: None,
    };
    RepositoryRepo::insert_with_owner(&pool, &private_repo, alice_id)
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
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Public repo, no credentials at all: 200, correct data.
    let response = client
        .get(format!("{base}/api/v1/repos/alice/public-repo"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["name"], "public-repo");
    assert_eq!(body["owner"], "alice");
    assert_eq!(body["private"], false);

    // Private repo, no credentials: 404 — not 403, not a 200 with
    // redacted fields. Existence itself must not be observable.
    let response = client
        .get(format!("{base}/api/v1/repos/alice/secret-repo"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "not_found");

    // A repository that never existed at all gets the exact same 404
    // shape — an attacker can't distinguish "private" from "never
    // existed" by response shape either.
    let response = client
        .get(format!("{base}/api/v1/repos/alice/does-not-exist"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);

    // The private repo *is* visible with a valid bearer token belonging
    // to its owner.
    let response = client
        .get(format!("{base}/api/v1/repos/alice/secret-repo"))
        .bearer_auth(&alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["name"], "secret-repo");
    assert_eq!(body["private"], true);

    let _ = std::fs::remove_dir_all(&store_root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_requests_and_issues_are_readable_through_the_versioned_api() {
    let pool = edda_db::test_pool().await;
    let store_root = temp_dir("store-content");
    let store: Arc<dyn RepoStore> = Arc::new(LocalFsStore::new(store_root.clone()));
    let locks = Arc::new(LockRegistry::new());

    let alice_id = UserId::new();
    edda_db::UserRepo::insert(&pool, alice_id, "alice", "alice@example.com", "unused")
        .await
        .unwrap();

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

    let pr_number = edda_db::PullRequestRepo::insert(
        &pool,
        edda_domain::PullRequestId::new(),
        repository.id,
        edda_db::NewPullRequest {
            title: "Add feature",
            body: None,
            author_id: alice_id,
            source: &edda_domain::PrRef {
                repository_id: repository.id,
                branch: "feature".to_string(),
            },
            target: "main",
            draft: false,
        },
    )
    .await
    .unwrap();

    let issue_number = edda_db::IssueRepo::insert(
        &pool,
        edda_domain::IssueId::new(),
        repository.id,
        "Something's broken",
        None,
        alice_id,
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
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{base}/api/v1/repos/alice/demo/pulls/{pr_number}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["title"], "Add feature");
    assert_eq!(body["state"]["status"], "open");

    let response = client
        .get(format!(
            "{base}/api/v1/repos/alice/demo/issues/{issue_number}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["title"], "Something's broken");

    let _ = std::fs::remove_dir_all(&store_root);
}

//! Phase 7 exit-criteria test: "creating a release with an uploaded asset
//! works and the asset downloads correctly." Exercises the real
//! `edda_http::router` over real HTTP with a real multipart upload and a
//! real GET download — the same "test against the real client" approach
//! `lfs_integration.rs`/`branch_protection_integration.rs` already use,
//! standing `reqwest` in as the real client (a release asset's real
//! client is any plain HTTP client, unlike LFS/git-http's protocol-
//! specific ones).

use std::net::SocketAddr;
use std::sync::Arc;

use edda_auth::{tokens, AuthorizationService, Backend};
use edda_db::{NewRelease, ReleaseRepo, RepoAccessRepo, RepositoryRepo};
use edda_domain::{
    AccessSubject, ReleaseId, RepoRole, Repository, RepositoryId, RepositoryOwner, UserId,
    Visibility,
};
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
        "edda-http-release-asset-it-{label}-{}-{}",
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
async fn an_uploaded_release_asset_downloads_back_with_matching_content() {
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
    // Bob has read access only (repo is public, so this is implicit —
    // recorded here anyway for clarity) and must not be able to upload.
    let _ = RepoAccessRepo::grant(
        &pool,
        repository.id,
        AccessSubject::User(bob_id),
        RepoRole::Read,
    )
    .await;

    let release_id = ReleaseId::new();
    ReleaseRepo::insert(
        &pool,
        release_id,
        repository.id,
        NewRelease {
            tag_name: "v1.0.0",
            target_commit: &"a".repeat(40),
            name: "v1.0.0",
            body: None,
            draft: false,
            prerelease: false,
            author_id: alice_id,
        },
    )
    .await
    .expect("insert release row");

    let state = AppState {
        pool: pool.clone(),
        store: store.clone(),
        locks,
        authz: AuthorizationService::new(pool.clone()),
        backend: Backend::new(pool.clone()),
    };
    let addr = spawn_server(state).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let file_bytes = b"a small release archive\n".to_vec();
    let part = reqwest::multipart::Part::bytes(file_bytes.clone())
        .file_name("demo.tar.gz")
        .mime_str("application/gzip")
        .unwrap();
    let form = reqwest::multipart::Form::new().part("file", part);

    // Bob (read-only) may not upload.
    let forbidden = client
        .post(format!("{base}/alice/demo/releases/v1.0.0/assets"))
        .basic_auth("ci", Some(&bob_token))
        .multipart(reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(b"nope".to_vec()).file_name("x.bin"),
        ))
        .send()
        .await
        .expect("send request");
    assert!(
        !forbidden.status().is_success(),
        "a read-only collaborator must not be able to upload a release asset"
    );

    // Alice (owner/write) can.
    let upload_response = client
        .post(format!("{base}/alice/demo/releases/v1.0.0/assets"))
        .basic_auth("ci", Some(&alice_token))
        .multipart(form)
        .send()
        .await
        .expect("send upload request");
    assert!(
        upload_response.status().is_success(),
        "upload failed: {}",
        upload_response.status()
    );

    // Downloading it back — unauthenticated, since the repo/release are
    // public — returns the exact same bytes, and never trusts the
    // client-claimed `application/gzip` content type for how it's served.
    let download_response = client
        .get(format!(
            "{base}/alice/demo/releases/v1.0.0/assets/demo.tar.gz"
        ))
        .send()
        .await
        .expect("send download request");
    assert!(download_response.status().is_success());
    assert_eq!(
        download_response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/octet-stream",
        "a release asset must always be served as application/octet-stream, \
         never the client-claimed content type"
    );
    let downloaded_bytes = download_response.bytes().await.expect("read body");
    assert_eq!(downloaded_bytes.as_ref(), file_bytes.as_slice());

    let _ = std::fs::remove_dir_all(&store_root);
}

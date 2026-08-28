//! Phase 5 (S8): the CSRF/Origin check on the cookie-authenticated,
//! state-changing surface. Drives `edda_app::router` over a real HTTP
//! server and asserts:
//!   * a cookie-auth write with a **cross-origin** `Origin` → 403,
//!   * the same write with a **same-origin** `Origin` → succeeds,
//!   * a **bearer-token** write with a cross-origin `Origin` → succeeds
//!     (no ambient credential, CSRF N/A),
//!   * a safe method (`GET`) with a cross-origin `Origin` → succeeds.

use std::net::SocketAddr;

use edda_app::{router, AppState};
use edda_auth::{tokens, AuthorizationService, Backend};
use edda_db::UserRepo;
use edda_domain::UserId;
use edda_git::store::{LocalFsStore, RepoStore};
use edda_git::LockRegistry;
use serde_json::json;
use std::sync::Arc;

async fn spawn_server(state: AppState) -> SocketAddr {
    let session_pool = sqlx::SqlitePool::connect("sqlite::memory:")
        .await
        .expect("session pool");
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
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = router(state).layer(auth_layer);
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    addr
}

fn temp_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "edda-app-csrf-it-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

async fn harness() -> (SocketAddr, String, std::path::PathBuf) {
    edda_auth::secret_box::init(Some([0x11; 32]));
    let pool = edda_db::test_pool().await;
    let store_root = temp_dir();
    let store: Arc<dyn RepoStore> = Arc::new(LocalFsStore::new(store_root.clone()));
    let locks = Arc::new(LockRegistry::new());

    let alice = UserId::new();
    UserRepo::insert(&pool, alice, "alice", "alice@example.com", "x")
        .await
        .unwrap();
    let (token, _) = tokens::create(&pool, alice, "ci").await.unwrap();

    let state = AppState {
        pool: pool.clone(),
        store,
        locks,
        authz: AuthorizationService::new(pool.clone()),
        backend: Backend::new(pool.clone()),
        config: Default::default(),
    };
    let addr = spawn_server(state).await;
    (addr, token, store_root)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cookie_write_from_a_cross_origin_is_refused_but_same_origin_and_bearer_are_not() {
    let (addr, token, _root) = harness().await;
    let base = format!("http://{addr}");

    // Establish a session (cookie jar) via signup.
    let jar = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let signup = jar
        .post(format!("{base}/api/auth/signup"))
        .json(&json!({
            "username": "carol",
            "email": "carol@example.com",
            "password": "correct horse battery staple",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(signup.status(), 200, "{}", signup.text().await.unwrap());

    // 1. Cookie-authenticated write with a cross-origin `Origin` → 403.
    let blocked = jar
        .post(format!("{base}/api/v1/repos"))
        .header("Origin", "https://evil.example")
        .json(&json!({ "name": "csrf-attempt" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        blocked.status(),
        403,
        "cross-origin cookie write must be refused"
    );

    // 2. Same write, same-origin `Origin` → succeeds.
    let allowed = jar
        .post(format!("{base}/api/v1/repos"))
        .header("Origin", &base)
        .json(&json!({ "name": "same-origin-ok" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        allowed.status(),
        200,
        "same-origin cookie write: {}",
        allowed.text().await.unwrap()
    );

    // 3. Bearer-token write with a cross-origin `Origin` → unaffected
    //    (no ambient credential to abuse).
    let bearer = reqwest::Client::new()
        .post(format!("{base}/api/v1/repos"))
        .bearer_auth(&token)
        .header("Origin", "https://evil.example")
        .json(&json!({ "name": "bearer-cross-origin-ok" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        bearer.status(),
        200,
        "bearer write is exempt: {}",
        bearer.text().await.unwrap()
    );

    // 4. A safe method (GET) is never checked, cross-origin or not.
    let read = jar
        .get(format!("{base}/api/v1/repos"))
        .header("Origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(read.status(), 200, "GET is exempt from the origin check");
}

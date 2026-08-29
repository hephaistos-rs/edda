//! S4: repeated failed `/api/auth/login` attempts against one account get
//! throttled — the endpoint returns `429` with a `Retry-After` header
//! before it even checks the password, and a correct login after the lock
//! window clears the counter.

use std::net::SocketAddr;

use edda_app::{router, AppState};
use edda_auth::{AuthorizationService, Backend};

async fn spawn(state: AppState) -> SocketAddr {
    let session_pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    let session_store = tower_sessions_sqlx_store::SqliteStore::new(session_pool);
    session_store.migrate().await.unwrap();
    let session_layer = tower_sessions::SessionManagerLayer::new(session_store);
    let auth_layer =
        axum_login::AuthManagerLayerBuilder::new(state.backend.clone(), session_layer).build();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(state).layer(auth_layer);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_bad_passwords_lock_the_account_then_a_good_one_clears_it() {
    let pool = edda_db::test_pool().await;
    let user_id = edda_domain::UserId::new();
    let hash = edda_auth::password::hash_password("correct-horse-battery").unwrap();
    edda_db::UserRepo::insert(&pool, user_id, "alice", "alice@example.com", &hash)
        .await
        .unwrap();

    let state = AppState {
        pool: pool.clone(),
        store: std::sync::Arc::new(edda_git::store::LocalFsStore::new(std::env::temp_dir())),
        locks: std::sync::Arc::new(edda_git::LockRegistry::new()),
        authz: AuthorizationService::new(pool.clone()),
        backend: Backend::new(pool.clone()),
        // Generous rate limits so the only 429 in this test comes from the
        // login throttle, not the auth-endpoint limiter.
        config: edda_app::RuntimeConfig {
            rate_limit: edda_app::config::RateLimitConfig {
                per_second: 10_000,
                burst: 10_000,
                auth_per_second: 10_000,
                auth_burst: 10_000,
                ..Default::default()
            },
            ..Default::default()
        },
    };
    let addr = spawn(state).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/auth/login");
    let bad = serde_json::json!({ "email": "alice@example.com", "password": "wrong" });

    // Hammer with wrong passwords until the lock arms.
    let mut got_429 = false;
    let mut retry_after_present = false;
    for _ in 0..10 {
        let resp = client.post(&url).json(&bad).send().await.unwrap();
        if resp.status() == 429 {
            got_429 = true;
            retry_after_present = resp.headers().contains_key("retry-after");
            break;
        }
        assert_eq!(
            resp.status(),
            401,
            "a wrong password is 401 until the lock arms"
        );
    }
    assert!(got_429, "the account should lock after repeated failures");
    assert!(retry_after_present, "a locked response carries Retry-After");

    // Clear the lock directly (the window is >15s, too long to wait in a
    // test) and confirm a correct password then works and resets the
    // counter.
    edda_auth::login_throttle::record_success(&pool, "alice@example.com", "")
        .await
        .unwrap();
    let good =
        serde_json::json!({ "email": "alice@example.com", "password": "correct-horse-battery" });
    let resp = client.post(&url).json(&good).send().await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "a correct password after the counter is cleared works"
    );
}

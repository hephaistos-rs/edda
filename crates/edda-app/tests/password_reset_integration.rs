//! Real end-to-end password-reset flow: request over real HTTP (which
//! enqueues a real `SendEmail` job — inspected directly rather than
//! actually sending mail, since this test has no SMTP server), consume
//! the token from that job's body, then verify a real login succeeds
//! with the new password and fails with the old one.

use std::net::SocketAddr;
use std::sync::Arc;

use edda_app::{router, AppState};
use edda_auth::{AuthorizationService, Backend};
use edda_db::JobRepo;
use edda_domain::{JobPayload, UserId};
use edda_git::store::LocalFsStore;
use edda_git::LockRegistry;

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

fn extract_reset_token(body_text: &str) -> String {
    let marker = "token=";
    let start = body_text
        .find(marker)
        .expect("reset link present in email body")
        + marker.len();
    let rest = &body_text[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    rest[..end].to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_password_reset_round_trip_changes_which_password_logs_in() {
    let pool = edda_db::test_pool().await;
    let store = Arc::new(LocalFsStore::new(std::env::temp_dir().join(format!(
        "edda-app-password-reset-it-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))));
    let locks = Arc::new(LockRegistry::new());

    let user_id = UserId::new();
    let old_password_hash = edda_auth::password::hash_password("old-password").unwrap();
    edda_db::UserRepo::insert(
        &pool,
        user_id,
        "alice",
        "alice@example.com",
        &old_password_hash,
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

    // Request a reset — always 200, regardless of what it finds
    // (information hiding applied to account-existence-by-email).
    let response = client
        .post(format!("{base}/api/auth/password-reset/request"))
        .json(&serde_json::json!({ "email": "alice@example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // The real job the request enqueued — this test inspects it directly
    // in place of an SMTP server, but it's the exact same `SendEmail` job
    // shape `job_handlers::send_email` would otherwise have delivered.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claimed = JobRepo::claim_batch(&pool, now, 10).await.unwrap();
    assert_eq!(claimed.len(), 1);
    let JobPayload::SendEmail {
        to_email,
        body_text,
        ..
    } = &claimed[0].payload
    else {
        panic!("expected a SendEmail job");
    };
    assert_eq!(to_email, "alice@example.com");
    let raw_token = extract_reset_token(body_text);

    // A wrong token is rejected.
    let response = client
        .post(format!("{base}/api/auth/password-reset/consume"))
        .json(&serde_json::json!({ "token": "not-the-real-token", "new_password": "new-password" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);

    // The real token succeeds.
    let response = client
        .post(format!("{base}/api/auth/password-reset/consume"))
        .json(&serde_json::json!({ "token": raw_token, "new_password": "new-password" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // The old password no longer logs in; the new one does.
    let response = client
        .post(format!("{base}/api/auth/login"))
        .json(&serde_json::json!({ "email": "alice@example.com", "password": "old-password" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);

    let response = client
        .post(format!("{base}/api/auth/login"))
        .json(&serde_json::json!({ "email": "alice@example.com", "password": "new-password" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // The token is single-use — replaying it fails even with a valid shape.
    let response = client
        .post(format!("{base}/api/auth/password-reset/consume"))
        .json(&serde_json::json!({ "token": raw_token, "new_password": "third-password" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
}

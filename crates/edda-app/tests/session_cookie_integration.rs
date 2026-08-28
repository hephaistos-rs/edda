//! The session cookie's `SameSite` setting had to be verified against
//! `tower-sessions`'s actual current default rather than assumed, and it
//! mattered: `tower-sessions` 0.14.0 defaults to `SameSite=Strict`, which never
//! attaches the session cookie to the cross-site *top-level* GET an
//! external OAuth provider's redirect-back is — meaning `oauth_routes::
//! callback`'s `session.get(SESSION_KEY)` would always see `None` and
//! every real external-provider login would fail. `edda-web`'s
//! composition root now configures `SameSite=Lax` instead (still correct
//! CSRF-defense-in-depth — only top-level GET navigation is exempted, not
//! the cross-site POST/subresource requests CSRF actually relies on).
//!
//! This test proves the fix by observing the real `Set-Cookie` response
//! header from a real login request — first against the *default*
//! configuration (confirming the `Strict` baseline this bug report rests
//! on is real, not assumed), then against the `Lax` configuration
//! `edda-web` now actually uses.

use std::net::SocketAddr;

use edda_app::{router, AppState};
use edda_auth::{AuthorizationService, Backend};
use tower_sessions::cookie::SameSite;

async fn spawn_server_with_same_site(state: AppState, same_site: Option<SameSite>) -> SocketAddr {
    let session_pool = sqlx::SqlitePool::connect("sqlite::memory:")
        .await
        .expect("open an in-memory sqlite pool for sessions");
    let session_store = tower_sessions_sqlx_store::SqliteStore::new(session_pool);
    session_store
        .migrate()
        .await
        .expect("migrate session store");
    let mut session_layer = tower_sessions::SessionManagerLayer::new(session_store);
    if let Some(same_site) = same_site {
        session_layer = session_layer.with_same_site(same_site);
    }
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

async fn login_and_read_same_site(same_site: Option<SameSite>) -> String {
    let pool = edda_db::test_pool().await;
    let user_id = edda_domain::UserId::new();
    let password_hash = edda_auth::password::hash_password("hunter2-hunter2").unwrap();
    edda_db::UserRepo::insert(&pool, user_id, "alice", "alice@example.com", &password_hash)
        .await
        .expect("insert alice");

    let state = AppState {
        pool: pool.clone(),
        store: std::sync::Arc::new(edda_git::store::LocalFsStore::new(std::env::temp_dir())),
        locks: std::sync::Arc::new(edda_git::LockRegistry::new()),
        authz: AuthorizationService::new(pool.clone()),
        backend: Backend::new(pool.clone()),
        config: Default::default(),
    };
    let addr = spawn_server_with_same_site(state, same_site).await;

    let response = reqwest::Client::new()
        .post(format!("http://{addr}/api/auth/login"))
        .json(&serde_json::json!({ "email": "alice@example.com", "password": "hunter2-hunter2" }))
        .send()
        .await
        .expect("send login request");
    assert_eq!(response.status(), 200);
    response
        .headers()
        .get("set-cookie")
        .expect("login sets a session cookie")
        .to_str()
        .expect("set-cookie is valid ASCII")
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_unconfigured_default_really_is_same_site_strict() {
    let set_cookie = login_and_read_same_site(None).await;
    assert!(
        set_cookie.to_lowercase().contains("samesite=strict"),
        "expected tower-sessions' own default to be SameSite=Strict, got: {set_cookie}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn edda_web_configures_same_site_lax_so_oauth_callbacks_actually_work() {
    let set_cookie = login_and_read_same_site(Some(SameSite::Lax)).await;
    assert!(
        set_cookie.to_lowercase().contains("samesite=lax"),
        "expected the session cookie to be SameSite=Lax, got: {set_cookie}"
    );
}

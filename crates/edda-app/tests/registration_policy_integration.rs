//! Phase 9 (H2/S3): registration modes, email-domain allowlist, the
//! admin approval queue, email-verification gating, and instance-private
//! mode — driven through the real `edda_app::router` over HTTP.

use std::net::SocketAddr;
use std::sync::Arc;

use edda_app::config::RegistrationConfig;
use edda_app::{router, AppState, RuntimeConfig};
use edda_auth::{AuthorizationService, Backend};
use edda_domain::{RegistrationMode, RegistrationPolicy};
use serde_json::json;

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

async fn state_with(registration: RegistrationConfig) -> AppState {
    let pool = edda_db::test_pool().await;
    let root = std::env::temp_dir().join(format!(
        "edda-reg-it-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    AppState {
        pool: pool.clone(),
        store: Arc::new(edda_git::store::LocalFsStore::new(root)),
        locks: Arc::new(edda_git::LockRegistry::new()),
        authz: AuthorizationService::new(pool.clone()),
        backend: Backend::new(pool.clone()),
        config: RuntimeConfig {
            registration: registration.policy,
            require_signin_to_view: registration.require_signin_to_view,
            ..Default::default()
        },
    }
}

fn signup_body(username: &str, email: &str) -> serde_json::Value {
    json!({ "username": username, "email": email, "password": "correct-horse-battery" })
}

#[tokio::test]
async fn closed_registration_refuses_signup() {
    let state = state_with(RegistrationConfig {
        policy: RegistrationPolicy {
            mode: RegistrationMode::Closed,
            ..Default::default()
        },
        require_signin_to_view: false,
    })
    .await;
    let addr = spawn(state).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/auth/signup"))
        .json(&signup_body("alice", "alice@example.com"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn the_email_domain_allowlist_is_enforced_at_signup() {
    let state = state_with(RegistrationConfig {
        policy: RegistrationPolicy {
            allowed_email_domains: vec!["example.com".to_string()],
            ..Default::default()
        },
        require_signin_to_view: false,
    })
    .await;
    let addr = spawn(state).await;
    let client = reqwest::Client::new();

    let denied = client
        .post(format!("http://{addr}/api/auth/signup"))
        .json(&signup_body("mallory", "mallory@evil.example"))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);

    let allowed = client
        .post(format!("http://{addr}/api/auth/signup"))
        .json(&signup_body("alice", "alice@example.com"))
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.status(), 200);
}

#[tokio::test]
async fn approval_mode_queues_the_account_and_blocks_login_until_an_admin_approves() {
    let state = state_with(RegistrationConfig {
        policy: RegistrationPolicy {
            mode: RegistrationMode::Approval,
            ..Default::default()
        },
        require_signin_to_view: false,
    })
    .await;
    let pool = state.pool.clone();
    let addr = spawn(state).await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let created = client
        .post(format!("http://{addr}/api/auth/signup"))
        .json(&signup_body("bob", "bob@example.com"))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 202, "pending approval, no session");

    // Correct password, but the account isn't active yet.
    let login = json!({ "email": "bob@example.com", "password": "correct-horse-battery" });
    let blocked = client
        .post(format!("http://{addr}/api/auth/login"))
        .json(&login)
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), 403);

    // Admin approves out of band (the admin API needs an admin session;
    // exercised directly here — its HTTP wiring is covered elsewhere).
    let bob = edda_db::UserRepo::list_pending_approval(&pool)
        .await
        .unwrap();
    assert_eq!(bob.len(), 1);
    assert!(edda_db::UserRepo::approve(&pool, bob[0].id).await.unwrap());

    let ok = client
        .post(format!("http://{addr}/api/auth/login"))
        .json(&login)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
}

#[tokio::test]
async fn an_unverified_account_can_sign_in_but_not_create_a_repository() {
    let state = state_with(RegistrationConfig {
        policy: RegistrationPolicy {
            require_email_verification: true,
            ..Default::default()
        },
        require_signin_to_view: false,
    })
    .await;
    let pool = state.pool.clone();
    let addr = spawn(state).await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    // Signup succeeds and starts a session (verification is required for
    // *writes*, not for browsing).
    let created = client
        .post(format!("http://{addr}/api/auth/signup"))
        .json(&signup_body("carol", "carol@example.com"))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 200);

    let blocked = client
        .post(format!("http://{addr}/api/v1/repos"))
        .json(&json!({ "name": "proj", "private": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), 403, "unverified email blocks repo create");

    // Confirm the email via the real endpoint, using a freshly minted
    // token (the one from signup went out by email).
    let carol = edda_db::UserRepo::list_all(&pool)
        .await
        .unwrap()
        .into_iter()
        .find(|u| u.username == "carol")
        .unwrap();
    let (_, token) = edda_auth::email_verification::request(&pool, carol.id)
        .await
        .unwrap()
        .unwrap();
    let verified = client
        .post(format!("http://{addr}/api/auth/verify-email"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(verified.status(), 200);

    let now_ok = client
        .post(format!("http://{addr}/api/v1/repos"))
        .json(&json!({ "name": "proj", "private": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(now_ok.status(), 200);
}

#[tokio::test]
async fn instance_private_mode_refuses_anonymous_api_access() {
    let state = state_with(RegistrationConfig {
        policy: RegistrationPolicy::default(),
        require_signin_to_view: true,
    })
    .await;
    let addr = spawn(state).await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let anon = client
        .get(format!("http://{addr}/api/v1/repos"))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), 401);

    // A signed-in user sees it fine.
    client
        .post(format!("http://{addr}/api/auth/signup"))
        .json(&signup_body("dave", "dave@example.com"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let signed_in = client
        .get(format!("http://{addr}/api/v1/repos"))
        .send()
        .await
        .unwrap();
    assert_eq!(signed_in.status(), 200);
}

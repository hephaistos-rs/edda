//! Phase 12: `GET /metrics` — token-gated Prometheus text exposition,
//! served on the main listener outside every `/api/v1` layer.

use std::net::SocketAddr;
use std::sync::Arc;

use edda_app::{router, AppState, RuntimeConfig};
use edda_auth::{AuthorizationService, Backend};
use edda_git::store::{LocalFsStore, RepoStore};
use edda_git::LockRegistry;

async fn spawn_server(state: AppState) -> SocketAddr {
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

async fn state_with_token(token: Option<&str>) -> AppState {
    let pool = edda_db::test_pool().await;
    let root = std::env::temp_dir().join(format!(
        "edda-app-metrics-it-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let store: Arc<dyn RepoStore> = Arc::new(LocalFsStore::new(root));
    AppState {
        pool: pool.clone(),
        store,
        locks: Arc::new(LockRegistry::new()),
        authz: AuthorizationService::new(pool.clone()),
        backend: Backend::new(pool.clone()),
        config: RuntimeConfig {
            metrics_token: token.map(str::to_string),
            ..Default::default()
        },
    }
}

#[tokio::test]
async fn the_metrics_endpoint_gates_on_the_token_and_renders_prometheus_text() {
    let addr = spawn_server(state_with_token(Some("s3cret")).await).await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    assert_eq!(
        client
            .get(format!("{base}/metrics"))
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "no token"
    );
    assert_eq!(
        client
            .get(format!("{base}/metrics"))
            .bearer_auth("wrong")
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "wrong token"
    );

    let ok = client
        .get(format!("{base}/metrics"))
        .bearer_auth("s3cret")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    assert!(ok
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/plain; version=0.0.4"));
    let body = ok.text().await.unwrap();
    assert!(body.contains("# TYPE edda_jobs_pending gauge"), "{body}");
    assert!(body.contains("edda_users "), "{body}");
    assert!(body.contains("edda_db_pool_connections "), "{body}");

    // The `?token=` form works too.
    assert_eq!(
        client
            .get(format!("{base}/metrics?token=s3cret"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}

#[tokio::test]
async fn the_metrics_endpoint_is_404_when_no_token_is_configured() {
    let addr = spawn_server(state_with_token(None).await).await;
    assert_eq!(
        reqwest::Client::new()
            .get(format!("http://{addr}/metrics"))
            .bearer_auth("anything")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}

use dioxus::prelude::*;

mod issue_server;
#[cfg(feature = "server")]
mod job_handlers;
#[cfg(feature = "server")]
mod mentions;
mod notification_server;
mod org_server;
mod pr_server;
mod release_server;
mod server;
#[cfg(feature = "server")]
mod session_store;
#[cfg(feature = "server")]
mod shared;
#[cfg(feature = "server")]
mod ssrf;
mod team_server;
mod ui;
mod webhook_server;

use ui::layouts::Navbar;
use ui::pages::{
    Admin, Home, IssueDetail, IssuesList, Login, Notifications, OrganizationDetail,
    OrganizationsList, PullDetail, PullsList, ReleaseDetail, ReleasesList, Repo, ResetPassword,
    Settings, Signup, TeamDetail, WebhooksSettings,
};

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(Navbar)]
    #[route("/")]
    Home {},
    #[route("/settings")]
    Settings {},
    #[route("/notifications")]
    Notifications {},
    #[route("/admin")]
    Admin {},
    #[route("/orgs")]
    OrganizationsList {},
    #[route("/orgs/:name")]
    OrganizationDetail { name: String },
    #[route("/orgs/:org_name/teams/:team_name")]
    TeamDetail { org_name: String, team_name: String },
    #[route("/:owner/:name/pulls")]
    PullsList { owner: String, name: String },
    #[route("/:owner/:name/pulls/:number")]
    PullDetail { owner: String, name: String, number: i64 },
    #[route("/:owner/:name/issues")]
    IssuesList { owner: String, name: String },
    #[route("/:owner/:name/issues/:number")]
    IssueDetail { owner: String, name: String, number: i64 },
    #[route("/:owner/:name/releases")]
    ReleasesList { owner: String, name: String },
    #[route("/:owner/:name/releases/:tag_name")]
    ReleaseDetail { owner: String, name: String, tag_name: String },
    #[route("/:owner/:name/settings/webhooks")]
    WebhooksSettings { owner: String, name: String },
    #[route("/:owner/:name")]
    Repo { owner: String, name: String },
    #[route("/signup")]
    Signup {},
    #[route("/login")]
    Login {},
    #[route("/reset-password?:token")]
    ResetPassword { token: Option<String> },
}

const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

/// Waits for either Ctrl-C or (on unix) SIGTERM — the two signals a process
/// manager / `docker stop` / an interactive terminal actually send.
#[cfg(feature = "server")]
async fn wait_for_shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        else {
            let _ = ctrl_c.await;
            return;
        };
        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}

/// The client (web) build launches normally. The server build needs its own
/// axum router instead: Dioxus's own router (SSR, assets, server functions)
/// merged with `edda_http::router` — the git-http bridge and account/token
/// routes aren't server functions; they need to speak raw git wire
/// protocol and plain REST, not typed RPC. This function is the workspace's
/// one composition root: every other crate is wired together here, and
/// nowhere else.
#[cfg(feature = "server")]
fn main() {
    // Must run before `dioxus::server::serve(...)` — it installs a default
    // `tracing` subscriber of its own unless one is already set. See
    // `edda_telemetry`'s module docs for the full explanation.
    let telemetry_guard = edda_telemetry::init();
    // `dioxus::server::serve`'s callback can run more than once (dev-mode hot
    // reload re-invokes it to rebuild the router); the shutdown watcher below
    // must still only ever be spawned once, so the guard is shared behind a
    // lock rather than moved in directly.
    let telemetry_guard = std::sync::Arc::new(tokio::sync::Mutex::new(Some(telemetry_guard)));
    let shutdown_watcher_started = std::sync::Arc::new(std::sync::Once::new());
    let ssh_server_started = std::sync::Arc::new(std::sync::Once::new());

    dioxus::server::serve(move || {
        let telemetry_guard = telemetry_guard.clone();
        let shutdown_watcher_started = shutdown_watcher_started.clone();
        let ssh_server_started = ssh_server_started.clone();
        async move {
            let pool = edda_db::pool().await?;

            // Session cookies persist in the same configured database as
            // everything else, via a second small typed connection
            // `session_store::connect` opens alongside `pool`'s `AnyPool`
            // — see that module's doc comment for why
            // `tower-sessions-sqlx-store` can't share the `AnyPool`
            // directly.
            let session_store = session_store::connect(&pool).await?;
            let session_layer = tower_sessions::SessionManagerLayer::new(session_store);

            let backend = edda_auth::Backend::new(pool.clone());
            let auth_layer =
                axum_login::AuthManagerLayerBuilder::new(backend.clone(), session_layer).build();

            let store: std::sync::Arc<dyn edda_git::store::RepoStore> =
                std::sync::Arc::new(edda_git::store::LocalFsStore::from_env());
            let locks = std::sync::Arc::new(edda_git::LockRegistry::new());
            let authz = edda_auth::AuthorizationService::new(pool.clone());

            // See `shared`'s module doc comment for why Dioxus server
            // functions need this in addition to `AppState` below — both
            // are built from the exact same values, not independently
            // constructed copies.
            shared::init(shared::SharedServerState {
                pool: pool.clone(),
                store: store.clone(),
                locks: locks.clone(),
                authz: authz.clone(),
            });

            let state = edda_http::AppState {
                pool: pool.clone(),
                store: store.clone(),
                locks: locks.clone(),
                authz: authz.clone(),
                backend,
            };
            let router = dioxus::server::router(App)
                .merge(edda_http::router(state))
                .layer(auth_layer);

            // The job poller (§12.2): handler logic is registered here,
            // in the composition root, because it needs `edda-auth`
            // (secret decryption, HMAC signing) and an HTTP client —
            // `edda-jobs` itself deliberately depends on neither (see
            // that crate's own `Cargo.toml` doc comment).
            let mailer = job_handlers::Mailer::from_env().map(std::sync::Arc::new);
            if mailer.is_none() {
                tracing::info!(
                    "EDDA_SMTP_URL not set — email delivery (password reset, mention \
                     notifications) is disabled; in-app notifications still work"
                );
            }
            let mut handlers = edda_jobs::HandlerRegistry::new();
            handlers.register(edda_domain::JobKind::SendEmail, {
                let mailer = mailer.clone();
                move |payload| job_handlers::send_email(mailer.clone(), payload)
            });
            handlers.register(edda_domain::JobKind::CreateNotification, {
                let pool = pool.clone();
                move |payload| job_handlers::create_notification(pool.clone(), payload)
            });
            handlers.register(edda_domain::JobKind::DeliverWebhook, {
                let pool = pool.clone();
                move |payload| job_handlers::deliver_webhook(pool.clone(), payload)
            });
            edda_jobs::spawn_poller(
                pool.clone(),
                std::sync::Arc::new(handlers),
                edda_jobs::PollerConfig::default(),
            );

            // Same `Once`-guarded pattern as the shutdown watcher below,
            // and for the same reason: this callback can re-run on
            // dev-mode hot reload, and a second SSH listener must never
            // try to bind the same port again.
            ssh_server_started.call_once(|| {
                let ssh_state = edda_ssh::SshState {
                    pool,
                    store,
                    locks,
                    authz,
                };
                tokio::spawn(async move {
                    let ip: std::net::IpAddr = std::env::var("IP")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(std::net::IpAddr::from([127, 0, 0, 1]));
                    let port: u16 = std::env::var("EDDA_SSH_PORT")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(2222);
                    let data_dir = std::env::var("EDDA_DATA_DIR")
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|_| "./data".into());
                    let host_key_path = data_dir.join("ssh_host_ed25519_key");

                    tracing::info!(%ip, port, "starting git-over-SSH listener");
                    if let Err(err) = edda_ssh::serve(
                        ssh_state,
                        std::net::SocketAddr::from((ip, port)),
                        &host_key_path,
                    )
                    .await
                    {
                        tracing::error!(error = %err, "git-over-SSH listener stopped");
                    }
                });
            });

            shutdown_watcher_started.call_once(|| {
                let telemetry_guard = telemetry_guard.clone();
                tokio::spawn(async move {
                    wait_for_shutdown_signal().await;
                    tracing::info!("shutdown signal received, flushing telemetry");
                    if let Some(guard) = telemetry_guard.lock().await.take() {
                        guard.shutdown().await;
                    }
                    std::process::exit(0);
                });
            });

            Ok(router)
        }
    });
}

#[cfg(not(feature = "server"))]
fn main() {
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        Router::<Route> {}
    }
}

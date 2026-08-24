use dioxus::prelude::*;

mod server;
#[cfg(feature = "server")]
mod shared;
mod ui;

use ui::layouts::Navbar;
use ui::pages::{Home, Login, Repo, Signup};

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(Navbar)]
    #[route("/")]
    Home {},
    #[route("/:owner/:name")]
    Repo { owner: String, name: String },
    #[route("/signup")]
    Signup {},
    #[route("/login")]
    Login {},
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
/// one composition root (plan.local.md §3.3): every other crate is wired
/// together here, and nowhere else.
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

    dioxus::server::serve(move || {
        let telemetry_guard = telemetry_guard.clone();
        let shutdown_watcher_started = shutdown_watcher_started.clone();
        async move {
            let pool = edda_db::pool().await?;

            // Session cookies persist in the same SQLite database as everything
            // else — no separate store to run or lose track of.
            let session_store = tower_sessions_sqlx_store::SqliteStore::new(pool.clone());
            session_store.migrate().await?;
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
                pool,
                store,
                locks,
                authz,
                backend,
            };
            let router = dioxus::server::router(App)
                .merge(edda_http::router(state))
                .layer(auth_layer);

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

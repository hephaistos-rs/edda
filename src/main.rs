use dioxus::prelude::*;

#[cfg(feature = "server")]
mod api;
#[cfg(feature = "server")]
mod auth;
#[cfg(feature = "server")]
mod db;
#[cfg(feature = "server")]
mod git;
#[cfg(feature = "server")]
mod migrations;
mod server;
#[cfg(feature = "server")]
mod telemetry;
mod ui;

use ui::layouts::Navbar;
use ui::pages::{Blog, Home, Login, Repo, Signup};

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(Navbar)]
    #[route("/")]
    Home {},
    #[route("/repo/:name")]
    Repo { name: String },
    #[route("/blog/:id")]
    Blog { id: i32 },
    #[route("/signup")]
    Signup {},
    #[route("/login")]
    Login {},
}

const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

/// Dioxus server functions (`#[get]`/`#[post]` in `server/mod.rs`) can't
/// take `AuthSession` as a parameter — its macro only recognizes a fixed
/// extractor allowlist, not arbitrary `FromRequestParts` types (see
/// `auth::routes`, which exists for the same reason). So the repo
/// create/update/delete endpoints are gated here instead, at the router
/// level: any POST under `/api/repos` requires a logged-in session.
/// Must be layered *before* `auth_layer` below — layers apply outside-in for
/// requests in the order they're added, so `auth_layer` (which populates the
/// session/backend that `AuthSession` extraction reads) has to be the
/// outermost, i.e. the last `.layer()` call.
#[cfg(feature = "server")]
async fn require_login_for_repo_writes(
    auth: axum_login::AuthSession<auth::Backend>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let protected = req.method() == axum::http::Method::POST && req.uri().path().starts_with("/api/repos");
    if protected && auth.user.is_none() {
        return (axum::http::StatusCode::UNAUTHORIZED, "login required").into_response();
    }
    next.run(req).await
}

/// axum's `MatchedPath` extractor (the templated route, e.g.
/// `/api/repos/{name}`, not the raw request URL — required so neither the
/// HTTP span nor the `edda.http.server.request.duration` metric ever carries
/// a high-cardinality raw path) is only populated in request extensions
/// *after* a router has matched a route. That only happens for middleware
/// added via `Router::route_layer` (applied per-router, before merging) — a
/// middleware added via the outer `Router::layer` calls below (like
/// `auth_layer`) runs *before* routing and would never see it. So
/// observability is applied here, per sub-router, rather than as one more
/// `.layer()` alongside `auth_layer` below.
///
/// Trade-off this implies: a request rejected by `require_login_for_repo_writes`
/// or one that matches no route at all (a 404) short-circuits before reaching
/// any of these route-matched routers, so it isn't individually traced or
/// measured. Both are near-instant, no-real-work responses — not the
/// "why was this slow" cases this instrumentation exists to answer — so this
/// is an accepted gap rather than something worth restructuring the existing
/// auth-layering order for.
#[cfg(feature = "server")]
fn with_http_observability(router: axum::Router) -> axum::Router {
    use axum::extract::{MatchedPath, Request};
    use axum::http::Response;
    use axum::middleware::Next;
    use axum::response::Response as AxumResponse;
    use std::time::{Duration, Instant};
    use tower_http::trace::TraceLayer;

    async fn track_http_metrics(request: Request, next: Next) -> AxumResponse {
        let method = request.method().to_string();
        let route = request
            .extensions()
            .get::<MatchedPath>()
            .map(|matched| matched.as_str().to_string())
            .unwrap_or_else(|| "unmatched".to_string());
        let start = Instant::now();
        let response = next.run(request).await;
        telemetry::metrics::record_http_request(&method, &route, response.status().as_u16(), start.elapsed());
        response
    }

    router
        .route_layer(axum::middleware::from_fn(track_http_metrics))
        .route_layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request| {
                    let route = request.extensions().get::<MatchedPath>().map(MatchedPath::as_str).unwrap_or("unmatched");
                    tracing::info_span!(
                        "http.request",
                        "http.method" = %request.method(),
                        "http.route" = %route,
                        "http.status_code" = tracing::field::Empty,
                    )
                })
                .on_response(|response: &Response<axum::body::Body>, latency: Duration, span: &tracing::Span| {
                    span.record("http.status_code", response.status().as_u16());
                    tracing::debug!(parent: span, latency_ms = latency.as_millis() as u64, "request completed");
                }),
        )
}

/// Waits for either Ctrl-C or (on unix) SIGTERM — the two signals a process
/// manager / `docker stop` / an interactive terminal actually send.
#[cfg(feature = "server")]
async fn wait_for_shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let Ok(mut terminate) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) else {
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
/// merged with the git-http routes in `api`, which aren't server functions —
/// they need to speak raw git wire protocol, not typed RPC.
#[cfg(feature = "server")]
fn main() {
    // Must run before `dioxus::server::serve(...)` — it installs a default
    // `tracing` subscriber of its own unless one is already set. See
    // `telemetry`'s module docs for the full explanation.
    let telemetry_guard = telemetry::init();
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
            let pool = db::pool().await?;

            // Session cookies persist in the same SQLite database as everything
            // else — no separate store to run or lose track of.
            let session_store = tower_sessions_sqlx_store::SqliteStore::new(pool.clone());
            session_store.migrate().await?;
            let session_layer = tower_sessions::SessionManagerLayer::new(session_store);

            let backend = auth::Backend::new(pool.clone());
            let auth_layer = axum_login::AuthManagerLayerBuilder::new(backend, session_layer).build();

            let router = with_http_observability(dioxus::server::router(App))
                .merge(with_http_observability(api::routes()))
                .merge(with_http_observability(auth::routes::routes()))
                .layer(axum::middleware::from_fn(require_login_for_repo_writes))
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

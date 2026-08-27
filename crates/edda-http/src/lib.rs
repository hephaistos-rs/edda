//! The axum application: git smart-HTTP bridge, account/token routes,
//! collaborator routes, and cross-cutting middleware. See this crate's
//! `Cargo.toml` doc comment.

mod access_routes;
mod admin_routes;
mod api_v1;
mod auth_routes;
pub mod config;
mod git_http;
mod lfs;
mod oauth_routes;
mod rate_limit;
mod release_assets;
mod ssh_key_routes;
mod state;
mod webauthn_routes;

pub use state::{AppState, RuntimeConfig};

use axum::extract::{MatchedPath, Request, State};
use axum::http::{Response as HttpResponse, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::time::{Duration, Instant};
use tower_http::trace::TraceLayer;

/// The complete `edda-http` surface, merged and instrumented, ready to be
/// `.merge()`d with Dioxus's own router and wrapped in the session/auth
/// layer by the composition root (`edda-web`).
///
/// Rate limiting (`rate_limit`) applies to every route here *except* the
/// git smart-HTTP bridge and LFS — real `git`/`git-lfs` clients routinely
/// issue several requests in quick succession as ordinary protocol
/// behavior, not abuse, and throttling that traffic would be a
/// git-compatibility hazard. `.route_layer(...)`, not `.layer(...)`, for the same
/// reason `with_http_observability` below already uses it: applied before
/// merging the exempt routes in, so it only ever wraps a route that
/// actually matched inside this half of the router.
pub fn router(state: AppState) -> Router {
    let rate_limited = Router::new()
        .merge(auth_routes::routes())
        .merge(oauth_routes::routes())
        .merge(webauthn_routes::routes())
        .merge(access_routes::routes())
        .merge(ssh_key_routes::routes())
        .merge(admin_routes::routes())
        .merge(release_assets::routes())
        .merge(api_v1::routes())
        .route_layer(rate_limit::layer(&state.config.rate_limit));

    let routes = Router::new()
        .merge(git_http::routes())
        .merge(lfs::routes())
        .merge(rate_limited)
        .route("/healthz", get(healthz));

    with_http_observability(routes).with_state(state)
}

async fn healthz(State(state): State<AppState>) -> Response {
    match edda_db::health(&state.pool).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(err) => (StatusCode::SERVICE_UNAVAILABLE, err.to_string()).into_response(),
    }
}

/// axum's `MatchedPath` extractor (the templated route, e.g.
/// `/api/repos/{name}`, not the raw request URL — required so neither the
/// HTTP span nor the `edda.http.server.request.duration` metric ever
/// carries a high-cardinality raw path) is only populated in request
/// extensions *after* a router has matched a route. That only happens for
/// middleware added via `Router::route_layer` (applied before the outer
/// session/auth layer wraps everything) — a middleware added via
/// `Router::layer` outside this function would run before routing and
/// never see it.
///
/// Trade-off this implies: a request that matches no route at all (a 404)
/// short-circuits before reaching this middleware, so it isn't
/// individually traced or measured. That's a near-instant, no-real-work
/// response — not the "why was this slow" case this instrumentation
/// exists to answer — so this is an accepted gap, not an oversight.
fn with_http_observability(router: Router<AppState>) -> Router<AppState> {
    async fn track_http_metrics(request: Request, next: Next) -> Response {
        let method = request.method().to_string();
        let route = request
            .extensions()
            .get::<MatchedPath>()
            .map(|matched| matched.as_str().to_string())
            .unwrap_or_else(|| "unmatched".to_string());
        let start = Instant::now();
        let response = next.run(request).await;
        edda_telemetry::metrics::record_http_request(
            &method,
            &route,
            response.status().as_u16(),
            start.elapsed(),
        );
        response
    }

    router.route_layer(axum::middleware::from_fn(track_http_metrics)).route_layer(
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
            .on_response(|response: &HttpResponse<axum::body::Body>, latency: Duration, span: &tracing::Span| {
                span.record("http.status_code", response.status().as_u16());
                tracing::debug!(parent: span, latency_ms = latency.as_millis() as u64, "request completed");
            }),
    )
}

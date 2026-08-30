//! `GET /metrics` — a small Prometheus text-exposition endpoint (Phase
//! 12), token-gated with `EDDA_METRICS_TOKEN`.
//!
//! Everything here is a gauge computed at scrape time from a handful of
//! cheap aggregate queries — there is no in-process metrics recorder to
//! keep in sync, and no cardinality risk (no metric carries a
//! repository, user, or path label). The request/git/job *duration*
//! histograms are a separate concern: they export over OTLP from
//! `edda-telemetry`, not here.
//!
//! The endpoint sits outside the `/api/v1` router — no `Actor`, no CSRF
//! origin check, no rate limiting — because a scraper is not a browser
//! and authenticates with its own bearer token. When `EDDA_METRICS_TOKEN`
//! is unset the route answers 404: metrics are never exposed
//! unauthenticated.

use std::fmt::Write as _;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/metrics", get(metrics))
}

#[derive(serde::Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

/// Bearer token from `Authorization`, else `?token=`.
fn presented_token(headers: &HeaderMap, query: &TokenQuery) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_string)
        .or_else(|| query.token.clone())
}

fn tokens_match(expected: &str, presented: &str) -> bool {
    // Length-then-constant-time-ish byte compare — a metrics token is a
    // deployment secret, not a password, but there is no reason to leak
    // its length or a prefix match through timing.
    if expected.len() != presented.len() {
        return false;
    }
    expected
        .bytes()
        .zip(presented.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[tracing::instrument(name = "metrics.scrape", skip_all)]
async fn metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> Response {
    let Some(expected) = state.config.metrics_token.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match presented_token(&headers, &query) {
        Some(presented) if tokens_match(expected, &presented) => {}
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                [(
                    axum::http::header::WWW_AUTHENTICATE,
                    "Bearer realm=\"edda-metrics\"",
                )],
                "a valid EDDA_METRICS_TOKEN bearer token is required",
            )
                .into_response()
        }
    }

    match render(&state).await {
        Ok(body) => (
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            body,
        )
            .into_response(),
        Err(err) => {
            tracing::warn!(error = %err, "failed to gather metrics");
            (StatusCode::INTERNAL_SERVER_ERROR, "metrics unavailable").into_response()
        }
    }
}

async fn render(state: &AppState) -> Result<String, edda_db::DbError> {
    let (pool_open, pool_idle) = edda_db::pool_stats(&state.pool);
    let (jobs_pending, jobs_running, jobs_dead) =
        edda_db::JobRepo::queue_depths(&state.pool).await?;
    let oldest_pending = edda_db::JobRepo::oldest_pending_run_at(&state.pool).await?;
    let (webhook_total, webhook_failed) = edda_db::WebhookDeliveryRepo::totals(&state.pool).await?;
    let stats = edda_db::AdminStatsRepo::snapshot(&state.pool).await?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let oldest_pending_age = oldest_pending.map_or(0, |run_at| (now - run_at).max(0));

    let mut out = String::with_capacity(2048);
    let mut gauge = |name: &str, help: &str, value: i64| {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} gauge");
        let _ = writeln!(out, "{name} {value}");
    };

    gauge(
        "edda_db_pool_connections",
        "Open connections in the database pool.",
        i64::from(pool_open),
    );
    gauge(
        "edda_db_pool_connections_idle",
        "Idle connections in the database pool.",
        i64::try_from(pool_idle).unwrap_or(i64::MAX),
    );
    gauge("edda_jobs_pending", "Jobs waiting to run.", jobs_pending);
    gauge(
        "edda_jobs_running",
        "Jobs currently executing.",
        jobs_running,
    );
    gauge(
        "edda_jobs_dead",
        "Jobs that exhausted their retry budget.",
        jobs_dead,
    );
    gauge(
        "edda_jobs_oldest_pending_age_seconds",
        "Age of the oldest still-pending job; 0 when the queue is empty.",
        oldest_pending_age,
    );
    gauge(
        "edda_webhook_deliveries_total",
        "Webhook delivery attempts recorded, all time.",
        webhook_total,
    );
    gauge(
        "edda_webhook_deliveries_failed",
        "Recorded delivery attempts that never reached a 2xx.",
        webhook_failed,
    );
    gauge("edda_users", "Registered user accounts.", stats.users);
    gauge("edda_repositories", "Repositories.", stats.repositories);
    gauge("edda_organizations", "Organizations.", stats.organizations);
    gauge(
        "edda_open_pull_requests",
        "Pull requests in the open or draft state.",
        stats.open_pull_requests,
    );
    gauge(
        "edda_open_issues",
        "Issues in the open state.",
        stats.open_issues,
    );
    gauge(
        "edda_repository_git_bytes",
        "Sum of last-measured git directory sizes.",
        stats.tracked_git_bytes,
    );
    gauge(
        "edda_repository_lfs_bytes",
        "Sum of last-measured LFS storage sizes.",
        stats.tracked_lfs_bytes,
    );

    Ok(out)
}

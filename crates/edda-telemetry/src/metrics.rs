//! A deliberately small metrics surface: two histograms, nothing else.
//!
//! No generic error/failure counter — HTTP status codes (an attribute here
//! already), `tracing` span ERROR events (via `#[tracing::instrument(err)]`
//! on fallible instrumented functions), and sqlx's own query-failure
//! logging already answer "did something fail and why" without a redundant,
//! low-information counter duplicating them.
//!
//! No database duration metric — sqlx already emits a `tracing` event with
//! per-query duration; a custom histogram around every `sqlx::query!` call
//! would just duplicate that.
//!
//! Neither histogram ever carries a repository name or id as an attribute —
//! only `operation`/`status`/`http.route`/`http.method`/`http.status_code`,
//! all low-cardinality by construction. Repository identity, where it
//! appears at all, lives on `tracing` span fields, never here (see the
//! `repo.name` comments in `server/mod.rs` and `git/mod.rs`).

use std::sync::OnceLock;
use std::time::Duration;

use opentelemetry::metrics::{Histogram, Meter};
use opentelemetry::KeyValue;

struct Instruments {
    http_request_duration: Histogram<f64>,
    git_operation_duration: Histogram<f64>,
}

static INSTRUMENTS: OnceLock<Instruments> = OnceLock::new();

/// Called once from `telemetry::init` when OTel export is enabled. When it's
/// never called (telemetry disabled), `record_*` below are no-ops — callers
/// never need to check whether telemetry is on.
pub fn install(meter: &Meter) {
    let http_request_duration = meter
        .f64_histogram("edda.http.server.request.duration")
        .with_unit("ms")
        .with_description("Duration of HTTP requests served by Edda.")
        .build();
    let git_operation_duration = meter
        .f64_histogram("edda.git.operation.duration")
        .with_unit("ms")
        .with_description("Duration of git object-store operations (open, resolve, read, pack).")
        .build();
    let _ = INSTRUMENTS.set(Instruments {
        http_request_duration,
        git_operation_duration,
    });
}

/// `route` must already be a templated route pattern (e.g. `/api/repos/{name}`),
/// not a raw request path — callers get this for free from axum's
/// `MatchedPath` extractor. Never pass a raw URL here.
pub fn record_http_request(method: &str, route: &str, status: u16, duration: Duration) {
    let Some(instruments) = INSTRUMENTS.get() else {
        return;
    };
    instruments.http_request_duration.record(
        duration.as_secs_f64() * 1000.0,
        &[
            KeyValue::new("http.method", method.to_string()),
            KeyValue::new("http.route", route.to_string()),
            KeyValue::new("http.status_code", status as i64),
        ],
    );
}

pub fn record_git_operation(operation: &'static str, status: &'static str, duration: Duration) {
    let Some(instruments) = INSTRUMENTS.get() else {
        return;
    };
    instruments.git_operation_duration.record(
        duration.as_secs_f64() * 1000.0,
        &[
            KeyValue::new("operation", operation),
            KeyValue::new("status", status),
        ],
    );
}

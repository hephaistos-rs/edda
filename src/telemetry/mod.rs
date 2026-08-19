//! Edda's single centralized observability entry point.
//!
//! `tracing` (structured logs + spans) is *always* active — it's the
//! application's own instrumentation API and doesn't depend on
//! OpenTelemetry at all. OpenTelemetry export is a separate, additive layer
//! on top: enabled only when an OTLP endpoint is explicitly configured (and
//! not force-disabled via `OTEL_SDK_DISABLED`), so a default install never
//! attempts a network connection to anywhere — not even the OTel spec's own
//! default `localhost:4318` — on its own.
//!
//! # Why this has to run before `dioxus::server::serve(...)`
//!
//! `dioxus::server::serve()` internally calls `dioxus_logger::initialize_default()`,
//! which installs a plain `fmt` subscriber as the global `tracing` dispatcher
//! *unless one has already been installed* (`tracing::dispatcher::has_been_set()`).
//! `tracing::subscriber::set_global_default` only succeeds once per process, so
//! [`init`] must run synchronously at the very top of `main()`, before
//! `dioxus::server::serve(...)` is called — otherwise Dioxus's own default
//! logger claims the slot first and this module's OpenTelemetry layer never
//! gets installed.

pub mod config;
pub mod metrics;

use std::time::Duration;

use opentelemetry::metrics::MeterProvider as _;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{LogExporter, MetricExporter, SpanExporter};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing::Subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{fmt, EnvFilter, Layer};

use config::{Config, LogFormat};

/// Returned by [`init`]; holds the OTel providers (if telemetry export is
/// enabled) so they can be flushed on shutdown. Dropping this without calling
/// [`TelemetryGuard::shutdown`] just stops exporting — it does not panic or
/// leak resources beyond the process's own lifetime.
pub struct TelemetryGuard {
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
    logger_provider: Option<SdkLoggerProvider>,
}

impl TelemetryGuard {
    /// Flushes pending spans/metrics/logs with a bounded timeout per
    /// provider — an unreachable collector must never hang process shutdown.
    pub async fn shutdown(self) {
        const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

        async fn shutdown_one<P, E>(name: &'static str, provider: Option<P>, shutdown: impl FnOnce(P) -> Result<(), E> + Send + 'static)
        where
            P: Send + 'static,
            E: std::fmt::Display + Send + 'static,
        {
            let Some(provider) = provider else { return };
            match tokio::time::timeout(SHUTDOWN_TIMEOUT, tokio::task::spawn_blocking(move || shutdown(provider))).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(err))) => tracing::warn!(provider = name, error = %err, "exporter shutdown reported an error"),
                Ok(Err(_)) => tracing::warn!(provider = name, "exporter shutdown task panicked"),
                Err(_) => tracing::warn!(provider = name, timeout = ?SHUTDOWN_TIMEOUT, "exporter shutdown timed out"),
            }
        }

        shutdown_one("trace", self.tracer_provider, |p| p.shutdown()).await;
        shutdown_one("metric", self.meter_provider, |p| p.shutdown()).await;
        shutdown_one("log", self.logger_provider, |p| p.shutdown()).await;
    }
}

/// Installs the global `tracing` subscriber. Must be called exactly once, as
/// the first statement of `main()`, before any other Edda or Dioxus code runs.
pub fn init() -> TelemetryGuard {
    let config = Config::from_env();

    let default_level = if cfg!(debug_assertions) { tracing::Level::DEBUG } else { tracing::Level::INFO };
    let env_filter = EnvFilter::builder()
        .with_default_directive(default_level.into())
        .from_env_lossy()
        // hyper has `debug!` events sitting around in some places that are
        // spammy at Edda's own default debug level — same directive
        // dioxus-logger itself adds for the same reason.
        .add_directive("hyper_util=warn".parse().expect("valid directive"));

    // `fmt::layer().json()` and `.pretty()` are different concrete types even
    // though both implement `Layer<S>` generically over `S` — `build_fmt_layer`
    // erases just that "which formatter" axis via a boxed trait object, while
    // its own `S` type parameter stays generic, so it unifies correctly with
    // whatever concrete subscriber type it ends up `.with()`'d onto.
    let fmt_layer = build_fmt_layer(config.log_format());
    let registry = tracing_subscriber::registry().with(env_filter).with(fmt_layer);

    if config.otel_enabled() {
        if let Some(guard) = build_otel_and_install(registry, &config) {
            return guard;
        }
        // `build_otel_and_install` only returns `None` if it never got as
        // far as installing a subscriber (exporter construction failed) —
        // fall through to installing the plain local one below so the app
        // still gets structured logging even when OTel is misconfigured.
        let env_filter_fallback = EnvFilter::builder().with_default_directive(default_level.into()).from_env_lossy();
        let fallback = tracing_subscriber::registry().with(env_filter_fallback).with(build_fmt_layer(config.log_format()));
        install_subscriber(fallback);
        return TelemetryGuard { tracer_provider: None, meter_provider: None, logger_provider: None };
    }

    install_subscriber(registry);
    TelemetryGuard { tracer_provider: None, meter_provider: None, logger_provider: None }
}

fn install_subscriber<S>(subscriber: S)
where
    S: Subscriber + Send + Sync + 'static,
{
    if tracing::subscriber::set_global_default(subscriber).is_err() {
        // Pre-subscriber-install: nothing is listening for `tracing` events
        // yet, so this genuinely needs eprintln rather than a `tracing` call.
        eprintln!(
            "edda: a tracing subscriber was already installed before telemetry::init() ran — \
             this should not happen if init() is called first in main(); telemetry may be misconfigured"
        );
    }
}

/// Boxes whichever formatter `LogFormat` selects behind one common type.
/// Generic over `S` (rather than fixed to a concrete subscriber type) so it
/// can be `.with()`'d at any position in the layer stack.
fn build_fmt_layer<S>(format: LogFormat) -> Box<dyn Layer<S> + Send + Sync>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    match format {
        LogFormat::Json => Box::new(fmt::layer().json().with_current_span(true).with_span_list(false)),
        LogFormat::Pretty => Box::new(fmt::layer().pretty()),
    }
}

/// Builds the OTLP exporters and OTel providers, adds their bridging
/// `tracing` layers (trace spans + the `tracing`-events-as-OTel-logs bridge,
/// which is what makes a log line carry the active `trace_id` for
/// correlation) on top of `registry`, and installs the result as the global
/// subscriber — all in one generic function so none of these layers' fairly
/// unwieldy concrete types ever need to be named outside the scope they're
/// constructed in.
///
/// Returns `None` (never having installed anything) only if an exporter
/// failed to construct — e.g. a malformed endpoint URL. Misconfigured
/// telemetry must degrade to "no OTel export," never take the app down or
/// leave it with no subscriber installed at all.
fn build_otel_and_install<S>(registry: S, config: &Config) -> Option<TelemetryGuard>
where
    S: Subscriber + for<'span> LookupSpan<'span> + Send + Sync + 'static,
{
    // No `.with_endpoint(...)`/`.with_protocol(...)` calls here on purpose:
    // the exporter builders already read `OTEL_EXPORTER_OTLP_ENDPOINT` (or
    // the signal-specific variants), `_HEADERS`, `_TIMEOUT`, `_COMPRESSION`
    // themselves — reimplementing that parsing would just duplicate it.
    //
    // These exporters use `opentelemetry-otlp`'s `reqwest-blocking-client`
    // feature — its default, and deliberately not the async `reqwest-client`
    // despite that looking like the "correct" non-blocking choice at a
    // glance. Read the actual SDK source (`opentelemetry_sdk-0.32.1/src/logs/
    // batch_log_processor.rs`) to confirm before assuming otherwise: each
    // signal's batch/periodic processor runs on its own dedicated
    // `std::thread` (named e.g. "OpenTelemetry.Logs.BatchProcessor"), never
    // as a task on Edda's own Tokio runtime, and drives its export via
    // `futures_executor::block_on` — a plain futures executor with no Tokio
    // reactor/timer/IO driver of its own. An async `reqwest` client's
    // request there panics at export time ("there is no reactor running,
    // must be called from the context of a Tokio 1.x runtime") the moment it
    // touches real I/O — confirmed live, not just in theory. The blocking
    // client carries its own self-contained runtime, so it works from this
    // thread regardless, and — crucially — it never blocks anything of
    // Edda's own, since this thread was never part of Edda's async request-
    // handling capacity to begin with.
    let span_exporter = SpanExporter::builder().with_http().build().inspect_err(|err| {
        eprintln!("edda: failed to configure OTLP trace exporter, continuing without OpenTelemetry export: {err}");
    }).ok()?;
    let metric_exporter = MetricExporter::builder().with_http().build().inspect_err(|err| {
        eprintln!("edda: failed to configure OTLP metric exporter, continuing without OpenTelemetry export: {err}");
    }).ok()?;
    let log_exporter = LogExporter::builder().with_http().build().inspect_err(|err| {
        eprintln!("edda: failed to configure OTLP log exporter, continuing without OpenTelemetry export: {err}");
    }).ok()?;

    let resource = build_resource(config);

    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_sampler(config.sampler())
        .with_batch_exporter(span_exporter)
        .build();
    let meter_provider =
        SdkMeterProvider::builder().with_resource(resource.clone()).with_periodic_exporter(metric_exporter).build();
    let logger_provider = SdkLoggerProvider::builder().with_resource(resource).with_batch_exporter(log_exporter).build();

    opentelemetry::global::set_tracer_provider(tracer_provider.clone());
    opentelemetry::global::set_meter_provider(meter_provider.clone());
    metrics::install(&meter_provider.meter("edda"));

    let tracer = tracer_provider.tracer("edda");
    let trace_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let log_layer = OpenTelemetryTracingBridge::new(&logger_provider);

    install_subscriber(registry.with(trace_layer).with(log_layer));

    Some(TelemetryGuard {
        tracer_provider: Some(tracer_provider),
        meter_provider: Some(meter_provider),
        logger_provider: Some(logger_provider),
    })
}

/// See `Config`'s doc comments: each attribute here is sourced from exactly
/// one place (either our default, or the env-backed detector) to sidestep an
/// undocumented precedence question between the two.
fn build_resource(config: &Config) -> Resource {
    let mut builder = Resource::builder();
    if let Some(name) = config.default_service_name {
        builder = builder.with_service_name(name);
    }

    let mut attributes = vec![KeyValue::new("service.version", config.service_version.clone())];
    if let Some(environment) = config.default_environment {
        attributes.push(KeyValue::new("deployment.environment.name", environment));
    }

    builder.with_attributes(attributes).build()
}

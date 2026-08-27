//! Parses the standard `OTEL_*` environment variables. Kept deliberately thin:
//! anywhere the current `opentelemetry`/`opentelemetry_sdk`/`opentelemetry-otlp`
//! crates already parse a variable themselves (endpoint/headers/timeout via
//! `WithExportConfig`, `OTEL_SERVICE_NAME`/`OTEL_RESOURCE_ATTRIBUTES` via
//! `Resource::builder()`'s built-in `EnvResourceDetector`), this module leaves
//! it alone rather than re-implementing it. It only handles the handful of
//! things verified (via docs.rs, at implementation time) to have no built-in
//! support: whether an OTLP endpoint was configured at all, the trace
//! sampler, and the two resource attributes (`service.version`,
//! `deployment.environment.name`) that aren't real OTel spec env vars or
//! aren't covered by a dedicated detector.

use std::env;

use opentelemetry_sdk::trace::Sampler;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Pretty,
    Json,
}

pub struct Config {
    /// `Some("edda")` only when `OTEL_SERVICE_NAME` is unset — when it *is*
    /// set, this stays `None` so the env-sourced value is the only source of
    /// truth for `service.name` (see `telemetry::mod` for why: avoids relying
    /// on undocumented precedence between an explicit builder call and
    /// `EnvResourceDetector`).
    pub default_service_name: Option<&'static str>,
    /// `OTEL_SERVICE_VERSION` isn't an OTel spec env var — nothing detects it
    /// automatically, so this is always resolved here, falling back to the
    /// crate's own version.
    pub service_version: String,
    /// `Some(default)` only when `OTEL_RESOURCE_ATTRIBUTES` doesn't already
    /// mention `deployment.environment.name` — same single-source reasoning
    /// as `default_service_name`.
    pub default_environment: Option<&'static str>,
    otlp_configured: bool,
    sdk_disabled: bool,
}

impl Config {
    pub fn from_env() -> Self {
        let default_service_name = if env_is_set("OTEL_SERVICE_NAME") {
            None
        } else {
            Some("edda")
        };

        let service_version = env::var("OTEL_SERVICE_VERSION")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

        let resource_attributes = env::var("OTEL_RESOURCE_ATTRIBUTES").unwrap_or_default();
        let default_environment = if resource_attributes.contains("deployment.environment.name") {
            None
        } else if cfg!(debug_assertions) {
            Some("development")
        } else {
            Some("production")
        };

        // No OTel crate exposes "was an OTLP endpoint actually configured" —
        // confirmed via docs.rs, `WithExportConfig` only documents setting
        // one, not querying whether one is set. Checking these three
        // ourselves is the one genuinely manual piece of config parsing here.
        let otlp_configured = env_is_set("OTEL_EXPORTER_OTLP_ENDPOINT")
            || env_is_set("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
            || env_is_set("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT");

        let sdk_disabled = env::var("OTEL_SDK_DISABLED")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            default_service_name,
            service_version,
            default_environment,
            otlp_configured,
            sdk_disabled,
        }
    }

    /// `OTEL_SDK_DISABLED=true` always wins, even over an explicitly
    /// configured endpoint. Otherwise, OTLP export is only attempted when an
    /// endpoint was actually configured — this app never probes a
    /// spec-default or hardcoded address on its own.
    pub fn otel_enabled(&self) -> bool {
        self.otlp_configured && !self.sdk_disabled
    }

    pub fn log_format(&self) -> LogFormat {
        match env::var("EDDA_LOG_FORMAT") {
            Ok(v) if v.eq_ignore_ascii_case("json") => LogFormat::Json,
            Ok(v) if v.eq_ignore_ascii_case("pretty") => LogFormat::Pretty,
            _ => {
                if cfg!(debug_assertions) {
                    LogFormat::Pretty
                } else {
                    LogFormat::Json
                }
            }
        }
    }

    /// `opentelemetry_sdk::trace::Sampler` has no `OTEL_TRACES_SAMPLER`
    /// auto-parsing (confirmed via docs.rs) — this is the manual parsing the
    /// spec variable genuinely requires. Falls back to a sensible default
    /// (not 100% unconditionally) rather than an error on an unrecognized
    /// value.
    pub fn sampler(&self) -> Sampler {
        let arg = || {
            env::var("OTEL_TRACES_SAMPLER_ARG")
                .ok()
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(1.0)
        };

        match env::var("OTEL_TRACES_SAMPLER").ok().as_deref() {
            Some("always_on") => Sampler::AlwaysOn,
            Some("always_off") => Sampler::AlwaysOff,
            Some("traceidratio") => Sampler::TraceIdRatioBased(arg()),
            Some("parentbased_always_on") => Sampler::ParentBased(Box::new(Sampler::AlwaysOn)),
            Some("parentbased_always_off") => Sampler::ParentBased(Box::new(Sampler::AlwaysOff)),
            Some("parentbased_traceidratio") => {
                Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(arg())))
            }
            // Unset or unrecognized: fall back to a traffic-appropriate
            // default rather than error out. Edda is a self-hosted,
            // human-scale-traffic tool, not a high-QPS service — 20% in
            // release builds is a reasonable non-zero starting point, not a
            // scale assumption, and it's fully overridable by setting the
            // two env vars above explicitly.
            _ => {
                if cfg!(debug_assertions) {
                    Sampler::AlwaysOn
                } else {
                    Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(0.2)))
                }
            }
        }
    }
}

fn env_is_set(key: &str) -> bool {
    env::var(key).map(|v| !v.is_empty()).unwrap_or(false)
}

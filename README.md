# Development

Your new bare-bones project includes minimal organization with a single `main.rs` file and a few assets.

```
project/
├─ assets/ # Any assets that are used by the app should be placed here
├─ src/
│  ├─ main.rs # main.rs is the entry point to your application and currently contains all components for the app
├─ Cargo.toml # The Cargo.toml file defines the dependencies and feature flags for your project
```

### Automatic Tailwind (Dioxus 0.7+)

As of Dioxus 0.7, there no longer is a need to manually install tailwind. Simply `dx serve` and you're good to go!

Automatic tailwind is supported by checking for a file called `tailwind.css` in your app's manifest directory (next to Cargo.toml). To customize the file, use the dioxus.toml:

```toml
[application]
tailwind_input = "my.css"
tailwind_output = "assets/out.css" # also customize the location of the out file!
```

### Tailwind Manual Install

To use tailwind plugins or manually customize tailwind, you can can install the Tailwind CLI and use it directly.

### Tailwind
1. Install npm: https://docs.npmjs.com/downloading-and-installing-node-js-and-npm
2. Install the Tailwind CSS CLI: https://tailwindcss.com/docs/installation/tailwind-cli
3. Run the following command in the root of the project to start the Tailwind CSS compiler:

```bash
npx @tailwindcss/cli -i ./input.css -o ./assets/tailwind.css --watch
```

### Serving Your App

Run the following command in the root of your project to start developing with the default platform:

```bash
dx serve --platform web
```

To run for a different platform, use the `--platform platform` flag. E.g.
```bash
dx serve --platform desktop
```

## Observability

The `server` build (`cargo run --features server` / `dx serve` with the server feature) is instrumented with [`tracing`](https://docs.rs/tracing) throughout, with an optional [OpenTelemetry](https://opentelemetry.io/) export path layered on top. Everything below is server-only — the wasm/web client build is untouched and carries none of these dependencies.

### What Edda produces

- **Structured logs**: every request, and the meaningful operations inside it (`repository.get`, `git.read_tree`, `authentication.login`, ...) emit structured `tracing` events, printed to stdout — pretty-printed in debug builds, JSON in release builds (override with `EDDA_LOG_FORMAT=pretty|json`).
- **Distributed traces**: nested spans following the real work a request does, e.g. `HTTP GET /api/repos/{name}/commits` → `repository.commits` → `git.open` → `git.resolve_revision` → `git.read_commit_log`. Git object-store operations (`gix`), server functions, and the raw git-HTTP clone/push bridge are all instrumented; SQLite query timing comes from `sqlx`'s own built-in `tracing` instrumentation rather than a redundant custom wrapper.
- **Metrics**: two histograms only, `edda.http.server.request.duration` and `edda.git.operation.duration`, both with low-cardinality attributes (`operation`/`status`/`http.route`/`http.method`/`http.status_code` — never a repository name or id).
- **Log/trace correlation**: when OTel export is enabled, `tracing` events are bridged to OTel logs and automatically carry the active `trace_id`/`span_id`, so a log line in Grafana/Loki links straight to its trace in Tempo.

### Enabling OpenTelemetry export

`tracing`/structured logging is always on. OTLP export is a separate, additive layer with three states:

| Configuration | Behavior |
| --- | --- |
| Nothing set | Local structured logging only. **No network connection is attempted anywhere** — not even to the OTel spec's own default `localhost:4318`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` (or a signal-specific `_TRACES_ENDPOINT`/`_METRICS_ENDPOINT`) set | Local logging **and** OTLP export (HTTP/protobuf) to that endpoint. |
| `OTEL_SDK_DISABLED=true` | OTel export forced off, even if an endpoint is also configured. Local logging is unaffected. |

Standard OpenTelemetry environment variables are supported, mostly via the underlying SDK's own built-in parsing (not reimplemented here):

- `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`
- `OTEL_SERVICE_NAME` (default: `edda`), `OTEL_RESOURCE_ATTRIBUTES`
- `OTEL_SERVICE_VERSION` (not a real OTel spec variable, but supported here; defaults to the crate version)
- `OTEL_TRACES_SAMPLER` / `OTEL_TRACES_SAMPLER_ARG` — supports `always_on`, `always_off`, `traceidratio`, `parentbased_always_on`, `parentbased_always_off`, `parentbased_traceidratio`. Default when unset: `always_on` in debug builds, `parentbased_traceidratio` at 20% in release builds.
- `OTEL_SDK_DISABLED`
- `EDDA_LOG_FORMAT=pretty|json` (Edda-specific, not an OTel variable) to override the debug/release log-format default.

Only OTLP over HTTP/protobuf is implemented (the OTel spec's own default protocol) — `OTEL_EXPORTER_OTLP_PROTOCOL=http/json` and gRPC/`tonic` transport are not wired up.

### Running the local stack

```bash
docker compose -f compose.otel.yml up
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 cargo run --features server
```

Then open **http://localhost:3000** (Grafana, no login required) and use the "Explore" view against the Tempo, Loki, or Prometheus data sources — all three are pre-configured. A convenient way to find a trace: search Loki for a log line from the request you care about, then follow its `trace_id` into Tempo.

To stop and remove the stack: `docker compose -f compose.otel.yml down`.

### Production OTLP configuration

Point `OTEL_EXPORTER_OTLP_ENDPOINT` at your OpenTelemetry Collector (never at a specific backend directly — the Collector is the backend-neutral boundary; Edda's own code has no Jaeger/Prometheus/Loki-specific dependencies) and set a real `OTEL_TRACES_SAMPLER_ARG` for your traffic volume. Set `OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=production` (or similar) to distinguish environments in your backend.

### What Edda deliberately never emits

Passwords, password hashes, session tokens/cookies, `Authorization` headers, personal access tokens (only a user-chosen *label* like `authentication.token.create`'s `token.name` field is recorded, never the token value), private repository file contents, or raw request bodies. Repository names appear as `tracing` span fields (there's no internal repository id to prefer — audited: no `repos` table exists) but never as a metric label. SQL statement text may appear in `sqlx`'s own query-timing logs; it's always parameterized, never bound values.

### Known limitations

- gRPC/OTLP transport and `http/json` protocol switching aren't implemented (HTTP/protobuf only).
- W3C trace-context propagation isn't wired up — Edda makes no outbound HTTP calls to other services today, so there's nothing to propagate a `traceparent` to.
- A request rejected by the login-required middleware, or one matching no route at all (a 404), isn't individually traced or measured — see the comment on `with_http_observability` in `src/main.rs` for why (axum's `MatchedPath`, needed to avoid a high-cardinality route label, is only available to middleware applied *after* routing).
- `dioxus::server::serve()` never returns and exposes no graceful-shutdown hook of its own; Edda works around this with its own Ctrl-C/SIGTERM watcher rather than relying on one.



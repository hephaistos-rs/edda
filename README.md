# Edda

Self-hosted git platform with a terminal-native, developer-console interface. Host and browse your own repositories — clone and push with a normal `git` client — without depending on GitHub, GitLab, or any other third-party hosting.

Built for solo developers and small teams who want full control and privacy over their code. Deployment is deliberately low-friction: a single self-contained binary, SQLite for storage, and nothing external required to get running.

## Features

- **Real git hosting** — a git smart-HTTP implementation (built directly on [`gix`](https://github.com/GitoxideLabs/gitoxide), no `git` subprocess) serves clone and push over plain HTTP.
- **Web UI** — repository listing with search, file/tree browsing, file viewing, and commit history, in a dense, keyboard-first interface (see `DESIGN.md`).
- **Accounts and access** — email/password signup and login, plus revocable personal access tokens for authenticating `git push`/`git clone` over HTTP.
- **Single-binary deploy** — SQLite-backed, no required external services (no mandatory Postgres, Redis, etc.).
- **Built-in observability** — structured logs, distributed traces, and metrics out of the box, exportable via OpenTelemetry (see [Observability](#observability)).

## Status

Early and actively developed. Core git hosting, repository browsing, and authentication work end to end; feature scope beyond that (pull requests, issues, CI, etc.) isn't decided yet.

## Quick start

```bash
cp .env.example .env
cargo run --features server
```

Edda listens on `127.0.0.1:8080` by default and serves the web UI there. Repository data and the SQLite database live under `./data` by default.

Clone a repository hosted on this instance the normal way:

```bash
git clone http://127.0.0.1:8080/<repo-name>.git
```

Pushing over HTTP requires being logged in (a browser session cookie) or a personal access token (created from the UI, sent as the HTTP Basic password).

### Configuration

Runtime behavior is controlled by environment variables — none of them are read from `.env` by the running binary itself (see `.env.example`'s top comment for why). At minimum:

| Variable        | Default              | Purpose                                             |
| --------------- | -------------------- | --------------------------------------------------- |
| `EDDA_DATA_DIR` | `./data`             | Where repository data and the SQLite database live. |
| `IP` / `PORT`   | `127.0.0.1` / `8080` | Address the server binds to.                        |

See `.env.example` for the full list, including the observability variables documented below.

## Development

First-time setup: `cp .env.example .env` — needed for `sqlx`'s query macros to use the committed `.sqlx/` cache instead of requiring a live database at build time.

```bash
dx serve --platform web
```

runs the client/server dev loop with hot reload. Use `--platform desktop` to run it as a desktop app instead. Tailwind is compiled automatically as of Dioxus 0.7 — no separate Tailwind install needed unless you want to customize the input/output paths (see `dioxus.toml`) or use Tailwind plugins, in which case install the [Tailwind CLI](https://tailwindcss.com/docs/installation/tailwind-cli) and run it directly:

```bash
npx @tailwindcss/cli -i ./input.css -o ./assets/tailwind.css --watch
```

### Project layout

```
src/
├─ main.rs        # entrypoints: native server (feature "server") and wasm/desktop client
├─ server/        # Dioxus server functions — the typed RPC boundary between client and server
├─ api/           # git smart-HTTP bridge (clone/push) — server-only
├─ auth/          # accounts, sessions, personal access tokens — server-only
├─ git/           # repository storage and gix-backed operations — server-only
├─ db/            # SQLite pool setup — server-only
├─ migrations/    # embedded SQL migrations — server-only
├─ telemetry/     # tracing/OpenTelemetry setup — server-only, see below
└─ ui/            # components, layouts, and pages — compiles for client and server
```

`server`-only modules never enter the wasm/web client build; see `Cargo.toml`'s feature list.

## Observability

The `server` build is instrumented with [`tracing`](https://docs.rs/tracing) throughout, with an optional [OpenTelemetry](https://opentelemetry.io/) export path layered on top. Everything below is server-only — the wasm/web client build is untouched and carries none of these dependencies.

### What Edda produces

- **Structured logs**: every request, and the meaningful operations inside it (`repository.get`, `git.read_tree`, `authentication.login`, ...) emit structured `tracing` events, printed to stdout — pretty-printed in debug builds, JSON in release builds (override with `EDDA_LOG_FORMAT=pretty|json`).
- **Distributed traces**: nested spans following the real work a request does, e.g. `HTTP GET /api/repos/{name}/commits` → `repository.commits` → `git.open` → `git.resolve_revision` → `git.read_commit_log`. Git object-store operations (`gix`), server functions, and the raw git-HTTP clone/push bridge are all instrumented; SQLite query timing comes from `sqlx`'s own built-in `tracing` instrumentation rather than a redundant custom wrapper.
- **Metrics**: two histograms only, `edda.http.server.request.duration` and `edda.git.operation.duration`, both with low-cardinality attributes (`operation`/`status`/`http.route`/`http.method`/`http.status_code` — never a repository name or id).
- **Log/trace correlation**: when OTel export is enabled, `tracing` events are bridged to OTel logs and automatically carry the active `trace_id`/`span_id`, so a log line in Grafana/Loki links straight to its trace in Tempo.

### Enabling OpenTelemetry export

`tracing`/structured logging is always on. OTLP export is a separate, additive layer with three states:

| Configuration                                                                                   | Behavior                                                                                                                                   |
| ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Nothing set                                                                                     | Local structured logging only. **No network connection is attempted anywhere** — not even to the OTel spec's own default `localhost:4318`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` (or a signal-specific `_TRACES_ENDPOINT`/`_METRICS_ENDPOINT`) set | Local logging **and** OTLP export (HTTP/protobuf) to that endpoint.                                                                        |
| `OTEL_SDK_DISABLED=true`                                                                        | OTel export forced off, even if an endpoint is also configured. Local logging is unaffected.                                               |

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

Then open **http://localhost:3000** (Grafana; login `admin`/`admin`) — traces, logs, and metrics are all pre-configured Grafana data sources. A convenient way to find a trace: search Loki for a log line from the request you care about, then follow its `trace_id` into Tempo.

To stop and remove the stack: `docker compose -f compose.otel.yml down`.

### Production OTLP configuration

Point `OTEL_EXPORTER_OTLP_ENDPOINT` at your OpenTelemetry Collector (never at a specific backend directly — the Collector is the backend-neutral boundary; Edda's own code has no Jaeger/Prometheus/Loki-specific dependencies) and set a real `OTEL_TRACES_SAMPLER_ARG` for your traffic volume. Set `OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=production` (or similar) to distinguish environments in your backend.

### What Edda deliberately never emits

Passwords, password hashes, session tokens/cookies, `Authorization` headers, personal access tokens (only a user-chosen _label_ like `authentication.token.create`'s `token.name` field is recorded, never the token value), private repository file contents, or raw request bodies. Repository names appear as `tracing` span fields (there's no internal repository id to prefer — audited: no `repos` table exists) but never as a metric label. SQL statement text may appear in `sqlx`'s own query-timing logs; it's always parameterized, never bound values.

### Known limitations

- gRPC/OTLP transport and `http/json` protocol switching aren't implemented (HTTP/protobuf only).
- W3C trace-context propagation isn't wired up — Edda makes no outbound HTTP calls to other services today, so there's nothing to propagate a `traceparent` to.
- A request rejected by the login-required middleware, or one matching no route at all (a 404), isn't individually traced or measured — see the comment on `with_http_observability` in `src/main.rs` for why (axum's `MatchedPath`, needed to avoid a high-cardinality route label, is only available to middleware applied _after_ routing).
- `dioxus::server::serve()` never returns and exposes no graceful-shutdown hook of its own; Edda works around this with its own Ctrl-C/SIGTERM watcher rather than relying on one.

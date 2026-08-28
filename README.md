# Edda

Self-hosted git platform with a terminal-native, developer-console interface. Host and browse your own repositories — clone and push with a normal `git` client — without depending on GitHub, GitLab, or any other third-party hosting.

Built for solo developers and small teams who want full control and privacy over their code. Deployment is deliberately low-friction: a single self-contained binary, SQLite for storage by default, and nothing external _required_ to get running. PostgreSQL and MySQL/MariaDB are both fully supported, first-class alternatives for larger or longer-lived deployments — chosen through configuration, not a rebuild — see [Database backend](#database-backend).

## Features

- **Real git hosting** — a git implementation built directly on [`gix`](https://github.com/GitoxideLabs/gitoxide) (no `git` subprocess), serving clone/fetch/push over both a smart-HTTP bridge and a native SSH transport (default port `2222`), sharing one protocol core.
- **Web UI** — repository listing with search, file/tree browsing, file viewing, commit history, diffs, pull requests, and an issue tracker, in a dense, keyboard-first interface (see `DESIGN.md`).
- **Accounts and access** — email/password signup and login, optional TOTP and WebAuthn/passkey second factors, optional OAuth2/OIDC login, revocable personal access tokens, SSH keys, and organizations/teams with per-repository roles.
- **Collaboration** — pull request review and merge, issues with labels and milestones, protected branches, tagged releases with assets, signed outbound webhooks, and in-app/email notifications.
- **Single-binary deploy** — SQLite-backed by default, no required external services (no mandatory Postgres, Redis, etc.); PostgreSQL and MySQL/MariaDB are available as opt-in backends, selected at runtime through configuration, not a rebuild.
- **Built-in observability** — structured logs, distributed traces, and metrics out of the box, exportable via OpenTelemetry (see [Observability](#observability)).
- **Rate limiting** — a per-client token-bucket limit on the API surface, on by default and tuned via configuration; real `git`/`git-lfs` traffic is never throttled.

## Status

Early and actively developed, but broad: git hosting over HTTP and SSH, repository browsing, authentication (password + TOTP/WebAuthn/OAuth), pull requests, issues, organizations/teams, releases, webhooks, and notifications all work end to end and are covered by integration tests. CI/CD (a Forgejo-Actions equivalent) and package registries are deliberately out of scope for now.

## Quick start

```bash
cp .env.example .env
cargo install dioxus-cli          # provides `dx`
dx serve --package edda --platform web
```

`dx serve` builds the client and server together, links the web UI's
assets, and hot-reloads on change. Run it from the workspace root, not
from `app/edda-web`: `dx serve` inside the member directory trips a
path-resolution panic in dioxus-cli 0.7.10 on some setups. (`just run` is
the same command.) Edda listens on `127.0.0.1:8080` by default; repository
data and the SQLite database live under `./data`.

`cargo run -p edda --features server` (from the workspace root, or `just
run-server`) also starts the server and is enough for the git endpoints
and the REST API, but it does **not** run the Dioxus asset pipeline, so
the served HTML references unresolved asset paths and the browser UI
renders unstyled — use `dx serve` for the web UI.

Clone a repository hosted on this instance the normal way:

```bash
git clone http://127.0.0.1:8080/<owner>/<repo>.git      # smart-HTTP
git clone ssh://git@127.0.0.1:2222/<owner>/<repo>.git   # SSH (add an SSH key in settings first)
```

Pushing over HTTP requires being logged in (a browser session cookie) or a personal access token (created from the UI, sent as the HTTP Basic password). Pushing over SSH uses a registered SSH key.

Web signup creates ordinary accounts; there is no "first user becomes admin" rule. Create the first admin with the offline CLI, run on the same host as the server (it reads the same `EDDA_DATABASE_URL`/`EDDA_DATA_DIR`):

```bash
cargo run -p edda-cli -- user create <username> <email> --admin
```

That account has no password set — sign in via a password reset or an SSH key. `cargo run -p edda-cli -- user` lists the other subcommands (`list`, `disable`, `enable`, `delete`).

### Configuration

Runtime behavior is controlled by environment variables — none of them are read from `.env` by the running binary itself (see `.env.example`'s top comment for why). At minimum:

| Variable         | Default              | Purpose                                                     |
| ---------------- | -------------------- | ---------------------------------------------------------- |
| `EDDA_DATA_DIR`     | `./data`             | Where repository data and the SQLite database live.        |
| `IP` / `PORT`       | `127.0.0.1` / `8080` | Address the HTTP server binds to.                          |
| `EDDA_SSH_PORT`     | `2222`               | Port the git-over-SSH listener binds to (on `IP`).         |
| `EDDA_EXTERNAL_URL` | `http://<IP>:<PORT>` | Public URL the instance is reached on (no trailing slash). |

See `.env.example` for the full list — database URL, `EDDA_EXTERNAL_URL`,
`EDDA_SECRET_KEYS` (optional; needed for TOTP enrollment and stored
webhook secrets), OAuth/WebAuthn/SMTP settings, rate-limit tuning, and the
observability variables documented below. Every `EDDA_*` variable is
validated once at startup — a misconfigured instance fails immediately
with the complete list of problems.

### Database backend

SQLite, PostgreSQL, and MySQL/MariaDB are all first-class, fully-tested backends — one compiled binary connects to whichever `EDDA_DATABASE_URL` names, at **runtime**, no rebuild required (matching how Forgejo's own `DB_TYPE=` config works). SQLite is only the zero-config _default_, not a "primary" database the other two are lesser fallbacks from:

```bash
# Default — SQLite, zero config:
cargo run --features server

# PostgreSQL instead:
EDDA_DATABASE_URL=postgres://user:pass@host/dbname cargo run --features server

# MySQL/MariaDB instead:
EDDA_DATABASE_URL=mysql://user:pass@host/dbname cargo run --features server
```

`EDDA_DATABASE_URL` unset falls back to a local SQLite file under `EDDA_DATA_DIR` — the same zero-config path as always. For PostgreSQL/MySQL there's no local default; the variable is required.

**TLS**: a networked PostgreSQL/MySQL connection uses TLS when the URL asks for it — `?sslmode=require` / `?sslmode=verify-full&sslrootcert=<path>` for PostgreSQL, `?ssl-mode=REQUIRED` for MySQL/MariaDB. Edda passes the URL to the driver verbatim; the `rustls`/`ring` stack is built in. `EDDA_DB_MAX_CONNECTIONS` (default 10) and `EDDA_DB_ACQUIRE_TIMEOUT_SECONDS` (default 30) tune the connection pool.

**MySQL/MariaDB-specific note**: `tower-sessions-sqlx-store`'s MySQL session store creates its own `tower_sessions` schema (unlike its SQLite/PostgreSQL stores, which use a table in the connected database) — the configured database user needs `CREATE` privilege, or an operator pre-creates that schema and grants access to it specifically. Confirmed against a real MariaDB instance.

One disclosed trade-off of a single binary supporting all three backends at runtime: `sqlx`'s compile-time query checking (`query!`) can't work with the `sqlx::Any` driver that makes runtime backend selection possible, so `edda-db`'s queries are runtime-checked instead — a query/column mismatch is now a test failure, not a compile error. Mitigated by running the same test suite against all three backends.

## Development

First-time setup: `cp .env.example .env`.

```bash
dx serve --package edda --platform web    # or: just run
```

runs the client/server dev loop with hot reload, from the workspace root
(see the Quick start note on why not from `app/edda-web`). Swap
`--platform desktop` to run it as a desktop app instead. Tailwind is compiled automatically as of Dioxus 0.7 — no separate Tailwind install needed unless you want to customize the input/output paths (see `app/edda-web/Dioxus.toml`) or use Tailwind plugins, in which case install the [Tailwind CLI](https://tailwindcss.com/docs/installation/tailwind-cli) and run it directly:

```bash
npx @tailwindcss/cli -i ./input.css -o ./assets/tailwind.css --watch
```

### Common tasks

A [`justfile`](justfile) wraps the usual lifecycle — `just` (or `just --list`)
shows every recipe. The important ones:

| Recipe                                | What it does                                                        |
| ------------------------------------- | ------------------------------------------------------------------ |
| `just verify`                         | fmt check, both clippy passes, `cargo test`, the wasm build, `git diff --check` — the pre-push gate |
| `just test`                           | full test suite against the default in-memory SQLite               |
| `just test-postgres` / `just test-mariadb` | same suite against a real backend (starts `compose.db.yml` first) |
| `just run`                            | `dx serve` — the browser UI with hot reload                        |
| `just run-server`                     | the server binary alone (no `dx`; see the Quick start caveat)      |

The database-backed tests default to in-memory SQLite; point
`EDDA_TEST_DATABASE_URL` at a PostgreSQL or MySQL/MariaDB server (a fresh
database is created per test) to run them against another backend, exactly
as `just test-postgres` / `just test-mariadb` do. Per `AGENTS.md`, a schema
or query change must pass on all three.

### Project layout

Edda is a Cargo workspace: a functional core of pure domain logic, thin
I/O-performing "shell" crates around it, and a composition root
(`app/edda-web`) that wires them together and hosts the Dioxus UI. See
`AGENTS.md` for the full architectural rules.

```
crates/
├─ edda-domain/     # entities, invariants, pure authorization/business-rule functions — no I/O
├─ edda-db/         # sqlx AnyPool (SQLite/PostgreSQL/MySQL-MariaDB, selected at runtime), embedded migrations, one repository struct per aggregate
├─ edda-git/        # repository storage and gix-backed operations (protocol core, diff, merge, LFS) — transport-agnostic
├─ edda-render/     # markdown rendering (sanitized) and syntax highlighting
├─ edda-auth/       # authentication (passwords/sessions/tokens/TOTP/WebAuthn/OAuth/SSH keys) and the authorization service
├─ edda-app/       # axum app: git smart-HTTP bridge, LFS, auth/OAuth/WebAuthn/token/collaborator/admin/SSH-key routes, release-asset transfer, REST /api/v1, rate limiting
├─ edda-ssh/        # git-over-SSH transport (russh), reusing edda-git's protocol core
├─ edda-jobs/       # the background-job poller and handler registry (handler logic is wired in app/edda-web)
├─ edda-cli/        # `edda-cli` — offline instance administration (user create/list/disable/enable/delete)
└─ edda-telemetry/  # tracing/OpenTelemetry setup, see below
app/
└─ edda-web/        # the composition root: main.rs, Dioxus server functions, UI (components/layouts/pages)
migrations/          # SQL migration history — sqlite/, postgres/, and mysql/ subdirectories, applied by edda-db (kept at the workspace root for `sqlx-cli` convenience)
```

`edda-web` is the only package built for both the wasm32 client and the native server (Dioxus fullstack's own constraint) — every other crate above is server-only, pulled in by `edda-web` behind its `server` feature, and never enters the wasm/web client build; see `app/edda-web/Cargo.toml`'s feature list.

## Observability

The `server` build is instrumented with [`tracing`](https://docs.rs/tracing) throughout, with an optional [OpenTelemetry](https://opentelemetry.io/) export path layered on top. Everything below is server-only — the wasm/web client build is untouched and carries none of these dependencies.

### What Edda produces

- **Structured logs**: every request, and the meaningful operations inside it (`repository.get`, `git.read_tree`, `authentication.login`, ...) emit structured `tracing` events, printed to stdout — pretty-printed in debug builds, JSON in release builds (override with `EDDA_LOG_FORMAT=pretty|json`).
- **Distributed traces**: nested spans following the real work a request does, e.g. `HTTP GET /api/repos/{name}/commits` → `repository.commits` → `git.open` → `git.resolve_revision` → `git.read_commit_log`. Git object-store operations (`gix`), server functions, and the raw git-HTTP clone/push bridge are all instrumented; database query timing (whichever of SQLite/PostgreSQL/MySQL is connected at runtime) comes from `sqlx`'s own built-in `tracing` instrumentation rather than a redundant custom wrapper.
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

Passwords, password hashes, session tokens/cookies, `Authorization` headers, personal access tokens (only a user-chosen _label_ like `authentication.token.create`'s `token.name` field is recorded, never the token value), private repository file contents, or raw request bodies. Repository names appear as `tracing` span fields but never as a metric label. SQL statement text may appear in `sqlx`'s own query-timing logs; it's always parameterized, never bound values.

### Known limitations

- gRPC/OTLP transport and `http/json` protocol switching aren't implemented (HTTP/protobuf only).
- W3C trace-context propagation isn't wired up — Edda makes no outbound HTTP calls to other services today, so there's nothing to propagate a `traceparent` to.
- A request rejected by the login-required middleware, or one matching no route at all (a 404), isn't individually traced or measured — see the comment on `with_http_observability` in `src/main.rs` for why (axum's `MatchedPath`, needed to avoid a high-cardinality route label, is only available to middleware applied _after_ routing).
- `dioxus::server::serve()` never returns and exposes no graceful-shutdown hook of its own; Edda works around this with its own Ctrl-C/SIGTERM watcher rather than relying on one.

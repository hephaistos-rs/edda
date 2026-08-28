# Edda task runner — https://github.com/casey/just
#
# `just` is a command runner (a saner Makefile). Install with
# `cargo install just` or a system package, then run `just` to list recipes
# or `just verify` before pushing.
#
# Prerequisites:
#   - Rust toolchain: pinned by `rust-toolchain.toml` at the repo root —
#     rustup installs it automatically on the first cargo invocation.
#   - The wasm target ships with that toolchain file too; if you use a
#     detached toolchain, add it with:
#       rustup target add wasm32-unknown-unknown
#   - `cargo-deny` + `cargo-audit`, for `just deny` / `just audit`:
#       cargo install cargo-deny cargo-audit
#   - Docker + compose, for `just test-postgres` / `just test-mariadb`
#     (they drive `compose.db.yml`).
#   - The Dioxus CLI, for `just run` (the browser UI): `cargo install dioxus-cli`.
#     `just run-server` needs only cargo, but a plain `cargo run` does not run
#     the `dx` asset pipeline, so the served HTML's asset links are unresolved
#     and the UI renders unstyled — use `just run` for the real web UI.
#
# Backend databases: SQLite (default, zero-config) plus PostgreSQL and
# MySQL/MariaDB are all first-class. The DB test recipes point
# `EDDA_TEST_DATABASE_URL` at the servers `compose.db.yml` defines
# (edda/edda @ localhost:5432 / :3306, database `eddadb`).

[windows]
set shell := ["pwsh.exe", "-NoLogo", "-Command"]

[unix]
set shell := ["bash", "-cu"]

# `edda` (the composition-root binary) and `edda-web` (the Dioxus UI) are
# excluded from the workspace-wide cargo commands: they only build for wasm
# (`--features web`) or as the server (`--features server`), never with
# default features on the host, so they get their own targeted recipes
# (`clippy-server`, `wasm`, `run*`).
no_app := "--workspace --exclude edda --exclude edda-web"
pg_url := env_var_or_default("EDDA_PG_TEST_URL", "postgres://edda:edda@localhost:5432/eddadb")
maria_url := env_var_or_default("EDDA_MARIA_TEST_URL", "mysql://edda:edda@localhost:3306/eddadb")

# List available recipes.
default:
    @just --list

# Format the whole workspace in place.
fmt:
    cargo fmt --all

# Check formatting without modifying files (CI gate).
fmt-check:
    cargo fmt --all -- --check

# Type-check the workspace (minus the app) and the app's server build.
check:
    cargo check {{no_app}} --all-targets
    cargo check -p edda --features server

# Clippy the workspace minus the app binary + UI crate, all targets.
clippy:
    cargo clippy {{no_app}} --all-targets

# Clippy the app binary (server) and the UI crate (server + wasm).
clippy-server:
    cargo clippy -p edda --features server
    cargo clippy -p edda-web --features server
    cargo clippy -p edda-web --target wasm32-unknown-unknown --features web

# Formatting check plus both clippy passes — the full lint gate.
lint: fmt-check clippy clippy-server

# Architectural boundary checks (plan.local.md §5.1) — enforced invariants
# plus a report of the ones later phases still have to establish.
boundary:
    bash scripts/boundary-check.sh

# Supply-chain gate: advisories, license policy, and the crypto-stack bans
# (no openssl/native-tls/aws-lc-rs/oniguruma). Needs `cargo install cargo-deny`.
deny:
    cargo deny check advisories bans licenses sources

# RUSTSEC advisory scan of the lockfile. Needs `cargo install cargo-audit`.
audit:
    cargo audit --deny warnings

# Full test suite against the default in-memory SQLite backend.
test:
    cargo test {{no_app}}

# Run the DB-backed suite against an arbitrary backend URL (e.g. `just test-db postgres://user:pass@host/db`).
test-db url:
    EDDA_TEST_DATABASE_URL="{{url}}" cargo test {{no_app}}

# Start the DB containers, then run the full suite against PostgreSQL.
test-postgres: db-up
    EDDA_TEST_DATABASE_URL="{{pg_url}}" cargo test {{no_app}}

# Start the DB containers, then run the full suite against MariaDB/MySQL.
test-mariadb: db-up
    EDDA_TEST_DATABASE_URL="{{maria_url}}" cargo test {{no_app}}

# The web (wasm32) build of the app crate — the fullstack client half.
wasm:
    cargo check -p edda --target wasm32-unknown-unknown --features web

# The pre-push gate: fmt check, both clippy passes, tests, the wasm build, boundary checks, whitespace check. Stops at the first failure. Does not touch external databases — run `just test-postgres` / `just test-mariadb` too when persistence changes; run `just deny` / `just audit` when dependencies change.
verify: fmt-check clippy clippy-server test wasm boundary
    git diff --check

# Run the full app (browser UI + server) with hot reload via `dx`.
# Invoked from the workspace root with `--package edda`, not from
# `app/edda-web`: `dx serve` inside the member directory trips a
# path-resolution panic in dioxus-cli 0.7.10 on some setups
# (`workspace.rs:325`), which this form avoids.
run:
    dx serve --package edda --platform web

# Run only the server binary (git smart-HTTP + SSH + REST API + SSR); no `dx`.
run-server:
    cargo run -p edda --features server

# Start the PostgreSQL + MariaDB dev containers and wait until both accept connections.
db-up:
    docker compose -f compose.db.yml up -d postgres mysql
    until docker exec postgres pg_isready -U edda -q; do sleep 1; done
    until docker exec mysql mariadb -uedda -pedda -e "SELECT 1" eddadb >/dev/null 2>&1; do sleep 1; done
    @echo "postgres + mariadb ready"

# Stop and remove the dev database containers.
db-down:
    docker compose -f compose.db.yml down

# Remove all build artifacts (cargo + dx).
clean:
    cargo clean
    rm -rf target/dx

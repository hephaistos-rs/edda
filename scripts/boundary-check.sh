#!/usr/bin/env bash
#
# Architectural boundary checks — the enforceable half of plan.local.md §5.1.
#
# Two tiers:
#
#   ENFORCED  — invariants that hold on the tree *today*. A violation fails
#               CI. Introducing an `axum` dependency in `edda-domain`, or an
#               `edda-auth` dependency in `edda-jobs`, trips these.
#
#   PENDING   — target invariants a later implementation phase establishes
#               (the API/Dioxus decoupling, the config consolidation, the
#               git-subsystem rewrite). Reported for visibility with the
#               owning phase, but not fatal yet. Each becomes ENFORCED in
#               its phase and this script is the place that flips it.
#
# Run from the workspace root: `bash scripts/boundary-check.sh`
# (or `just boundary`).

set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
red()   { printf '\033[31m%s\033[0m\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }
dim()   { printf '\033[2m%s\033[0m\n'  "$1"; }

# enforce <description> <grep-hits>
# Fails the run if the final argument (a command substitution) is non-empty.
enforce() {
    local desc=$1 hits=$2
    if [[ -n "$hits" ]]; then
        red "FAIL  $desc"
        printf '%s\n' "$hits" | sed 's/^/        /'
        fail=1
    else
        green "ok    $desc"
    fi
}

# pending <phase> <description> <grep-hits>
pending() {
    local phase=$1 desc=$2 hits=$3
    if [[ -n "$hits" ]]; then
        local n
        n=$(printf '%s\n' "$hits" | grep -c .)
        dim "pend  [$phase] $desc — $n file(s)"
    else
        dim "pend  [$phase] $desc — already clean (promote to ENFORCED)"
    fi
}

# A grep that treats "no match" as success (empty output), never an error.
g() { grep -rnE "$@" 2>/dev/null || true; }

echo "── ENFORCED ─────────────────────────────────────────────"

# edda-domain is the pure functional core: no I/O crate, no framework, ever.
enforce "edda-domain manifest carries no I/O / framework dependency" \
    "$(g '^\s*(sqlx|axum|tower|gix|gix-[a-z]+|dioxus|reqwest|hyper|russh|tokio|lettre|comrak)\s*[=.]' crates/edda-domain/Cargo.toml)"

enforce "edda-domain source names no I/O / framework crate" \
    "$(g '\b(sqlx|axum|gix|gix_[a-z]+|dioxus|reqwest|hyper|russh|tokio)::' crates/edda-domain/src \
        | grep -vE ':[0-9]+:\s*(//|//!|\*)')"

# edda-jobs owns the queue *mechanism* only — handler logic (which needs
# auth + a HTTP client) is injected from the composition root.
enforce "edda-jobs manifest does not depend on the HTTP app or edda-auth" \
    "$(g '^\s*(edda-app|edda-auth)\s*[=.]' crates/edda-jobs/Cargo.toml)"

# edda-git is transport- and storage-decision-agnostic: protected-ref names
# and hook decisions are passed in by the caller.
enforce "edda-git manifest does not depend on edda-db or edda-auth" \
    "$(g '^\s*(edda-db|edda-auth)\s*[=.]' crates/edda-git/Cargo.toml)"

# edda-render is a leaf: heavy markdown/highlight deps, no Edda deps.
enforce "edda-render manifest depends on no other Edda crate" \
    "$(g '^\s*edda-[a-z]+\s*[=.]' crates/edda-render/Cargo.toml)"

# One config surface (plan.local.md §4.13 / Phase 1): only `edda-app::config`
# and the two binary roots read Edda's own `EDDA_*` (and `IP`/`PORT`)
# variables. Exceptions, each deliberate:
#   - crates/edda-telemetry/src/config.rs — the OTel SDK's own OTEL_* vars
#     plus EDDA_LOG_FORMAT (plan §4.9)
#   - EDDA_TEST_* anywhere               — test-harness plumbing, not config
#   - src/main.rs (either binary)        — the composition roots
#   - tests/ dirs                        — tests set their own env
enforce "only edda-app::config + the binaries read EDDA_* / IP / PORT from the environment" \
    "$(g 'env::(var|set_var|remove_var)\s*\(\s*\"(EDDA_|IP\"|PORT\")' --include=*.rs crates app \
        | grep -vE 'edda-app/src/config\.rs|edda-telemetry/src/config\.rs|/src/main\.rs|/tests/|EDDA_TEST_' \
        || true)"

# One persistence boundary (plan.local.md §5.1 / Phase 2): SQL, `sqlx`
# types, and `sqlx::Error` live only in `edda-db`; every other crate names
# `edda_db::DbError` and the narrow repo methods instead. Exceptions, each
# deliberate:
#   - app/edda-web/src/session_store.rs — `tower-sessions-sqlx-store` needs
#     a *concrete* `SqlitePool`/`PgPool`/`MySqlPool` that `AnyPool` can't
#     provide; this one composition-root module opens that typed pool
#     itself (moves into the `edda` binary in Phase 4).
#   - tests/ dirs — integration-test harnesses stand up their own session
#     store / fixtures the same way.
enforce "sqlx types stay inside crates/edda-db/" \
    "$(g '\bsqlx::' --include=*.rs crates app \
        | grep -vE 'crates/edda-db/|app/edda-web/src/session_store\.rs|/tests/' \
        || true)"

# Transactional outbox (plan.local.md §13 / Phase 3): a domain event is
# written to the `events` table (`EventRepo::append`) inside the same
# transaction as its state change, and `spawn_dispatcher` fans it out —
# never `edda_jobs::dispatch(event, …)` right after a commit, whose event
# was lost for good if the process died in the window. That call, and the
# `EmailContent` struct it took, no longer exist.
enforce "no post-commit event dispatch — the outbox is the only path" \
    "$(g '\bedda_jobs::dispatch\b|\bEmailContent\b' --include=*.rs crates app || true)"

echo
echo "── PENDING (target invariants, not yet enforced) ────────"

pending "Phase 4" "axum:: / http:: outside the HTTP app crate" \
    "$(g '\b(axum|http)::' --include=*.rs crates app | grep -vE 'crates/edda-app/|:[0-9]+:\s*(//|//!)' || true)"

pending "Phase 4" "dioxus outside the web UI crate" \
    "$(g '\bdioxus\b' --include=*.rs crates app | grep -vE 'app/edda-web/|:[0-9]+:\s*(//|//!)' || true)"

pending "Phase 6/7" "gix:: / gix_*:: outside crates/edda-git/" \
    "$(g '\bgix(_[a-z]+)?::' --include=*.rs crates app | grep -v 'crates/edda-git/' || true)"

echo
if [[ $fail -ne 0 ]]; then
    red "boundary-check: FAILED"
    exit 1
fi
green "boundary-check: passed"

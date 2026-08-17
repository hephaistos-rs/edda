# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Rust + Dioxus 0.7 (fullstack: server-rendered + hydrated web client), existing in the codebase. Persistence and deploy story confirmed: single self-contained binary, SQLite storage, no required external services to get started.

## Users

Solo developers and small teams self-hosting their own git platform — running it on a server or VPS they control, instead of relying on GitHub/GitLab/a big SaaS.

## Product Purpose

Edda is a self-hosted git platform: hosts and serves git repositories with a web UI, giving people who self-host full control and privacy over their code instead of depending on third-party hosting.

## Positioning

Not yet settled. No committed claim over Gitea/Forgejo/Gitness beyond the confirmed deploy story (single binary, SQLite, minimal setup). Open decision to revisit once more of the product is built.

## Operating Context

Self-hosted: the operator installs and runs the binary themselves (own server/VPS/homelab), pointed at local storage. No managed/SaaS deployment in scope currently.

## Capabilities and Constraints

- Deployment: single binary, SQLite-backed, no required external services (e.g. no mandatory external Postgres/Redis) to run.
- Codebase currently scaffolds (empty stubs, no logic yet): `api`, `auth`, `db`, `git`, `migrations`, `server` modules, plus a `ui` module for the frontend (`layouts`, `pages`, `components`).
- Feature scope beyond core git hosting (PRs/issues/CI/etc.) is undecided — not yet confirmed.

## Evidence on Hand

None yet. No existing screenshots, testimonials, or reference deployments — this is a from-scratch build.

## Product Principles

- Self-host-first: assume the operator is running this themselves, not signing up for a hosted service.
- Low-friction deploy: a single binary + SQLite should be enough to get running; don't require a services stack.
- Privacy and control over the code being hosted are the reason this exists, not a side benefit.

## Accessibility & Inclusion

Confirmed requirement (explicit user request during visual-direction selection): status/state must never be conveyed by color alone — every status carries a distinct glyph/shape in addition to its color, since the chosen terminal-native direction leans on status colors that read like ANSI codes. Body/description text stays in a readable proportional face rather than being forced into monospace. Contrast is verified against the dark ground rather than assumed from terminal convention.

# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Rust + Dioxus 0.7 (fullstack: server-rendered + hydrated web client), existing in the codebase. Persistence and deploy story confirmed: single self-contained binary, SQLite storage by default, no required external services to get started. PostgreSQL and MySQL/MariaDB are both fully supported, first-class backends (chosen at runtime via configuration, not a rebuild) for larger or longer-lived deployments — the "no required external services" story is about the default, not a ceiling, and neither alternative backend is second-class relative to SQLite.

## Users

Solo developers and small teams self-hosting their own git platform — running it on a server or VPS they control, instead of relying on GitHub/GitLab/a big SaaS.

## Product Purpose

Edda is a self-hosted git platform: hosts and serves git repositories with a web UI, giving people who self-host full control and privacy over their code instead of depending on third-party hosting.

## Positioning

Not yet settled. No committed claim over Gitea/Forgejo/Gitness beyond the confirmed deploy story (single binary, SQLite, minimal setup). Open decision to revisit once more of the product is built.

## Operating Context

Self-hosted: the operator installs and runs the binary themselves (own server/VPS/homelab), pointed at local storage. No managed/SaaS deployment in scope currently.

## Capabilities and Constraints

- Deployment: single binary, SQLite-backed by default, no required external services (e.g. no mandatory external Postgres/Redis) to run. PostgreSQL and MySQL/MariaDB are both available as explicitly-chosen, first-class backends for operators who want them — never the default, never required, but not lesser options either.
- Codebase is an implemented Cargo workspace: `edda-domain`, `edda-db`, `edda-git`, `edda-render`, `edda-auth`, `edda-jobs`, `edda-http`, `edda-ssh`, `edda-telemetry`, `edda-cli`, and the `edda-web` composition root (Dioxus UI: `layouts`, `pages`, `components`).
- Implemented beyond core git hosting: pull request review/merge, issues with labels and milestones, protected branches, tagged releases with assets, signed outbound webhooks, in-app/email notifications, organizations/teams with per-repo roles, and optional TOTP/WebAuthn/OAuth. CI/CD and package registries are deliberately out of scope for now.

## Evidence on Hand

None yet. No existing screenshots, testimonials, or reference deployments — this is a from-scratch build.

## Product Principles

- Self-host-first: assume the operator is running this themselves, not signing up for a hosted service.
- Low-friction deploy: a single binary + SQLite should be enough to get running; don't require a services stack. A larger deployment may opt into PostgreSQL or MySQL/MariaDB, but that's an option the operator reaches for, never a default imposed on them.
- Privacy and control over the code being hosted are the reason this exists, not a side benefit.

## Accessibility & Inclusion

Confirmed requirement (explicit user request during visual-direction selection): status/state must never be conveyed by color alone — every status carries a distinct glyph/shape in addition to its color, since the chosen terminal-native direction leans on status colors that read like ANSI codes. Body/description text stays in a readable proportional face rather than being forced into monospace. Contrast is verified against the dark ground rather than assumed from terminal convention.

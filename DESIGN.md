---
name: Edda
description: Self-hosted git platform with a terminal-native, developer-console interface
colors:
  bg: "oklch(15% 0.01 260)"
  surface: "oklch(22% 0.013 260)"
  line: "oklch(34% 0.015 260)"
  ink: "oklch(94% 0.004 260)"
  ink-muted: "oklch(72% 0.01 260)"
  accent: "oklch(78% 0.14 85)"
  accent-ink: "oklch(15% 0.01 260)"
  status-clean: "oklch(72% 0.15 150)"
  status-ahead: "oklch(75% 0.12 230)"
  status-conflict: "oklch(72% 0.19 25)"
  status-empty: "oklch(60% 0.012 260)"
typography:
  data:
    fontFamily: "ui-monospace, 'Cascadia Code', 'Segoe UI Mono', Consolas, 'Liberation Mono', monospace"
    fontSize: "0.75rem–0.9375rem"
    fontWeight: 500
  body:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
spacing:
  row-x: "1rem"
  row-y: "0.75rem"
components:
  repo-row:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    padding: "0.75rem 1rem"
    rounded: "0"
  repo-row-hover:
    backgroundColor: "{colors.surface}"
  search-input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    padding: "0.375rem 0.625rem"
    rounded: "0"
---

# Design System: Edda

## Overview

**Creative North Star: "The Developer's Console"**

Edda's interface reads like the terminal tools its audience — solo devs and small teams self-hosting their own infrastructure — already keep open all day: lazygit, htop, k9s. It is dense, monospace-driven where data lives, and keyboard-first, refusing the generic sidebar-and-card-grid dashboard every other self-hosted git tool ships.

System requirements shaped the world as much as taste did: because the terminal aesthetic naturally leans on ANSI-style status colors, every status is deliberately carried by a distinct icon shape and a text label as well as its color — confirmed as a hard requirement during design, not a nice-to-have.

**Key Characteristics:**
- Graphite ground, no cards, no shadows — regions are separated by 1px hairline seams only.
- One accent (gold) reserved for interactive/brand moments; status meaning lives in its own, separate hue family.
- Monospace is earned by data (names, counts, hashes) — prose stays in a readable proportional face.
- Status is always color + shape + label, never color alone.

## Colors

A near-black graphite ground with a single warm accent and four distinct, non-overlapping status hues.

### Primary
- **Signal Gold** (`oklch(78% 0.14 85)` / `#e0af3b`): the one interactive/brand accent — links, primary actions, active nav, focus rings. Used sparingly (restrained strategy); its rarity is the point.

### Neutral
- **Graphite Ground** (`oklch(15% 0.01 260)` / `#090b0f`): page background.
- **Panel Surface** (`oklch(22% 0.013 260)` / `#171b21`): hover/focus state fill for interactive rows.
- **Hairline** (`oklch(34% 0.015 260)` / `#333840`): the only divider — a 1px border, never a shadow or card.
- **Ink** (`oklch(94% 0.004 260)` / `#e9ebee`): primary text. 16.5:1 against the ground.
- **Ink Muted** (`oklch(72% 0.01 260)` / `#a1a5ab`): secondary text (descriptions, counts). Still 7.9:1 against the ground — never a low-contrast decorative gray.

### Status (Neutral role, functional)
- **Status Clean** (`oklch(72% 0.15 150)` / `#53be70`): up to date. Paired with a checked-circle icon.
- **Status Ahead** (`oklch(75% 0.12 230)` / `#4ebceb`): ahead of remote / pending. Paired with an arrow-up-circle icon.
- **Status Conflict** (`oklch(72% 0.19 25)` / `#ff706a`): needs attention / destructive. Paired with a triangle-alert icon.
- **Status Empty** (`oklch(60% 0.012 260)` / `#7c8088`): no commits yet. Paired with a dashed-circle icon.

### Named Rules
**The Never-Color-Alone Rule.** Every status carries a distinct icon shape and an `sr-only` text label in addition to its color. This is a confirmed accessibility requirement, not a style preference — verify it on every new status introduced.

**The One Voice Rule.** Signal Gold is the only accent used for interactive/brand meaning. It never doubles as a status color, and status colors never substitute for it on interactive elements.

## Typography

**Body Font:** system-ui, -apple-system, "Segoe UI", Roboto, sans-serif
**Data/Mono Font:** ui-monospace, "Cascadia Code", "Segoe UI Mono", Consolas, "Liberation Mono", monospace

**Character:** System stacks by deliberate choice, not default laziness — a self-hosted tool that phones out to a font CDN undercuts its own "self-hosted, no external dependencies" premise. The pairing is functional, not expressive: mono is reserved for the data it's earned (names, hashes, counts), sans carries everything read as prose.

### Hierarchy
- **Title** (600 weight, 1.5rem): repo detail page name.
- **Body** (500 weight, 15px, mono): repo name in a list row — the primary scan target.
- **Body** (400 weight, 0.875rem, sans): repo description.
- **Label** (500 weight, 0.75rem, mono, tabular-nums): ahead/behind counts, always right-aligned.

### Named Rules
**The Earned-Mono Rule.** Monospace marks data (names, hashes, counts, branches) — never used as a "technical-looking" costume on prose or UI chrome labels.

## Layout

Single-column, dense list as the primary composition — not a grid of cards. A sticky top bar (wordmark, nav, search) persists across routes via the `Navbar` layout; each route swaps only the content below it. Container caps at `max-w-3xl`, left-aligned reading width appropriate to a scanning list rather than a marketing-width page.

## Elevation & Depth

Flat by design — no shadows anywhere. Depth and separation come entirely from the hairline-seam border and a one-step surface tint on hover/focus, never from blur or offset shadow.

### Named Rules
**The No-Shadow Rule.** Panels and rows are separated by a 1px `border-line` hairline or a `bg-surface` tint on interaction. A shadow anywhere in this system is a bug, not a stylistic choice.

## Shapes

Sharp corners throughout (`rounded: 0`) — no rounded rectangles. This is a deliberate refusal of the soft-rounded-card look most dashboards default to; it reinforces the flat, panel-native world.

## Components

### Repo Row
- **Shape:** full-bleed row, sharp corners, `border-line` bottom hairline separating rows (no side borders, no card wrapper).
- **Content:** status icon (with `sr-only` label) + mono repo name + sans description (truncates) + tabular-nums ahead/behind counts, right-aligned.
- **Hover / Focus:** `bg-surface` fill across the full row; the whole row is the click target (wraps a `<Link>`).
- **Disabled:** the trailing "new repository" row uses the same anatomy at 60% opacity with `aria-disabled="true"` and a `title` explaining why, rather than pretending to be a live control.

### Search Input
- **Style:** `bg-surface` fill, `border-line` border, sharp corners, leading search icon.
- **Focus:** border shifts to `accent`.

### Navigation
- **Style:** mono wordmark + mono nav links in `ink-muted`, `ink` on hover. No active-state pill or underline — current page is conveyed via `aria-current` for assistive tech, not a visual treatment yet (open item, see Do's and Don'ts).

## Do's and Don'ts

### Do:
- **Do** pair every status color with a distinct drawn icon shape and a text label — confirmed accessibility requirement.
- **Do** keep monospace scoped to data (names, hashes, counts) and sans to prose.
- **Do** use system font stacks — no external font requests, consistent with the self-hosted product premise.
- **Do** separate regions with a 1px `border-line` hairline, never a shadow or a card wrapper.

### Don't:
- **Don't** introduce a second interactive accent color — Signal Gold stays the only one.
- **Don't** reuse a status color for a non-status, non-decorative meaning (e.g. don't make a random illustrative element status-conflict red).
- **Don't** add shadows, rounded corners, or card containers — flat and sharp is the invariant, not a placeholder.
- **Don't** rely on unicode/emoji glyphs as a substitute icon system; icons come from `dioxus-free-icons`' `lucide` pack (`dioxus_free_icons::icons::ld_icons`), one consistent 2px stroke weight, 16×16.

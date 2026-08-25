# Edda architecture rules

Permanent engineering rules for agents working on Edda. This section is
the durable rule set — it does not track implementation status or task
lists; it states the architectural decisions themselves, directly, so
that following it never depends on any other document being present.

If a repository fact contradicts a rule below, fix the rule (or flag the
contradiction) rather than silently reinterpreting it.

## The general dependency principle

**Optional does not mean unimportant.** A dependency being non-mandatory
for a standalone deployment is not a reason to exclude it from support —
those are different questions entirely.

Classify every significant infrastructure choice as one of:

1. **Mandatory** — Edda cannot reasonably operate without it.
2. **Optional but first-class** — a standalone path exists, and the
   external integration is a fully-supported deployment target, not a
   lesser one (this is where SQLite + PostgreSQL + MySQL/MariaDB live).
3. **Optional integration** — valuable for specific deployments, not part
   of the core supported set.
4. **Not supported** — deliberately excluded, with a documented technical
   reason (not just "it's optional").

Never collapse (2) into (4). When evaluating a new integration, the
question is never "is this optional, therefore skip it" — it's "does a
standalone path make sense, and does the external option provide enough
value to support properly." Don't add external infrastructure just
because another platform has it, and don't reject mature infrastructure
just because a simpler local implementation exists — decide each
capability on its own technical and operational merits.

## Database architecture

**SQLite, PostgreSQL, and MySQL/MariaDB are all first-class Edda
backends.** None is architecturally privileged. SQLite is the
zero-external-dependency **default** for simple/zero-config deployments —
a user-experience choice, not a "primary" database the other two are
compatibility layers for.

- **Backend selection is a runtime deployment decision**, made via
  `EDDA_DATABASE_URL`'s scheme (`sqlite:`, `postgres:`/`postgresql:`,
  `mysql:`/`mariadb:`). One compiled binary connects to whichever backend
  is configured — changing backend never requires a source change or a
  rebuild. Unset falls back to a local SQLite file under `EDDA_DATA_DIR`.
- `edda_db::DbPool` is the persistence handle every other crate holds. It
  wraps a runtime-selected `sqlx::AnyPool`; backend identity is tracked
  internally (`Backend`, crate-private). **No crate outside `edda-db` may
  name a concrete pool type** (`SqlitePool`/`PgPool`/`MySqlPool`) or
  branch on which backend is connected.
  - **Documented exception**: `tower-sessions-sqlx-store` does not
    support `AnyPool`. `edda-web`'s `session_store` module opens a
    second, small, *concrete* typed connection specifically to satisfy
    that one dependency. This is an explicit, narrow infrastructure
    exception — do not generalize it to any other persistence code.
- **`sqlx::Any` cannot use the `query!`/`query_as!` compile-time-checked
  macros** (no fixed schema exists until a runtime config value is read).
  All `edda-db` queries use runtime `sqlx::query`/`.bind(...)` with
  explicit row decoding (`AnyRow::try_get`). Do not reintroduce
  compile-time query macros into the `AnyPool` path. Because compile-time
  checking is gone, **the same behavioral test suite must run against
  every supported backend** — that's what stands in for the lost safety
  net. A database change is not validated until it's been tested against
  SQLite, PostgreSQL, and MySQL/MariaDB, not just one of them as a proxy
  for the others.
- **Migrations**: `migrations/sqlite/`, `migrations/postgres/`,
  `migrations/mysql/` — three independent, complete chains, all embedded
  at compile time, the right one selected at runtime. A schema change
  must update all three, verified against a real instance of each — never
  add a migration to only one backend, and never copy one backend's SQL
  into another's directory unexamined (dialects genuinely differ: no
  `STRICT` outside SQLite, no partial/filtered indexes on MySQL/MariaDB —
  use the generated-column workaround already established in
  `migrations/mysql/*repo_access*` — MySQL's wire protocol reports `TEXT`
  the same way it reports `BLOB` through `sqlx::Any`, so MySQL text
  columns that need to decode as `String` use bounded `VARCHAR` instead).
- **Don't design a feature against one backend and retrofit the others
  later.** For any new persistence work: determine the portable
  behavior, identify genuine backend differences, isolate those
  differences inside `edda-db` (a `match` on `pool.backend`, not a new
  abstraction layer), and test all three backends before considering it
  done.

## `edda-db` is the persistence boundary

SQL lives in `edda-db` and nowhere else. Higher-level crates call narrow,
intention-revealing repository methods (`UserRepo::find_by_username`,
`RepoAccessRepo::grant_owner`, ...), never raw SQL, never a backend-
specific type. Don't build a second abstraction layer on top of
`edda-db` to "hide" it further — the repository-struct boundary already
is that abstraction.

```
application / domain
        |
        v
     edda-db
        |
        +---- SQLite
        +---- PostgreSQL
        +---- MySQL/MariaDB
```

## Crate architecture (modular monolith)

```
edda-domain
     |
     v
edda-db, edda-git, edda-auth, edda-telemetry   (infrastructure/application crates)
     |
     v
edda-http, edda-ssh                             (transport shells)
     |
     v
edda-web                                        (composition root)
```

Current crates: `edda-domain`, `edda-db`, `edda-git`, `edda-auth`,
`edda-http`, `edda-ssh`, `edda-telemetry`, `edda-web`. (`edda-jobs`
doesn't exist yet — add it only when a real job-queue need lands, not
preemptively.)

- **`edda-domain`** is infrastructure-independent: entities, typed IDs,
  invariants, pure policy/authorization functions, business rules. It
  must never depend on `sqlx`, `axum`, `gix`, `dioxus`, `tokio`, or any
  filesystem/HTTP/database/SSH type — enforced today by that crate's own
  `Cargo.toml` doc comment, not just convention.
- **`edda-auth`** owns authentication (identifying the actor) and
  authorization (deciding what that actor may do) via
  `AuthorizationService`, built on `edda-domain`'s pure policy functions.
  No transport (HTTP/SSH/web) may reimplement a repository permission
  check independently — every permission decision goes through
  `AuthorizationService`.
- **`edda-git`** is transport-agnostic: all actual git operations (pack
  build/parse, ref advertisement, protocol negotiation) live here once,
  shared by both `edda-http`'s smart-HTTP bridge and `edda-ssh`. Neither
  transport shells out to a `git` binary or reimplements git logic
  independently — they own protocol/transport framing only.
- A crate boundary must represent a real architectural seam. Don't add a
  crate for organizational aesthetics, and don't merge unrelated
  responsibilities to minimize crate count either.

## Standalone deployment + external integrations

Edda should keep a strong, genuinely useful standalone deployment path
(no mandatory external services) — but standalone support is not a
reason to reject or under-build a mature external integration. The goal
is **strong standalone capability plus mature optional integrations**,
not minimum dependency count and not maximum external-service count.

When evaluating a new infrastructure integration, ask explicitly:

1. Is this mandatory?
2. Can Edda provide a useful standalone alternative?
3. Is the external service valuable enough to support properly?
4. Should it be first-class (like PostgreSQL/MySQL) or a narrower
   optional integration?
5. What's the actual Rust ecosystem support (research it, don't assume)?
6. Where does the architectural boundary live?
7. Does it affect the existing standalone deployment story?
8. How is it configured (should be deployment config, not a source change
   or rebuild — see the database backend precedent)?
9. How is it tested?

**Never answer question 3 with "it's optional, therefore no."** That
reasoning already produced one incorrect architectural decision in this
project (SQLite-only, later corrected) — treat it as a known failure
mode, not a hypothetical one.

## Dependency selection

Don't hand-roll mature, complex infrastructure to avoid a dependency —
cryptography, SSH, git protocol handling, SQL engines, parsers, diff
algorithms, object-storage protocols, authentication protocols, and
mature serialization formats all belong to well-established crates
(`russh`, `gix`, `sqlx`, etc.), not custom implementations. A dependency
with native/C components is a trade-off to evaluate honestly (native
footprint, build complexity, maintenance), not something to reject on
sight or accept without thought.

When choosing between candidate dependencies, weigh capability,
correctness, maturity, security, maintenance, ecosystem quality,
operational complexity, and deployment implications — not "fewest
dependencies" and not "what a bigger platform happens to use."

## Configuration

Deployment-specific infrastructure choices (database backend and
connection, and any future optional integration) belong in runtime
configuration, not application source code. If a choice can reasonably
be expressed as config, it should be — the database backend is the
concrete precedent: one binary, `EDDA_DATABASE_URL` selects the backend,
no rebuild.

---

# Dioxus 0.7 Reference

You are an expert [0.7 Dioxus](https://dioxuslabs.com/learn/0.7) assistant. Dioxus 0.7 changes every api in dioxus. Only use this up to date documentation. `cx`, `Scope`, and `use_state` are gone

Provide concise code examples with detailed descriptions

## Dioxus Dependency

You can add Dioxus to your `Cargo.toml` like this:

```toml
[dependencies]
dioxus = { version = "0.7.1" }

[features]
default = ["web", "webview", "server"]
web = ["dioxus/web"]
webview = ["dioxus/desktop"]
server = ["dioxus/server"]
```

## Launching your application

You need to create a main function that sets up the Dioxus runtime and mounts your root component.

```rust
use dioxus::prelude::*;

fn main() {
	dioxus::launch(App);
}

#[component]
fn App() -> Element {
	rsx! { "Hello, Dioxus!" }
}
```

Then serve with `dx serve`:

```sh
curl -sSL http://dioxus.dev/install.sh | sh
dx serve
```

This will automatically rebuild the application on any code change. Do not stop the running server if this is happening.

## UI with RSX

```rust
rsx! {
	div {
		class: "container", // Attribute
		color: "red", // Inline styles
		width: if condition { "100%" }, // Conditional attributes
		"Hello, Dioxus!"
	}
	// Prefer loops over iterators
	for i in 0..5 {
		div { "{i}" } // use elements or components directly in loops
	}
	if condition {
		div { "Condition is true!" } // use elements or components directly in conditionals
	}

	{children} // Expressions are wrapped in brace
	{(0..5).map(|i| rsx! { span { "Item {i}" } })} // Iterators must be wrapped in braces
}
```

## Assets

The asset macro can be used to link to local files to use in your project. All links start with `/` and are relative to the root of your project.

```rust
rsx! {
	img {
		src: asset!("/assets/image.png"),
		alt: "An image",
	}
}
```

### Styles

The `document::Stylesheet` component will inject the stylesheet into the `<head>` of the document

```rust
rsx! {
	document::Stylesheet {
		href: asset!("/assets/styles.css"),
	}
}
```

## Components

Components are the building blocks of apps

- Component are functions annotated with the `#[component]` macro.
- The function name must start with a capital letter or contain an underscore.
- A component re-renders only under two conditions:
  1.  Its props change (as determined by `PartialEq`).
  2.  An internal reactive state it depends on is updated.

```rust
#[component]
fn Input(mut value: Signal<String>) -> Element {
	rsx! {
		input {
            value,
			oninput: move |e| {
				*value.write() = e.value();
			},
			onkeydown: move |e| {
				if e.key() == Key::Enter {
					value.write().clear();
				}
			},
		}
	}
}
```

Each component accepts function arguments (props)

- Props must be owned values, not references. Use `String` and `Vec<T>` instead of `&str` or `&[T]`.
- Props must implement `PartialEq` and `Clone`.
- To make props reactive and copy, you can wrap the type in `ReadOnlySignal`. Any reactive state like memos and resources that read `ReadOnlySignal` props will automatically re-run when the prop changes.

## State

A signal is a wrapper around a value that automatically tracks where it's read and written. Changing a signal's value causes code that relies on the signal to rerun.

### Local State

The `use_signal` hook creates state that is local to a single component. You can call the signal like a function (e.g. `my_signal()`) to clone the value, or use `.read()` to get a reference. `.write()` gets a mutable reference to the value.

Use `use_memo` to create a memoized value that recalculates when its dependencies change. Memos are useful for expensive calculations that you don't want to repeat unnecessarily.

```rust
#[component]
fn Counter() -> Element {
	let mut count = use_signal(|| 0);
	let mut doubled = use_memo(move || count() * 2); // doubled will re-run when count changes because it reads the signal

	rsx! {
		h1 { "Count: {count}" } // Counter will re-render when count changes because it reads the signal
		h2 { "Doubled: {doubled}" }
		button {
			onclick: move |_| *count.write() += 1, // Writing to the signal rerenders Counter
			"Increment"
		}
		button {
			onclick: move |_| count.with_mut(|count| *count += 1), // use with_mut to mutate the signal
			"Increment with with_mut"
		}
	}
}
```

### Context API

The Context API allows you to share state down the component tree. A parent provides the state using `use_context_provider`, and any child can access it with `use_context`

```rust
#[component]
fn App() -> Element {
	let mut theme = use_signal(|| "light".to_string());
	use_context_provider(|| theme); // Provide a type to children
	rsx! { Child {} }
}

#[component]
fn Child() -> Element {
	let theme = use_context::<Signal<String>>(); // Consume the same type
	rsx! {
		div {
			"Current theme: {theme}"
		}
	}
}
```

## Async

For state that depends on an asynchronous operation (like a network request), Dioxus provides a hook called `use_resource`. This hook manages the lifecycle of the async task and provides the result to your component.

- The `use_resource` hook takes an `async` closure. It re-runs this closure whenever any signals it depends on (reads) are updated
- The `Resource` object returned can be in several states when read:

1. `None` if the resource is still loading
2. `Some(value)` if the resource has successfully loaded

```rust
let mut dog = use_resource(move || async move {
	// api request
});

match dog() {
	Some(dog_info) => rsx! { Dog { dog_info } },
	None => rsx! { "Loading..." },
}
```

## Routing

All possible routes are defined in a single Rust `enum` that derives `Routable`. Each variant represents a route and is annotated with `#[route("/path")]`. Dynamic Segments can capture parts of the URL path as parameters by using `:name` in the route string. These become fields in the enum variant.

The `Router<Route> {}` component is the entry point that manages rendering the correct component for the current URL.

You can use the `#[layout(NavBar)]` to create a layout shared between pages and place an `Outlet<Route> {}` inside your layout component. The child routes will be rendered in the outlet.

```rust
#[derive(Routable, Clone, PartialEq)]
enum Route {
	#[layout(NavBar)] // This will use NavBar as the layout for all routes
		#[route("/")]
		Home {},
		#[route("/blog/:id")] // Dynamic segment
		BlogPost { id: i32 },
}

#[component]
fn NavBar() -> Element {
	rsx! {
		a { href: "/", "Home" }
		Outlet<Route> {} // Renders Home or BlogPost
	}
}

#[component]
fn App() -> Element {
	rsx! { Router::<Route> {} }
}
```

```toml
dioxus = { version = "0.7.1", features = ["router"] }
```

## Fullstack

Fullstack enables server rendering and ipc calls. It uses Cargo features (`server` and a client feature like `web`) to split the code into a server and client binaries.

```toml
dioxus = { version = "0.7.1", features = ["fullstack"] }
```

### Server Functions

Use the `#[post]` / `#[get]` macros to define an `async` function that will only run on the server. On the server, this macro generates an API endpoint. On the client, it generates a function that makes an HTTP request to that endpoint.

```rust
#[post("/api/double/:path/&query")]
async fn double_server(number: i32, path: String, query: i32) -> Result<i32, ServerFnError> {
	tokio::time::sleep(std::time::Duration::from_secs(1)).await;
	Ok(number * 2)
}
```

### Hydration

Hydration is the process of making a server-rendered HTML page interactive on the client. The server sends the initial HTML, and then the client-side runs, attaches event listeners, and takes control of future rendering.

#### Errors

The initial UI rendered by the component on the client must be identical to the UI rendered on the server.

- Use the `use_server_future` hook instead of `use_resource`. It runs the future on the server, serializes the result, and sends it to the client, ensuring the client has the data immediately for its first render.
- Any code that relies on browser-specific APIs (like accessing `localStorage`) must be run _after_ hydration. Place this code inside a `use_effect` hook.

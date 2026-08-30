//! The Edda web UI — a Dioxus 0.7 fullstack app that renders pages and
//! consumes `/api/v1` over HTTP. It holds no server state, defines no
//! server functions, and depends on no server-side Edda crate: `dioxus`
//! and an HTTP client (`gloo-net` on wasm) are all it needs (plus
//! `edda-api-types` for the wire DTOs). `dioxus` lives here and nowhere
//! else — the composition-root binary (`edda`) never names it: it calls
//! [`launch_client`] for the wasm build and [`ssr_router`] for the server
//! build, and this crate keeps every Dioxus detail (including the
//! `axum::Router` that `dioxus::server` produces for SSR) behind those two
//! functions.

use dioxus::prelude::*;

pub mod api_client;
pub mod ui;

use ui::layouts::Navbar;
use ui::pages::{
    Admin, Home, IssueDetail, IssuesList, Login, Notifications, OrganizationDetail,
    OrganizationsList, PullDetail, PullsList, ReleaseDetail, ReleasesList, Repo, ResetPassword,
    Settings, Signup, TeamDetail, WebhooksSettings,
};

/// The full client-side route table. Every page links via `Route::…`, so
/// this type is `pub` and lives at the crate root.
#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
pub enum Route {
    #[layout(Navbar)]
    #[route("/")]
    Home {},
    #[route("/settings")]
    Settings {},
    #[route("/notifications")]
    Notifications {},
    #[route("/admin")]
    Admin {},
    #[route("/orgs")]
    OrganizationsList {},
    #[route("/orgs/:name")]
    OrganizationDetail { name: String },
    #[route("/orgs/:org_name/teams/:team_name")]
    TeamDetail { org_name: String, team_name: String },
    #[route("/:owner/:name/pulls")]
    PullsList { owner: String, name: String },
    #[route("/:owner/:name/pulls/:number")]
    PullDetail { owner: String, name: String, number: i64 },
    #[route("/:owner/:name/issues")]
    IssuesList { owner: String, name: String },
    #[route("/:owner/:name/issues/:number")]
    IssueDetail { owner: String, name: String, number: i64 },
    #[route("/:owner/:name/releases")]
    ReleasesList { owner: String, name: String },
    #[route("/:owner/:name/releases/:tag_name")]
    ReleaseDetail { owner: String, name: String, tag_name: String },
    #[route("/:owner/:name/settings/webhooks")]
    WebhooksSettings { owner: String, name: String },
    #[route("/:owner/:name")]
    Repo { owner: String, name: String },
    #[route("/signup")]
    Signup {},
    #[route("/login")]
    Login {},
    #[route("/reset-password?:token")]
    ResetPassword { token: Option<String> },
}

const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

/// The root component: injects the favicon + stylesheet links and renders
/// the router. Reached through [`launch_client`] on the wasm build and
/// [`ssr_router`] on the server build.
#[component]
pub fn App() -> Element {
    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        Router::<Route> {}
    }
}

/// The wasm client entrypoint: hydrates [`App`] in the browser. The
/// `edda` binary's client `main` is just a call to this — so `dioxus`
/// stays contained in this crate.
#[cfg(not(feature = "server"))]
pub fn launch_client() {
    dioxus::launch(App);
}

/// The SSR + static-asset router for [`App`], as built by
/// `dioxus::server`. The `edda` binary merges this with
/// `edda_app::router` and owns the `axum::serve` loop itself (Phase 13):
/// there is no `dioxus::server::serve` call anywhere. Returning the
/// concrete `axum::Router` here — rather than exposing `dioxus::server`
/// to the binary — is what keeps `dioxus` out of every other crate.
#[cfg(feature = "server")]
pub fn ssr_router() -> dioxus::server::axum::Router {
    dioxus::server::router(App)
}

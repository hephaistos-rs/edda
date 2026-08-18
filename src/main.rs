use dioxus::prelude::*;

#[cfg(feature = "server")]
mod api;
mod auth;
mod db;
#[cfg(feature = "server")]
mod git;
mod migrations;
mod server;
mod ui;

use ui::layouts::Navbar;
use ui::pages::{Blog, Home, Repo};

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(Navbar)]
    #[route("/")]
    Home {},
    #[route("/repo/:name")]
    Repo { name: String },
    #[route("/blog/:id")]
    Blog { id: i32 },
}

const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

/// The client (web) build launches normally. The server build needs its own
/// axum router instead: Dioxus's own router (SSR, assets, server functions)
/// merged with the git-http routes in `api`, which aren't server functions —
/// they need to speak raw git wire protocol, not typed RPC.
#[cfg(feature = "server")]
fn main() {
    dioxus::server::serve(|| async {
        let router = dioxus::server::router(App).merge(api::routes());
        Ok(router)
    });
}

#[cfg(not(feature = "server"))]
fn main() {
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        Router::<Route> {}
    }
}

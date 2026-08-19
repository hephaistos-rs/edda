use dioxus::prelude::*;

#[cfg(feature = "server")]
mod api;
#[cfg(feature = "server")]
mod auth;
#[cfg(feature = "server")]
mod db;
#[cfg(feature = "server")]
mod git;
#[cfg(feature = "server")]
mod migrations;
mod server;
mod ui;

use ui::layouts::Navbar;
use ui::pages::{Blog, Home, Login, Repo, Signup};

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
    #[route("/signup")]
    Signup {},
    #[route("/login")]
    Login {},
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
        let pool = db::pool().await?;

        // Session cookies persist in the same SQLite database as everything
        // else — no separate store to run or lose track of.
        let session_store = tower_sessions_sqlx_store::SqliteStore::new(pool.clone());
        session_store.migrate().await?;
        let session_layer = tower_sessions::SessionManagerLayer::new(session_store);

        let backend = auth::Backend::new(pool.clone());
        let auth_layer = axum_login::AuthManagerLayerBuilder::new(backend, session_layer).build();

        let router =
            dioxus::server::router(App).merge(api::routes()).merge(auth::routes::routes()).layer(auth_layer);
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

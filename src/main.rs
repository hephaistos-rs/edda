use dioxus::prelude::*;

mod api;
mod auth;
mod db;
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

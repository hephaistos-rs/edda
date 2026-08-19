use dioxus::prelude::*;
use dioxus_free_icons::icons::ld_icons::LdSearch;
use dioxus_free_icons::Icon;
use serde::Deserialize;

use crate::Route;

/// Provided here, above the `Outlet`, so pages rendered inside it (e.g. the
/// repo list) can read what's typed into the top bar's search box.
pub type SearchQuery = Signal<String>;

#[derive(Deserialize, Clone, PartialEq)]
struct CurrentUser {
    email: String,
}

// `gloo-net` calls the browser `fetch` API under the hood, so it only
// compiles for wasm32 — but this component's code is shared with the server
// build (for SSR). These calls never actually run there (`use_effect`'s
// spawned task and the click handler below only fire after hydration in a
// real browser), but the code still has to compile for both targets, hence
// the two implementations.
#[cfg(target_arch = "wasm32")]
async fn fetch_current_user() -> Option<CurrentUser> {
    let response = gloo_net::http::Request::get("/api/auth/me").send().await.ok()?;
    if !response.ok() {
        return None;
    }
    response.json().await.ok().flatten()
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_current_user() -> Option<CurrentUser> {
    None
}

#[cfg(target_arch = "wasm32")]
async fn request_logout() {
    let _ = gloo_net::http::Request::post("/api/auth/logout").send().await;
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_logout() {}

#[component]
pub fn Navbar() -> Element {
    let mut search = use_context_provider::<SearchQuery>(|| Signal::new(String::new()));
    let mut current_user = use_signal(|| Option::<CurrentUser>::None);
    let mut checked = use_signal(|| false);

    use_effect(move || {
        spawn(async move {
            current_user.set(fetch_current_user().await);
            checked.set(true);
        });
    });

    let sign_out = move |_| {
        spawn(async move {
            request_logout().await;
            current_user.set(None);
        });
    };

    rsx! {
        header {
            class: "sticky top-0 z-10 flex items-center gap-6 border-b border-line bg-bg px-4 py-3",
            Link {
                to: Route::Home {},
                class: "font-mono text-sm font-semibold tracking-tight text-ink no-underline",
                "edda"
            }
            nav { class: "flex items-center gap-4 font-mono text-sm text-ink-muted",
                Link {
                    to: Route::Home {},
                    class: "no-underline hover:text-ink",
                    "repos"
                }
            }
            label {
                class: "ml-auto flex w-full max-w-xs items-center gap-2 rounded-none border border-line bg-surface px-2.5 py-1.5 text-ink-muted focus-within:border-accent",
                span { class: "sr-only", "Search repositories" }
                Icon { icon: LdSearch, width: 16, height: 16 }
                input {
                    r#type: "text",
                    placeholder: "search repositories…",
                    class: "w-full bg-transparent font-mono text-sm text-ink placeholder:text-ink-muted focus:outline-none",
                    value: "{search}",
                    oninput: move |event| search.set(event.value()),
                }
            }
            nav { class: "flex items-center gap-4 font-mono text-sm text-ink-muted",
                if !checked() {
                    span { class: "opacity-0", "…" }
                } else if let Some(user) = current_user() {
                    span { class: "text-ink", "{user.email}" }
                    button {
                        r#type: "button",
                        class: "no-underline hover:text-ink",
                        onclick: sign_out,
                        "sign out"
                    }
                } else {
                    Link { to: Route::Login {}, class: "no-underline hover:text-ink", "sign in" }
                    Link { to: Route::Signup {}, class: "no-underline hover:text-ink", "sign up" }
                }
            }
        }

        Outlet::<Route> {}
    }
}

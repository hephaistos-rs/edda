use dioxus::prelude::*;
use dioxus_free_icons::icons::ld_icons::LdSearch;
use dioxus_free_icons::Icon;

use crate::server::CurrentUser;
use crate::Route;

/// Provided here, above the `Outlet`, so pages rendered inside it (e.g. the
/// repo list) can read what's typed into the top bar's search box.
pub type SearchQuery = Signal<String>;

/// Whether the current visitor is signed in — `Checking` until the
/// client-side `/api/auth/me` probe below resolves (always true during SSR,
/// since that probe never runs there; see `fetch_current_user`'s doc
/// comment). Kept as one three-state value rather than a plain
/// `Option<CurrentUser>` specifically so pages like `Home` can tell "still
/// finding out" apart from "confirmed logged out" — collapsing those would
/// flash a logged-out landing page at every visitor, even ones who are
/// signed in, until hydration catches up.
#[derive(Clone, PartialEq)]
pub enum AuthState {
    Checking,
    LoggedOut,
    LoggedIn(CurrentUser),
}

/// Provided here, above the `Outlet`, so pages rendered inside it (e.g.
/// `Home`) can read whether the visitor is signed in without each repeating
/// their own `/api/auth/me` fetch.
pub type AuthStateSignal = Signal<AuthState>;

// `gloo-net` calls the browser `fetch` API under the hood, so it only
// compiles for wasm32 — but this component's code is shared with the server
// build (for SSR). These calls never actually run there (`use_effect`'s
// spawned task and the click handler below only fire after hydration in a
// real browser), but the code still has to compile for both targets, hence
// the two implementations.
#[cfg(target_arch = "wasm32")]
async fn fetch_current_user() -> Option<CurrentUser> {
    let response = gloo_net::http::Request::get("/api/auth/me")
        .send()
        .await
        .ok()?;
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
    let _ = gloo_net::http::Request::post("/api/auth/logout")
        .send()
        .await;
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_logout() {}

#[component]
pub fn Navbar() -> Element {
    let mut search = use_context_provider::<SearchQuery>(|| Signal::new(String::new()));
    let mut auth_state =
        use_context_provider::<AuthStateSignal>(|| Signal::new(AuthState::Checking));

    use_effect(move || {
        spawn(async move {
            auth_state.set(match fetch_current_user().await {
                Some(user) => AuthState::LoggedIn(user),
                None => AuthState::LoggedOut,
            });
        });
    });

    let sign_out = move |_| {
        spawn(async move {
            request_logout().await;
            auth_state.set(AuthState::LoggedOut);
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
                match auth_state() {
                    AuthState::Checking => rsx! { span { class: "opacity-0", "…" } },
                    AuthState::LoggedIn(user) => rsx! {
                        span { class: "font-mono text-ink", "{user.username}" }
                        Link { to: Route::Settings {}, class: "no-underline hover:text-ink", "settings" }
                        button {
                            r#type: "button",
                            class: "no-underline hover:text-ink",
                            onclick: sign_out,
                            "sign out"
                        }
                    },
                    AuthState::LoggedOut => rsx! {
                        Link { to: Route::Login {}, class: "no-underline hover:text-ink", "sign in" }
                        Link { to: Route::Signup {}, class: "no-underline hover:text-ink", "sign up" }
                    },
                }
            }
        }

        Outlet::<Route> {}
    }
}

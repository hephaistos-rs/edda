use dioxus::prelude::*;

use edda_api_types::RepoDto;

use crate::api_client;
use crate::ui::components::repo::{NewRepoRow, Repo, RepoRow};
use crate::ui::layouts::{AuthState, AuthStateSignal, SearchQuery};
use crate::Route;

#[component]
pub fn Home() -> Element {
    let auth_state = use_context::<AuthStateSignal>();

    match auth_state() {
        // Same reasoning as `Navbar`'s `AuthState::Checking` arm: render
        // nothing distinctive yet rather than guessing, so a signed-in
        // visitor never sees the logged-out landing page flash before
        // hydration confirms who they are.
        AuthState::Checking => rsx! {
            main { class: "mx-auto max-w-3xl px-4 py-8" }
        },
        AuthState::LoggedOut => rsx! {
            LandingPage {}
        },
        AuthState::LoggedIn(_) => rsx! {
            RepoList {}
        },
    }
}

/// Logged-out `/` — no repository list (see `RepoList`, gated to signed-in
/// visitors only): a self-hosted instance's repos aren't a public directory
/// by default, so there's nothing useful to browse before signing in.
#[component]
fn LandingPage() -> Element {
    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-20",
            div { class: "border border-line px-8 py-12 text-center",
                h1 { class: "font-mono text-3xl font-semibold tracking-tight text-ink", "edda" }
                p { class: "mx-auto mt-4 max-w-md text-sm text-ink-muted",
                    "A self-hosted git platform. Host and browse your own repositories, with full control over where your code lives."
                }
                div { class: "mt-8 flex items-center justify-center gap-3",
                    Link {
                        to: Route::Signup {},
                        class: "border border-accent bg-accent px-4 py-2 font-mono text-sm text-accent-ink no-underline",
                        "create an account"
                    }
                    Link {
                        to: Route::Login {},
                        class: "border border-line px-4 py-2 font-mono text-sm text-ink no-underline hover:border-accent",
                        "sign in"
                    }
                }
            }
        }
    }
}

#[component]
fn RepoList() -> Element {
    let search = use_context::<SearchQuery>();
    let mut repos = use_resource(|| api_client::get_json::<Vec<RepoDto>>("/api/v1/repos"));
    let query = search.read().to_lowercase();

    let body = match repos() {
        Some(Ok(list)) => {
            let filtered: Vec<Repo> = list
                .into_iter()
                .map(Repo::from)
                .filter(|repo| {
                    query.is_empty()
                        || repo.owner.to_lowercase().contains(&query)
                        || repo.name.to_lowercase().contains(&query)
                        || repo.description.to_lowercase().contains(&query)
                })
                .collect();

            if filtered.is_empty() && !query.is_empty() {
                rsx! {
                    div { class: "border border-dashed border-line px-4 py-10 text-center text-sm text-ink-muted",
                        "No repositories match \"{search}\"."
                    }
                }
            } else {
                rsx! {
                    div { class: "border border-line",
                        for repo in filtered {
                            RepoRow { key: "{repo.owner}/{repo.name}", repo }
                        }
                        NewRepoRow { on_created: move |_| repos.restart() }
                    }
                }
            }
        }
        Some(Err(err)) => rsx! {
            div { class: "border border-dashed border-status-conflict px-4 py-10 text-center text-sm text-status-conflict",
                "Couldn't load repositories: {err}"
            }
        },
        None => rsx! {
            div { class: "px-4 py-10 text-center text-sm text-ink-muted", "Loading…" }
        },
    };

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            h1 { class: "sr-only", "Repositories" }
            {body}
        }
    }
}

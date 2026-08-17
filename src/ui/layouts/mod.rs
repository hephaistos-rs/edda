use dioxus::prelude::*;
use dioxus_free_icons::icons::ld_icons::LdSearch;
use dioxus_free_icons::Icon;

use crate::Route;

/// Provided here, above the `Outlet`, so pages rendered inside it (e.g. the
/// repo list) can read what's typed into the top bar's search box.
pub type SearchQuery = Signal<String>;

#[component]
pub fn Navbar() -> Element {
    let mut search = use_context_provider::<SearchQuery>(|| Signal::new(String::new()));

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
        }

        Outlet::<Route> {}
    }
}

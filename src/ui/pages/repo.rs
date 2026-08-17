use dioxus::prelude::*;

use crate::Route;

/// Repo detail page. Stub for now — real content (file tree, commits,
/// branches) lands once `db`/`git` are implemented.
#[component]
pub fn Repo(name: String) -> Element {
    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            Link {
                to: Route::Home {},
                class: "font-mono text-sm text-ink-muted no-underline hover:text-ink",
                "← repos"
            }
            h1 { class: "mt-4 font-mono text-2xl font-semibold text-ink", "{name}" }
            p { class: "mt-2 text-sm text-ink-muted", "Repository view isn't built yet." }
        }
    }
}

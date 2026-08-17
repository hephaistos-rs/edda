use dioxus::prelude::*;
use dioxus_free_icons::icons::ld_icons::LdPlus;
use dioxus_free_icons::Icon;

use crate::ui::components::repo::{sample_repos, RepoRow};
use crate::ui::layouts::SearchQuery;

#[component]
pub fn Home() -> Element {
    let search = use_context::<SearchQuery>();
    let query = search.read().to_lowercase();

    let repos = sample_repos();
    let filtered: Vec<_> = repos
        .into_iter()
        .filter(|repo| {
            query.is_empty()
                || repo.name.to_lowercase().contains(&query)
                || repo.description.to_lowercase().contains(&query)
        })
        .collect();

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            h1 { class: "sr-only", "Repositories" }

            if filtered.is_empty() {
                div { class: "border border-dashed border-line px-4 py-10 text-center text-sm text-ink-muted",
                    "No repositories match \"{search}\"."
                }
            } else {
                div { class: "border border-line",
                    for repo in filtered {
                        RepoRow { key: "{repo.name}", repo }
                    }
                    div {
                        class: "flex items-center gap-2 px-4 py-3 text-ink-muted opacity-60",
                        title: "Creating repositories isn't wired up yet",
                        "aria-disabled": "true",
                        Icon { icon: LdPlus, width: 16, height: 16 }
                        span { class: "font-mono text-sm", "new repository" }
                        span { class: "ml-auto text-xs", "soon" }
                    }
                }
            }
        }
    }
}

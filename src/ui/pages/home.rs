use dioxus::prelude::*;

use crate::server::list_repos;
use crate::ui::components::repo::{NewRepoRow, Repo, RepoRow};
use crate::ui::layouts::SearchQuery;

#[component]
pub fn Home() -> Element {
    let search = use_context::<SearchQuery>();
    let mut repos = use_server_future(list_repos)?;
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

use dioxus::prelude::*;
use dioxus_free_icons::icons::ld_icons::LdPencil;
use dioxus_free_icons::Icon;

use crate::server::{delete_repo, get_repo, update_repo};
use crate::Route;

/// Relative time without pulling in a date-formatting crate — repo activity
/// only ever needs coarse granularity here.
fn relative_time(unix_seconds: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(unix_seconds);
    let delta = (now - unix_seconds).max(0);

    const MINUTE: i64 = 60;
    const HOUR: i64 = 60 * MINUTE;
    const DAY: i64 = 24 * HOUR;

    if delta < MINUTE {
        "just now".to_string()
    } else if delta < HOUR {
        format!("{}m ago", delta / MINUTE)
    } else if delta < DAY {
        format!("{}h ago", delta / HOUR)
    } else {
        format!("{}d ago", delta / DAY)
    }
}

#[component]
pub fn Repo(name: String) -> Element {
    let navigator = use_navigator();
    let mut repo = use_server_future({
        let name = name.clone();
        move || get_repo(name.clone())
    })?;

    let mut confirming_delete = use_signal(|| false);
    let mut delete_error = use_signal(|| Option::<String>::None);

    let mut editing_description = use_signal(|| false);
    let mut description_draft = use_signal(String::new);
    let mut description_error = use_signal(|| Option::<String>::None);

    let body = match repo() {
        Some(Ok(dto)) => {
            let status_line = if dto.is_empty {
                "empty repository — no commits yet".to_string()
            } else {
                let branch = dto.default_branch.as_deref().unwrap_or("HEAD");
                let noun = if dto.branch_count == 1 { "branch" } else { "branches" };
                format!("{branch} · {} {noun}", dto.branch_count)
            };

            let description_text = dto.description.clone().unwrap_or_else(|| "No description".to_string());
            let description_class = if dto.description.is_some() { "text-ink" } else { "text-ink-muted italic" };
            let current_description = dto.description.clone().unwrap_or_default();

            rsx! {
                h1 { class: "mt-4 font-mono text-2xl font-semibold text-ink", "{dto.name}" }
                p { class: "mt-1 font-mono text-xs text-ink-muted", "{status_line}" }

                div { class: "mt-4",
                    if editing_description() {
                        div {
                            textarea {
                                class: "w-full border border-line bg-surface px-2 py-1.5 text-sm text-ink placeholder:text-ink-muted focus:border-accent focus:outline-none",
                                rows: "2",
                                placeholder: "description",
                                value: "{description_draft}",
                                autofocus: true,
                                oninput: move |event| description_draft.set(event.value()),
                            }
                            div { class: "mt-2 flex items-center gap-3",
                                button {
                                    r#type: "button",
                                    class: "border border-line px-2 py-1 font-mono text-xs text-ink hover:border-accent",
                                    onclick: {
                                        let name = name.clone();
                                        move |_| {
                                            let name = name.clone();
                                            let text = description_draft.read().clone();
                                            spawn(async move {
                                                let value = if text.trim().is_empty() { None } else { Some(text) };
                                                match update_repo(name, value).await {
                                                    Ok(()) => {
                                                        editing_description.set(false);
                                                        description_error.set(None);
                                                        repo.restart();
                                                    }
                                                    Err(err) => description_error.set(Some(err.to_string())),
                                                }
                                            });
                                        }
                                    },
                                    "save"
                                }
                                button {
                                    r#type: "button",
                                    class: "font-mono text-xs text-ink-muted hover:text-ink",
                                    onclick: move |_| {
                                        editing_description.set(false);
                                        description_error.set(None);
                                    },
                                    "cancel"
                                }
                            }
                            if let Some(message) = description_error() {
                                p { class: "mt-2 font-mono text-xs text-status-conflict", "{message}" }
                            }
                        }
                    } else {
                        div { class: "group flex items-start gap-2",
                            p { class: "text-sm {description_class}", "{description_text}" }
                            button {
                                r#type: "button",
                                class: "shrink-0 text-ink-muted opacity-0 hover:text-ink focus-visible:opacity-100 group-hover:opacity-100",
                                title: "Edit description",
                                onclick: move |_| {
                                    description_draft.set(current_description.clone());
                                    editing_description.set(true);
                                },
                                Icon { icon: LdPencil, width: 14, height: 14 }
                                span { class: "sr-only", "Edit description" }
                            }
                        }
                    }
                }

                if let Some(commit) = &dto.last_commit {
                    div { class: "mt-6 border border-line px-4 py-3",
                        div { class: "text-sm text-ink", "{commit.summary}" }
                        div { class: "mt-1 font-mono text-xs text-ink-muted",
                            "{commit.author_name} · {relative_time(commit.unix_seconds)}"
                        }
                    }
                }

                div { class: "mt-8 border-t border-line pt-4",
                    if confirming_delete() {
                        div { class: "flex items-center gap-3",
                            span { class: "text-sm text-status-conflict", "Delete \"{dto.name}\" permanently?" }
                            button {
                                r#type: "button",
                                class: "border border-status-conflict px-2 py-1 font-mono text-xs text-status-conflict hover:bg-status-conflict hover:text-accent-ink",
                                onclick: {
                                    let name = name.clone();
                                    move |_| {
                                        let name = name.clone();
                                        spawn(async move {
                                            match delete_repo(name).await {
                                                Ok(()) => { navigator.push(Route::Home {}); }
                                                Err(err) => {
                                                    delete_error.set(Some(err.to_string()));
                                                    confirming_delete.set(false);
                                                }
                                            }
                                        });
                                    }
                                },
                                "confirm delete"
                            }
                            button {
                                r#type: "button",
                                class: "font-mono text-xs text-ink-muted hover:text-ink",
                                onclick: move |_| confirming_delete.set(false),
                                "cancel"
                            }
                        }
                    } else {
                        button {
                            r#type: "button",
                            class: "font-mono text-xs text-ink-muted hover:text-status-conflict",
                            onclick: move |_| confirming_delete.set(true),
                            "delete repository"
                        }
                    }
                    if let Some(message) = delete_error() {
                        p { class: "mt-2 font-mono text-xs text-status-conflict", "{message}" }
                    }
                }
            }
        }
        Some(Err(err)) => rsx! {
            p { class: "mt-4 text-sm text-status-conflict", "Couldn't load \"{name}\": {err}" }
        },
        None => rsx! {
            p { class: "mt-4 text-sm text-ink-muted", "Loading…" }
        },
    };

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            Link {
                to: Route::Home {},
                class: "font-mono text-sm text-ink-muted no-underline hover:text-ink",
                "← repos"
            }
            {body}
        }
    }
}

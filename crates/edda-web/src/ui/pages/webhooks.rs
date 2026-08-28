use dioxus::prelude::*;

use edda_api_types::{CreateWebhookRequest, CreatedWebhookDto, WebhookDto};

use crate::api_client;

fn webhooks_path(owner: &str, name: &str) -> String {
    format!("/api/v1/repos/{owner}/{name}/webhooks")
}

const ALL_EVENTS: &[&str] = &[
    "pull_request.opened",
    "pull_request.merged",
    "issue.opened",
    "issue.commented",
    "push",
];

#[component]
pub fn WebhooksSettings(owner: String, name: String) -> Element {
    let owner_c = owner.clone();
    let name_c = name.clone();
    let mut webhooks = use_resource(move || {
        let path = webhooks_path(&owner_c, &name_c);
        async move { api_client::get_json::<Vec<WebhookDto>>(&path).await }
    });

    let mut target_url = use_signal(String::new);
    let mut selected_events = use_signal(std::collections::HashSet::<String>::new);
    let mut error = use_signal(|| Option::<String>::None);
    let mut submitting = use_signal(|| false);
    let mut just_created_secret = use_signal(|| Option::<String>::None);

    let owner_for_submit = owner.clone();
    let name_for_submit = name.clone();

    let on_submit = move |event: FormEvent| {
        event.prevent_default();
        let path = webhooks_path(&owner_for_submit, &name_for_submit);
        let url_value = target_url.read().clone();
        let events_value: Vec<String> = selected_events.read().iter().cloned().collect();
        submitting.set(true);
        error.set(None);
        spawn(async move {
            let request = CreateWebhookRequest {
                target_url: url_value,
                events: events_value,
            };
            let result = api_client::post_json::<_, CreatedWebhookDto>(&path, &request).await;
            submitting.set(false);
            match result {
                Ok(created) => {
                    target_url.set(String::new());
                    selected_events.set(std::collections::HashSet::new());
                    just_created_secret.set(Some(created.secret));
                    webhooks.restart();
                }
                Err(err) => error.set(Some(err.to_string())),
            }
        });
    };

    let owner_for_delete = owner.clone();
    let name_for_delete = name.clone();

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            h1 { class: "font-mono text-xl font-semibold text-ink", "Webhooks" }
            p { class: "mt-1 text-sm text-ink-muted",
                "Notify an external URL, HMAC-signed, when selected events happen in this repository."
            }

            form { class: "mt-6 flex flex-col gap-3 border border-line p-4", onsubmit: on_submit,
                label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                    "target URL"
                    input {
                        r#type: "url", required: true, placeholder: "https://example.com/hook",
                        class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                        value: "{target_url}",
                        oninput: move |event| target_url.set(event.value()),
                    }
                }
                div { class: "flex flex-col gap-1 text-sm text-ink-muted",
                    "events"
                    div { class: "flex flex-wrap gap-4",
                        for ev in ALL_EVENTS {
                            label { class: "flex items-center gap-1.5 font-mono text-xs text-ink",
                                input {
                                    r#type: "checkbox",
                                    checked: selected_events.read().contains(*ev),
                                    onchange: {
                                        let ev = ev.to_string();
                                        move |event: FormEvent| {
                                            let ev = ev.clone();
                                            selected_events.with_mut(|set| {
                                                if event.checked() {
                                                    set.insert(ev);
                                                } else {
                                                    set.remove(&ev);
                                                }
                                            });
                                        }
                                    },
                                }
                                "{ev}"
                            }
                        }
                    }
                }
                if let Some(message) = error() {
                    p { class: "font-mono text-xs text-status-conflict", "{message}" }
                }
                button {
                    r#type: "submit",
                    disabled: submitting(),
                    class: "self-start border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                    if submitting() { "creating…" } else { "add webhook" }
                }
            }

            if let Some(secret) = just_created_secret() {
                div { class: "mt-4 flex flex-col gap-2 border border-accent bg-surface p-4",
                    p { class: "font-mono text-xs font-semibold text-ink",
                        "Copy this signing secret now — you won't be able to see it again."
                    }
                    div { class: "flex items-center gap-2",
                        code { class: "flex-1 overflow-x-auto border border-line bg-canvas px-2 py-1.5 font-mono text-xs text-ink", "{secret}" }
                        button {
                            r#type: "button",
                            class: "shrink-0 border border-line px-2 py-1.5 font-mono text-xs text-ink-muted hover:text-ink",
                            onclick: move |_| just_created_secret.set(None),
                            "dismiss"
                        }
                    }
                }
            }

            div { class: "mt-6",
                match &*webhooks.read() {
                    Some(Ok(list)) if list.is_empty() => rsx! {
                        p { class: "text-sm text-ink-muted italic", "no webhooks configured" }
                    },
                    Some(Ok(list)) => rsx! {
                        div { class: "divide-y divide-line border border-line",
                            for hook in list.clone() {
                                div { class: "flex items-center justify-between gap-4 px-4 py-3",
                                    div { class: "min-w-0",
                                        div { class: "truncate font-mono text-sm text-ink", "{hook.target_url}" }
                                        div { class: "truncate font-mono text-xs text-ink-muted", "{hook.events.join(\", \")}" }
                                    }
                                    button {
                                        r#type: "button",
                                        class: "shrink-0 font-mono text-xs text-ink-muted hover:text-status-conflict",
                                        onclick: {
                                            let base = webhooks_path(&owner_for_delete, &name_for_delete);
                                            let id = hook.id.clone();
                                            move |_| {
                                                let path = format!("{base}/{id}");
                                                spawn(async move {
                                                    if api_client::delete_ok(&path).await.is_ok() {
                                                        webhooks.restart();
                                                    }
                                                });
                                            }
                                        },
                                        "delete"
                                    }
                                }
                            }
                        }
                    },
                    Some(Err(err)) => rsx! { p { class: "text-sm text-status-conflict", "{err}" } },
                    None => rsx! { p { class: "text-sm text-ink-muted", "loading…" } },
                }
            }
        }
    }
}

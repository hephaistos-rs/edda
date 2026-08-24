use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct SshKeyDto {
    id: String,
    title: String,
    fingerprint: String,
    created_at: i64,
    #[allow(dead_code)]
    last_used_at: Option<i64>,
}

#[derive(Serialize)]
struct AddSshKeyBody<'a> {
    title: &'a str,
    public_key: &'a str,
}

// Same wasm32-only-fetch / server-side-stub split as every other hand-written
// (non-server-function) API call in `ui/` — see `login.rs`'s doc comment.
#[cfg(target_arch = "wasm32")]
async fn fetch_keys() -> Result<Vec<SshKeyDto>, String> {
    let response = gloo_net::http::Request::get("/api/ssh-keys")
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.ok() {
        return Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't load SSH keys".to_string()));
    }
    response.json().await.map_err(|err| err.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_keys() -> Result<Vec<SshKeyDto>, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_add_key(body: &AddSshKeyBody<'_>) -> Result<(), String> {
    let request = gloo_net::http::Request::post("/api/ssh-keys")
        .json(body)
        .map_err(|err| err.to_string())?;
    let response = request.send().await.map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't add key".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_add_key(_body: &AddSshKeyBody<'_>) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_revoke_key(id: &str) -> Result<(), String> {
    let response = gloo_net::http::Request::post(&format!("/api/ssh-keys/{id}/revoke"))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't revoke key".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_revoke_key(_id: &str) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

/// Coarse "N days ago" — same reasoning as `repo.rs`'s own `relative_time`:
/// this data only ever needs day-scale granularity, not a date-formatting
/// dependency.
fn relative_time(unix_seconds: i64) -> String {
    let now = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(unix_seconds);
    let delta = (now - unix_seconds).max(0);
    const DAY: i64 = 86400;
    if delta < DAY {
        "today".to_string()
    } else {
        format!("{}d ago", delta / DAY)
    }
}

#[component]
pub fn Settings() -> Element {
    let mut keys = use_resource(fetch_keys);

    let mut title = use_signal(String::new);
    let mut public_key = use_signal(String::new);
    let mut add_error = use_signal(|| Option::<String>::None);
    let mut submitting = use_signal(|| false);

    let on_submit = move |event: FormEvent| {
        event.prevent_default();
        let title_value = title.read().clone();
        let public_key_value = public_key.read().clone();

        submitting.set(true);
        add_error.set(None);
        spawn(async move {
            let body = AddSshKeyBody {
                title: &title_value,
                public_key: &public_key_value,
            };
            match request_add_key(&body).await {
                Ok(()) => {
                    title.set(String::new());
                    public_key.set(String::new());
                    keys.restart();
                }
                Err(message) => add_error.set(Some(message)),
            }
            submitting.set(false);
        });
    };

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            h1 { class: "font-mono text-xl font-semibold text-ink", "SSH keys" }
            p { class: "mt-1 text-sm text-ink-muted",
                "Add a public key to push and pull over SSH — paste the contents of e.g. "
                span { class: "font-mono", "~/.ssh/id_ed25519.pub" }
                "."
            }

            form { class: "mt-6 flex flex-col gap-3 border border-line p-4", onsubmit: on_submit,
                label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                    "title"
                    input {
                        r#type: "text",
                        required: true,
                        placeholder: "e.g. laptop",
                        class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                        value: "{title}",
                        oninput: move |event| title.set(event.value()),
                    }
                }
                label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                    "public key"
                    textarea {
                        required: true,
                        rows: "3",
                        placeholder: "ssh-ed25519 AAAA...",
                        class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-xs text-ink focus:border-accent focus:outline-none",
                        value: "{public_key}",
                        oninput: move |event| public_key.set(event.value()),
                    }
                }
                if let Some(message) = add_error() {
                    p { class: "font-mono text-xs text-status-conflict", "{message}" }
                }
                button {
                    r#type: "submit",
                    disabled: submitting(),
                    class: "self-start border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                    if submitting() { "adding…" } else { "add key" }
                }
            }

            div { class: "mt-8",
                match &*keys.read() {
                    Some(Ok(list)) if list.is_empty() => rsx! {
                        p { class: "text-sm text-ink-muted italic", "no keys registered yet" }
                    },
                    Some(Ok(list)) => rsx! {
                        div { class: "divide-y divide-line border border-line",
                            for key in list.clone() {
                                div { class: "flex items-center justify-between gap-4 px-4 py-3",
                                    div { class: "min-w-0",
                                        div { class: "font-mono text-sm text-ink", "{key.title}" }
                                        div { class: "truncate font-mono text-xs text-ink-muted", "{key.fingerprint} · added {relative_time(key.created_at)}" }
                                    }
                                    button {
                                        r#type: "button",
                                        class: "shrink-0 font-mono text-xs text-ink-muted hover:text-status-conflict",
                                        onclick: {
                                            let id = key.id.clone();
                                            move |_| {
                                                let id = id.clone();
                                                spawn(async move {
                                                    if request_revoke_key(&id).await.is_ok() {
                                                        keys.restart();
                                                    }
                                                });
                                            }
                                        },
                                        "revoke"
                                    }
                                }
                            }
                        }
                    },
                    Some(Err(err)) => rsx! {
                        p { class: "text-sm text-status-conflict", "{err}" }
                    },
                    None => rsx! {
                        p { class: "text-sm text-ink-muted", "loading…" }
                    },
                }
            }
        }
    }
}

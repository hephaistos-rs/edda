use dioxus::prelude::*;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct AdminUserDto {
    id: String,
    username: String,
    email: String,
    is_admin: bool,
    disabled: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct AuditEventDto {
    id: String,
    occurred_at: i64,
    event_type: String,
    actor_id: Option<String>,
    #[allow(dead_code)]
    target_type: Option<String>,
    #[allow(dead_code)]
    target_id: Option<String>,
    #[allow(dead_code)]
    detail_json: Option<String>,
}

// Same wasm32-only-fetch / server-side-stub split as every other
// hand-written (non-server-function) API call in `ui/` — see `login.rs`'s
// doc comment. The UI-level check here (rendering this page/its actions
// at all) is not the security boundary — every `/api/admin/*` route
// independently enforces `require_instance_admin` server-side regardless
// of what this page renders.
#[cfg(target_arch = "wasm32")]
async fn fetch_users() -> Result<Vec<AdminUserDto>, String> {
    let response = gloo_net::http::Request::get("/api/admin/users")
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.ok() {
        return Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't load users".to_string()));
    }
    response.json().await.map_err(|err| err.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_users() -> Result<Vec<AdminUserDto>, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn fetch_audit_events() -> Result<Vec<AuditEventDto>, String> {
    let response = gloo_net::http::Request::get("/api/admin/audit-events")
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.ok() {
        return Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't load audit events".to_string()));
    }
    response.json().await.map_err(|err| err.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_audit_events() -> Result<Vec<AuditEventDto>, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_set_disabled(id: &str, disabled: bool) -> Result<(), String> {
    let action = if disabled { "disable" } else { "enable" };
    let response = gloo_net::http::Request::post(&format!("/api/admin/users/{id}/{action}"))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't update user".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_set_disabled(_id: &str, _disabled: bool) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_delete_user(id: &str) -> Result<(), String> {
    let response = gloo_net::http::Request::delete(&format!("/api/admin/users/{id}"))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't delete user".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_delete_user(_id: &str) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

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
pub fn Admin() -> Element {
    let mut users = use_resource(fetch_users);
    let events = use_resource(fetch_audit_events);
    let mut action_error = use_signal(|| Option::<String>::None);

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            h1 { class: "font-mono text-xl font-semibold text-ink", "Instance administration" }
            p { class: "mt-1 text-sm text-ink-muted",
                "Server-side access control applies regardless of this page — a non-admin sees these actions fail, not just hidden."
            }

            h2 { class: "mt-8 font-mono text-sm font-semibold text-ink", "Users" }
            if let Some(message) = action_error() {
                p { class: "mt-2 font-mono text-xs text-status-conflict", "{message}" }
            }
            div { class: "mt-2",
                match &*users.read() {
                    Some(Ok(list)) => rsx! {
                        div { class: "divide-y divide-line border border-line",
                            for user in list.clone() {
                                div { class: "flex items-center justify-between gap-4 px-4 py-3",
                                    div { class: "min-w-0",
                                        div { class: "font-mono text-sm text-ink",
                                            "{user.username} "
                                            span { class: "text-ink-muted", "({user.email})" }
                                            if user.is_admin {
                                                span { class: "ml-2 font-mono text-xs text-accent", "[admin]" }
                                            }
                                            if user.disabled {
                                                span { class: "ml-2 font-mono text-xs text-status-conflict", "[disabled]" }
                                            }
                                        }
                                    }
                                    div { class: "flex shrink-0 gap-3",
                                        button {
                                            r#type: "button",
                                            class: "font-mono text-xs text-ink-muted hover:text-ink",
                                            onclick: {
                                                let id = user.id.clone();
                                                let disabled = user.disabled;
                                                move |_| {
                                                    let id = id.clone();
                                                    spawn(async move {
                                                        match request_set_disabled(&id, !disabled).await {
                                                            Ok(()) => users.restart(),
                                                            Err(message) => action_error.set(Some(message)),
                                                        }
                                                    });
                                                }
                                            },
                                            if user.disabled { "enable" } else { "disable" }
                                        }
                                        button {
                                            r#type: "button",
                                            class: "font-mono text-xs text-ink-muted hover:text-status-conflict",
                                            onclick: {
                                                let id = user.id.clone();
                                                move |_| {
                                                    let id = id.clone();
                                                    spawn(async move {
                                                        match request_delete_user(&id).await {
                                                            Ok(()) => users.restart(),
                                                            Err(message) => action_error.set(Some(message)),
                                                        }
                                                    });
                                                }
                                            },
                                            "delete"
                                        }
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

            h2 { class: "mt-10 font-mono text-sm font-semibold text-ink", "Recent audit events" }
            div { class: "mt-2",
                match &*events.read() {
                    Some(Ok(list)) if list.is_empty() => rsx! {
                        p { class: "text-sm text-ink-muted italic", "no events recorded yet" }
                    },
                    Some(Ok(list)) => rsx! {
                        div { class: "divide-y divide-line border border-line",
                            for event in list.clone() {
                                div { class: "px-4 py-2 font-mono text-xs text-ink-muted",
                                    "{relative_time(event.occurred_at)} · {event.event_type}"
                                    if let Some(actor) = &event.actor_id {
                                        " · actor {actor}"
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

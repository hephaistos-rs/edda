use dioxus::prelude::*;

use crate::notification_server::{list_notifications, mark_notification_read};

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

fn kind_label(kind: &str) -> &'static str {
    match kind {
        "mention" => "mentioned you",
        "pr_review_requested" => "requested your review",
        "issue_assigned" => "assigned you",
        _ => "notified you",
    }
}

#[component]
pub fn Notifications() -> Element {
    let mut notifications = use_resource(list_notifications);

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            h1 { class: "font-mono text-xl font-semibold text-ink", "Notifications" }
            div { class: "mt-6",
                match &*notifications.read() {
                    Some(Ok(list)) if list.is_empty() => rsx! {
                        p { class: "text-sm text-ink-muted italic", "nothing here yet" }
                    },
                    Some(Ok(list)) => rsx! {
                        div { class: "divide-y divide-line border border-line",
                            for item in list.clone() {
                                div {
                                    class: if item.read { "flex items-center justify-between gap-4 px-4 py-3 opacity-60" } else { "flex items-center justify-between gap-4 px-4 py-3" },
                                    div { class: "min-w-0",
                                        div { class: "font-mono text-sm text-ink",
                                            "someone {kind_label(&item.kind)} on {item.subject_type} "
                                            span { class: "text-ink-muted", "{item.subject_id}" }
                                        }
                                        div { class: "font-mono text-xs text-ink-muted", "{relative_time(item.created_at)}" }
                                    }
                                    if !item.read {
                                        button {
                                            r#type: "button",
                                            class: "shrink-0 font-mono text-xs text-accent hover:opacity-80",
                                            onclick: {
                                                let id = item.id.clone();
                                                move |_| {
                                                    let id = id.clone();
                                                    spawn(async move {
                                                        if mark_notification_read(id).await.is_ok() {
                                                            notifications.restart();
                                                        }
                                                    });
                                                }
                                            },
                                            "mark read"
                                        }
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

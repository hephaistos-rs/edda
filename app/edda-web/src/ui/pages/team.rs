use dioxus::prelude::*;

use crate::team_server::{add_team_member, get_team, remove_team_member, set_team_code_permission};

#[component]
pub fn TeamDetail(org_name: String, team_name: String) -> Element {
    let org_c = org_name.clone();
    let team_c = team_name.clone();
    let mut team = use_resource(move || {
        let org = org_c.clone();
        let team = team_c.clone();
        async move { get_team(org, team).await }
    });

    let mut username = use_signal(String::new);
    let mut error = use_signal(|| Option::<String>::None);
    let mut submitting = use_signal(|| false);

    let org_for_add = org_name.clone();
    let team_for_add = team_name.clone();
    let on_add_member = move |event: FormEvent| {
        event.prevent_default();
        let username_value = username.read().trim().to_string();
        if username_value.is_empty() {
            return;
        }
        let org = org_for_add.clone();
        let team_name = team_for_add.clone();
        submitting.set(true);
        error.set(None);
        spawn(async move {
            let result = add_team_member(org, team_name, username_value).await;
            submitting.set(false);
            match result {
                Ok(()) => {
                    username.set(String::new());
                    team.restart();
                }
                Err(err) => error.set(Some(err.to_string())),
            }
        });
    };

    let org_for_remove = org_name.clone();
    let team_for_remove = team_name.clone();
    let org_for_permission = org_name.clone();
    let team_for_permission = team_name.clone();

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            match &*team.read() {
                Some(Ok(details)) => rsx! {
                    h1 { class: "font-mono text-xl font-semibold text-ink", "{org_name} / {details.name}" }
                    p { class: "mt-1 text-sm text-ink-muted",
                        "default permission: {details.permission}"
                        if let Some(code_override) = &details.code_permission_override {
                            " · code unit: {code_override}"
                        }
                    }

                    div { class: "mt-4 flex flex-wrap gap-2",
                        for level in ["none", "read", "write", "admin"] {
                            button {
                                r#type: "button",
                                class: "border border-line px-2.5 py-1 font-mono text-xs text-ink-muted hover:border-accent hover:text-ink",
                                onclick: {
                                    let org = org_for_permission.clone();
                                    let team_name = team_for_permission.clone();
                                    move |_| {
                                        let org = org.clone();
                                        let team_name = team_name.clone();
                                        spawn(async move {
                                            if set_team_code_permission(org, team_name, level.to_string())
                                                .await
                                                .is_ok()
                                            {
                                                team.restart();
                                            }
                                        });
                                    }
                                },
                                "code: {level}"
                            }
                        }
                    }

                    h2 { class: "mt-6 font-mono text-sm font-semibold text-ink", "Members" }
                    form { class: "mt-3 flex items-end gap-3 border border-line p-4", onsubmit: on_add_member,
                        label { class: "flex flex-1 flex-col gap-1 text-sm text-ink-muted",
                            "username"
                            input {
                                r#type: "text", required: true, placeholder: "alice",
                                class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                                value: "{username}",
                                oninput: move |event| username.set(event.value()),
                            }
                        }
                        button {
                            r#type: "submit",
                            disabled: submitting(),
                            class: "border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                            if submitting() { "adding…" } else { "add member" }
                        }
                    }
                    if let Some(message) = error() {
                        p { class: "mt-2 font-mono text-xs text-status-conflict", "{message}" }
                    }

                    div { class: "mt-4 divide-y divide-line border border-line",
                        for member in details.members.clone() {
                            div { class: "flex items-center justify-between gap-4 px-4 py-3",
                                span { class: "font-mono text-sm text-ink", "{member}" }
                                button {
                                    r#type: "button",
                                    class: "font-mono text-xs text-ink-muted hover:text-status-conflict",
                                    onclick: {
                                        let org = org_for_remove.clone();
                                        let team_name = team_for_remove.clone();
                                        let member = member.clone();
                                        move |_| {
                                            let org = org.clone();
                                            let team_name = team_name.clone();
                                            let member = member.clone();
                                            spawn(async move {
                                                if remove_team_member(org, team_name, member).await.is_ok() {
                                                    team.restart();
                                                }
                                            });
                                        }
                                    },
                                    "remove"
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

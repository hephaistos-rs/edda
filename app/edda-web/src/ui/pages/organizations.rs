use dioxus::prelude::*;

use crate::org_server::{create_organization, get_organization, list_my_organizations};
use crate::team_server::{create_team, list_teams};
use crate::Route;

#[component]
pub fn OrganizationsList() -> Element {
    let mut orgs = use_resource(list_my_organizations);

    let mut name = use_signal(String::new);
    let mut display_name = use_signal(String::new);
    let mut error = use_signal(|| Option::<String>::None);
    let mut submitting = use_signal(|| false);

    let on_submit = move |event: FormEvent| {
        event.prevent_default();
        let name_value = name.read().trim().to_string();
        if name_value.is_empty() {
            return;
        }
        let display_value = display_name.read().trim().to_string();
        let display_value = (!display_value.is_empty()).then_some(display_value);
        submitting.set(true);
        error.set(None);
        spawn(async move {
            let result = create_organization(name_value, display_value).await;
            submitting.set(false);
            match result {
                Ok(()) => {
                    name.set(String::new());
                    display_name.set(String::new());
                    orgs.restart();
                }
                Err(err) => error.set(Some(err.to_string())),
            }
        });
    };

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            h1 { class: "font-mono text-xl font-semibold text-ink", "Organizations" }
            p { class: "mt-1 text-sm text-ink-muted",
                "Organizations own repositories on behalf of a group, with access controlled through teams."
            }

            form { class: "mt-6 flex flex-col gap-3 border border-line p-4", onsubmit: on_submit,
                label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                    "name"
                    input {
                        r#type: "text", required: true, placeholder: "acme-corp",
                        class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                        value: "{name}",
                        oninput: move |event| name.set(event.value()),
                    }
                }
                label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                    "display name (optional)"
                    input {
                        r#type: "text", placeholder: "Acme Corporation",
                        class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                        value: "{display_name}",
                        oninput: move |event| display_name.set(event.value()),
                    }
                }
                if let Some(message) = error() {
                    p { class: "font-mono text-xs text-status-conflict", "{message}" }
                }
                button {
                    r#type: "submit",
                    disabled: submitting(),
                    class: "self-start border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                    if submitting() { "creating…" } else { "new organization" }
                }
            }

            div { class: "mt-6",
                match &*orgs.read() {
                    Some(Ok(list)) if list.is_empty() => rsx! {
                        p { class: "text-sm text-ink-muted italic", "you don't belong to any organizations yet" }
                    },
                    Some(Ok(list)) => rsx! {
                        div { class: "divide-y divide-line border border-line",
                            for org in list.clone() {
                                Link {
                                    to: Route::OrganizationDetail { name: org.name.clone() },
                                    class: "flex items-center justify-between gap-4 px-4 py-3 hover:bg-surface",
                                    span { class: "font-mono text-sm text-ink", "{org.name}" }
                                    if org.is_admin {
                                        span { class: "font-mono text-xs text-ink-muted", "owner" }
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

#[component]
pub fn OrganizationDetail(name: String) -> Element {
    let name_c = name.clone();
    let org = use_resource(move || {
        let name = name_c.clone();
        async move { get_organization(name).await }
    });

    let name_for_teams = name.clone();
    let mut teams = use_resource(move || {
        let name = name_for_teams.clone();
        async move { list_teams(name).await }
    });

    let mut team_name = use_signal(String::new);
    let mut permission = use_signal(|| "read".to_string());
    let mut error = use_signal(|| Option::<String>::None);
    let mut submitting = use_signal(|| false);

    let org_for_submit = name.clone();
    let on_submit = move |event: FormEvent| {
        event.prevent_default();
        let team_value = team_name.read().trim().to_string();
        if team_value.is_empty() {
            return;
        }
        let org_name = org_for_submit.clone();
        let permission_value = permission.read().clone();
        submitting.set(true);
        error.set(None);
        spawn(async move {
            let result = create_team(org_name, team_value, permission_value).await;
            submitting.set(false);
            match result {
                Ok(()) => {
                    team_name.set(String::new());
                    teams.restart();
                }
                Err(err) => error.set(Some(err.to_string())),
            }
        });
    };

    let org_for_links = name.clone();

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            match &*org.read() {
                Some(Ok(details)) => rsx! {
                    h1 { class: "font-mono text-xl font-semibold text-ink", "{details.name}" }
                    if let Some(display_name) = &details.display_name {
                        p { class: "mt-1 text-sm text-ink-muted", "{display_name}" }
                    }

                    if details.is_admin {
                        div { class: "mt-6",
                            h2 { class: "font-mono text-sm font-semibold text-ink", "Teams" }
                            form { class: "mt-3 flex flex-wrap items-end gap-3 border border-line p-4", onsubmit: on_submit,
                                label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                                    "name"
                                    input {
                                        r#type: "text", required: true, placeholder: "developers",
                                        class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                                        value: "{team_name}",
                                        oninput: move |event| team_name.set(event.value()),
                                    }
                                }
                                label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                                    "default permission"
                                    select {
                                        class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                                        value: "{permission}",
                                        onchange: move |event| permission.set(event.value()),
                                        option { value: "none", "none" }
                                        option { value: "read", "read" }
                                        option { value: "write", "write" }
                                        option { value: "admin", "admin" }
                                    }
                                }
                                button {
                                    r#type: "submit",
                                    disabled: submitting(),
                                    class: "border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                                    if submitting() { "creating…" } else { "new team" }
                                }
                            }
                            if let Some(message) = error() {
                                p { class: "mt-2 font-mono text-xs text-status-conflict", "{message}" }
                            }

                            div { class: "mt-4",
                                match &*teams.read() {
                                    Some(Ok(list)) if list.is_empty() => rsx! {
                                        p { class: "text-sm text-ink-muted italic", "no teams yet" }
                                    },
                                    Some(Ok(list)) => rsx! {
                                        div { class: "divide-y divide-line border border-line",
                                            for team in list.clone() {
                                                Link {
                                                    to: Route::TeamDetail { org_name: org_for_links.clone(), team_name: team.name.clone() },
                                                    class: "flex items-center justify-between gap-4 px-4 py-3 hover:bg-surface",
                                                    span { class: "font-mono text-sm text-ink", "{team.name}" }
                                                    span { class: "font-mono text-xs text-ink-muted", "{team.permission}" }
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
                },
                Some(Err(err)) => rsx! { p { class: "text-sm text-status-conflict", "{err}" } },
                None => rsx! { p { class: "text-sm text-ink-muted", "loading…" } },
            }
        }
    }
}

use dioxus::prelude::*;

use edda_api_types::{CreateReleaseRequest, ReleaseDto};

use crate::api_client;
use crate::Route;

fn releases_path(owner: &str, name: &str) -> String {
    format!("/api/v1/repos/{owner}/{name}/releases")
}

#[component]
pub fn ReleasesList(owner: String, name: String) -> Element {
    let owner_c = owner.clone();
    let name_c = name.clone();
    let mut releases = use_resource(move || {
        let path = releases_path(&owner_c, &name_c);
        async move { api_client::get_json::<Vec<ReleaseDto>>(&path).await }
    });

    let mut show_form = use_signal(|| false);
    let mut tag_name = use_signal(String::new);
    let mut target = use_signal(|| "main".to_string());
    let mut title = use_signal(String::new);
    let mut body = use_signal(String::new);
    let mut draft = use_signal(|| false);
    let mut prerelease = use_signal(|| false);
    let mut generate_notes = use_signal(|| false);
    let mut error = use_signal(|| Option::<String>::None);
    let mut submitting = use_signal(|| false);

    let owner_for_submit = owner.clone();
    let name_for_submit = name.clone();
    let route_owner = owner.clone();
    let route_name = name.clone();

    let on_submit = move |event: FormEvent| {
        event.prevent_default();
        let path = releases_path(&owner_for_submit, &name_for_submit);
        let tag_value = tag_name.read().clone();
        let target_value = target.read().clone();
        let title_value = title.read().clone();
        let body_value = body.read().clone();
        let draft_value = draft();
        let prerelease_value = prerelease();
        let generate_notes_value = generate_notes();
        submitting.set(true);
        error.set(None);
        spawn(async move {
            let request = CreateReleaseRequest {
                tag_name: tag_value,
                target: target_value,
                title: title_value,
                body: (!body_value.trim().is_empty()).then_some(body_value),
                draft: draft_value,
                prerelease: prerelease_value,
                generate_notes: generate_notes_value,
            };
            let result = api_client::post_ok(&path, &request).await;
            submitting.set(false);
            match result {
                Ok(()) => {
                    tag_name.set(String::new());
                    title.set(String::new());
                    body.set(String::new());
                    show_form.set(false);
                    releases.restart();
                }
                Err(err) => error.set(Some(err.to_string())),
            }
        });
    };

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            div { class: "flex items-center justify-between",
                h1 { class: "font-mono text-xl font-semibold text-ink", "Releases" }
                button {
                    r#type: "button",
                    class: "border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink",
                    onclick: move |_| show_form.set(!show_form()),
                    if show_form() { "cancel" } else { "new release" }
                }
            }

            if show_form() {
                form { class: "mt-4 flex flex-col gap-3 border border-line p-4", onsubmit: on_submit,
                    div { class: "flex gap-3",
                        label { class: "flex flex-1 flex-col gap-1 text-sm text-ink-muted",
                            "tag"
                            input {
                                r#type: "text", required: true, placeholder: "v1.0.0",
                                class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                                value: "{tag_name}",
                                oninput: move |event| tag_name.set(event.value()),
                            }
                        }
                        label { class: "flex flex-1 flex-col gap-1 text-sm text-ink-muted",
                            "target (branch or commit)"
                            input {
                                r#type: "text", required: true,
                                class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                                value: "{target}",
                                oninput: move |event| target.set(event.value()),
                            }
                        }
                    }
                    label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                        "title"
                        input {
                            r#type: "text", required: true,
                            class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                            value: "{title}",
                            oninput: move |event| title.set(event.value()),
                        }
                    }
                    label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                        "notes"
                        textarea {
                            rows: "4",
                            disabled: generate_notes(),
                            placeholder: if generate_notes() { "auto-generated from the commit log" } else { "" },
                            class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-xs text-ink focus:border-accent focus:outline-none disabled:opacity-60",
                            value: "{body}",
                            oninput: move |event| body.set(event.value()),
                        }
                    }
                    div { class: "flex gap-4 text-sm text-ink-muted",
                        label { class: "flex items-center gap-1.5",
                            input { r#type: "checkbox", checked: generate_notes(), onchange: move |event| generate_notes.set(event.checked()) }
                            "auto-generate notes"
                        }
                        label { class: "flex items-center gap-1.5",
                            input { r#type: "checkbox", checked: draft(), onchange: move |event| draft.set(event.checked()) }
                            "draft"
                        }
                        label { class: "flex items-center gap-1.5",
                            input { r#type: "checkbox", checked: prerelease(), onchange: move |event| prerelease.set(event.checked()) }
                            "prerelease"
                        }
                    }
                    if let Some(message) = error() {
                        p { class: "font-mono text-xs text-status-conflict", "{message}" }
                    }
                    button {
                        r#type: "submit",
                        disabled: submitting(),
                        class: "self-start border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                        if submitting() { "creating…" } else { "create release" }
                    }
                }
            }

            div { class: "mt-6",
                match &*releases.read() {
                    Some(Ok(list)) if list.is_empty() => rsx! {
                        p { class: "text-sm text-ink-muted italic", "no releases yet" }
                    },
                    Some(Ok(list)) => rsx! {
                        div { class: "divide-y divide-line border border-line",
                            for release in list.clone() {
                                {
                                    let to = Route::ReleaseDetail { owner: route_owner.clone(), name: route_name.clone(), tag_name: release.tag_name.clone() };
                                    rsx! {
                                        Link {
                                            to,
                                            class: "flex items-center justify-between gap-4 px-4 py-3 no-underline hover:bg-surface",
                                            div { class: "min-w-0",
                                                div { class: "font-mono text-sm text-ink", "{release.name}" }
                                                div { class: "truncate font-mono text-xs text-ink-muted", "{release.tag_name} · {release.assets.len()} asset(s)" }
                                            }
                                            if release.draft {
                                                span { class: "shrink-0 font-mono text-xs text-ink-muted", "draft" }
                                            } else if release.prerelease {
                                                span { class: "shrink-0 font-mono text-xs text-status-ahead", "prerelease" }
                                            } else {
                                                span { class: "shrink-0 font-mono text-xs text-status-clean", "published" }
                                            }
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

#[component]
pub fn ReleaseDetail(owner: String, name: String, tag_name: String) -> Element {
    let owner_c = owner.clone();
    let name_c = name.clone();
    let tag_c = tag_name.clone();
    let detail = use_resource(move || {
        let path = format!("{}/{}", releases_path(&owner_c, &name_c), tag_c);
        async move { api_client::get_json::<ReleaseDto>(&path).await }
    });

    let upload_action = format!("/{owner}/{name}/releases/{tag_name}/assets");

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            match &*detail.read() {
                Some(Ok(release)) => {
                    let release: ReleaseDto = release.clone();
                    rsx! {
                        h1 { class: "font-mono text-xl font-semibold text-ink", "{release.name}" }
                        p { class: "mt-1 font-mono text-xs text-ink-muted",
                            "{release.tag_name} · {release.target_commit} · by {release.author_username}"
                        }
                        if let Some(html) = &release.body_html {
                            div { class: "mt-4 border border-line p-4 text-sm text-ink", dangerous_inner_html: "{html}" }
                        }

                        h2 { class: "mt-8 font-mono text-sm font-semibold text-ink", "Assets" }
                        div { class: "mt-2 flex flex-col gap-2",
                            if release.assets.is_empty() {
                                p { class: "text-sm text-ink-muted italic", "no assets uploaded yet" }
                            }
                            for asset in release.assets.clone() {
                                {
                                    let href = format!("/{owner}/{name}/releases/{tag_name}/assets/{}", asset.filename);
                                    rsx! {
                                        a {
                                            href,
                                            class: "flex items-center justify-between gap-4 border border-line px-3 py-2 no-underline hover:bg-surface",
                                            span { class: "font-mono text-sm text-ink", "{asset.filename}" }
                                            span { class: "font-mono text-xs text-ink-muted", "{asset.size_bytes} bytes" }
                                        }
                                    }
                                }
                            }
                        }

                        h2 { class: "mt-8 font-mono text-sm font-semibold text-ink", "Upload an asset" }
                        form {
                            class: "mt-2 flex flex-col gap-3 border border-line p-4",
                            action: "{upload_action}",
                            method: "post",
                            enctype: "multipart/form-data",
                            input {
                                r#type: "file",
                                name: "file",
                                required: true,
                                class: "font-mono text-sm text-ink",
                            }
                            button {
                                r#type: "submit",
                                class: "self-start border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink",
                                "upload"
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

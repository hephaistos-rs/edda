use dioxus::prelude::*;

use crate::pr_server::{
    add_pull_request_comment, close_pull_request, create_pull_request, get_pull_request,
    list_pull_requests, merge_pull_request, submit_pull_request_review, PrStateDto, PullRequestDto,
};
use crate::Route;

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

fn state_label(state: &PrStateDto) -> (&'static str, &'static str) {
    match state {
        PrStateDto::Open => ("open", "text-status-ahead"),
        PrStateDto::Draft => ("draft", "text-ink-muted"),
        PrStateDto::Merged { .. } => ("merged", "text-accent"),
        PrStateDto::Closed { .. } => ("closed", "text-status-conflict"),
    }
}

#[component]
pub fn PullsList(owner: String, name: String) -> Element {
    let owner_c = owner.clone();
    let name_c = name.clone();
    let mut pulls = use_resource(move || {
        let owner = owner_c.clone();
        let name = name_c.clone();
        async move { list_pull_requests(owner, name).await }
    });

    let mut show_form = use_signal(|| false);
    let mut title = use_signal(String::new);
    let mut body = use_signal(String::new);
    let mut source_branch = use_signal(String::new);
    let mut target_branch = use_signal(|| "main".to_string());
    let mut error = use_signal(|| Option::<String>::None);
    let mut submitting = use_signal(|| false);

    let owner_for_submit = owner.clone();
    let name_for_submit = name.clone();
    let route_owner = owner.clone();
    let route_name = name.clone();

    let on_submit = move |event: FormEvent| {
        event.prevent_default();
        let owner = owner_for_submit.clone();
        let name = name_for_submit.clone();
        let title_value = title.read().clone();
        let body_value = body.read().clone();
        let source_value = source_branch.read().clone();
        let target_value = target_branch.read().clone();
        submitting.set(true);
        error.set(None);
        spawn(async move {
            let result = create_pull_request(
                owner,
                name,
                title_value,
                (!body_value.trim().is_empty()).then_some(body_value),
                source_value,
                target_value,
                false,
            )
            .await;
            submitting.set(false);
            match result {
                Ok(_number) => {
                    title.set(String::new());
                    body.set(String::new());
                    source_branch.set(String::new());
                    show_form.set(false);
                    pulls.restart();
                }
                Err(err) => error.set(Some(err.to_string())),
            }
        });
    };

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            div { class: "flex items-center justify-between",
                h1 { class: "font-mono text-xl font-semibold text-ink", "Pull requests" }
                button {
                    r#type: "button",
                    class: "border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink",
                    onclick: move |_| show_form.set(!show_form()),
                    if show_form() { "cancel" } else { "new pull request" }
                }
            }

            if show_form() {
                form { class: "mt-4 flex flex-col gap-3 border border-line p-4", onsubmit: on_submit,
                    div { class: "flex gap-3",
                        label { class: "flex flex-1 flex-col gap-1 text-sm text-ink-muted",
                            "source branch"
                            input {
                                r#type: "text", required: true, placeholder: "feature",
                                class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                                value: "{source_branch}",
                                oninput: move |event| source_branch.set(event.value()),
                            }
                        }
                        label { class: "flex flex-1 flex-col gap-1 text-sm text-ink-muted",
                            "target branch"
                            input {
                                r#type: "text", required: true,
                                class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                                value: "{target_branch}",
                                oninput: move |event| target_branch.set(event.value()),
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
                        "description"
                        textarea {
                            rows: "4",
                            class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-xs text-ink focus:border-accent focus:outline-none",
                            value: "{body}",
                            oninput: move |event| body.set(event.value()),
                        }
                    }
                    if let Some(message) = error() {
                        p { class: "font-mono text-xs text-status-conflict", "{message}" }
                    }
                    button {
                        r#type: "submit",
                        disabled: submitting(),
                        class: "self-start border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                        if submitting() { "opening…" } else { "open pull request" }
                    }
                }
            }

            div { class: "mt-6",
                match &*pulls.read() {
                    Some(Ok(list)) if list.is_empty() => rsx! {
                        p { class: "text-sm text-ink-muted italic", "no pull requests yet" }
                    },
                    Some(Ok(list)) => rsx! {
                        div { class: "divide-y divide-line border border-line",
                            for pr in list.clone() {
                                {
                                    let (label, color) = state_label(&pr.state);
                                    let to = Route::PullDetail { owner: route_owner.clone(), name: route_name.clone(), number: pr.number };
                                    rsx! {
                                        Link {
                                            to,
                                            class: "flex items-center justify-between gap-4 px-4 py-3 no-underline hover:bg-surface",
                                            div { class: "min-w-0",
                                                div { class: "font-mono text-sm text-ink", "#{pr.number} {pr.title}" }
                                                div { class: "truncate font-mono text-xs text-ink-muted",
                                                    "{pr.source_branch} → {pr.target_branch} · opened {relative_time(pr.created_at)} by {pr.author_username}"
                                                }
                                            }
                                            span { class: "shrink-0 font-mono text-xs {color}", "{label}" }
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
        }
    }
}

#[component]
pub fn PullDetail(owner: String, name: String, number: i64) -> Element {
    let owner_c = owner.clone();
    let name_c = name.clone();
    let mut detail = use_resource(move || {
        let owner = owner_c.clone();
        let name = name_c.clone();
        async move { get_pull_request(owner, name, number).await }
    });

    let mut comment_body = use_signal(String::new);
    let mut action_error = use_signal(|| Option::<String>::None);
    let mut busy = use_signal(|| false);

    let owner_for_comment = owner.clone();
    let name_for_comment = name.clone();
    let on_add_comment = move |event: FormEvent| {
        event.prevent_default();
        let owner = owner_for_comment.clone();
        let name = name_for_comment.clone();
        let body_value = comment_body.read().clone();
        busy.set(true);
        action_error.set(None);
        spawn(async move {
            match add_pull_request_comment(owner, name, number, body_value, None).await {
                Ok(()) => {
                    comment_body.set(String::new());
                    detail.restart();
                }
                Err(err) => action_error.set(Some(err.to_string())),
            }
            busy.set(false);
        });
    };

    fn submit_review(
        owner: String,
        name: String,
        number: i64,
        state: &'static str,
        mut busy: Signal<bool>,
        mut action_error: Signal<Option<String>>,
        mut detail: Resource<Result<crate::pr_server::PullRequestDetailDto, ServerFnError>>,
    ) {
        busy.set(true);
        action_error.set(None);
        spawn(async move {
            match submit_pull_request_review(owner, name, number, state.to_string(), None).await {
                Ok(()) => detail.restart(),
                Err(err) => action_error.set(Some(err.to_string())),
            }
            busy.set(false);
        });
    }

    let owner_for_merge = owner.clone();
    let name_for_merge = name.clone();
    let on_merge = move |_| {
        let owner = owner_for_merge.clone();
        let name = name_for_merge.clone();
        busy.set(true);
        action_error.set(None);
        spawn(async move {
            match merge_pull_request(owner, name, number).await {
                Ok(()) => detail.restart(),
                Err(err) => action_error.set(Some(err.to_string())),
            }
            busy.set(false);
        });
    };

    let owner_for_close = owner.clone();
    let name_for_close = name.clone();
    let on_close = move |_| {
        let owner = owner_for_close.clone();
        let name = name_for_close.clone();
        busy.set(true);
        action_error.set(None);
        spawn(async move {
            match close_pull_request(owner, name, number).await {
                Ok(()) => detail.restart(),
                Err(err) => action_error.set(Some(err.to_string())),
            }
            busy.set(false);
        });
    };

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            match &*detail.read() {
                Some(Ok(data)) => {
                    let pr: PullRequestDto = data.pull_request.clone();
                    let (label, color) = state_label(&pr.state);
                    rsx! {
                        h1 { class: "font-mono text-xl font-semibold text-ink", "{pr.title} " span { class: "text-ink-muted", "#{pr.number}" } }
                        div { class: "mt-1 font-mono text-xs {color}", "{label}" }
                        p { class: "mt-1 font-mono text-xs text-ink-muted",
                            "{pr.source_branch} → {pr.target_branch} · opened by {pr.author_username}"
                        }
                        if let Some(html) = &pr.body_html {
                            div { class: "mt-4 border border-line p-4 text-sm text-ink", dangerous_inner_html: "{html}" }
                        }

                        h2 { class: "mt-8 font-mono text-sm font-semibold text-ink", "Reviews" }
                        div { class: "mt-2 flex flex-col gap-2",
                            for review in data.reviews.clone() {
                                div { class: "border border-line px-3 py-2",
                                    div { class: "font-mono text-xs text-ink", "{review.reviewer_username} — {review.state}" }
                                    if let Some(html) = &review.body_html {
                                        div { class: "mt-1 text-sm text-ink-muted", dangerous_inner_html: "{html}" }
                                    }
                                }
                            }
                        }

                        h2 { class: "mt-8 font-mono text-sm font-semibold text-ink", "Comments" }
                        div { class: "mt-2 flex flex-col gap-2",
                            for comment in data.comments.clone() {
                                div { class: "border border-line px-3 py-2",
                                    div { class: "font-mono text-xs text-ink-muted",
                                        "{comment.author_username}"
                                        if let Some(path) = &comment.anchor_file_path {
                                            " on {path}"
                                        }
                                    }
                                    div { class: "mt-1 text-sm text-ink", dangerous_inner_html: "{comment.body_html}" }
                                }
                            }
                        }

                        form { class: "mt-4 flex flex-col gap-2", onsubmit: on_add_comment,
                            textarea {
                                rows: "3", required: true,
                                placeholder: "leave a comment",
                                class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-xs text-ink focus:border-accent focus:outline-none",
                                value: "{comment_body}",
                                oninput: move |event| comment_body.set(event.value()),
                            }
                            button {
                                r#type: "submit", disabled: busy(),
                                class: "self-start border border-line px-3 py-1.5 font-mono text-sm text-ink-muted hover:text-ink disabled:opacity-60",
                                "comment"
                            }
                        }

                        if let Some(message) = action_error() {
                            p { class: "mt-4 font-mono text-xs text-status-conflict", "{message}" }
                        }

                        if matches!(pr.state, PrStateDto::Open | PrStateDto::Draft) {
                            div { class: "mt-6 flex gap-3",
                                button {
                                    r#type: "button", disabled: busy(),
                                    class: "border border-line px-3 py-1.5 font-mono text-sm text-status-ahead hover:opacity-80 disabled:opacity-60",
                                    onclick: {
                                        let owner = owner.clone();
                                        let name = name.clone();
                                        move |_| submit_review(owner.clone(), name.clone(), number, "approved", busy, action_error, detail)
                                    },
                                    "approve"
                                }
                                button {
                                    r#type: "button", disabled: busy(),
                                    class: "border border-line px-3 py-1.5 font-mono text-sm text-status-conflict hover:opacity-80 disabled:opacity-60",
                                    onclick: {
                                        let owner = owner.clone();
                                        let name = name.clone();
                                        move |_| submit_review(owner.clone(), name.clone(), number, "changes_requested", busy, action_error, detail)
                                    },
                                    "request changes"
                                }
                                button {
                                    r#type: "button", disabled: busy() || !data.can_merge,
                                    title: if !data.can_merge { "not enough approvals, or you lack write access" } else { "" },
                                    class: "border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                                    onclick: on_merge,
                                    "merge"
                                }
                                button {
                                    r#type: "button", disabled: busy(),
                                    class: "border border-line px-3 py-1.5 font-mono text-sm text-ink-muted hover:text-status-conflict disabled:opacity-60",
                                    onclick: on_close,
                                    "close"
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

use dioxus::prelude::*;

use crate::issue_server::{
    add_issue_comment, apply_label_to_issue, close_issue, create_issue, create_label, get_issue,
    list_issues, list_labels, reopen_issue, IssueStateDto,
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

#[component]
pub fn IssuesList(owner: String, name: String) -> Element {
    let owner_c = owner.clone();
    let name_c = name.clone();
    let mut issues = use_resource(move || {
        let owner = owner_c.clone();
        let name = name_c.clone();
        async move { list_issues(owner, name).await }
    });

    let mut show_form = use_signal(|| false);
    let mut title = use_signal(String::new);
    let mut body = use_signal(String::new);
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
        submitting.set(true);
        error.set(None);
        spawn(async move {
            let result = create_issue(
                owner,
                name,
                title_value,
                (!body_value.trim().is_empty()).then_some(body_value),
            )
            .await;
            submitting.set(false);
            match result {
                Ok(_number) => {
                    title.set(String::new());
                    body.set(String::new());
                    show_form.set(false);
                    issues.restart();
                }
                Err(err) => error.set(Some(err.to_string())),
            }
        });
    };

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            div { class: "flex items-center justify-between",
                h1 { class: "font-mono text-xl font-semibold text-ink", "Issues" }
                button {
                    r#type: "button",
                    class: "border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink",
                    onclick: move |_| show_form.set(!show_form()),
                    if show_form() { "cancel" } else { "new issue" }
                }
            }

            if show_form() {
                form { class: "mt-4 flex flex-col gap-3 border border-line p-4", onsubmit: on_submit,
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
                        if submitting() { "opening…" } else { "open issue" }
                    }
                }
            }

            div { class: "mt-6",
                match &*issues.read() {
                    Some(Ok(list)) if list.is_empty() => rsx! {
                        p { class: "text-sm text-ink-muted italic", "no issues yet" }
                    },
                    Some(Ok(list)) => rsx! {
                        div { class: "divide-y divide-line border border-line",
                            for issue in list.clone() {
                                {
                                    let (label, color) = match &issue.state {
                                        IssueStateDto::Open => ("open", "text-status-ahead"),
                                        IssueStateDto::Closed { .. } => ("closed", "text-status-conflict"),
                                    };
                                    let to = Route::IssueDetail { owner: route_owner.clone(), name: route_name.clone(), number: issue.number };
                                    rsx! {
                                        Link {
                                            to,
                                            class: "flex items-center justify-between gap-4 px-4 py-3 no-underline hover:bg-surface",
                                            div { class: "min-w-0",
                                                div { class: "font-mono text-sm text-ink", "#{issue.number} {issue.title}" }
                                                div { class: "truncate font-mono text-xs text-ink-muted",
                                                    "opened {relative_time(issue.created_at)} by {issue.author_username}"
                                                    if let Some(milestone) = &issue.milestone_title {
                                                        " · {milestone}"
                                                    }
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
pub fn IssueDetail(owner: String, name: String, number: i64) -> Element {
    let owner_c = owner.clone();
    let name_c = name.clone();
    let mut detail = use_resource(move || {
        let owner = owner_c.clone();
        let name = name_c.clone();
        async move { get_issue(owner, name, number).await }
    });
    let owner_c2 = owner.clone();
    let name_c2 = name.clone();
    let mut repo_labels = use_resource(move || {
        let owner = owner_c2.clone();
        let name = name_c2.clone();
        async move { list_labels(owner, name).await }
    });

    let mut comment_body = use_signal(String::new);
    let mut action_error = use_signal(|| Option::<String>::None);
    let mut busy = use_signal(|| false);
    let mut new_label_name = use_signal(String::new);
    let mut new_label_color = use_signal(|| "#e0af3b".to_string());

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
            match add_issue_comment(owner, name, number, body_value).await {
                Ok(()) => {
                    comment_body.set(String::new());
                    detail.restart();
                }
                Err(err) => action_error.set(Some(err.to_string())),
            }
            busy.set(false);
        });
    };

    let owner_for_toggle = owner.clone();
    let name_for_toggle = name.clone();
    let mut on_toggle_state = move |currently_open: bool| {
        let owner = owner_for_toggle.clone();
        let name = name_for_toggle.clone();
        busy.set(true);
        action_error.set(None);
        spawn(async move {
            let result = if currently_open {
                close_issue(owner, name, number).await
            } else {
                reopen_issue(owner, name, number).await
            };
            match result {
                Ok(()) => detail.restart(),
                Err(err) => action_error.set(Some(err.to_string())),
            }
            busy.set(false);
        });
    };

    fn apply_label(
        owner: String,
        name: String,
        number: i64,
        label_id: String,
        mut detail: Resource<Result<crate::issue_server::IssueDetailDto, ServerFnError>>,
    ) {
        spawn(async move {
            let _ = apply_label_to_issue(owner, name, number, label_id).await;
            detail.restart();
        });
    }

    let owner_for_new_label = owner.clone();
    let name_for_new_label = name.clone();
    let on_create_label = move |event: FormEvent| {
        event.prevent_default();
        let owner = owner_for_new_label.clone();
        let name = name_for_new_label.clone();
        let label_name = new_label_name.read().clone();
        let color = new_label_color.read().clone();
        spawn(async move {
            if create_label(owner, name, label_name, color, None)
                .await
                .is_ok()
            {
                new_label_name.set(String::new());
                repo_labels.restart();
            }
        });
    };

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            match &*detail.read() {
                Some(Ok(data)) => {
                    let issue = data.issue.clone();
                    let (label, color, currently_open) = match &issue.state {
                        IssueStateDto::Open => ("open", "text-status-ahead", true),
                        IssueStateDto::Closed { .. } => ("closed", "text-status-conflict", false),
                    };
                    rsx! {
                        h1 { class: "font-mono text-xl font-semibold text-ink", "{issue.title} " span { class: "text-ink-muted", "#{issue.number}" } }
                        div { class: "mt-1 font-mono text-xs {color}", "{label}" }
                        p { class: "mt-1 font-mono text-xs text-ink-muted", "opened by {issue.author_username}" }
                        if let Some(html) = &issue.body_html {
                            div { class: "mt-4 border border-line p-4 text-sm text-ink", dangerous_inner_html: "{html}" }
                        }

                        h2 { class: "mt-8 font-mono text-sm font-semibold text-ink", "Labels" }
                        div { class: "mt-2 flex flex-wrap gap-2",
                            for l in data.labels.clone() {
                                span {
                                    class: "border px-2 py-0.5 font-mono text-xs text-ink",
                                    style: "border-color: {l.color}; color: {l.color}",
                                    "{l.name}"
                                }
                            }
                        }
                        if let Some(Ok(available)) = &*repo_labels.read() {
                            div { class: "mt-2 flex flex-wrap gap-2",
                                for l in available.clone() {
                                    button {
                                        r#type: "button",
                                        class: "border border-line px-2 py-0.5 font-mono text-xs text-ink-muted hover:text-ink",
                                        onclick: {
                                            let owner = owner.clone();
                                            let name = name.clone();
                                            let label_id = l.id.clone();
                                            move |_| apply_label(owner.clone(), name.clone(), number, label_id.clone(), detail)
                                        },
                                        "+ {l.name}"
                                    }
                                }
                            }
                        }

                        h2 { class: "mt-8 font-mono text-sm font-semibold text-ink", "Comments" }
                        div { class: "mt-2 flex flex-col gap-2",
                            for comment in data.comments.clone() {
                                div { class: "border border-line px-3 py-2",
                                    div { class: "font-mono text-xs text-ink-muted", "{comment.author_username}" }
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

                        div { class: "mt-6",
                            button {
                                r#type: "button", disabled: busy(),
                                class: "border border-line px-3 py-1.5 font-mono text-sm text-ink-muted hover:text-ink disabled:opacity-60",
                                onclick: move |_| on_toggle_state(currently_open),
                                if currently_open { "close issue" } else { "reopen issue" }
                            }
                        }
                    }
                },
                Some(Err(err)) => rsx! { p { class: "text-sm text-status-conflict", "{err}" } },
                None => rsx! { p { class: "text-sm text-ink-muted", "loading…" } },
            }

            h2 { class: "mt-12 font-mono text-sm font-semibold text-ink", "Add a repository label" }
            form { class: "mt-2 flex items-end gap-3", onsubmit: on_create_label,
                label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                    "name"
                    input {
                        r#type: "text", required: true, placeholder: "e.g. priority/high",
                        class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                        value: "{new_label_name}",
                        oninput: move |event| new_label_name.set(event.value()),
                    }
                }
                label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                    "color"
                    input {
                        r#type: "color",
                        class: "h-9 w-14 border border-line bg-surface",
                        value: "{new_label_color}",
                        oninput: move |event| new_label_color.set(event.value()),
                    }
                }
                button {
                    r#type: "submit",
                    class: "border border-line px-3 py-1.5 font-mono text-sm text-ink-muted hover:text-ink",
                    "add label"
                }
            }
        }
    }
}

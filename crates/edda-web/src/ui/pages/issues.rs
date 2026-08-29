use dioxus::prelude::*;

use edda_api_types::{
    ApplyLabelRequest, BodyRequest, CreateIssueRequest, CreateLabelRequest, IssueDetailDto,
    IssueDto, IssueStateDto, LabelDto, UsernameRequest,
};

use crate::api_client::{self, ApiResult};
use crate::Route;

fn issues_path(owner: &str, name: &str) -> String {
    format!("/api/v1/repos/{owner}/{name}/issues")
}
fn labels_path(owner: &str, name: &str) -> String {
    format!("/api/v1/repos/{owner}/{name}/labels")
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
pub fn IssuesList(owner: String, name: String) -> Element {
    let owner_c = owner.clone();
    let name_c = name.clone();
    let mut issues = use_resource(move || {
        let path = issues_path(&owner_c, &name_c);
        async move { api_client::get_json::<Vec<IssueDto>>(&path).await }
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
        let path = issues_path(&owner_for_submit, &name_for_submit);
        let title_value = title.read().clone();
        let body_value = body.read().clone();
        submitting.set(true);
        error.set(None);
        spawn(async move {
            let request = CreateIssueRequest {
                title: title_value,
                body: (!body_value.trim().is_empty()).then_some(body_value),
            };
            let result = api_client::post_ok(&path, &request).await;
            submitting.set(false);
            match result {
                Ok(()) => {
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
        let path = format!("{}/{number}", issues_path(&owner_c, &name_c));
        async move { api_client::get_json::<IssueDetailDto>(&path).await }
    });
    let owner_c2 = owner.clone();
    let name_c2 = name.clone();
    let mut repo_labels = use_resource(move || {
        let path = labels_path(&owner_c2, &name_c2);
        async move { api_client::get_json::<Vec<LabelDto>>(&path).await }
    });

    let mut comment_body = use_signal(String::new);
    let mut action_error = use_signal(|| Option::<String>::None);
    let mut busy = use_signal(|| false);
    let mut new_label_name = use_signal(String::new);
    let mut new_label_color = use_signal(|| "#e0af3b".to_string());
    let mut assignee_input = use_signal(String::new);

    let issues_base = issues_path(&owner, &name);
    let labels_base = labels_path(&owner, &name);

    let comment_base = issues_base.clone();
    let on_add_comment = move |event: FormEvent| {
        event.prevent_default();
        let path = format!("{comment_base}/{number}/comments");
        let body_value = comment_body.read().clone();
        busy.set(true);
        action_error.set(None);
        spawn(async move {
            match api_client::post_ok(&path, &BodyRequest { body: body_value }).await {
                Ok(()) => {
                    comment_body.set(String::new());
                    detail.restart();
                }
                Err(err) => action_error.set(Some(err.to_string())),
            }
            busy.set(false);
        });
    };

    let assign_base = issues_base.clone();
    let on_assign = move |event: FormEvent| {
        event.prevent_default();
        let username = assignee_input.read().trim().to_string();
        if username.is_empty() {
            return;
        }
        let path = format!("{assign_base}/{number}/assignees");
        busy.set(true);
        action_error.set(None);
        spawn(async move {
            match api_client::post_ok(&path, &UsernameRequest { username }).await {
                Ok(()) => {
                    assignee_input.set(String::new());
                    detail.restart();
                }
                Err(err) => action_error.set(Some(err.to_string())),
            }
            busy.set(false);
        });
    };

    fn unassign(
        base: String,
        number: i64,
        username: String,
        mut busy: Signal<bool>,
        mut action_error: Signal<Option<String>>,
        mut detail: Resource<ApiResult<IssueDetailDto>>,
    ) {
        busy.set(true);
        action_error.set(None);
        spawn(async move {
            let path = format!("{base}/{number}/assignees/{username}");
            match api_client::delete_ok(&path).await {
                Ok(()) => detail.restart(),
                Err(err) => action_error.set(Some(err.to_string())),
            }
            busy.set(false);
        });
    }

    let toggle_base = issues_base.clone();
    let mut on_toggle_state = move |currently_open: bool| {
        let verb = if currently_open { "close" } else { "reopen" };
        let path = format!("{toggle_base}/{number}/{verb}");
        busy.set(true);
        action_error.set(None);
        spawn(async move {
            match api_client::post_empty_ok(&path).await {
                Ok(()) => detail.restart(),
                Err(err) => action_error.set(Some(err.to_string())),
            }
            busy.set(false);
        });
    };

    fn apply_label(
        base: String,
        number: i64,
        label_id: String,
        mut detail: Resource<ApiResult<IssueDetailDto>>,
    ) {
        spawn(async move {
            let request = ApplyLabelRequest { label_id };
            let _ = api_client::post_ok(&format!("{base}/{number}/labels"), &request).await;
            detail.restart();
        });
    }

    let new_label_base = labels_base.clone();
    let on_create_label = move |event: FormEvent| {
        event.prevent_default();
        let path = new_label_base.clone();
        let label_name = new_label_name.read().clone();
        let color = new_label_color.read().clone();
        spawn(async move {
            let request = CreateLabelRequest {
                name: label_name,
                color,
                description: None,
            };
            if api_client::post_ok(&path, &request).await.is_ok() {
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

                        h2 { class: "mt-8 font-mono text-sm font-semibold text-ink", "Assignees" }
                        div { class: "mt-2 flex flex-wrap items-center gap-2",
                            for username in issue.assignees.clone() {
                                button {
                                    r#type: "button", disabled: busy(),
                                    class: "border border-line px-2 py-0.5 font-mono text-xs text-ink hover:text-status-conflict disabled:opacity-60",
                                    title: "remove assignee",
                                    onclick: {
                                        let base = issues_base.clone();
                                        let username = username.clone();
                                        move |_| unassign(base.clone(), number, username.clone(), busy, action_error, detail)
                                    },
                                    "{username} ×"
                                }
                            }
                            if issue.assignees.is_empty() {
                                span { class: "font-mono text-xs text-ink-muted", "none" }
                            }
                        }
                        form { class: "mt-2 flex gap-2", onsubmit: on_assign,
                            input {
                                r#type: "text", placeholder: "username",
                                class: "border border-line bg-surface px-2 py-1 font-mono text-xs text-ink focus:border-accent focus:outline-none",
                                value: "{assignee_input}",
                                oninput: move |event| assignee_input.set(event.value()),
                            }
                            button {
                                r#type: "submit", disabled: busy(),
                                class: "border border-line px-3 py-1 font-mono text-xs text-ink-muted hover:text-ink disabled:opacity-60",
                                "assign"
                            }
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
                                            let base = issues_base.clone();
                                            let label_id = l.id.clone();
                                            move |_| apply_label(base.clone(), number, label_id.clone(), detail)
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

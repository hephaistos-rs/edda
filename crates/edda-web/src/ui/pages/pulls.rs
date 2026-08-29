use dioxus::prelude::*;

use edda_api_types::{
    AddCommentRequest, CreatePullRequest, MergeRequest, MergedPullDto, PrStateDto,
    PullRequestDetailDto, PullRequestDto, SubmitReviewRequest,
};

/// `(value, label)` for the merge-strategy picker.
const MERGE_STRATEGIES: [(&str, &str); 4] = [
    ("merge", "merge commit"),
    ("squash", "squash and merge"),
    ("rebase", "rebase and merge"),
    ("fast_forward", "fast-forward only"),
];

use crate::api_client::{self, ApiResult};
use crate::Route;

fn pulls_path(owner: &str, name: &str) -> String {
    format!("/api/v1/repos/{owner}/{name}/pulls")
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

fn state_label(state: &PrStateDto) -> (&'static str, &'static str) {
    match state {
        PrStateDto::Open => ("open", "text-status-ahead"),
        PrStateDto::Draft => ("draft", "text-ink-muted"),
        PrStateDto::Merged { .. } => ("merged", "text-accent"),
        PrStateDto::Closed { .. } => ("closed", "text-status-conflict"),
    }
}

/// The head-side label a PR shows: `owner:branch` for a fork-sourced pull
/// request (so it reads like a real git host's compare view), plain
/// `branch` for a same-repository one.
fn head_label(pr: &PullRequestDto) -> String {
    if pr.is_cross_repo {
        format!("{}:{}", pr.source_owner, pr.source_branch)
    } else {
        pr.source_branch.clone()
    }
}

#[component]
pub fn PullsList(owner: String, name: String) -> Element {
    let owner_c = owner.clone();
    let name_c = name.clone();
    let mut pulls = use_resource(move || {
        let path = pulls_path(&owner_c, &name_c);
        async move { api_client::get_json::<Vec<PullRequestDto>>(&path).await }
    });

    let mut show_form = use_signal(|| false);
    let mut title = use_signal(String::new);
    let mut body = use_signal(String::new);
    let mut source_owner = use_signal(String::new);
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
        let path = pulls_path(&owner_for_submit, &name_for_submit);
        let title_value = title.read().clone();
        let body_value = body.read().clone();
        let source_owner_value = source_owner.read().clone();
        let source_value = source_branch.read().clone();
        let target_value = target_branch.read().clone();
        submitting.set(true);
        error.set(None);
        spawn(async move {
            let request = CreatePullRequest {
                title: title_value,
                body: (!body_value.trim().is_empty()).then_some(body_value),
                source_owner: (!source_owner_value.trim().is_empty()).then_some(source_owner_value),
                source_branch: source_value,
                target_branch: target_value,
                draft: false,
            };
            let result = api_client::post_ok(&path, &request).await;
            submitting.set(false);
            match result {
                Ok(()) => {
                    title.set(String::new());
                    body.set(String::new());
                    source_owner.set(String::new());
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
                            "source fork owner"
                            input {
                                r#type: "text", placeholder: "(this repo) — or a fork's owner",
                                class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                                value: "{source_owner}",
                                oninput: move |event| source_owner.set(event.value()),
                            }
                        }
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
                                                    "{head_label(&pr)} → {pr.target_branch} · opened {relative_time(pr.created_at)} by {pr.author_username}"
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
        let path = format!("{}/{number}", pulls_path(&owner_c, &name_c));
        async move { api_client::get_json::<PullRequestDetailDto>(&path).await }
    });

    let mut comment_body = use_signal(String::new);
    let mut action_error = use_signal(|| Option::<String>::None);
    let mut busy = use_signal(|| false);
    let mut merge_strategy = use_signal(|| "merge".to_string());

    let pr_base = pulls_path(&owner, &name);

    let comment_base = pr_base.clone();
    let on_add_comment = move |event: FormEvent| {
        event.prevent_default();
        let path = format!("{comment_base}/{number}/comments");
        let body_value = comment_body.read().clone();
        busy.set(true);
        action_error.set(None);
        spawn(async move {
            let request = AddCommentRequest {
                body: body_value,
                anchor: None,
            };
            match api_client::post_ok(&path, &request).await {
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
        base: String,
        number: i64,
        state: &'static str,
        mut busy: Signal<bool>,
        mut action_error: Signal<Option<String>>,
        mut detail: Resource<ApiResult<PullRequestDetailDto>>,
    ) {
        busy.set(true);
        action_error.set(None);
        spawn(async move {
            let request = SubmitReviewRequest {
                state: state.to_string(),
                body: None,
            };
            match api_client::post_ok(&format!("{base}/{number}/reviews"), &request).await {
                Ok(()) => detail.restart(),
                Err(err) => action_error.set(Some(err.to_string())),
            }
            busy.set(false);
        });
    }

    let merge_base = pr_base.clone();
    let on_merge = move |_| {
        let path = format!("{merge_base}/{number}/merge");
        let request = MergeRequest {
            strategy: Some(merge_strategy.read().clone()),
        };
        busy.set(true);
        action_error.set(None);
        spawn(async move {
            match api_client::post_json::<_, MergedPullDto>(&path, &request).await {
                Ok(_) => detail.restart(),
                Err(err) => action_error.set(Some(err.to_string())),
            }
            busy.set(false);
        });
    };

    let close_base = pr_base.clone();
    let on_close = move |_| {
        let path = format!("{close_base}/{number}/close");
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
                            "{head_label(&pr)} → {pr.target_branch} · opened by {pr.author_username}"
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
                                        let base = pr_base.clone();
                                        move |_| submit_review(base.clone(), number, "approved", busy, action_error, detail)
                                    },
                                    "approve"
                                }
                                button {
                                    r#type: "button", disabled: busy(),
                                    class: "border border-line px-3 py-1.5 font-mono text-sm text-status-conflict hover:opacity-80 disabled:opacity-60",
                                    onclick: {
                                        let base = pr_base.clone();
                                        move |_| submit_review(base.clone(), number, "changes_requested", busy, action_error, detail)
                                    },
                                    "request changes"
                                }
                                select {
                                    class: "border border-line bg-surface px-2 py-1.5 font-mono text-sm text-ink disabled:opacity-60",
                                    disabled: busy(),
                                    value: "{merge_strategy}",
                                    onchange: move |event| merge_strategy.set(event.value()),
                                    for (value, label) in MERGE_STRATEGIES {
                                        option { value: "{value}", "{label}" }
                                    }
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

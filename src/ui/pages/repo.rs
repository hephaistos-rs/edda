use dioxus::prelude::*;
use dioxus_free_icons::icons::ld_icons::{LdFile, LdFolder, LdLock, LdLockOpen, LdPencil};
use dioxus_free_icons::Icon;

use crate::server::{delete_repo, get_blob, get_branches, get_commit_log, get_repo, get_tree, set_repo_visibility, update_repo};
use crate::Route;

#[derive(Clone, Copy, PartialEq)]
enum RepoTab {
    Files,
    Commits,
}

/// Relative time without pulling in a date-formatting crate — repo activity
/// only ever needs coarse granularity here.
fn relative_time(unix_seconds: i64) -> String {
    let now = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(unix_seconds);
    let delta = (now - unix_seconds).max(0);

    const MINUTE: i64 = 60;
    const HOUR: i64 = 60 * MINUTE;
    const DAY: i64 = 24 * HOUR;

    if delta < MINUTE {
        "just now".to_string()
    } else if delta < HOUR {
        format!("{}m ago", delta / MINUTE)
    } else if delta < DAY {
        format!("{}h ago", delta / HOUR)
    } else {
        format!("{}d ago", delta / DAY)
    }
}

#[component]
pub fn Repo(name: String) -> Element {
    let navigator = use_navigator();
    let mut repo = use_server_future({
        let name = name.clone();
        move || get_repo(name.clone())
    })?;

    let mut confirming_delete = use_signal(|| false);
    let mut delete_error = use_signal(|| Option::<String>::None);

    let mut editing_description = use_signal(|| false);
    let mut description_draft = use_signal(String::new);

    let mut tab = use_signal(|| RepoTab::Files);
    let mut path_segments = use_signal(Vec::<String>::new);
    let mut viewing_file = use_signal(|| Option::<String>::None);
    // `None` means "the repo's default branch" — never resolved to a
    // concrete name client-side, since `get_tree`/`get_blob`/`get_commit_log`
    // already treat `None` that way server-side (see `open_and_resolve`).
    let mut selected_branch = use_signal(|| Option::<String>::None);

    let branches = use_resource({
        let name = name.clone();
        move || {
            let name = name.clone();
            async move { get_branches(name).await }
        }
    });

    let tree = use_resource({
        let name = name.clone();
        move || {
            let name = name.clone();
            let branch = selected_branch.read().clone();
            let path = path_segments.read().join("/");
            async move { get_tree(name, branch, if path.is_empty() { None } else { Some(path) }).await }
        }
    });

    let blob = use_resource({
        let name = name.clone();
        move || {
            let name = name.clone();
            let branch = selected_branch.read().clone();
            let file = viewing_file.read().clone();
            async move {
                match file {
                    Some(path) => Some(get_blob(name, branch, path).await),
                    None => None,
                }
            }
        }
    });

    // Gated on the active tab rather than fetching unconditionally on
    // mount — walking commit history is real work, and most repo visits
    // never open this tab.
    let commits = use_resource({
        let name = name.clone();
        move || {
            let name = name.clone();
            let branch = selected_branch.read().clone();
            let active = tab() == RepoTab::Commits;
            async move {
                if !active {
                    return None;
                }
                Some(get_commit_log(name, branch).await)
            }
        }
    });
    let mut description_error = use_signal(|| Option::<String>::None);
    let mut visibility_error = use_signal(|| Option::<String>::None);
    let mut visibility_pending = use_signal(|| false);

    let body = match repo() {
        Some(Ok(dto)) => {
            let status_line = if dto.is_empty {
                "empty repository — no commits yet".to_string()
            } else {
                let branch = dto.default_branch.as_deref().unwrap_or("HEAD");
                let noun = if dto.branch_count == 1 { "branch" } else { "branches" };
                format!("{branch} · {} {noun}", dto.branch_count)
            };

            let description_text = dto.description.clone().unwrap_or_else(|| "No description".to_string());
            let description_class = if dto.description.is_some() { "text-ink" } else { "text-ink-muted italic" };
            let current_description = dto.description.clone().unwrap_or_default();

            let is_private = dto.is_private;
            let is_owner = dto.is_owner;

            rsx! {
                div { class: "mt-4 flex items-center gap-2",
                    h1 { class: "font-mono text-2xl font-semibold text-ink", "{dto.name}" }
                    span {
                        class: "flex items-center gap-1 border border-line px-1.5 py-0.5 font-mono text-[11px] uppercase tracking-wide text-ink-muted",
                        title: if is_private { "only the owner and collaborators can see this repo" } else { "anyone can see this repo" },
                        if is_private {
                            Icon { icon: LdLock, width: 11, height: 11 }
                        } else {
                            Icon { icon: LdLockOpen, width: 11, height: 11 }
                        }
                        if is_private { "private" } else { "public" }
                    }
                    if is_owner {
                        button {
                            r#type: "button",
                            class: "font-mono text-xs text-ink-muted underline hover:text-ink disabled:opacity-50",
                            disabled: visibility_pending(),
                            onclick: {
                                let name = name.clone();
                                move |_| {
                                    let name = name.clone();
                                    let next_private = !is_private;
                                    visibility_pending.set(true);
                                    spawn(async move {
                                        match set_repo_visibility(name, next_private).await {
                                            Ok(()) => {
                                                visibility_error.set(None);
                                                repo.restart();
                                            }
                                            Err(err) => visibility_error.set(Some(err.to_string())),
                                        }
                                        visibility_pending.set(false);
                                    });
                                }
                            },
                            if is_private { "make public" } else { "make private" }
                        }
                    }
                }
                if let Some(message) = visibility_error() {
                    p { class: "mt-1 font-mono text-xs text-status-conflict", "{message}" }
                }
                p { class: "mt-1 font-mono text-xs text-ink-muted", "{status_line}" }

                div { class: "mt-4",
                    if editing_description() {
                        div {
                            textarea {
                                class: "w-full border border-line bg-surface px-2 py-1.5 text-sm text-ink placeholder:text-ink-muted focus:border-accent focus:outline-none",
                                rows: "2",
                                placeholder: "description",
                                value: "{description_draft}",
                                autofocus: true,
                                oninput: move |event| description_draft.set(event.value()),
                            }
                            div { class: "mt-2 flex items-center gap-3",
                                button {
                                    r#type: "button",
                                    class: "border border-line px-2 py-1 font-mono text-xs text-ink hover:border-accent",
                                    onclick: {
                                        let name = name.clone();
                                        move |_| {
                                            let name = name.clone();
                                            let text = description_draft.read().clone();
                                            spawn(async move {
                                                let value = if text.trim().is_empty() { None } else { Some(text) };
                                                match update_repo(name, value).await {
                                                    Ok(()) => {
                                                        editing_description.set(false);
                                                        description_error.set(None);
                                                        repo.restart();
                                                    }
                                                    Err(err) => description_error.set(Some(err.to_string())),
                                                }
                                            });
                                        }
                                    },
                                    "save"
                                }
                                button {
                                    r#type: "button",
                                    class: "font-mono text-xs text-ink-muted hover:text-ink",
                                    onclick: move |_| {
                                        editing_description.set(false);
                                        description_error.set(None);
                                    },
                                    "cancel"
                                }
                            }
                            if let Some(message) = description_error() {
                                p { class: "mt-2 font-mono text-xs text-status-conflict", "{message}" }
                            }
                        }
                    } else {
                        div { class: "group flex items-start gap-2",
                            p { class: "text-sm {description_class}", "{description_text}" }
                            button {
                                r#type: "button",
                                class: "shrink-0 text-ink-muted opacity-0 hover:text-ink focus-visible:opacity-100 group-hover:opacity-100",
                                title: "Edit description",
                                onclick: move |_| {
                                    description_draft.set(current_description.clone());
                                    editing_description.set(true);
                                },
                                Icon { icon: LdPencil, width: 14, height: 14 }
                                span { class: "sr-only", "Edit description" }
                            }
                        }
                    }
                }

                if let Some(commit) = &dto.last_commit {
                    div { class: "mt-6 border border-line px-4 py-3",
                        div { class: "text-sm text-ink", "{commit.summary}" }
                        div { class: "mt-1 font-mono text-xs text-ink-muted",
                            "{commit.author_name} · {relative_time(commit.unix_seconds)}"
                        }
                    }
                }

                if !dto.is_empty {
                    nav { class: "mt-8 flex items-center justify-between gap-4 border-b border-line font-mono text-sm",
                        div { class: "flex gap-4",
                            button {
                                r#type: "button",
                                class: if tab() == RepoTab::Files { "border-b-2 border-accent px-1 pb-2 text-ink" } else { "border-b-2 border-transparent px-1 pb-2 text-ink-muted hover:text-ink" },
                                onclick: move |_| tab.set(RepoTab::Files),
                                "files"
                            }
                            button {
                                r#type: "button",
                                class: if tab() == RepoTab::Commits { "border-b-2 border-accent px-1 pb-2 text-ink" } else { "border-b-2 border-transparent px-1 pb-2 text-ink-muted hover:text-ink" },
                                onclick: move |_| tab.set(RepoTab::Commits),
                                "commits"
                            }
                        }
                        if let Some(Ok(names)) = &*branches.read() {
                            select {
                                class: "mb-2 shrink-0 border border-line bg-surface px-2 py-1 text-xs text-ink focus:border-accent focus:outline-none",
                                value: selected_branch.read().clone().or_else(|| dto.default_branch.clone()).unwrap_or_default(),
                                onchange: move |event| {
                                    let value = event.value();
                                    selected_branch.set(if value.is_empty() { None } else { Some(value) });
                                    path_segments.write().clear();
                                    viewing_file.set(None);
                                },
                                for branch_name in names.clone() {
                                    option { value: "{branch_name}", "{branch_name}" }
                                }
                            }
                        }
                    }

                    if tab() == RepoTab::Files {
                        if let Some(file_path) = viewing_file() {
                            div { class: "mt-4",
                                button {
                                    r#type: "button",
                                    class: "font-mono text-xs text-ink-muted hover:text-ink",
                                    onclick: move |_| viewing_file.set(None),
                                    "← back to files"
                                }
                                p { class: "mt-2 font-mono text-xs text-ink-muted", "{file_path}" }
                                match &*blob.read() {
                                    Some(Some(Ok(blob))) => rsx! {
                                        if blob.is_binary {
                                            p { class: "mt-2 text-sm text-ink-muted italic", "binary file ({blob.size} bytes)" }
                                        } else if let Some(content) = &blob.content {
                                            pre { class: "mt-2 overflow-x-auto border border-line bg-surface p-3 font-mono text-xs text-ink",
                                                "{content}"
                                            }
                                        } else {
                                            p { class: "mt-2 text-sm text-ink-muted italic", "file too large to preview ({blob.size} bytes)" }
                                        }
                                    },
                                    Some(Some(Err(err))) => rsx! {
                                        p { class: "mt-2 text-sm text-status-conflict", "{err}" }
                                    },
                                    _ => rsx! {
                                        p { class: "mt-2 text-sm text-ink-muted", "loading…" }
                                    },
                                }
                            }
                        } else {
                            div { class: "mt-4",
                                div { class: "flex flex-wrap items-center gap-1 font-mono text-xs text-ink-muted",
                                    button {
                                        r#type: "button",
                                        class: "hover:text-ink",
                                        onclick: move |_| path_segments.write().clear(),
                                        "{dto.name}"
                                    }
                                    for (index , segment) in path_segments.read().iter().enumerate() {
                                        span { "/" }
                                        button {
                                            r#type: "button",
                                            class: "hover:text-ink",
                                            onclick: move |_| path_segments.write().truncate(index + 1),
                                            "{segment}"
                                        }
                                    }
                                }
                                match &*tree.read() {
                                    Some(Ok(entries)) => rsx! {
                                        div { class: "mt-2 divide-y divide-line border border-line",
                                            for entry in entries.clone() {
                                                button {
                                                    r#type: "button",
                                                    class: "flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-ink hover:bg-surface",
                                                    onclick: {
                                                        let entry = entry.clone();
                                                        move |_| {
                                                            if entry.is_dir {
                                                                path_segments.write().push(entry.name.clone());
                                                            } else {
                                                                let mut full_path = path_segments.read().clone();
                                                                full_path.push(entry.name.clone());
                                                                viewing_file.set(Some(full_path.join("/")));
                                                            }
                                                        }
                                                    },
                                                    if entry.is_dir {
                                                        Icon { icon: LdFolder, width: 16, height: 16 }
                                                    } else {
                                                        Icon { icon: LdFile, width: 16, height: 16 }
                                                    }
                                                    span { "{entry.name}" }
                                                    if let Some(size) = entry.size {
                                                        span { class: "ml-auto font-mono text-xs text-ink-muted", "{size} B" }
                                                    }
                                                }
                                            }
                                            if entries.is_empty() {
                                                p { class: "px-3 py-2 text-sm text-ink-muted italic", "empty directory" }
                                            }
                                        }
                                    },
                                    Some(Err(err)) => rsx! {
                                        p { class: "mt-2 text-sm text-status-conflict", "{err}" }
                                    },
                                    None => rsx! {
                                        p { class: "mt-2 text-sm text-ink-muted", "loading…" }
                                    },
                                }
                            }
                        }
                    } else {
                        div { class: "mt-4",
                            match &*commits.read() {
                                Some(Some(Ok(entries))) => rsx! {
                                    div { class: "divide-y divide-line border border-line",
                                        for commit in entries.clone() {
                                            div { class: "px-3 py-2",
                                                div { class: "text-sm text-ink", "{commit.summary}" }
                                                div { class: "mt-0.5 font-mono text-xs text-ink-muted",
                                                    "{commit.author_name} · {relative_time(commit.unix_seconds)} · {&commit.id[..7.min(commit.id.len())]}"
                                                }
                                            }
                                        }
                                        if entries.is_empty() {
                                            p { class: "px-3 py-2 text-sm text-ink-muted italic", "no commits" }
                                        }
                                    }
                                },
                                Some(Some(Err(err))) => rsx! {
                                    p { class: "text-sm text-status-conflict", "{err}" }
                                },
                                _ => rsx! {
                                    p { class: "text-sm text-ink-muted", "loading…" }
                                },
                            }
                        }
                    }
                }

                div { class: "mt-8 border-t border-line pt-4",
                    if confirming_delete() {
                        div { class: "flex items-center gap-3",
                            span { class: "text-sm text-status-conflict", "Delete \"{dto.name}\" permanently?" }
                            button {
                                r#type: "button",
                                class: "border border-status-conflict px-2 py-1 font-mono text-xs text-status-conflict hover:bg-status-conflict hover:text-accent-ink",
                                onclick: {
                                    let name = name.clone();
                                    move |_| {
                                        let name = name.clone();
                                        spawn(async move {
                                            match delete_repo(name).await {
                                                Ok(()) => { navigator.push(Route::Home {}); }
                                                Err(err) => {
                                                    delete_error.set(Some(err.to_string()));
                                                    confirming_delete.set(false);
                                                }
                                            }
                                        });
                                    }
                                },
                                "confirm delete"
                            }
                            button {
                                r#type: "button",
                                class: "font-mono text-xs text-ink-muted hover:text-ink",
                                onclick: move |_| confirming_delete.set(false),
                                "cancel"
                            }
                        }
                    } else {
                        button {
                            r#type: "button",
                            class: "font-mono text-xs text-ink-muted hover:text-status-conflict",
                            onclick: move |_| confirming_delete.set(true),
                            "delete repository"
                        }
                    }
                    if let Some(message) = delete_error() {
                        p { class: "mt-2 font-mono text-xs text-status-conflict", "{message}" }
                    }
                }
            }
        }
        Some(Err(err)) => rsx! {
            p { class: "mt-4 text-sm text-status-conflict", "Couldn't load \"{name}\": {err}" }
        },
        None => rsx! {
            p { class: "mt-4 text-sm text-ink-muted", "Loading…" }
        },
    };

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            Link {
                to: Route::Home {},
                class: "font-mono text-sm text-ink-muted no-underline hover:text-ink",
                "← repos"
            }
            {body}
        }
    }
}

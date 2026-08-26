use dioxus::prelude::*;
use dioxus_free_icons::icons::ld_icons::{
    LdFile, LdFolder, LdLock, LdLockOpen, LdPencil, LdSearch,
};
use dioxus_free_icons::Icon;

use crate::server::{
    delete_repo, fork_repo, get_blob, get_branches, get_commit_diff, get_commit_log, get_repo,
    get_tree, search_code, set_repo_visibility, update_repo, DiffLineDto, DiffLineKind,
    FileDiffDto,
};
use crate::Route;

#[derive(Clone, Copy, PartialEq)]
enum RepoTab {
    Files,
    Commits,
    Search,
}

/// `README`/`README.md`/`README.markdown`, case-insensitively — mirrors
/// `server::is_readme_filename` exactly (server-side that decides whether
/// to render markdown into `BlobDto::rendered_html`; client-side this only
/// decides which root-level tree entry to fetch and display below the file
/// listing). Kept as its own small duplicate rather than a shared crate:
/// this file already can't call server-only code directly, and the check
/// is a one-line match, not logic worth a shared dependency over.
fn is_readme_filename(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "readme.md" | "readme.markdown" | "readme"
    )
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
pub fn Repo(owner: String, name: String) -> Element {
    let navigator = use_navigator();
    let mut repo = use_server_future({
        let owner = owner.clone();
        let name = name.clone();
        move || get_repo(owner.clone(), name.clone())
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
        let owner = owner.clone();
        let name = name.clone();
        move || {
            let owner = owner.clone();
            let name = name.clone();
            async move { get_branches(owner, name).await }
        }
    });

    let tree = use_resource({
        let owner = owner.clone();
        let name = name.clone();
        move || {
            let owner = owner.clone();
            let name = name.clone();
            let branch = selected_branch.read().clone();
            let path = path_segments.read().join("/");
            async move {
                get_tree(
                    owner,
                    name,
                    branch,
                    if path.is_empty() { None } else { Some(path) },
                )
                .await
            }
        }
    });

    let blob = use_resource({
        let owner = owner.clone();
        let name = name.clone();
        move || {
            let owner = owner.clone();
            let name = name.clone();
            let branch = selected_branch.read().clone();
            let file = viewing_file.read().clone();
            async move {
                match file {
                    Some(path) => Some(get_blob(owner, name, branch, path).await),
                    None => None,
                }
            }
        }
    });

    // Gated on the active tab rather than fetching unconditionally on
    // mount — walking commit history is real work, and most repo visits
    // never open this tab.
    let commits = use_resource({
        let owner = owner.clone();
        let name = name.clone();
        move || {
            let owner = owner.clone();
            let name = name.clone();
            let branch = selected_branch.read().clone();
            let active = tab() == RepoTab::Commits;
            async move {
                if !active {
                    return None;
                }
                Some(get_commit_log(owner, name, branch).await)
            }
        }
    });
    // README rendering (Files tab, at the tree root, no specific file
    // selected) — looks at the already-fetched root tree for an entry
    // matching `is_readme_filename`, then fetches and renders just that
    // blob. Gated the same way `blob` is: no request at all unless
    // there's actually a README to show.
    let readme = use_resource({
        let owner = owner.clone();
        let name = name.clone();
        move || {
            let owner = owner.clone();
            let name = name.clone();
            let branch = selected_branch.read().clone();
            let at_root = tab() == RepoTab::Files
                && path_segments.read().is_empty()
                && viewing_file.read().is_none();
            let readme_name = if at_root {
                tree.read()
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .and_then(|entries| {
                        entries
                            .iter()
                            .find(|entry| !entry.is_dir && is_readme_filename(&entry.name))
                            .map(|entry| entry.name.clone())
                    })
            } else {
                None
            };
            async move {
                match readme_name {
                    Some(file_name) => Some(get_blob(owner, name, branch, file_name).await),
                    None => None,
                }
            }
        }
    });

    // Commit diff view: clicking a commit in the `Commits` tab toggles
    // this. `None` collapses whatever was showing.
    let mut selected_commit = use_signal(|| Option::<String>::None);
    let diff = use_resource({
        let owner = owner.clone();
        let name = name.clone();
        move || {
            let owner = owner.clone();
            let name = name.clone();
            let commit_id = selected_commit.read().clone();
            async move {
                match commit_id {
                    Some(commit_id) => Some(get_commit_diff(owner, name, commit_id).await),
                    None => None,
                }
            }
        }
    });

    // Code search: a plain text input plus a submit — no live-as-you-type
    // search, so `search_query` (the input's live value) and
    // `search_submitted` (what the last submit actually searched for) are
    // deliberately separate signals.
    let mut search_query = use_signal(String::new);
    let mut search_submitted = use_signal(|| Option::<String>::None);
    let search_results = use_resource({
        let owner = owner.clone();
        let name = name.clone();
        move || {
            let owner = owner.clone();
            let name = name.clone();
            let branch = selected_branch.read().clone();
            let query = search_submitted.read().clone();
            async move {
                match query {
                    Some(query) => Some(search_code(owner, name, branch, query).await),
                    None => None,
                }
            }
        }
    });

    let mut description_error = use_signal(|| Option::<String>::None);
    let mut visibility_error = use_signal(|| Option::<String>::None);
    let mut visibility_pending = use_signal(|| false);
    let mut fork_error = use_signal(|| Option::<String>::None);
    let mut fork_pending = use_signal(|| false);

    let body = match repo() {
        Some(Ok(dto)) => {
            let status_line = if dto.is_empty {
                "empty repository — no commits yet".to_string()
            } else {
                let branch = dto.default_branch.as_deref().unwrap_or("HEAD");
                let noun = if dto.branch_count == 1 {
                    "branch"
                } else {
                    "branches"
                };
                format!("{branch} · {} {noun}", dto.branch_count)
            };

            let description_text = dto
                .description
                .clone()
                .unwrap_or_else(|| "No description".to_string());
            let description_class = if dto.description.is_some() {
                "text-ink"
            } else {
                "text-ink-muted italic"
            };
            let current_description = dto.description.clone().unwrap_or_default();

            let is_private = dto.is_private;
            let is_owner = dto.is_owner;

            rsx! {
                div { class: "mt-4 flex items-center gap-2",
                    h1 { class: "font-mono text-2xl font-semibold text-ink", "{dto.owner}/{dto.name}" }
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
                                let owner = owner.clone();
                                let name = name.clone();
                                move |_| {
                                    let owner = owner.clone();
                                    let name = name.clone();
                                    let next_private = !is_private;
                                    visibility_pending.set(true);
                                    spawn(async move {
                                        match set_repo_visibility(owner, name, next_private).await {
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
                    if !is_owner {
                        button {
                            r#type: "button",
                            class: "font-mono text-xs text-ink-muted underline hover:text-ink disabled:opacity-50",
                            disabled: fork_pending(),
                            onclick: {
                                let owner = owner.clone();
                                let name = name.clone();
                                move |_| {
                                    let owner = owner.clone();
                                    let name = name.clone();
                                    fork_pending.set(true);
                                    spawn(async move {
                                        match fork_repo(owner, name).await {
                                            Ok((new_owner, new_name)) => {
                                                fork_error.set(None);
                                                navigator.push(Route::Repo { owner: new_owner, name: new_name });
                                            }
                                            Err(err) => {
                                                fork_error.set(Some(err.to_string()));
                                                fork_pending.set(false);
                                            }
                                        }
                                    });
                                }
                            },
                            "fork"
                        }
                    }
                }
                if let Some(message) = visibility_error() {
                    p { class: "mt-1 font-mono text-xs text-status-conflict", "{message}" }
                }
                if let Some(message) = fork_error() {
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
                                        let owner = owner.clone();
                                        let name = name.clone();
                                        move |_| {
                                            let owner = owner.clone();
                                            let name = name.clone();
                                            let text = description_draft.read().clone();
                                            spawn(async move {
                                                let value = if text.trim().is_empty() { None } else { Some(text) };
                                                match update_repo(owner, name, value).await {
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
                            button {
                                r#type: "button",
                                class: if tab() == RepoTab::Search { "border-b-2 border-accent px-1 pb-2 text-ink" } else { "border-b-2 border-transparent px-1 pb-2 text-ink-muted hover:text-ink" },
                                onclick: move |_| tab.set(RepoTab::Search),
                                "search"
                            }
                            Link {
                                to: Route::PullsList { owner: owner.clone(), name: name.clone() },
                                class: "border-b-2 border-transparent px-1 pb-2 text-ink-muted no-underline hover:text-ink",
                                "pull requests"
                            }
                            Link {
                                to: Route::IssuesList { owner: owner.clone(), name: name.clone() },
                                class: "border-b-2 border-transparent px-1 pb-2 text-ink-muted no-underline hover:text-ink",
                                "issues"
                            }
                            Link {
                                to: Route::ReleasesList { owner: owner.clone(), name: name.clone() },
                                class: "border-b-2 border-transparent px-1 pb-2 text-ink-muted no-underline hover:text-ink",
                                "releases"
                            }
                            Link {
                                to: Route::WebhooksSettings { owner: owner.clone(), name: name.clone() },
                                class: "border-b-2 border-transparent px-1 pb-2 text-ink-muted no-underline hover:text-ink",
                                "webhooks"
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
                                        } else if let Some(html) = &blob.rendered_html {
                                            // Safety: `rendered_html` for a non-README text file
                                            // is `edda_render::syntax::highlight`'s output —
                                            // built entirely from `syntect`'s own HTML-escaping
                                            // of the source text (see that module's doc comment),
                                            // never from unsanitized markdown or other
                                            // caller-controlled markup, so injecting it directly
                                            // carries the same safety argument as the README spot
                                            // above, just for a different (also-safe-by-
                                            // construction) source.
                                            div {
                                                class: "mt-2 overflow-x-auto border border-line bg-surface p-3 font-mono text-xs text-ink [&_pre]:m-0",
                                                dangerous_inner_html: "{html}",
                                            }
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
                                if let Some(Some(Ok(readme_blob))) = &*readme.read() {
                                    if let Some(html) = &readme_blob.rendered_html {
                                        div { class: "mt-6 border border-line",
                                            div { class: "border-b border-line px-3 py-2 font-mono text-xs text-ink-muted",
                                                "{readme_blob.name}"
                                            }
                                            // Safety: `html` is `BlobDto::rendered_html`, which the
                                            // server only ever populates via `edda_render::
                                            // markdown::render` for a README — that function
                                            // unconditionally pipes its output through
                                            // `ammonia::clean` before returning (see its own doc
                                            // comment), so this is sanitized HTML, not raw
                                            // caller-controlled markup. This is the only place in
                                            // this frontend that renders raw *markdown-derived*
                                            // HTML; the file-view and commit-diff spots below also
                                            // use `dangerous_inner_html`, but only for
                                            // `edda_render::syntax::highlight` output, which is a
                                            // different, separately-safe category (built from
                                            // `syntect`'s own escaping of source text, never from
                                            // sanitized-but-still-arbitrary markdown) — see that
                                            // module's doc comment. Every other server-derived
                                            // string on this page is interpolated as text
                                            // (`"{...}"`), which Dioxus escapes.
                                            div {
                                                class: "prose-invert max-w-none px-4 py-3 text-sm text-ink",
                                                dangerous_inner_html: "{html}",
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else if tab() == RepoTab::Commits {
                        div { class: "mt-4",
                            match &*commits.read() {
                                Some(Some(Ok(entries))) => rsx! {
                                    div { class: "divide-y divide-line border border-line",
                                        for commit in entries.clone() {
                                            {
                                                let is_selected = selected_commit.read().as_deref() == Some(commit.id.as_str());
                                                let commit_id = commit.id.clone();
                                                rsx! {
                                                    button {
                                                        r#type: "button",
                                                        class: "flex w-full flex-col items-start gap-0.5 px-3 py-2 text-left hover:bg-surface",
                                                        onclick: move |_| {
                                                            let commit_id = commit_id.clone();
                                                            selected_commit.set(if is_selected { None } else { Some(commit_id) });
                                                        },
                                                        div { class: "text-sm text-ink", "{commit.summary}" }
                                                        div { class: "mt-0.5 font-mono text-xs text-ink-muted",
                                                            "{commit.author_name} · {relative_time(commit.unix_seconds)} · {&commit.id[..7.min(commit.id.len())]}"
                                                        }
                                                    }
                                                    if is_selected {
                                                        div { class: "border-t border-line bg-surface px-3 py-3",
                                                            match &*diff.read() {
                                                                Some(Some(Ok(files))) => rsx! {
                                                                    CommitDiffView { files: files.clone() }
                                                                },
                                                                Some(Some(Err(err))) => rsx! {
                                                                    p { class: "font-mono text-xs text-status-conflict", "{err}" }
                                                                },
                                                                _ => rsx! {
                                                                    p { class: "font-mono text-xs text-ink-muted", "loading diff…" }
                                                                },
                                                            }
                                                        }
                                                    }
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
                    } else {
                        div { class: "mt-4",
                            form {
                                class: "flex items-center gap-2",
                                onsubmit: move |event| {
                                    event.prevent_default();
                                    let query = search_query.read().clone();
                                    search_submitted.set(if query.trim().is_empty() { None } else { Some(query) });
                                },
                                input {
                                    r#type: "text",
                                    class: "flex-1 border border-line bg-surface px-2 py-1.5 text-sm text-ink placeholder:text-ink-muted focus:border-accent focus:outline-none",
                                    placeholder: "search code…",
                                    value: "{search_query}",
                                    oninput: move |event| search_query.set(event.value()),
                                }
                                button {
                                    r#type: "submit",
                                    class: "flex items-center gap-1.5 border border-line px-3 py-1.5 font-mono text-xs text-ink hover:border-accent",
                                    Icon { icon: LdSearch, width: 14, height: 14 }
                                    "search"
                                }
                            }
                            match &*search_results.read() {
                                Some(Some(Ok(matches))) => rsx! {
                                    div { class: "mt-3 divide-y divide-line border border-line",
                                        for search_match in matches.clone() {
                                            div { class: "px-3 py-2",
                                                div { class: "font-mono text-xs text-ink-muted",
                                                    "{search_match.path}:{search_match.line_number}"
                                                }
                                                pre { class: "mt-1 overflow-x-auto font-mono text-xs text-ink", "{search_match.line}" }
                                            }
                                        }
                                        if matches.is_empty() {
                                            p { class: "px-3 py-2 text-sm text-ink-muted italic", "no matches" }
                                        }
                                    }
                                },
                                Some(Some(Err(err))) => rsx! {
                                    p { class: "mt-3 text-sm text-status-conflict", "{err}" }
                                },
                                Some(None) => rsx! {
                                    p { class: "mt-3 text-sm text-ink-muted italic", "enter a query and press search" }
                                },
                                None => rsx! {
                                    p { class: "mt-3 text-sm text-ink-muted", "loading…" }
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
                                    let owner = owner.clone();
                                    let name = name.clone();
                                    move |_| {
                                        let owner = owner.clone();
                                        let name = name.clone();
                                        spawn(async move {
                                            match delete_repo(owner, name).await {
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
            p { class: "mt-4 text-sm text-status-conflict", "Couldn't load \"{owner}/{name}\": {err}" }
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

/// One `{old_path} → {new_path}`-shaped header per changed file — added/
/// deleted files annotate which side is missing rather than showing a bare
/// arrow to/from nothing, matching `DESIGN.md`'s earned-mono rule (this is
/// data, so it stays in the surrounding mono context) without needing its
/// own icon: the annotation text already carries the meaning a status icon
/// would, and this isn't a status indicator in the same sense repo-row
/// icons are.
fn diff_file_header(file: &FileDiffDto) -> String {
    match (&file.old_path, &file.new_path) {
        (Some(old), Some(new)) if old == new => new.clone(),
        (Some(old), Some(new)) => format!("{old} → {new}"),
        (None, Some(new)) => format!("{new} (added)"),
        (Some(old), None) => format!("{old} (deleted)"),
        (None, None) => "(unknown file)".to_string(),
    }
}

/// A single unified diff view (not side-by-side) for a commit — this
/// phase's exit criterion is diff rendering existing and working, ready
/// for Phase 6's PR review UI to build on, not a full review interface.
#[component]
fn CommitDiffView(files: Vec<FileDiffDto>) -> Element {
    let is_empty = files.is_empty();
    rsx! {
        div { class: "flex flex-col gap-4",
            for file in files {
                div { class: "border border-line",
                    div { class: "border-b border-line bg-surface px-3 py-1.5 font-mono text-xs text-ink-muted",
                        {diff_file_header(&file)}
                    }
                    if file.is_binary {
                        p { class: "px-3 py-2 text-sm text-ink-muted italic", "binary file — no line diff to show" }
                    } else {
                        div { class: "divide-y divide-line",
                            for hunk in file.hunks {
                                for line in hunk.lines {
                                    DiffLineRow { line }
                                }
                            }
                        }
                    }
                }
            }
            if is_empty {
                p { class: "text-sm text-ink-muted italic", "no changes" }
            }
        }
    }
}

/// One added/removed/context line. Per `DESIGN.md`'s never-color-alone
/// rule (written for repo-status icons, but the same accessibility
/// argument applies here): each row carries a leading `+`/`-`/` ` glyph and
/// an `sr-only` label in addition to its background tint, so the
/// added/removed distinction survives for anyone who can't rely on color.
#[component]
fn DiffLineRow(line: DiffLineDto) -> Element {
    let (symbol, row_class, label) = match line.kind {
        DiffLineKind::Added => ("+", "bg-status-clean/10", "added"),
        DiffLineKind::Removed => ("-", "bg-status-conflict/10", "removed"),
        DiffLineKind::Context => (" ", "", "context"),
    };
    rsx! {
        div { class: "flex items-start gap-2 px-3 py-0.5 font-mono text-xs text-ink {row_class}",
            span { "aria-hidden": "true", class: "select-none text-ink-muted", "{symbol}" }
            span { class: "sr-only", "{label} line" }
            // Safety: `line.html` is `edda_render::syntax::highlight`'s
            // per-line output, reached via `server::highlighted_line_html`
            // — see the file-view `dangerous_inner_html` spot above for
            // why syntax-highlighted output is safe to inject as-is (it's
            // built entirely from `syntect`'s own escaping, never from
            // unsanitized markup).
            span { class: "min-w-0 flex-1 overflow-x-auto", dangerous_inner_html: "{line.html}" }
        }
    }
}

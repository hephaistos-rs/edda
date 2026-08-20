use dioxus::prelude::*;
use dioxus_free_icons::icons::ld_icons::{LdCircleArrowUp, LdCircleCheck, LdCircleDashed, LdLock, LdPlus, LdTriangleAlert};
use dioxus_free_icons::Icon;

use crate::server::{create_repo, RepoDto};

#[derive(Clone, Copy, PartialEq)]
pub enum RepoStatus {
    Clean,
    Ahead,
    Conflict,
    Empty,
}

impl RepoStatus {
    /// Status is never carried by color alone: every status has its own icon shape
    /// (checked circle, dashed circle, arrow, triangle) plus this text label for
    /// screen readers, in addition to its status color.
    fn label(&self) -> &'static str {
        match self {
            RepoStatus::Clean => "up to date",
            RepoStatus::Ahead => "ahead of remote",
            RepoStatus::Conflict => "needs attention",
            RepoStatus::Empty => "empty repository",
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct Repo {
    pub owner: String,
    pub name: String,
    pub description: String,
    pub status: RepoStatus,
    pub ahead: u32,
    pub behind: u32,
    pub is_private: bool,
}

impl From<RepoDto> for Repo {
    fn from(dto: RepoDto) -> Self {
        let status = if dto.is_empty { RepoStatus::Empty } else { RepoStatus::Clean };

        // ahead/behind stay at 0 until repos can mirror an external upstream —
        // there's nothing for a canonical, self-hosted repo to be ahead/behind of yet.
        let description = dto.description.unwrap_or_else(|| {
            if dto.is_empty {
                "No commits yet".to_string()
            } else {
                match &dto.default_branch {
                    Some(branch) => {
                        let branches = dto.branch_count;
                        let noun = if branches == 1 { "branch" } else { "branches" };
                        format!("{branch} · {branches} {noun}")
                    }
                    None => "No description".to_string(),
                }
            }
        });

        Repo { owner: dto.owner, name: dto.name, description, status, ahead: 0, behind: 0, is_private: dto.is_private }
    }
}

#[component]
pub fn RepoRow(repo: Repo) -> Element {
    let (status_color_class, status_icon) = match repo.status {
        RepoStatus::Clean => ("text-status-clean", rsx! { Icon { icon: LdCircleCheck, width: 16, height: 16 } }),
        RepoStatus::Ahead => ("text-status-ahead", rsx! { Icon { icon: LdCircleArrowUp, width: 16, height: 16 } }),
        RepoStatus::Conflict => ("text-status-conflict", rsx! { Icon { icon: LdTriangleAlert, width: 16, height: 16 } }),
        RepoStatus::Empty => ("text-status-empty", rsx! { Icon { icon: LdCircleDashed, width: 16, height: 16 } }),
    };

    rsx! {
        Link {
            to: crate::Route::Repo { owner: repo.owner.clone(), name: repo.name.clone() },
            class: "group flex items-center gap-4 border-b border-line px-4 py-3 no-underline hover:bg-surface focus-visible:bg-surface",
            span {
                class: "shrink-0 {status_color_class}",
                title: "{repo.status.label()}",
                {status_icon}
                span { class: "sr-only", "{repo.status.label()}" }
            }
            div { class: "min-w-0 flex-1",
                div { class: "flex items-center gap-1.5 truncate font-mono text-[15px] font-medium text-ink",
                    span { "{repo.owner}/{repo.name}" }
                    if repo.is_private {
                        span { class: "shrink-0 text-ink-muted", title: "private repository",
                            Icon { icon: LdLock, width: 12, height: 12 }
                            span { class: "sr-only", "private" }
                        }
                    }
                }
                div { class: "truncate text-sm text-ink-muted", "{repo.description}" }
            }
            div { class: "shrink-0 font-mono text-xs tabular-nums text-ink-muted",
                if repo.ahead > 0 {
                    span { class: "text-status-ahead", "↑{repo.ahead} " }
                }
                if repo.behind > 0 {
                    span { class: "text-status-conflict", "↓{repo.behind}" }
                }
                if repo.ahead == 0 && repo.behind == 0 {
                    span { "—" }
                }
            }
        }
    }
}

/// Trailing row: click to reveal an inline name field (no modal — creating a
/// repo doesn't need one), Enter to submit, Escape to back out.
#[component]
pub fn NewRepoRow(on_created: EventHandler<()>) -> Element {
    let mut creating = use_signal(|| false);
    let mut name = use_signal(String::new);
    let mut error = use_signal(|| Option::<String>::None);
    // Defaults to checked: a new repo should be private unless someone
    // deliberately opens it up, not the other way around.
    let mut private = use_signal(|| true);

    if !creating() {
        return rsx! {
            button {
                r#type: "button",
                class: "flex w-full items-center gap-2 px-4 py-3 text-left text-ink-muted hover:bg-surface hover:text-ink focus-visible:bg-surface",
                onclick: move |_| creating.set(true),
                Icon { icon: LdPlus, width: 16, height: 16 }
                span { class: "font-mono text-sm", "new repository" }
            }
        };
    }

    rsx! {
        div { class: "flex items-center gap-2 px-4 py-3",
            Icon { icon: LdPlus, width: 16, height: 16, class: "shrink-0 text-ink-muted" }
            input {
                r#type: "text",
                class: "min-w-0 flex-1 bg-transparent font-mono text-sm text-ink placeholder:text-ink-muted focus:outline-none",
                placeholder: "repository name",
                value: "{name}",
                autofocus: true,
                oninput: move |event| {
                    name.set(event.value());
                    error.set(None);
                },
                onkeydown: move |event| match event.key() {
                    Key::Escape => {
                        creating.set(false);
                        name.set(String::new());
                        error.set(None);
                    }
                    Key::Enter => {
                        let repo_name = name.read().trim().to_string();
                        if repo_name.is_empty() {
                            return;
                        }
                        let is_private = private();
                        spawn(async move {
                            match create_repo(repo_name, None, is_private).await {
                                Ok(()) => {
                                    creating.set(false);
                                    name.set(String::new());
                                    private.set(true);
                                    error.set(None);
                                    on_created.call(());
                                }
                                Err(err) => error.set(Some(err.to_string())),
                            }
                        });
                    }
                    _ => {}
                },
            }
            label { class: "flex shrink-0 items-center gap-1.5 font-mono text-xs text-ink-muted",
                input {
                    r#type: "checkbox",
                    checked: private(),
                    onchange: move |event| private.set(event.checked()),
                }
                "private"
            }
        }
        if let Some(message) = error() {
            div { class: "px-4 pb-3 font-mono text-xs text-status-conflict", "{message}" }
        }
    }
}

use dioxus::prelude::*;
use dioxus_free_icons::icons::ld_icons::{LdCircleArrowUp, LdCircleCheck, LdCircleDashed, LdTriangleAlert};
use dioxus_free_icons::Icon;

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
    pub name: &'static str,
    pub description: &'static str,
    pub status: RepoStatus,
    pub ahead: u32,
    pub behind: u32,
}

pub fn sample_repos() -> Vec<Repo> {
    vec![
        Repo {
            name: "edda",
            description: "Self-hosted git platform, written in Rust.",
            status: RepoStatus::Ahead,
            ahead: 3,
            behind: 0,
        },
        Repo {
            name: "homelab",
            description: "Docker Compose stack for the home server.",
            status: RepoStatus::Clean,
            ahead: 0,
            behind: 0,
        },
        Repo {
            name: "dotfiles",
            description: "Personal shell, editor, and tmux config.",
            status: RepoStatus::Clean,
            ahead: 0,
            behind: 0,
        },
        Repo {
            name: "blog",
            description: "Static site source, built with Zola.",
            status: RepoStatus::Conflict,
            ahead: 2,
            behind: 1,
        },
        Repo {
            name: "scratch",
            description: "Initialized but unused, no commits yet.",
            status: RepoStatus::Empty,
            ahead: 0,
            behind: 0,
        },
    ]
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
            to: crate::Route::Repo { name: repo.name.to_string() },
            class: "group flex items-center gap-4 border-b border-line px-4 py-3 no-underline hover:bg-surface focus-visible:bg-surface",
            span {
                class: "shrink-0 {status_color_class}",
                title: "{repo.status.label()}",
                {status_icon}
                span { class: "sr-only", "{repo.status.label()}" }
            }
            div { class: "min-w-0 flex-1",
                div { class: "truncate font-mono text-[15px] font-medium text-ink", "{repo.name}" }
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

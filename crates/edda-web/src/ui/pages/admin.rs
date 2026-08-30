use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

/// The admin-editable instance settings (Phase 12). Mirrors the
/// `InstanceSettingsDto` the `/api/admin/settings` route returns and
/// accepts.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
struct InstanceSettingsForm {
    registration_mode: String,
    default_repo_visibility: String,
    welcome_message: Option<String>,
    require_signin_to_view: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct AdminUserDto {
    id: String,
    username: String,
    email: String,
    is_admin: bool,
    disabled: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct AuditEventDto {
    id: String,
    occurred_at: i64,
    event_type: String,
    actor_id: Option<String>,
    #[allow(dead_code)]
    target_type: Option<String>,
    #[allow(dead_code)]
    target_id: Option<String>,
    #[allow(dead_code)]
    detail_json: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct SystemInfoDto {
    version: String,
    database_backend: String,
    users: i64,
    repositories: i64,
    organizations: i64,
    open_pull_requests: i64,
    open_issues: i64,
    jobs_pending: i64,
    jobs_running: i64,
    jobs_dead: i64,
    tracked_git_bytes: i64,
    tracked_lfs_bytes: i64,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct AdminRepoDto {
    id: String,
    owner: String,
    name: String,
    private: bool,
    is_fork: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct AdminJobDto {
    id: String,
    kind: String,
    status: String,
    attempts: u32,
    max_attempts: u32,
    #[allow(dead_code)]
    run_at: i64,
    #[allow(dead_code)]
    created_at: i64,
    last_error: Option<String>,
}

// Same wasm32-only-fetch / server-side-stub split as every other
// hand-written (non-server-function) API call in `ui/` — see `login.rs`'s
// doc comment. The UI-level check here (rendering this page/its actions
// at all) is not the security boundary — every `/api/admin/*` route
// independently enforces `require_instance_admin` server-side regardless
// of what this page renders.
#[cfg(target_arch = "wasm32")]
async fn fetch_users() -> Result<Vec<AdminUserDto>, String> {
    let response = gloo_net::http::Request::get("/api/admin/users")
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.ok() {
        return Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't load users".to_string()));
    }
    response.json().await.map_err(|err| err.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_users() -> Result<Vec<AdminUserDto>, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn fetch_audit_events() -> Result<Vec<AuditEventDto>, String> {
    let response = gloo_net::http::Request::get("/api/admin/audit-events")
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.ok() {
        return Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't load audit events".to_string()));
    }
    response.json().await.map_err(|err| err.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_audit_events() -> Result<Vec<AuditEventDto>, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_set_disabled(id: &str, disabled: bool) -> Result<(), String> {
    let action = if disabled { "disable" } else { "enable" };
    let response = gloo_net::http::Request::post(&format!("/api/admin/users/{id}/{action}"))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't update user".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_set_disabled(_id: &str, _disabled: bool) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_delete_user(id: &str) -> Result<(), String> {
    let response = gloo_net::http::Request::delete(&format!("/api/admin/users/{id}"))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't delete user".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_delete_user(_id: &str) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn fetch_settings() -> Result<InstanceSettingsForm, String> {
    let response = gloo_net::http::Request::get("/api/admin/settings")
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.ok() {
        return Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't load settings".to_string()));
    }
    response.json().await.map_err(|err| err.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_settings() -> Result<InstanceSettingsForm, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn save_settings(body: InstanceSettingsForm) -> Result<(), String> {
    let request = gloo_net::http::Request::put("/api/admin/settings")
        .json(&body)
        .map_err(|err| err.to_string())?;
    let response = request.send().await.map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't save settings".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn save_settings(_body: InstanceSettingsForm) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn fetch_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let response = gloo_net::http::Request::get(path)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.ok() {
        return Err(response
            .text()
            .await
            .unwrap_or_else(|_| format!("request to {path} failed")));
    }
    response.json().await.map_err(|err| err.to_string())
}

#[cfg(target_arch = "wasm32")]
async fn post_action(path: &str) -> Result<(), String> {
    let response = gloo_net::http::Request::post(path)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "the action failed".to_string()))
    }
}

#[cfg(target_arch = "wasm32")]
async fn fetch_system() -> Result<SystemInfoDto, String> {
    fetch_json("/api/admin/system").await
}
#[cfg(not(target_arch = "wasm32"))]
async fn fetch_system() -> Result<SystemInfoDto, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn fetch_repos() -> Result<Vec<AdminRepoDto>, String> {
    fetch_json("/api/admin/repos").await
}
#[cfg(not(target_arch = "wasm32"))]
async fn fetch_repos() -> Result<Vec<AdminRepoDto>, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_delete_repo(id: &str) -> Result<(), String> {
    let response = gloo_net::http::Request::delete(&format!("/api/admin/repos/{id}"))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't delete repository".to_string()))
    }
}
#[cfg(not(target_arch = "wasm32"))]
async fn request_delete_repo(_id: &str) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn fetch_jobs(only_dead: bool) -> Result<Vec<AdminJobDto>, String> {
    let path = if only_dead {
        "/api/admin/jobs?status=failed"
    } else {
        "/api/admin/jobs"
    };
    fetch_json(path).await
}
#[cfg(not(target_arch = "wasm32"))]
async fn fetch_jobs(_only_dead: bool) -> Result<Vec<AdminJobDto>, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_job_action(id: &str, action: &str) -> Result<(), String> {
    post_action(&format!("/api/admin/jobs/{id}/{action}")).await
}
#[cfg(not(target_arch = "wasm32"))]
async fn request_job_action(_id: &str, _action: &str) -> Result<(), String> {
    Err("not available during server rendering".to_string())
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

/// Plain `fn` (not a closure) so each per-row `onclick` can call it by
/// value — a per-iteration `FnMut` closure can't be moved into the next
/// row's handler (the `apply_label` pattern used elsewhere in `ui/`).
fn job_action(
    id: String,
    action: &'static str,
    mut jobs: Resource<Result<Vec<AdminJobDto>, String>>,
    mut action_error: Signal<Option<String>>,
) {
    spawn(async move {
        match request_job_action(&id, action).await {
            Ok(()) => jobs.restart(),
            Err(message) => action_error.set(Some(message)),
        }
    });
}

fn delete_repo(
    id: String,
    mut repos: Resource<Result<Vec<AdminRepoDto>, String>>,
    mut action_error: Signal<Option<String>>,
) {
    spawn(async move {
        match request_delete_repo(&id).await {
            Ok(()) => repos.restart(),
            Err(message) => action_error.set(Some(message)),
        }
    });
}

#[component]
pub fn Admin() -> Element {
    let mut users = use_resource(fetch_users);
    let events = use_resource(fetch_audit_events);
    let settings = use_resource(fetch_settings);
    let system = use_resource(fetch_system);
    let repos = use_resource(fetch_repos);
    let jobs = use_resource(move || fetch_jobs(true));
    let mut action_error = use_signal(|| Option::<String>::None);

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            h1 { class: "font-mono text-xl font-semibold text-ink", "Instance administration" }
            p { class: "mt-1 text-sm text-ink-muted",
                "Server-side access control applies regardless of this page — a non-admin sees these actions fail, not just hidden."
            }

            h2 { class: "mt-8 font-mono text-sm font-semibold text-ink", "System" }
            div { class: "mt-2",
                match &*system.read() {
                    Some(Ok(info)) => rsx! {
                        dl { class: "grid grid-cols-2 gap-x-6 gap-y-1 border border-line p-4 font-mono text-xs text-ink-muted sm:grid-cols-3",
                            div { "edda " span { class: "text-ink", "{info.version}" } }
                            div { "db " span { class: "text-ink", "{info.database_backend}" } }
                            div { "users " span { class: "text-ink", "{info.users}" } }
                            div { "repos " span { class: "text-ink", "{info.repositories}" } }
                            div { "orgs " span { class: "text-ink", "{info.organizations}" } }
                            div { "open PRs " span { class: "text-ink", "{info.open_pull_requests}" } }
                            div { "open issues " span { class: "text-ink", "{info.open_issues}" } }
                            div { "jobs pending " span { class: "text-ink", "{info.jobs_pending}" } }
                            div { "jobs running " span { class: "text-ink", "{info.jobs_running}" } }
                            div {
                                "jobs dead "
                                span {
                                    class: if info.jobs_dead > 0 { "text-status-conflict" } else { "text-ink" },
                                    "{info.jobs_dead}"
                                }
                            }
                            div { "git bytes " span { class: "text-ink", "{info.tracked_git_bytes}" } }
                            div { "lfs bytes " span { class: "text-ink", "{info.tracked_lfs_bytes}" } }
                        }
                    },
                    Some(Err(err)) => rsx! { p { class: "text-sm text-status-conflict", "{err}" } },
                    None => rsx! { p { class: "text-sm text-ink-muted", "loading…" } },
                }
            }

            h2 { class: "mt-10 font-mono text-sm font-semibold text-ink", "Dead-lettered jobs" }
            div { class: "mt-2",
                match &*jobs.read() {
                    Some(Ok(list)) if list.is_empty() => rsx! {
                        p { class: "text-sm text-ink-muted italic", "the queue has no dead letters" }
                    },
                    Some(Ok(list)) => rsx! {
                        div { class: "divide-y divide-line border border-line",
                            for job in list.clone() {
                                div { class: "flex items-center justify-between gap-4 px-4 py-3",
                                    div { class: "min-w-0",
                                        div { class: "font-mono text-sm text-ink", "{job.kind}" }
                                        div { class: "font-mono text-xs text-ink-muted",
                                            "{job.attempts}/{job.max_attempts} attempts"
                                            if let Some(err) = &job.last_error {
                                                " · {err}"
                                            }
                                        }
                                    }
                                    div { class: "flex shrink-0 gap-3",
                                        button {
                                            r#type: "button",
                                            class: "font-mono text-xs text-ink-muted hover:text-ink",
                                            onclick: {
                                                let job_id = job.id.clone();
                                                move |_| job_action(job_id.clone(), "retry", jobs, action_error)
                                            },
                                            "retry"
                                        }
                                        button {
                                            r#type: "button",
                                            class: "font-mono text-xs text-ink-muted hover:text-status-conflict",
                                            onclick: {
                                                let job_id = job.id.clone();
                                                move |_| job_action(job_id.clone(), "cancel", jobs, action_error)
                                            },
                                            "cancel"
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

            h2 { class: "mt-10 font-mono text-sm font-semibold text-ink", "Repositories" }
            div { class: "mt-2",
                match &*repos.read() {
                    Some(Ok(list)) => rsx! {
                        div { class: "divide-y divide-line border border-line",
                            for repo in list.clone() {
                                div { class: "flex items-center justify-between gap-4 px-4 py-3",
                                    div { class: "min-w-0 font-mono text-sm text-ink",
                                        "{repo.owner}/{repo.name}"
                                        if repo.private {
                                            span { class: "ml-2 text-xs text-ink-muted", "[private]" }
                                        }
                                        if repo.is_fork {
                                            span { class: "ml-2 text-xs text-ink-muted", "[fork]" }
                                        }
                                    }
                                    button {
                                        r#type: "button",
                                        class: "shrink-0 font-mono text-xs text-ink-muted hover:text-status-conflict",
                                        onclick: {
                                            let repo_id = repo.id.clone();
                                            move |_| delete_repo(repo_id.clone(), repos, action_error)
                                        },
                                        "delete"
                                    }
                                }
                            }
                        }
                    },
                    Some(Err(err)) => rsx! { p { class: "text-sm text-status-conflict", "{err}" } },
                    None => rsx! { p { class: "text-sm text-ink-muted", "loading…" } },
                }
            }

            h2 { class: "mt-10 font-mono text-sm font-semibold text-ink", "Instance settings" }
            p { class: "mt-1 text-sm text-ink-muted",
                "Applied immediately, no restart. These override the matching EDDA_* startup values."
            }
            div { class: "mt-2",
                match &*settings.read() {
                    Some(Ok(current)) => rsx! { SettingsForm { initial: current.clone() } },
                    Some(Err(err)) => rsx! {
                        p { class: "text-sm text-status-conflict", "{err}" }
                    },
                    None => rsx! {
                        p { class: "text-sm text-ink-muted", "loading…" }
                    },
                }
            }

            h2 { class: "mt-10 font-mono text-sm font-semibold text-ink", "Users" }
            if let Some(message) = action_error() {
                p { class: "mt-2 font-mono text-xs text-status-conflict", "{message}" }
            }
            div { class: "mt-2",
                match &*users.read() {
                    Some(Ok(list)) => rsx! {
                        div { class: "divide-y divide-line border border-line",
                            for user in list.clone() {
                                div { class: "flex items-center justify-between gap-4 px-4 py-3",
                                    div { class: "min-w-0",
                                        div { class: "font-mono text-sm text-ink",
                                            "{user.username} "
                                            span { class: "text-ink-muted", "({user.email})" }
                                            if user.is_admin {
                                                span { class: "ml-2 font-mono text-xs text-accent", "[admin]" }
                                            }
                                            if user.disabled {
                                                span { class: "ml-2 font-mono text-xs text-status-conflict", "[disabled]" }
                                            }
                                        }
                                    }
                                    div { class: "flex shrink-0 gap-3",
                                        button {
                                            r#type: "button",
                                            class: "font-mono text-xs text-ink-muted hover:text-ink",
                                            onclick: {
                                                let id = user.id.clone();
                                                let disabled = user.disabled;
                                                move |_| {
                                                    let id = id.clone();
                                                    spawn(async move {
                                                        match request_set_disabled(&id, !disabled).await {
                                                            Ok(()) => users.restart(),
                                                            Err(message) => action_error.set(Some(message)),
                                                        }
                                                    });
                                                }
                                            },
                                            if user.disabled { "enable" } else { "disable" }
                                        }
                                        button {
                                            r#type: "button",
                                            class: "font-mono text-xs text-ink-muted hover:text-status-conflict",
                                            onclick: {
                                                let id = user.id.clone();
                                                move |_| {
                                                    let id = id.clone();
                                                    spawn(async move {
                                                        match request_delete_user(&id).await {
                                                            Ok(()) => users.restart(),
                                                            Err(message) => action_error.set(Some(message)),
                                                        }
                                                    });
                                                }
                                            },
                                            "delete"
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

            h2 { class: "mt-10 font-mono text-sm font-semibold text-ink", "Recent audit events" }
            div { class: "mt-2",
                match &*events.read() {
                    Some(Ok(list)) if list.is_empty() => rsx! {
                        p { class: "text-sm text-ink-muted italic", "no events recorded yet" }
                    },
                    Some(Ok(list)) => rsx! {
                        div { class: "divide-y divide-line border border-line",
                            for event in list.clone() {
                                div { class: "px-4 py-2 font-mono text-xs text-ink-muted",
                                    "{relative_time(event.occurred_at)} · {event.event_type}"
                                    if let Some(actor) = &event.actor_id {
                                        " · actor {actor}"
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

/// The instance-settings editor. Its own child component so its per-field
/// signals can be seeded directly from the loaded values — no
/// populate-after-fetch dance.
#[component]
fn SettingsForm(initial: InstanceSettingsForm) -> Element {
    let mut registration_mode = use_signal(|| initial.registration_mode.clone());
    let mut default_repo_visibility = use_signal(|| initial.default_repo_visibility.clone());
    let mut welcome_message = use_signal(|| initial.welcome_message.clone().unwrap_or_default());
    let mut require_signin = use_signal(|| initial.require_signin_to_view);
    let mut saving = use_signal(|| false);
    let mut status = use_signal(|| Option::<Result<String, String>>::None);

    let field =
        "border border-line bg-surface px-2 py-1.5 font-mono text-sm text-ink disabled:opacity-60";

    let on_save = move |_| {
        let body = InstanceSettingsForm {
            registration_mode: registration_mode(),
            default_repo_visibility: default_repo_visibility(),
            welcome_message: {
                let trimmed = welcome_message().trim().to_string();
                (!trimmed.is_empty()).then_some(trimmed)
            },
            require_signin_to_view: require_signin(),
        };
        saving.set(true);
        status.set(None);
        spawn(async move {
            let result = save_settings(body).await;
            saving.set(false);
            status.set(Some(result.map(|()| {
                "Saved — changes are live for the next request.".to_string()
            })));
        });
    };

    rsx! {
        div { class: "space-y-4 border border-line p-4",
            label { class: "block",
                span { class: "font-mono text-xs text-ink-muted", "Registration mode" }
                select {
                    class: "{field} mt-1 block w-full",
                    disabled: saving(),
                    value: "{registration_mode}",
                    onchange: move |event| registration_mode.set(event.value()),
                    option { value: "open", "open — anyone may sign up and is active immediately" }
                    option { value: "approval", "approval — an admin must approve each new account" }
                    option { value: "closed", "closed — no self-service signup" }
                }
            }
            label { class: "block",
                span { class: "font-mono text-xs text-ink-muted", "Default repository visibility" }
                select {
                    class: "{field} mt-1 block w-full",
                    disabled: saving(),
                    value: "{default_repo_visibility}",
                    onchange: move |event| default_repo_visibility.set(event.value()),
                    option { value: "private", "private" }
                    option { value: "public", "public" }
                }
            }
            label { class: "block",
                span { class: "font-mono text-xs text-ink-muted", "Welcome message (shown on the sign-in page; blank to remove)" }
                textarea {
                    class: "{field} mt-1 block w-full",
                    disabled: saving(),
                    rows: "3",
                    value: "{welcome_message}",
                    oninput: move |event| welcome_message.set(event.value()),
                }
            }
            label { class: "flex items-center gap-2",
                input {
                    r#type: "checkbox",
                    checked: require_signin(),
                    disabled: saving(),
                    onchange: move |event| require_signin.set(event.checked()),
                }
                span { class: "font-mono text-xs text-ink-muted",
                    "Require sign-in to view anything (whole instance private, git clone included)"
                }
            }
            div { class: "flex items-center gap-3",
                button {
                    r#type: "button",
                    class: "border border-line px-3 py-1.5 font-mono text-sm text-ink hover:bg-surface disabled:opacity-60",
                    disabled: saving(),
                    onclick: on_save,
                    if saving() { "saving…" } else { "Save settings" }
                }
                match status() {
                    Some(Ok(message)) => rsx! {
                        span { class: "font-mono text-xs text-accent", "{message}" }
                    },
                    Some(Err(err)) => rsx! {
                        span { class: "font-mono text-xs text-status-conflict", "{err}" }
                    },
                    None => rsx! {},
                }
            }
        }
    }
}

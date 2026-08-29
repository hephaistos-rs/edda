use dioxus::prelude::*;
use serde::Serialize;

use crate::Route;

#[derive(Serialize)]
struct SignupBody<'a> {
    username: &'a str,
    email: &'a str,
    password: &'a str,
}

/// What a successful signup did: `Active` means a session is established
/// (navigate home); `PendingApproval` means the instance runs
/// `Approval`-mode registration and an admin must approve the account
/// before it can sign in.
// The non-wasm SSR build only has the stub `request_signup`, which never
// constructs these — the real one is wasm32-only (browser `fetch`).
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
enum SignupResult {
    Active,
    PendingApproval,
}

/// `Ok(result)` on success, `Err(message)` otherwise. `gloo-net` only
/// compiles for wasm32 (it calls the browser `fetch` API) — this
/// component's code is shared with the server build for SSR, so the real
/// call is wasm32-only, with a stub for the server target that this
/// form's submit handler never actually reaches there (SSR doesn't fire
/// `onsubmit`).
#[cfg(target_arch = "wasm32")]
async fn request_signup(body: &SignupBody<'_>) -> Result<SignupResult, String> {
    let request = gloo_net::http::Request::post("/api/auth/signup")
        .json(body)
        .map_err(|err| err.to_string())?;
    let response = request.send().await.map_err(|err| err.to_string())?;
    if response.ok() {
        // 202 Accepted = created but pending admin approval (no session).
        if response.status() == 202 {
            Ok(SignupResult::PendingApproval)
        } else {
            Ok(SignupResult::Active)
        }
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "signup failed".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_signup(_body: &SignupBody<'_>) -> Result<SignupResult, String> {
    Err("not available during server rendering".to_string())
}

#[component]
pub fn Signup() -> Element {
    let navigator = use_navigator();
    let mut username = use_signal(String::new);
    let mut email = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let mut error = use_signal(|| Option::<String>::None);
    let mut pending_notice = use_signal(|| false);
    let mut submitting = use_signal(|| false);

    let on_submit = move |event: FormEvent| {
        event.prevent_default();
        if password.read().as_str() != confirm.read().as_str() {
            error.set(Some("passwords don't match".to_string()));
            return;
        }
        let username_value = username.read().clone();
        let email_value = email.read().clone();
        let password_value = password.read().clone();

        submitting.set(true);
        error.set(None);
        spawn(async move {
            let body = SignupBody {
                username: &username_value,
                email: &email_value,
                password: &password_value,
            };
            let outcome = request_signup(&body).await;

            submitting.set(false);
            match outcome {
                Ok(SignupResult::Active) => {
                    navigator.push(Route::Home {});
                }
                Ok(SignupResult::PendingApproval) => pending_notice.set(true),
                Err(message) => error.set(Some(message)),
            }
        });
    };

    rsx! {
        main { class: "mx-auto max-w-sm px-4 py-16",
            h1 { class: "font-mono text-xl font-semibold text-ink", "create account" }
            form { class: "mt-6 flex flex-col gap-4", onsubmit: on_submit,
                label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                    "username"
                    input {
                        r#type: "text",
                        required: true,
                        maxlength: 39,
                        pattern: "[A-Za-z0-9][A-Za-z0-9_-]*[A-Za-z0-9]|[A-Za-z0-9]",
                        title: "1-39 characters, start and end with a letter or digit, and only letters, digits, '-' or '_'",
                        class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                        value: "{username}",
                        oninput: move |event| username.set(event.value()),
                    }
                }
                label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                    "email"
                    input {
                        r#type: "email",
                        required: true,
                        class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                        value: "{email}",
                        oninput: move |event| email.set(event.value()),
                    }
                }
                label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                    "password"
                    input {
                        r#type: "password",
                        required: true,
                        class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                        value: "{password}",
                        oninput: move |event| password.set(event.value()),
                    }
                }
                label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                    "confirm password"
                    input {
                        r#type: "password",
                        required: true,
                        class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                        value: "{confirm}",
                        oninput: move |event| confirm.set(event.value()),
                    }
                }
                if let Some(message) = error() {
                    p { class: "font-mono text-xs text-status-conflict", "{message}" }
                }
                if pending_notice() {
                    p { class: "font-mono text-xs text-ink-muted",
                        "your account was created and is awaiting administrator approval — you'll be able to sign in once it's approved."
                    }
                }
                button {
                    r#type: "submit",
                    disabled: submitting(),
                    class: "border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                    if submitting() { "creating…" } else { "create account" }
                }
            }
            p { class: "mt-4 font-mono text-xs text-ink-muted",
                "already have an account? "
                Link { to: Route::Login {}, class: "text-accent no-underline hover:underline", "sign in" }
            }
        }
    }
}

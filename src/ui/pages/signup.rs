use dioxus::prelude::*;
use serde::Serialize;

use crate::Route;

#[derive(Serialize)]
struct SignupBody<'a> {
    username: &'a str,
    email: &'a str,
    password: &'a str,
}

/// `Ok(())` on success, `Err(message)` otherwise. `gloo-net` only compiles
/// for wasm32 (it calls the browser `fetch` API) — this component's code is
/// shared with the server build for SSR, so the real call is wasm32-only,
/// with a stub for the server target that this form's submit handler never
/// actually reaches there (SSR doesn't fire `onsubmit`).
#[cfg(target_arch = "wasm32")]
async fn request_signup(body: &SignupBody<'_>) -> Result<(), String> {
    let request = gloo_net::http::Request::post("/api/auth/signup").json(body).map_err(|err| err.to_string())?;
    let response = request.send().await.map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response.text().await.unwrap_or_else(|_| "signup failed".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_signup(_body: &SignupBody<'_>) -> Result<(), String> {
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
            let body = SignupBody { username: &username_value, email: &email_value, password: &password_value };
            let outcome = request_signup(&body).await;

            submitting.set(false);
            match outcome {
                Ok(()) => {
                    navigator.push(Route::Home {});
                }
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

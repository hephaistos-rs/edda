use dioxus::prelude::*;
use serde::Serialize;

use crate::Route;

#[derive(Serialize)]
struct RequestBody<'a> {
    email: &'a str,
}

#[derive(Serialize)]
struct ConsumeBody<'a> {
    token: &'a str,
    new_password: &'a str,
}

// Same wasm32-only-fetch / server-side-stub split as every other hand-written
// (non-server-function) API call in `ui/` — these are raw `edda-app`
// routes, not Dioxus server functions, so there's no macro-generated stub
// to lean on.
#[cfg(target_arch = "wasm32")]
async fn request_reset(body: &RequestBody<'_>) -> Result<(), String> {
    let request = gloo_net::http::Request::post("/api/auth/password-reset/request")
        .json(body)
        .map_err(|err| err.to_string())?;
    request.send().await.map_err(|err| err.to_string())?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_reset(_body: &RequestBody<'_>) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn consume_reset(body: &ConsumeBody<'_>) -> Result<(), String> {
    let request = gloo_net::http::Request::post("/api/auth/password-reset/consume")
        .json(body)
        .map_err(|err| err.to_string())?;
    let response = request.send().await.map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "that reset link is invalid or has expired".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn consume_reset(_body: &ConsumeBody<'_>) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

#[component]
pub fn ResetPassword(token: Option<String>) -> Element {
    let mut email = use_signal(String::new);
    let mut new_password = use_signal(String::new);
    let mut error = use_signal(|| Option::<String>::None);
    let mut submitting = use_signal(|| false);
    let mut requested = use_signal(|| false);
    let mut done = use_signal(|| false);

    if let Some(token) = token.clone() {
        let on_submit = move |event: FormEvent| {
            event.prevent_default();
            let token = token.clone();
            let new_password_value = new_password.read().clone();
            submitting.set(true);
            error.set(None);
            spawn(async move {
                let body = ConsumeBody {
                    token: &token,
                    new_password: &new_password_value,
                };
                let outcome = consume_reset(&body).await;
                submitting.set(false);
                match outcome {
                    Ok(()) => done.set(true),
                    Err(message) => error.set(Some(message)),
                }
            });
        };

        return rsx! {
            main { class: "mx-auto max-w-sm px-4 py-16",
                h1 { class: "font-mono text-xl font-semibold text-ink", "set a new password" }
                if done() {
                    p { class: "mt-4 text-sm text-ink-muted", "your password has been changed." }
                    Link { to: Route::Login {}, class: "mt-4 inline-block text-accent no-underline hover:underline", "sign in" }
                } else {
                    form { class: "mt-6 flex flex-col gap-4", onsubmit: on_submit,
                        label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                            "new password"
                            input {
                                r#type: "password", required: true, autofocus: true,
                                class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                                value: "{new_password}",
                                oninput: move |event| new_password.set(event.value()),
                            }
                        }
                        if let Some(message) = error() {
                            p { class: "font-mono text-xs text-status-conflict", "{message}" }
                        }
                        button {
                            r#type: "submit",
                            disabled: submitting(),
                            class: "border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                            if submitting() { "saving…" } else { "set new password" }
                        }
                    }
                }
            }
        };
    }

    let on_request = move |event: FormEvent| {
        event.prevent_default();
        let email_value = email.read().clone();
        submitting.set(true);
        error.set(None);
        spawn(async move {
            let body = RequestBody {
                email: &email_value,
            };
            let _ = request_reset(&body).await;
            submitting.set(false);
            // Same response regardless of whether the email matched a real
            // account — the server itself never distinguishes this either
            // (see `edda_auth::password_reset::request`'s doc comment).
            requested.set(true);
        });
    };

    rsx! {
        main { class: "mx-auto max-w-sm px-4 py-16",
            h1 { class: "font-mono text-xl font-semibold text-ink", "reset your password" }
            if requested() {
                p { class: "mt-4 text-sm text-ink-muted",
                    "if that email is registered, a reset link is on its way."
                }
            } else {
                form { class: "mt-6 flex flex-col gap-4", onsubmit: on_request,
                    label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                        "email"
                        input {
                            r#type: "email", required: true, autofocus: true,
                            class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                            value: "{email}",
                            oninput: move |event| email.set(event.value()),
                        }
                    }
                    button {
                        r#type: "submit",
                        disabled: submitting(),
                        class: "border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                        if submitting() { "sending…" } else { "send reset link" }
                    }
                }
            }
        }
    }
}

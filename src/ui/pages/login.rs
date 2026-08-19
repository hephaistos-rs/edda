use dioxus::prelude::*;
use serde::Serialize;

use crate::Route;

#[derive(Serialize)]
struct LoginBody<'a> {
    email: &'a str,
    password: &'a str,
}

/// See the matching helper in `signup.rs`: `gloo-net` only compiles for
/// wasm32, but this component's code is shared with the server (SSR) build.
#[cfg(target_arch = "wasm32")]
async fn request_login(body: &LoginBody<'_>) -> Result<(), String> {
    let request = gloo_net::http::Request::post("/api/auth/login").json(body).map_err(|err| err.to_string())?;
    let response = request.send().await.map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response.text().await.unwrap_or_else(|_| "sign in failed".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_login(_body: &LoginBody<'_>) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

#[component]
pub fn Login() -> Element {
    let navigator = use_navigator();
    let mut email = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut error = use_signal(|| Option::<String>::None);
    let mut submitting = use_signal(|| false);

    let on_submit = move |event: FormEvent| {
        event.prevent_default();
        let email_value = email.read().clone();
        let password_value = password.read().clone();

        submitting.set(true);
        error.set(None);
        spawn(async move {
            let body = LoginBody { email: &email_value, password: &password_value };
            let outcome = request_login(&body).await;

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
            h1 { class: "font-mono text-xl font-semibold text-ink", "sign in" }
            form { class: "mt-6 flex flex-col gap-4", onsubmit: on_submit,
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
                if let Some(message) = error() {
                    p { class: "font-mono text-xs text-status-conflict", "{message}" }
                }
                button {
                    r#type: "submit",
                    disabled: submitting(),
                    class: "border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                    if submitting() { "signing in…" } else { "sign in" }
                }
            }
            p { class: "mt-4 font-mono text-xs text-ink-muted",
                "no account yet? "
                Link { to: Route::Signup {}, class: "text-accent no-underline hover:underline", "create one" }
            }
        }
    }
}

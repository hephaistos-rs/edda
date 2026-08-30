use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

use crate::ui::webauthn_js;
use crate::Route;

#[derive(Serialize)]
struct LoginBody<'a> {
    email: &'a str,
    password: &'a str,
}

/// Mirrors `edda_app::auth_routes::LoginResponse` — an untagged enum on
/// the wire, told apart here the same way: whichever field is present.
/// Only ever deserialized inside the wasm32-only `request_login`; the
/// native (SSR) stub never constructs it, hence `allow(dead_code)`.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct LoginResponse {
    #[serde(default)]
    pending_login_token: Option<String>,
}

#[allow(dead_code)]
enum LoginOutcome {
    LoggedIn,
    NeedsTotp { pending_login_token: String },
}

#[derive(Serialize)]
struct LoginTotpBody<'a> {
    pending_login_token: &'a str,
    code: &'a str,
}

/// See the matching helper in `signup.rs`: `gloo-net` only compiles for
/// wasm32, but this component's code is shared with the server (SSR) build.
#[cfg(target_arch = "wasm32")]
async fn request_login(body: &LoginBody<'_>) -> Result<LoginOutcome, String> {
    let request = gloo_net::http::Request::post("/api/auth/login")
        .json(body)
        .map_err(|err| err.to_string())?;
    let response = request.send().await.map_err(|err| err.to_string())?;
    if !response.ok() {
        return Err(response
            .text()
            .await
            .unwrap_or_else(|_| "sign in failed".to_string()));
    }
    let parsed: LoginResponse = response.json().await.map_err(|err| err.to_string())?;
    Ok(match parsed.pending_login_token {
        Some(pending_login_token) => LoginOutcome::NeedsTotp {
            pending_login_token,
        },
        None => LoginOutcome::LoggedIn,
    })
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_login(_body: &LoginBody<'_>) -> Result<LoginOutcome, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_login_totp(body: &LoginTotpBody<'_>) -> Result<(), String> {
    let request = gloo_net::http::Request::post("/api/auth/login/totp")
        .json(body)
        .map_err(|err| err.to_string())?;
    let response = request.send().await.map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "that code was incorrect".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_login_totp(_body: &LoginTotpBody<'_>) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn fetch_oauth_enabled() -> bool {
    // Best-effort: a network error or malformed body just means "don't
    // show the SSO option," never a hard error surfaced to the user.
    let Ok(response) = gloo_net::http::Request::get("/api/auth/oauth/enabled")
        .send()
        .await
    else {
        return false;
    };
    if !response.ok() {
        return false;
    }
    response.json::<bool>().await.unwrap_or(false)
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_oauth_enabled() -> bool {
    false
}

/// The admin-configured instance welcome banner, if any. Best-effort,
/// same reasoning as `fetch_oauth_enabled`.
#[cfg(target_arch = "wasm32")]
async fn fetch_welcome_message() -> Option<String> {
    let Ok(response) = gloo_net::http::Request::get("/api/instance").send().await else {
        return None;
    };
    if !response.ok() {
        return None;
    }
    let body = response.json::<serde_json::Value>().await.ok()?;
    body.get("welcome_message")?.as_str().map(str::to_string)
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_welcome_message() -> Option<String> {
    None
}

/// The `{options, state_token}` shape `webauthn/login/options` returns —
/// `options` is passed through to `webauthn_js` untouched (see that
/// module's own doc comment for why this stays opaque JSON rather than a
/// duplicated set of typed WebAuthn DTOs).
#[derive(Debug, Clone, Deserialize)]
struct CeremonyOptionsDto {
    options: serde_json::Value,
    state_token: String,
}

/// Best-effort, same reasoning as `fetch_oauth_enabled`: a network error
/// or a 404 (this account has no registered passkey) both just mean
/// "don't offer a passkey button," never a hard error surfaced mid-login.
#[cfg(target_arch = "wasm32")]
async fn fetch_webauthn_login_options(pending_login_token: &str) -> Option<CeremonyOptionsDto> {
    let request = gloo_net::http::Request::post("/api/auth/webauthn/login/options")
        .json(&serde_json::json!({ "pending_login_token": pending_login_token }))
        .ok()?;
    let response = request.send().await.ok()?;
    if !response.ok() {
        return None;
    }
    response.json().await.ok()
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_webauthn_login_options(_pending_login_token: &str) -> Option<CeremonyOptionsDto> {
    None
}

#[cfg(target_arch = "wasm32")]
async fn request_webauthn_login_verify(
    pending_login_token: &str,
    state_token: &str,
    credential: serde_json::Value,
) -> Result<(), String> {
    let request = gloo_net::http::Request::post("/api/auth/webauthn/login/verify")
        .json(&serde_json::json!({
            "pending_login_token": pending_login_token,
            "state_token": state_token,
            "credential": credential,
        }))
        .map_err(|err| err.to_string())?;
    let response = request.send().await.map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "that passkey was not accepted".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_webauthn_login_verify(
    _pending_login_token: &str,
    _state_token: &str,
    _credential: serde_json::Value,
) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

#[component]
pub fn Login() -> Element {
    let navigator = use_navigator();
    let mut email = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut error = use_signal(|| Option::<String>::None);
    let mut submitting = use_signal(|| false);
    let mut pending_totp = use_signal(|| Option::<String>::None);
    let mut totp_code = use_signal(String::new);
    let oauth_enabled = use_resource(fetch_oauth_enabled);
    let welcome_message = use_resource(fetch_welcome_message);
    // `Some` once a password-verified login is pending 2FA *and* that
    // account has a registered passkey — populated alongside
    // `pending_totp`, never fetched separately, so there's no window
    // where the passkey button could appear before a password has
    // actually been verified.
    let mut webauthn_options = use_signal(|| Option::<CeremonyOptionsDto>::None);
    let mut webauthn_busy = use_signal(|| false);

    let on_submit = move |event: FormEvent| {
        event.prevent_default();
        let email_value = email.read().clone();
        let password_value = password.read().clone();

        submitting.set(true);
        error.set(None);
        spawn(async move {
            let body = LoginBody {
                email: &email_value,
                password: &password_value,
            };
            let outcome = request_login(&body).await;

            submitting.set(false);
            match outcome {
                Ok(LoginOutcome::LoggedIn) => {
                    navigator.push(Route::Home {});
                }
                Ok(LoginOutcome::NeedsTotp {
                    pending_login_token,
                }) => {
                    pending_totp.set(Some(pending_login_token.clone()));
                    spawn(async move {
                        webauthn_options
                            .set(fetch_webauthn_login_options(&pending_login_token).await);
                    });
                }
                Err(message) => error.set(Some(message)),
            }
        });
    };

    let on_use_passkey = move |_| {
        let Some(pending_login_token) = pending_totp.read().clone() else {
            return;
        };
        let Some(ceremony) = webauthn_options.read().clone() else {
            return;
        };

        webauthn_busy.set(true);
        error.set(None);
        spawn(async move {
            let outcome = async {
                let credential = webauthn_js::get_credential(ceremony.options).await?;
                request_webauthn_login_verify(
                    &pending_login_token,
                    &ceremony.state_token,
                    credential,
                )
                .await
            }
            .await;
            webauthn_busy.set(false);
            match outcome {
                Ok(()) => {
                    navigator.push(Route::Home {});
                }
                Err(message) => error.set(Some(message)),
            }
        });
    };

    let on_submit_totp = move |event: FormEvent| {
        event.prevent_default();
        let Some(token) = pending_totp.read().clone() else {
            return;
        };
        let code_value = totp_code.read().clone();

        submitting.set(true);
        error.set(None);
        spawn(async move {
            let body = LoginTotpBody {
                pending_login_token: &token,
                code: &code_value,
            };
            let outcome = request_login_totp(&body).await;
            submitting.set(false);
            match outcome {
                Ok(()) => {
                    navigator.push(Route::Home {});
                }
                Err(message) => error.set(Some(message)),
            }
        });
    };

    if let Some(_token) = pending_totp() {
        return rsx! {
            main { class: "mx-auto max-w-sm px-4 py-16",
                h1 { class: "font-mono text-xl font-semibold text-ink", "two-factor code" }
                p { class: "mt-1 text-sm text-ink-muted", "enter the 6-digit code from your authenticator app, or a recovery code" }
                form { class: "mt-6 flex flex-col gap-4", onsubmit: on_submit_totp,
                    label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                        "code"
                        input {
                            r#type: "text",
                            required: true,
                            autofocus: true,
                            placeholder: "123456",
                            class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                            value: "{totp_code}",
                            oninput: move |event| totp_code.set(event.value()),
                        }
                    }
                    if let Some(message) = error() {
                        p { class: "font-mono text-xs text-status-conflict", "{message}" }
                    }
                    button {
                        r#type: "submit",
                        disabled: submitting(),
                        class: "border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                        if submitting() { "verifying…" } else { "verify" }
                    }
                }
                if webauthn_options().is_some() {
                    button {
                        r#type: "button",
                        disabled: webauthn_busy(),
                        class: "mt-4 w-full border border-line px-3 py-1.5 font-mono text-sm text-ink-muted hover:text-ink disabled:opacity-60",
                        onclick: on_use_passkey,
                        if webauthn_busy() { "waiting for your passkey…" } else { "use a passkey instead" }
                    }
                }
            }
        };
    }

    rsx! {
        main { class: "mx-auto max-w-sm px-4 py-16",
            h1 { class: "font-mono text-xl font-semibold text-ink", "sign in" }
            if let Some(Some(message)) = &*welcome_message.read() {
                p { class: "mt-3 border border-line bg-surface px-3 py-2 text-sm text-ink-muted whitespace-pre-wrap",
                    "{message}"
                }
            }
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
            if (*oauth_enabled.read()).unwrap_or(false) {
                a {
                    href: "/api/auth/oauth/login",
                    class: "mt-4 block border border-line px-3 py-1.5 text-center font-mono text-sm text-ink-muted no-underline hover:text-ink",
                    "sign in with SSO"
                }
            }
            p { class: "mt-4 font-mono text-xs text-ink-muted",
                "no account yet? "
                Link { to: Route::Signup {}, class: "text-accent no-underline hover:underline", "create one" }
            }
            p { class: "mt-1 font-mono text-xs text-ink-muted",
                Link { to: Route::ResetPassword { token: None }, class: "text-accent no-underline hover:underline", "forgot your password?" }
            }
        }
    }
}

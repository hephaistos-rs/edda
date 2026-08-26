use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

use crate::ui::webauthn_js;

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct SshKeyDto {
    id: String,
    title: String,
    fingerprint: String,
    created_at: i64,
    #[allow(dead_code)]
    last_used_at: Option<i64>,
}

#[derive(Serialize)]
struct AddSshKeyBody<'a> {
    title: &'a str,
    public_key: &'a str,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct TokenDto {
    id: String,
    name: String,
    created_at: i64,
    #[allow(dead_code)]
    last_used_at: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct CreatedTokenDto {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    name: String,
    token: String,
    #[allow(dead_code)]
    created_at: i64,
}

#[derive(Serialize)]
struct CreateTokenBody<'a> {
    name: &'a str,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct TotpEnrollDto {
    secret_base32: String,
    otpauth_uri: String,
}

#[derive(Serialize)]
struct TotpActivateBody<'a> {
    code: &'a str,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct TotpActivateDto {
    recovery_codes: Vec<String>,
}

// Same wasm32-only-fetch / server-side-stub split as every other hand-written
// (non-server-function) API call in `ui/` — see `login.rs`'s doc comment.
#[cfg(target_arch = "wasm32")]
async fn fetch_keys() -> Result<Vec<SshKeyDto>, String> {
    let response = gloo_net::http::Request::get("/api/ssh-keys")
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.ok() {
        return Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't load SSH keys".to_string()));
    }
    response.json().await.map_err(|err| err.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_keys() -> Result<Vec<SshKeyDto>, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_add_key(body: &AddSshKeyBody<'_>) -> Result<(), String> {
    let request = gloo_net::http::Request::post("/api/ssh-keys")
        .json(body)
        .map_err(|err| err.to_string())?;
    let response = request.send().await.map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't add key".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_add_key(_body: &AddSshKeyBody<'_>) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_revoke_key(id: &str) -> Result<(), String> {
    let response = gloo_net::http::Request::post(&format!("/api/ssh-keys/{id}/revoke"))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't revoke key".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_revoke_key(_id: &str) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn fetch_tokens() -> Result<Vec<TokenDto>, String> {
    let response = gloo_net::http::Request::get("/api/auth/tokens")
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.ok() {
        return Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't load tokens".to_string()));
    }
    response.json().await.map_err(|err| err.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_tokens() -> Result<Vec<TokenDto>, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_create_token(body: &CreateTokenBody<'_>) -> Result<CreatedTokenDto, String> {
    let request = gloo_net::http::Request::post("/api/auth/tokens")
        .json(body)
        .map_err(|err| err.to_string())?;
    let response = request.send().await.map_err(|err| err.to_string())?;
    if response.ok() {
        response.json().await.map_err(|err| err.to_string())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't create token".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_create_token(_body: &CreateTokenBody<'_>) -> Result<CreatedTokenDto, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_revoke_token(id: &str) -> Result<(), String> {
    let response = gloo_net::http::Request::post(&format!("/api/auth/tokens/{id}/revoke"))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't revoke token".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_revoke_token(_id: &str) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_totp_enroll() -> Result<TotpEnrollDto, String> {
    let response = gloo_net::http::Request::post("/api/auth/totp/enroll")
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if response.ok() {
        response.json().await.map_err(|err| err.to_string())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't start enrollment".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_totp_enroll() -> Result<TotpEnrollDto, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_totp_activate(body: &TotpActivateBody<'_>) -> Result<TotpActivateDto, String> {
    let request = gloo_net::http::Request::post("/api/auth/totp/activate")
        .json(body)
        .map_err(|err| err.to_string())?;
    let response = request.send().await.map_err(|err| err.to_string())?;
    if response.ok() {
        response.json().await.map_err(|err| err.to_string())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "that code was incorrect".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_totp_activate(_body: &TotpActivateBody<'_>) -> Result<TotpActivateDto, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_totp_disable() -> Result<(), String> {
    let response = gloo_net::http::Request::post("/api/auth/totp/disable")
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't disable 2FA".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_totp_disable() -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn fetch_oauth_enabled() -> bool {
    // Best-effort: a network error or malformed body just means "don't
    // show the linked-accounts section," never a hard error surfaced to
    // the user — same reasoning as `login.rs`'s identical helper.
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

#[cfg(target_arch = "wasm32")]
async fn fetch_webauthn_enabled() -> bool {
    // Same best-effort reasoning as `fetch_oauth_enabled` above.
    let Ok(response) = gloo_net::http::Request::get("/api/auth/webauthn/enabled")
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
async fn fetch_webauthn_enabled() -> bool {
    false
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct WebauthnCredentialDto {
    id: String,
    label: String,
    created_at: i64,
    #[allow(dead_code)]
    last_used_at: Option<i64>,
}

/// The `{options, state_token}` shape every `webauthn/*/options` endpoint
/// returns — `options` is passed through to `webauthn_js` untouched, so
/// it's kept as opaque JSON here rather than a duplicated set of typed
/// WebAuthn DTOs (see `webauthn_js`'s own doc comment).
#[derive(Debug, Deserialize)]
struct CeremonyOptionsDto {
    options: serde_json::Value,
    state_token: String,
}

#[cfg(target_arch = "wasm32")]
async fn fetch_webauthn_credentials() -> Result<Vec<WebauthnCredentialDto>, String> {
    let response = gloo_net::http::Request::get("/api/auth/webauthn/credentials")
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.ok() {
        return Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't load passkeys".to_string()));
    }
    response.json().await.map_err(|err| err.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_webauthn_credentials() -> Result<Vec<WebauthnCredentialDto>, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_webauthn_register_options() -> Result<CeremonyOptionsDto, String> {
    let response = gloo_net::http::Request::post("/api/auth/webauthn/register/options")
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.ok() {
        return Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't start passkey registration".to_string()));
    }
    response.json().await.map_err(|err| err.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_webauthn_register_options() -> Result<CeremonyOptionsDto, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_webauthn_register_verify(
    state_token: &str,
    label: &str,
    credential: serde_json::Value,
) -> Result<(), String> {
    let request = gloo_net::http::Request::post("/api/auth/webauthn/register/verify")
        .json(&serde_json::json!({
            "state_token": state_token,
            "label": label,
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
            .unwrap_or_else(|_| "that passkey could not be registered".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_webauthn_register_verify(
    _state_token: &str,
    _label: &str,
    _credential: serde_json::Value,
) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn request_webauthn_revoke(id: &str) -> Result<(), String> {
    let response =
        gloo_net::http::Request::post(&format!("/api/auth/webauthn/credentials/{id}/revoke"))
            .send()
            .await
            .map_err(|err| err.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(response
            .text()
            .await
            .unwrap_or_else(|_| "couldn't revoke that passkey".to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn request_webauthn_revoke(_id: &str) -> Result<(), String> {
    Err("not available during server rendering".to_string())
}

/// Coarse "N days ago" — same reasoning as `repo.rs`'s own `relative_time`:
/// this data only ever needs day-scale granularity, not a date-formatting
/// dependency.
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

#[component]
pub fn Settings() -> Element {
    let mut keys = use_resource(fetch_keys);
    let oauth_enabled = use_resource(fetch_oauth_enabled);
    let webauthn_enabled = use_resource(fetch_webauthn_enabled);

    let mut title = use_signal(String::new);
    let mut public_key = use_signal(String::new);
    let mut add_error = use_signal(|| Option::<String>::None);
    let mut submitting = use_signal(|| false);

    let on_submit = move |event: FormEvent| {
        event.prevent_default();
        let title_value = title.read().clone();
        let public_key_value = public_key.read().clone();

        submitting.set(true);
        add_error.set(None);
        spawn(async move {
            let body = AddSshKeyBody {
                title: &title_value,
                public_key: &public_key_value,
            };
            match request_add_key(&body).await {
                Ok(()) => {
                    title.set(String::new());
                    public_key.set(String::new());
                    keys.restart();
                }
                Err(message) => add_error.set(Some(message)),
            }
            submitting.set(false);
        });
    };

    let mut tokens = use_resource(fetch_tokens);
    let mut token_name = use_signal(String::new);
    let mut token_error = use_signal(|| Option::<String>::None);
    let mut token_submitting = use_signal(|| false);
    // The raw token is only ever available once, right after creation —
    // never re-derivable from the list endpoint (which only ever returns
    // the hash-backed metadata) — see `edda_auth::tokens::create`'s own
    // "shown once" doc comment for why.
    let mut just_created_token = use_signal(|| Option::<String>::None);

    let on_create_token = move |event: FormEvent| {
        event.prevent_default();
        let name_value = token_name.read().clone();

        token_submitting.set(true);
        token_error.set(None);
        spawn(async move {
            let body = CreateTokenBody { name: &name_value };
            match request_create_token(&body).await {
                Ok(created) => {
                    token_name.set(String::new());
                    just_created_token.set(Some(created.token));
                    tokens.restart();
                }
                Err(message) => token_error.set(Some(message)),
            }
            token_submitting.set(false);
        });
    };

    // 2FA has no "current status" fetch endpoint — the settings page
    // treats "not enrolled" as the default UI state and lets a completed
    // enrollment replace it, matching how `just_created_token` above
    // already handles a one-time, not-re-fetchable secret. A page reload
    // resets back to the enrollment form even if 2FA is already active;
    // this is a UI-completeness gap, not a security one (the server-side
    // enforcement doesn't depend on this page's state).
    let mut totp_enrollment = use_signal(|| Option::<TotpEnrollDto>::None);
    let mut totp_code = use_signal(String::new);
    let mut totp_error = use_signal(|| Option::<String>::None);
    let mut totp_recovery_codes = use_signal(|| Option::<Vec<String>>::None);
    let mut totp_busy = use_signal(|| false);

    let on_start_totp_enroll = move |_| {
        totp_busy.set(true);
        totp_error.set(None);
        spawn(async move {
            match request_totp_enroll().await {
                Ok(enrollment) => totp_enrollment.set(Some(enrollment)),
                Err(message) => totp_error.set(Some(message)),
            }
            totp_busy.set(false);
        });
    };

    let on_activate_totp = move |event: FormEvent| {
        event.prevent_default();
        let code = totp_code.read().clone();
        totp_busy.set(true);
        totp_error.set(None);
        spawn(async move {
            let body = TotpActivateBody { code: &code };
            match request_totp_activate(&body).await {
                Ok(activated) => {
                    totp_enrollment.set(None);
                    totp_code.set(String::new());
                    totp_recovery_codes.set(Some(activated.recovery_codes));
                }
                Err(message) => totp_error.set(Some(message)),
            }
            totp_busy.set(false);
        });
    };

    let on_disable_totp = move |_| {
        totp_busy.set(true);
        spawn(async move {
            if request_totp_disable().await.is_ok() {
                totp_recovery_codes.set(None);
                totp_enrollment.set(None);
            }
            totp_busy.set(false);
        });
    };

    let mut webauthn_credentials = use_resource(fetch_webauthn_credentials);
    let mut webauthn_label = use_signal(String::new);
    let mut webauthn_error = use_signal(|| Option::<String>::None);
    let mut webauthn_busy = use_signal(|| false);

    let on_add_passkey = move |event: FormEvent| {
        event.prevent_default();
        let label_value = webauthn_label.read().clone();
        webauthn_busy.set(true);
        webauthn_error.set(None);
        spawn(async move {
            let outcome = async {
                let ceremony = request_webauthn_register_options().await?;
                let credential = webauthn_js::create_credential(ceremony.options).await?;
                request_webauthn_register_verify(&ceremony.state_token, &label_value, credential)
                    .await
            }
            .await;
            match outcome {
                Ok(()) => {
                    webauthn_label.set(String::new());
                    webauthn_credentials.restart();
                }
                Err(message) => webauthn_error.set(Some(message)),
            }
            webauthn_busy.set(false);
        });
    };

    rsx! {
        main { class: "mx-auto max-w-3xl px-4 py-8",
            h1 { class: "font-mono text-xl font-semibold text-ink", "SSH keys" }
            p { class: "mt-1 text-sm text-ink-muted",
                "Add a public key to push and pull over SSH — paste the contents of e.g. "
                span { class: "font-mono", "~/.ssh/id_ed25519.pub" }
                "."
            }

            form { class: "mt-6 flex flex-col gap-3 border border-line p-4", onsubmit: on_submit,
                label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                    "title"
                    input {
                        r#type: "text",
                        required: true,
                        placeholder: "e.g. laptop",
                        class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                        value: "{title}",
                        oninput: move |event| title.set(event.value()),
                    }
                }
                label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                    "public key"
                    textarea {
                        required: true,
                        rows: "3",
                        placeholder: "ssh-ed25519 AAAA...",
                        class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-xs text-ink focus:border-accent focus:outline-none",
                        value: "{public_key}",
                        oninput: move |event| public_key.set(event.value()),
                    }
                }
                if let Some(message) = add_error() {
                    p { class: "font-mono text-xs text-status-conflict", "{message}" }
                }
                button {
                    r#type: "submit",
                    disabled: submitting(),
                    class: "self-start border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                    if submitting() { "adding…" } else { "add key" }
                }
            }

            div { class: "mt-8",
                match &*keys.read() {
                    Some(Ok(list)) if list.is_empty() => rsx! {
                        p { class: "text-sm text-ink-muted italic", "no keys registered yet" }
                    },
                    Some(Ok(list)) => rsx! {
                        div { class: "divide-y divide-line border border-line",
                            for key in list.clone() {
                                div { class: "flex items-center justify-between gap-4 px-4 py-3",
                                    div { class: "min-w-0",
                                        div { class: "font-mono text-sm text-ink", "{key.title}" }
                                        div { class: "truncate font-mono text-xs text-ink-muted", "{key.fingerprint} · added {relative_time(key.created_at)}" }
                                    }
                                    button {
                                        r#type: "button",
                                        class: "shrink-0 font-mono text-xs text-ink-muted hover:text-status-conflict",
                                        onclick: {
                                            let id = key.id.clone();
                                            move |_| {
                                                let id = id.clone();
                                                spawn(async move {
                                                    if request_revoke_key(&id).await.is_ok() {
                                                        keys.restart();
                                                    }
                                                });
                                            }
                                        },
                                        "revoke"
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

            h1 { class: "mt-12 font-mono text-xl font-semibold text-ink", "Personal access tokens" }
            p { class: "mt-1 text-sm text-ink-muted",
                "Use a token in place of your password for git-over-HTTPS or the API."
            }

            form { class: "mt-6 flex flex-col gap-3 border border-line p-4", onsubmit: on_create_token,
                label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                    "name"
                    input {
                        r#type: "text",
                        required: true,
                        placeholder: "e.g. ci",
                        class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                        value: "{token_name}",
                        oninput: move |event| token_name.set(event.value()),
                    }
                }
                if let Some(message) = token_error() {
                    p { class: "font-mono text-xs text-status-conflict", "{message}" }
                }
                button {
                    r#type: "submit",
                    disabled: token_submitting(),
                    class: "self-start border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                    if token_submitting() { "creating…" } else { "create token" }
                }
            }

            if let Some(raw_token) = just_created_token() {
                div { class: "mt-4 flex flex-col gap-2 border border-accent bg-surface p-4",
                    p { class: "font-mono text-xs font-semibold text-ink",
                        "Copy this token now — you won't be able to see it again."
                    }
                    div { class: "flex items-center gap-2",
                        code { class: "flex-1 overflow-x-auto border border-line bg-canvas px-2 py-1.5 font-mono text-xs text-ink", "{raw_token}" }
                        button {
                            r#type: "button",
                            class: "shrink-0 border border-line px-2 py-1.5 font-mono text-xs text-ink-muted hover:text-ink",
                            onclick: move |_| just_created_token.set(None),
                            "dismiss"
                        }
                    }
                }
            }

            div { class: "mt-4",
                match &*tokens.read() {
                    Some(Ok(list)) if list.is_empty() => rsx! {
                        p { class: "text-sm text-ink-muted italic", "no tokens yet" }
                    },
                    Some(Ok(list)) => rsx! {
                        div { class: "divide-y divide-line border border-line",
                            for tok in list.clone() {
                                div { class: "flex items-center justify-between gap-4 px-4 py-3",
                                    div { class: "min-w-0",
                                        div { class: "font-mono text-sm text-ink", "{tok.name}" }
                                        div { class: "truncate font-mono text-xs text-ink-muted", "created {relative_time(tok.created_at)}" }
                                    }
                                    button {
                                        r#type: "button",
                                        class: "shrink-0 font-mono text-xs text-ink-muted hover:text-status-conflict",
                                        onclick: {
                                            let id = tok.id.clone();
                                            move |_| {
                                                let id = id.clone();
                                                spawn(async move {
                                                    if request_revoke_token(&id).await.is_ok() {
                                                        tokens.restart();
                                                    }
                                                });
                                            }
                                        },
                                        "revoke"
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

            h1 { class: "mt-12 font-mono text-xl font-semibold text-ink", "Two-factor authentication" }
            p { class: "mt-1 text-sm text-ink-muted",
                "Require a time-based code from an authenticator app on every login."
            }

            if let Some(codes) = totp_recovery_codes() {
                div { class: "mt-4 flex flex-col gap-2 border border-accent bg-surface p-4",
                    p { class: "font-mono text-xs font-semibold text-ink",
                        "2FA is now active. Save these recovery codes — each works once, and you won't see them again."
                    }
                    div { class: "grid grid-cols-2 gap-1 font-mono text-xs text-ink",
                        for code in codes {
                            code { class: "border border-line bg-canvas px-2 py-1", "{code}" }
                        }
                    }
                }
            } else if let Some(enrollment) = totp_enrollment() {
                form { class: "mt-4 flex flex-col gap-3 border border-line p-4", onsubmit: on_activate_totp,
                    p { class: "text-sm text-ink-muted",
                        "Add this secret to your authenticator app, then enter the 6-digit code it shows."
                    }
                    code { class: "break-all border border-line bg-canvas px-2 py-1.5 font-mono text-xs text-ink", "{enrollment.secret_base32}" }
                    label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                        "code"
                        input {
                            r#type: "text",
                            required: true,
                            placeholder: "123456",
                            class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                            value: "{totp_code}",
                            oninput: move |event| totp_code.set(event.value()),
                        }
                    }
                    if let Some(message) = totp_error() {
                        p { class: "font-mono text-xs text-status-conflict", "{message}" }
                    }
                    button {
                        r#type: "submit",
                        disabled: totp_busy(),
                        class: "self-start border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                        if totp_busy() { "verifying…" } else { "confirm" }
                    }
                }
            } else {
                div { class: "mt-4",
                    if let Some(message) = totp_error() {
                        p { class: "mb-2 font-mono text-xs text-status-conflict", "{message}" }
                    }
                    div { class: "flex gap-3",
                        button {
                            r#type: "button",
                            disabled: totp_busy(),
                            class: "border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                            onclick: on_start_totp_enroll,
                            "enroll in 2FA"
                        }
                        button {
                            r#type: "button",
                            disabled: totp_busy(),
                            class: "border border-line px-3 py-1.5 font-mono text-sm text-ink-muted hover:text-status-conflict disabled:opacity-60",
                            onclick: on_disable_totp,
                            "disable 2FA"
                        }
                    }
                }
            }

            if (*webauthn_enabled.read()).unwrap_or(false) {
                h1 { class: "mt-12 font-mono text-xl font-semibold text-ink", "Passkeys" }
                p { class: "mt-1 text-sm text-ink-muted",
                    "Sign in with a security key, or your device's built-in biometrics, as an "
                    "alternative to a 2FA code."
                }

                form { class: "mt-6 flex flex-col gap-3 border border-line p-4", onsubmit: on_add_passkey,
                    label { class: "flex flex-col gap-1 text-sm text-ink-muted",
                        "label"
                        input {
                            r#type: "text",
                            required: true,
                            placeholder: "e.g. yubikey",
                            class: "border border-line bg-surface px-2.5 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none",
                            value: "{webauthn_label}",
                            oninput: move |event| webauthn_label.set(event.value()),
                        }
                    }
                    if let Some(message) = webauthn_error() {
                        p { class: "font-mono text-xs text-status-conflict", "{message}" }
                    }
                    button {
                        r#type: "submit",
                        disabled: webauthn_busy(),
                        class: "self-start border border-accent bg-accent px-3 py-1.5 font-mono text-sm text-accent-ink disabled:opacity-60",
                        if webauthn_busy() { "waiting for your passkey…" } else { "add a passkey" }
                    }
                }

                div { class: "mt-4",
                    match &*webauthn_credentials.read() {
                        Some(Ok(list)) if list.is_empty() => rsx! {
                            p { class: "text-sm text-ink-muted italic", "no passkeys registered yet" }
                        },
                        Some(Ok(list)) => rsx! {
                            div { class: "divide-y divide-line border border-line",
                                for cred in list.clone() {
                                    div { class: "flex items-center justify-between gap-4 px-4 py-3",
                                        div { class: "min-w-0",
                                            div { class: "font-mono text-sm text-ink", "{cred.label}" }
                                            div { class: "truncate font-mono text-xs text-ink-muted", "added {relative_time(cred.created_at)}" }
                                        }
                                        button {
                                            r#type: "button",
                                            class: "shrink-0 font-mono text-xs text-ink-muted hover:text-status-conflict",
                                            onclick: {
                                                let id = cred.id.clone();
                                                move |_| {
                                                    let id = id.clone();
                                                    spawn(async move {
                                                        if request_webauthn_revoke(&id).await.is_ok() {
                                                            webauthn_credentials.restart();
                                                        }
                                                    });
                                                }
                                            },
                                            "revoke"
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

            if (*oauth_enabled.read()).unwrap_or(false) {
                h1 { class: "mt-12 font-mono text-xl font-semibold text-ink", "Linked accounts" }
                p { class: "mt-1 text-sm text-ink-muted",
                    "Link an external SSO identity to sign in without a password. This never replaces "
                    "your existing password login."
                }
                a {
                    href: "/api/auth/oauth/link",
                    class: "mt-4 inline-block border border-line px-3 py-1.5 font-mono text-sm text-ink-muted no-underline hover:text-ink",
                    "link external account"
                }
            }
        }
    }
}

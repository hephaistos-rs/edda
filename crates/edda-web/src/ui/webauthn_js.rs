//! Browser-side glue for WebAuthn ceremonies: shared by `pages::settings`
//! (registration) and `pages::login` (authentication).
//!
//! There's no `web-sys`/`wasm-bindgen` dependency anywhere in this
//! workspace, and adding one just for `navigator.credentials.create`/
//! `.get()` (two calls, used in exactly two places) would be a lot of new
//! surface for a narrow need — Dioxus's own `document::eval` bridge
//! (already how every other browser-JS interaction in this workspace
//! would be done, had any existed before this) is enough: send the
//! server's ceremony options JSON in, decode its base64url fields to
//! `ArrayBuffer`s in JS, call the real browser API, re-encode the
//! response's `ArrayBuffer`s back to base64url, and hand the result back
//! to Rust as JSON. The server's `CredentialCreationOptions`/
//! `CredentialRequestOptions` are passed through untouched (`ui/` never
//! interprets their fields, only relays them) — see `edda_auth::webauthn`
//! for what's actually inside.

#[cfg(target_arch = "wasm32")]
use dioxus::prelude::*;

#[cfg(target_arch = "wasm32")]
const B64URL_HELPERS: &str = r#"
function b64urlToBuf(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) { s += '='; }
    const bin = atob(s);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) { buf[i] = bin.charCodeAt(i); }
    return buf.buffer;
}
function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) { bin += String.fromCharCode(bytes[i]); }
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
"#;

/// Drives `navigator.credentials.create()` for a registration ceremony.
/// `options` is the server's `CredentialCreationOptions` JSON verbatim;
/// the returned value is shaped to deserialize as
/// `PublicKeyCredential<AuthenticatorAttestationResponse>` server-side.
#[cfg(target_arch = "wasm32")]
pub async fn create_credential(options: serde_json::Value) -> Result<serde_json::Value, String> {
    let script = format!(
        r#"{B64URL_HELPERS}
        const wrapper = await dioxus.recv();
        const options = wrapper.publicKey;
        options.challenge = b64urlToBuf(options.challenge);
        options.user.id = b64urlToBuf(options.user.id);
        if (options.excludeCredentials) {{
            for (const c of options.excludeCredentials) {{ c.id = b64urlToBuf(c.id); }}
        }}
        try {{
            const cred = await navigator.credentials.create({{ publicKey: options }});
            dioxus.send({{
                ok: true,
                id: cred.id,
                rawId: bufToB64url(cred.rawId),
                type: cred.type,
                response: {{
                    clientDataJSON: bufToB64url(cred.response.clientDataJSON),
                    attestationObject: bufToB64url(cred.response.attestationObject),
                    authenticatorData: bufToB64url(cred.response.getAuthenticatorData()),
                    publicKey: null,
                    publicKeyAlgorithm: cred.response.getPublicKeyAlgorithm
                        ? cred.response.getPublicKeyAlgorithm()
                        : -7,
                }},
            }});
        }} catch (e) {{
            dioxus.send({{ ok: false, error: String(e) }});
        }}"#
    );
    let mut eval = document::eval(&script);
    eval.send(options).map_err(|err| err.to_string())?;
    let result: serde_json::Value = eval.recv().await.map_err(|err| err.to_string())?;
    unwrap_js_result(result)
}

/// Drives `navigator.credentials.get()` for an authentication ceremony.
/// `options` is the server's `CredentialRequestOptions` JSON verbatim;
/// the returned value is shaped to deserialize as
/// `PublicKeyCredential<AuthenticatorAssertionResponse>` server-side.
#[cfg(target_arch = "wasm32")]
pub async fn get_credential(options: serde_json::Value) -> Result<serde_json::Value, String> {
    let script = format!(
        r#"{B64URL_HELPERS}
        const wrapper = await dioxus.recv();
        const options = wrapper.publicKey;
        options.challenge = b64urlToBuf(options.challenge);
        if (options.allowCredentials) {{
            for (const c of options.allowCredentials) {{ c.id = b64urlToBuf(c.id); }}
        }}
        try {{
            const cred = await navigator.credentials.get({{ publicKey: options }});
            dioxus.send({{
                ok: true,
                id: cred.id,
                rawId: bufToB64url(cred.rawId),
                type: cred.type,
                response: {{
                    clientDataJSON: bufToB64url(cred.response.clientDataJSON),
                    authenticatorData: bufToB64url(cred.response.authenticatorData),
                    signature: bufToB64url(cred.response.signature),
                    userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
                }},
            }});
        }} catch (e) {{
            dioxus.send({{ ok: false, error: String(e) }});
        }}"#
    );
    let mut eval = document::eval(&script);
    eval.send(options).map_err(|err| err.to_string())?;
    let result: serde_json::Value = eval.recv().await.map_err(|err| err.to_string())?;
    unwrap_js_result(result)
}

/// The eval'd script always resolves (JS-side `try`/`catch`) rather than
/// rejecting, so a denied prompt or an unsupported browser comes back as
/// `{ok: false, error}` here instead of an `EvalError` — this is the one
/// place that distinction is turned into a `Result`.
#[cfg(target_arch = "wasm32")]
fn unwrap_js_result(result: serde_json::Value) -> Result<serde_json::Value, String> {
    if result.get("ok").and_then(|v| v.as_bool()) == Some(false) {
        let message = result
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("the browser rejected that passkey request");
        return Err(message.to_string());
    }
    Ok(result)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn create_credential(_options: serde_json::Value) -> Result<serde_json::Value, String> {
    Err("not available during server rendering".to_string())
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn get_credential(_options: serde_json::Value) -> Result<serde_json::Value, String> {
    Err("not available during server rendering".to_string())
}

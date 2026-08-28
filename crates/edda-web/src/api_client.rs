//! The UI's `/api/v1` HTTP client.
//!
//! On `wasm32` (the browser) this is `gloo-net` — the browser `fetch`
//! API. Requests are same-origin, so the `HttpOnly` session cookie rides
//! along automatically; the UI never sees or handles it.
//!
//! On the SSR (`server`-feature) build every call is a stub that returns
//! [`ApiError::server_side`] immediately. Server-side rendering paints a
//! shell (the pages' own "Loading…" states) and the client re-fetches
//! after hydration — the Phase-4 SSR-data decision (plan.local.md §4.11).
//! Because SSR never awaits a `use_resource` future, these stubs are only
//! ever *constructed*, never observed.

use serde::de::DeserializeOwned;
use serde::Serialize;

/// A failed `/api/v1` call — an HTTP error status (with the server's
/// `{ "error": { "message" } }` text pulled out when present) or a
/// transport/serialization failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl ApiError {
    fn transport(message: impl Into<String>) -> Self {
        Self {
            status: 0,
            message: message.into(),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn server_side() -> Self {
        Self::transport("server-side rendering does not fetch; the client will")
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

/// Percent-encode one query-string component (RFC 3986 unreserved set is
/// left as-is, everything else `%XX`). A tiny hand-roll rather than a
/// dependency — the UI only ever encodes branch names and file paths.
fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Append `?k=v&…` to `path`, dropping pairs whose value is empty. Used by
/// the browsing pages for the `branch` / `path` / `query` parameters.
#[must_use]
pub fn with_query(path: &str, params: &[(&str, &str)]) -> String {
    let pairs: Vec<String> = params
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(key, value)| format!("{key}={}", encode_component(value)))
        .collect();
    if pairs.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{}", pairs.join("&"))
    }
}

// ─────────────────────────────── wasm ─────────────────────────────────

#[cfg(target_arch = "wasm32")]
mod imp {
    use super::{ApiError, ApiResult, DeserializeOwned, Serialize};
    use gloo_net::http::{Request, RequestBuilder, Response};

    fn transport(err: gloo_net::Error) -> ApiError {
        ApiError::transport(err.to_string())
    }

    async fn handle<T: DeserializeOwned>(response: Response) -> ApiResult<T> {
        let status = response.status();
        if (200..300).contains(&status) {
            return response.json::<T>().await.map_err(transport);
        }
        let message = match response.json::<edda_api_types::ApiError>().await {
            Ok(body) => body.error.message,
            Err(_) => format!("the request failed ({status})"),
        };
        Err(ApiError { status, message })
    }

    /// A bodyless request (`GET` / bodyless `POST` / `DELETE`) — sent
    /// straight off the builder.
    async fn send_bare<T: DeserializeOwned>(builder: RequestBuilder) -> ApiResult<T> {
        handle(builder.send().await.map_err(transport)?).await
    }

    /// A JSON-body request — `RequestBuilder::json` builds the `Request`,
    /// which is then sent.
    async fn send_body<B: Serialize, T: DeserializeOwned>(
        builder: RequestBuilder,
        body: &B,
    ) -> ApiResult<T> {
        let request: Request = builder.json(body).map_err(transport)?;
        handle(request.send().await.map_err(transport)?).await
    }

    pub async fn get_json<T: DeserializeOwned>(path: &str) -> ApiResult<T> {
        send_bare(Request::get(path)).await
    }

    pub async fn post_json<B: Serialize, T: DeserializeOwned>(
        path: &str,
        body: &B,
    ) -> ApiResult<T> {
        send_body(Request::post(path), body).await
    }

    pub async fn put_json<B: Serialize, T: DeserializeOwned>(path: &str, body: &B) -> ApiResult<T> {
        send_body(Request::put(path), body).await
    }

    pub async fn patch_json<B: Serialize, T: DeserializeOwned>(
        path: &str,
        body: &B,
    ) -> ApiResult<T> {
        send_body(Request::patch(path), body).await
    }

    pub async fn post_empty<T: DeserializeOwned>(path: &str) -> ApiResult<T> {
        send_bare(Request::post(path)).await
    }

    pub async fn delete_empty<T: DeserializeOwned>(path: &str) -> ApiResult<T> {
        send_bare(Request::delete(path)).await
    }
}

// ─────────────────────────── SSR stub ─────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use super::{ApiError, ApiResult, DeserializeOwned, Serialize};

    pub async fn get_json<T: DeserializeOwned>(_path: &str) -> ApiResult<T> {
        Err(ApiError::server_side())
    }
    pub async fn post_json<B: Serialize, T: DeserializeOwned>(
        _path: &str,
        _body: &B,
    ) -> ApiResult<T> {
        Err(ApiError::server_side())
    }
    pub async fn put_json<B: Serialize, T: DeserializeOwned>(
        _path: &str,
        _body: &B,
    ) -> ApiResult<T> {
        Err(ApiError::server_side())
    }
    pub async fn patch_json<B: Serialize, T: DeserializeOwned>(
        _path: &str,
        _body: &B,
    ) -> ApiResult<T> {
        Err(ApiError::server_side())
    }
    pub async fn post_empty<T: DeserializeOwned>(_path: &str) -> ApiResult<T> {
        Err(ApiError::server_side())
    }
    pub async fn delete_empty<T: DeserializeOwned>(_path: &str) -> ApiResult<T> {
        Err(ApiError::server_side())
    }
}

pub use imp::{delete_empty, get_json, patch_json, post_empty, post_json, put_json};

/// The many write endpoints answer `null` (`Json(())`); callers that only
/// care whether it succeeded use these instead of turbofishing `::<()>`.
pub async fn post_ok<B: Serialize>(path: &str, body: &B) -> ApiResult<()> {
    post_json::<B, ()>(path, body).await
}
pub async fn put_ok<B: Serialize>(path: &str, body: &B) -> ApiResult<()> {
    put_json::<B, ()>(path, body).await
}
pub async fn patch_ok<B: Serialize>(path: &str, body: &B) -> ApiResult<()> {
    patch_json::<B, ()>(path, body).await
}
pub async fn post_empty_ok(path: &str) -> ApiResult<()> {
    post_empty::<()>(path).await
}
pub async fn delete_ok(path: &str) -> ApiResult<()> {
    delete_empty::<()>(path).await
}

//! CSRF defence for the cookie-authenticated surface: an `Origin` /
//! `Sec-Fetch-Site` check on state-changing requests that carry a session
//! cookie.
//!
//! The session cookie is `SameSite=Lax`, which already withholds it from
//! cross-site subresource and form-POST requests — the classic CSRF
//! vector. This layer is defence in depth for the cases `Lax` doesn't
//! cover on its own (a `GET`-shaped state change would, but Edda has
//! none; a same-site-but-different-origin attacker; browsers or proxies
//! that mishandle `SameSite`) and makes the guarantee explicit rather than
//! implicit in one cookie attribute.
//!
//! Scope, deliberately narrow:
//! * **Safe methods** (`GET`/`HEAD`/`OPTIONS`/`TRACE`) are never checked.
//! * A request with an `Authorization` header is a bearer-token API call —
//!   no ambient credentials, so CSRF doesn't apply; skipped.
//! * A request with **no `Cookie` header at all** is anonymous as far as
//!   this layer cares; skipped.
//! * Everything else (cookie present, state-changing, no bearer) must
//!   present an `Origin` that is same-origin or in the trusted set, or a
//!   `Sec-Fetch-Site` of `same-origin`/`none`. A request with neither
//!   header is allowed — that's a non-browser client (no CSRF surface),
//!   and `SameSite=Lax` still covers the browser case.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// The web origins a browser may send a credentialed, state-changing
/// request from. Same-origin (an `Origin` whose authority equals the
/// request's own `Host`) is always allowed; `configured` holds the
/// instance's `external_url` plus any `EDDA_TRUSTED_ORIGINS`, each
/// normalized to `scheme://host[:port]` with default ports dropped (the
/// form browsers put in the `Origin` header).
#[derive(Clone, Default)]
pub struct OriginPolicy {
    configured: Arc<Vec<String>>,
}

impl OriginPolicy {
    #[must_use]
    pub fn new(external_url: &str, trusted_origins: &[String]) -> Self {
        let mut configured = Vec::new();
        let candidates =
            std::iter::once(external_url).chain(trusted_origins.iter().map(String::as_str));
        for raw in candidates {
            if let Some(origin) = normalize_origin(raw) {
                if !configured.iter().any(|existing| existing == &origin) {
                    configured.push(origin);
                }
            }
        }
        Self {
            configured: Arc::new(configured),
        }
    }

    fn allows(&self, headers: &HeaderMap) -> bool {
        let host = headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok());

        if let Some(origin) = headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
        {
            // `Origin: null` (sandboxed iframe, some privacy modes) is not
            // a trusted origin.
            if origin.eq_ignore_ascii_case("null") {
                return false;
            }
            let Some(normalized) = normalize_origin(origin) else {
                return false;
            };
            if self
                .configured
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(&normalized))
            {
                return true;
            }
            return host.is_some_and(|host| origin_matches_host(&normalized, host));
        }

        // No `Origin` (a same-origin request on an older browser, or a
        // non-browser client): fall back to the Fetch Metadata hint if the
        // browser sent one, otherwise allow — `SameSite=Lax` is the
        // backstop and a non-browser client has no CSRF surface.
        match headers
            .get("sec-fetch-site")
            .and_then(|value| value.to_str().ok())
        {
            Some(site) => matches!(site, "same-origin" | "none"),
            None => true,
        }
    }
}

/// axum middleware: enforce [`OriginPolicy`] on the cookie-authenticated,
/// state-changing subset. Wire it with
/// `axum::middleware::from_fn_with_state(policy, enforce)`.
pub async fn enforce(State(policy): State<OriginPolicy>, request: Request, next: Next) -> Response {
    if is_safe_method(request.method()) || !is_cookie_authenticated(request.headers()) {
        return next.run(request).await;
    }
    if policy.allows(request.headers()) {
        return next.run(request).await;
    }
    (
        StatusCode::FORBIDDEN,
        "cross-origin request refused: the Origin/Sec-Fetch-Site of this \
         cookie-authenticated request is not trusted",
    )
        .into_response()
}

fn is_safe_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

/// A request the CSRF check applies to: it carries a `Cookie` (so a
/// session could ride along) and *no* `Authorization` header (a bearer
/// call brings its own non-ambient credential and needs no CSRF check).
fn is_cookie_authenticated(headers: &HeaderMap) -> bool {
    headers.contains_key(header::COOKIE) && !headers.contains_key(header::AUTHORIZATION)
}

/// Strip a scheme's default port and any path/query so `https://x/y` and
/// `https://x:443` both become `https://x`. `None` for anything that
/// isn't an `http`/`https` URL.
fn normalize_origin(raw: &str) -> Option<String> {
    let url = reqwest::Url::parse(raw.trim()).ok()?;
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let host = url.host_str()?;
    match url.port() {
        Some(port) => Some(format!("{scheme}://{host}:{port}")),
        None => Some(format!("{scheme}://{host}")),
    }
}

/// Whether a normalized `Origin` (`scheme://host[:port]`) is same-origin
/// with the request's `Host` header — scheme-agnostic, since a
/// reverse-proxied server can't reliably know its own external scheme
/// from the request alone.
fn origin_matches_host(normalized_origin: &str, host_header: &str) -> bool {
    let origin_authority = normalized_origin
        .split_once("://")
        .map_or(normalized_origin, |(_, rest)| rest);
    let strip_default = |authority: &str| -> String {
        authority
            .trim_end_matches(":443")
            .trim_end_matches(":80")
            .to_string()
    };
    origin_authority.eq_ignore_ascii_case(host_header)
        || strip_default(origin_authority).eq_ignore_ascii_case(&strip_default(host_header))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn normalize_drops_default_ports_and_paths() {
        assert_eq!(
            normalize_origin("https://git.example.com/"),
            Some("https://git.example.com".to_string())
        );
        assert_eq!(
            normalize_origin("https://git.example.com:443"),
            Some("https://git.example.com".to_string())
        );
        assert_eq!(
            normalize_origin("http://127.0.0.1:8080"),
            Some("http://127.0.0.1:8080".to_string())
        );
        assert_eq!(normalize_origin("ftp://x"), None);
    }

    #[test]
    fn same_origin_request_is_allowed_with_no_configuration() {
        let policy = OriginPolicy::default();
        assert!(policy.allows(&headers(&[
            ("host", "127.0.0.1:8080"),
            ("origin", "http://127.0.0.1:8080"),
        ])));
    }

    #[test]
    fn a_cross_origin_request_is_refused() {
        let policy = OriginPolicy::default();
        assert!(!policy.allows(&headers(&[
            ("host", "git.example.com"),
            ("origin", "https://evil.example"),
        ])));
    }

    #[test]
    fn a_configured_trusted_origin_is_allowed() {
        let policy = OriginPolicy::new(
            "https://git.example.com",
            &["https://app.example.com".to_string()],
        );
        assert!(policy.allows(&headers(&[
            ("host", "git.example.com"),
            ("origin", "https://app.example.com"),
        ])));
        assert!(!policy.allows(&headers(&[
            ("host", "git.example.com"),
            ("origin", "https://other.example.com"),
        ])));
    }

    #[test]
    fn sec_fetch_site_is_the_fallback_when_no_origin_header_is_present() {
        let policy = OriginPolicy::default();
        assert!(policy.allows(&headers(&[("sec-fetch-site", "same-origin")])));
        assert!(policy.allows(&headers(&[("sec-fetch-site", "none")])));
        assert!(!policy.allows(&headers(&[("sec-fetch-site", "cross-site")])));
    }

    #[test]
    fn no_origin_and_no_fetch_metadata_is_allowed_non_browser_client() {
        let policy = OriginPolicy::default();
        assert!(policy.allows(&headers(&[("host", "git.example.com")])));
    }

    #[test]
    fn origin_literally_null_is_never_trusted() {
        let policy = OriginPolicy::default();
        assert!(!policy.allows(&headers(&[("host", "git.example.com"), ("origin", "null")])));
    }

    #[test]
    fn bearer_requests_are_out_of_scope() {
        assert!(!is_cookie_authenticated(&headers(&[
            ("cookie", "id=abc"),
            ("authorization", "Bearer tok"),
        ])));
        assert!(is_cookie_authenticated(&headers(&[("cookie", "id=abc")])));
        assert!(!is_cookie_authenticated(&headers(&[])));
    }
}

//! General API rate limiting — a key-based token-bucket middleware over
//! `governor`/`tower_governor`, applied to every route in
//! [`crate::router`] *except* the git smart-HTTP bridge (`git_http`) and
//! Git LFS (`lfs`): throttling legitimate `git clone`/`git push`/LFS
//! transfer traffic, which routinely issues several requests in quick
//! succession as a normal, non-abusive part of the protocol, would be a
//! git-compatibility hazard. Everything else — auth,
//! OAuth/WebAuthn, collaborator/SSH-key management, admin, release
//! assets, and the versioned `/api/v1/` surface — shares one limiter.
//!
//! **Key extraction, and why it isn't `tower_governor`'s own
//! `PeerIpKeyExtractor`/`SmartIpKeyExtractor`**: both of those extractors
//! ultimately fall back to `axum::extract::ConnectInfo<SocketAddr>`, which
//! is only populated when the server is bound via `Router::
//! into_make_service_with_connect_info`. `edda-web`'s composition root
//! hands its merged router to `dioxus::server::serve`, which — confirmed
//! directly against `dioxus-server` 0.7.10's own `launch.rs`, not assumed
//! — calls `axum::serve`/`.into_make_service()` on a plain `Router` in
//! both debug and release builds, so `ConnectInfo` is never available
//! here, in production or in this crate's own integration tests (which
//! bind a real `TcpListener` and call `axum::serve` the same plain way).
//! `EddaKeyExtractor` below reads `Forwarded` (RFC 7239) / `X-Forwarded-For`
//! / `X-Real-IP` instead — correct for the common "self-hosted,
//! reverse-proxied" deployment shape (the proxy sets one of these) — and
//! falls back to a single shared bucket for direct, unproxied traffic
//! rather than failing every request outright, so the
//! no-mandatory-external-services standalone deployment path (`AGENTS.md`'s
//! dependency principle) still starts and serves traffic normally.
//!
//! **Forwarded headers are trusted only when `EDDA_TRUSTED_PROXIES` is
//! non-empty** (S4). Without it, every direct client shares one bucket
//! regardless of what `X-Forwarded-For` it sends — a spoofed header can no
//! longer hand an attacker a private per-key budget. Actually matching the
//! *peer* IP against the configured CIDRs needs `ConnectInfo`, which this
//! serve loop doesn't provide until Phase 13; until then a non-empty list
//! is simply the operator's assertion that "there is a trusted proxy in
//! front, honour its forwarded hop."

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use axum::http::{HeaderMap, Request};
use governor::clock::QuantaInstant;
use governor::middleware::NoOpMiddleware;
use tower_governor::errors::GovernorError;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::KeyExtractor;
use tower_governor::GovernorLayer;

/// The shared bucket every request with no identifiable client IP falls
/// into — see this module's doc comment.
const ANONYMOUS_BUCKET: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

#[derive(Debug, Clone, Copy)]
pub struct EddaKeyExtractor {
    /// Whether `EDDA_TRUSTED_PROXIES` is configured — the gate on reading
    /// any client-supplied forwarding header.
    trust_forwarded: bool,
}

impl KeyExtractor for EddaKeyExtractor {
    type Key = IpAddr;

    fn extract<B>(&self, req: &Request<B>) -> Result<Self::Key, GovernorError> {
        let ip = if self.trust_forwarded {
            client_ip(req.headers())
        } else {
            None
        };
        Ok(ip.unwrap_or(ANONYMOUS_BUCKET))
    }

    fn key_name(&self, key: &Self::Key) -> Option<String> {
        Some(key.to_string())
    }

    fn name(&self) -> &'static str {
        "client-ip"
    }
}

/// The client IP from a forwarding header, checked in the order a
/// standards-aware proxy sets them: `Forwarded` (RFC 7239) `for=` of the
/// first hop, then `X-Forwarded-For`'s left-most hop, then `X-Real-IP`.
/// Only consulted when `EDDA_TRUSTED_PROXIES` is set (see the module doc) —
/// otherwise these are attacker-controlled.
pub(crate) fn client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    if let Some(ip) = headers
        .get("forwarded")
        .and_then(|value| value.to_str().ok())
        .and_then(first_forwarded_for)
    {
        return Some(ip);
    }
    if let Some(ip) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|first| first.trim().parse().ok())
    {
        return Some(ip);
    }
    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse().ok())
}

/// The `for=` identifier of the first hop in an RFC 7239 `Forwarded`
/// header, as an `IpAddr`. Handles the quoted `for="[2001:db8::1]:41237"`
/// and bare `for=192.0.2.60` forms; `for=unknown` / `for=_obfuscated`
/// yield `None`.
fn first_forwarded_for(value: &str) -> Option<IpAddr> {
    let first_hop = value.split(',').next()?;
    for pair in first_hop.split(';') {
        let (key, val) = pair.split_once('=')?;
        if !key.trim().eq_ignore_ascii_case("for") {
            continue;
        }
        let val = val.trim().trim_matches('"');
        let host = if let Some(rest) = val.strip_prefix('[') {
            // `[2001:db8::1]:41237` — everything between the brackets.
            rest.split_once(']').map_or(rest, |(inner, _)| inner)
        } else if let Some((h, port)) = val.rsplit_once(':') {
            // `192.0.2.60:8080` — a single colon means host:port for IPv4;
            // a bare IPv6 literal has several colons and no port here.
            if !h.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
                h
            } else {
                val
            }
        } else {
            val
        };
        return host.parse().ok();
    }
    None
}

pub type EddaGovernorLayer =
    GovernorLayer<EddaKeyExtractor, NoOpMiddleware<QuantaInstant>, axum::body::Body>;

/// Builds the rate-limiting layer and spawns its periodic cleanup task
/// (`tower_governor`'s own documented recommendation: without it, every
/// distinct key this process has ever seen stays resident in memory for
/// the life of the process). Called once per [`crate::router`] call — in
/// production that's once per process (release builds call the
/// composition root's router-building callback exactly once); in `dx
/// serve` hot-reload dev builds, which re-invoke it on every reload, each
/// reload's cleanup task keeps running against its own (by then
/// unreachable) limiter rather than being cancelled — a small, bounded,
/// dev-only resource lingerer, not a production concern, and not worth
/// the composition-root API change (hoisting this above the per-`router()`
/// -call boundary, unlike `edda_jobs::spawn_poller` which already lives
/// there) that would be needed to close it.
pub fn layer(settings: &crate::config::RateLimitConfig) -> EddaGovernorLayer {
    build(
        settings.per_second,
        settings.burst,
        !settings.trusted_proxies.is_empty(),
    )
}

/// A **stricter** limiter for the auth endpoints (`/api/auth/*`, OAuth /
/// WebAuthn begin+verify) — `EDDA_AUTH_RATE_LIMIT_*`, which default well
/// below the general bucket. Applied via its own `route_layer` on an
/// auth-only sub-router in [`crate::router`], so an auth request is charged
/// against both this and the general bucket and the tighter one bites
/// first.
pub fn auth_layer(settings: &crate::config::RateLimitConfig) -> EddaGovernorLayer {
    build(
        settings.auth_per_second,
        settings.auth_burst,
        !settings.trusted_proxies.is_empty(),
    )
}

fn build(per_second: u64, burst: u32, trust_forwarded: bool) -> EddaGovernorLayer {
    let config = GovernorConfigBuilder::default()
        .per_second(per_second)
        .burst_size(burst)
        .key_extractor(EddaKeyExtractor { trust_forwarded })
        .finish()
        .expect("a RateLimitConfig validated by edda_app::config produces a valid governor config");

    let limiter = config.limiter().clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            limiter.retain_recent();
        }
    });

    GovernorLayer::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with(name: &'static str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn extracts_the_first_hop_of_x_forwarded_for() {
        let headers = headers_with("x-forwarded-for", "203.0.113.7, 10.0.0.1");
        assert_eq!(client_ip(&headers), Some("203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn falls_back_to_x_real_ip_when_forwarded_for_is_absent() {
        let headers = headers_with("x-real-ip", "203.0.113.9");
        assert_eq!(client_ip(&headers), Some("203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn returns_none_with_no_identifying_header_at_all() {
        assert_eq!(client_ip(&HeaderMap::new()), None);
    }

    #[test]
    fn a_malformed_header_value_is_ignored_not_panicked_on() {
        let headers = headers_with("x-forwarded-for", "not-an-ip-address");
        assert_eq!(client_ip(&headers), None);
    }

    #[test]
    fn parses_the_first_for_of_an_rfc7239_forwarded_header() {
        let headers = headers_with(
            "forwarded",
            "for=192.0.2.60;proto=http;by=203.0.113.43, for=198.51.100.17",
        );
        assert_eq!(client_ip(&headers), Some("192.0.2.60".parse().unwrap()));
    }

    #[test]
    fn parses_a_quoted_bracketed_ipv6_forwarded_for_with_a_port() {
        let headers = headers_with("forwarded", r#"For="[2001:db8:cafe::17]:4711""#);
        assert_eq!(
            client_ip(&headers),
            Some("2001:db8:cafe::17".parse().unwrap())
        );
    }

    #[test]
    fn an_obfuscated_forwarded_identifier_yields_no_ip() {
        let headers = headers_with("forwarded", "for=_hidden;proto=https");
        assert_eq!(client_ip(&headers), None);
    }

    #[test]
    fn the_key_extractor_never_errors_even_with_no_identifying_header() {
        let req = Request::builder().body(()).unwrap();
        let extractor = EddaKeyExtractor {
            trust_forwarded: true,
        };
        assert_eq!(extractor.extract(&req).unwrap(), ANONYMOUS_BUCKET);
    }

    #[test]
    fn an_untrusting_extractor_ignores_a_spoofable_forwarded_header() {
        let mut req = Request::builder().body(()).unwrap();
        req.headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
        let untrusting = EddaKeyExtractor {
            trust_forwarded: false,
        };
        assert_eq!(untrusting.extract(&req).unwrap(), ANONYMOUS_BUCKET);
        let trusting = EddaKeyExtractor {
            trust_forwarded: true,
        };
        assert_eq!(
            trusting.extract(&req).unwrap(),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }
}

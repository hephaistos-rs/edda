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
//! **Key extraction (`EddaKeyExtractor`).** The composition-root binary
//! owns `axum::serve` and binds the router with
//! `into_make_service_with_connect_info::<SocketAddr>()` (Phase 13), so
//! the real socket peer IP is available here as
//! `axum::extract::ConnectInfo<SocketAddr>`. The default key is that peer
//! IP.
//!
//! A `Forwarded` (RFC 7239) / `X-Forwarded-For` / `X-Real-IP` header is
//! honoured **only when the peer IP is itself inside one of the
//! `EDDA_TRUSTED_PROXIES` CIDRs** (S4) — i.e. the request genuinely came
//! from a configured reverse proxy. A direct client's spoofed forwarding
//! header is ignored: it just gets keyed on its own peer IP. With no
//! trusted proxies configured (the standalone default), every request is
//! keyed purely on its peer IP.
//!
//! If `ConnectInfo` is somehow absent (a serve loop that didn't opt in, a
//! unit test with a bare `Request`), the request falls into one shared
//! bucket rather than failing outright, so the no-mandatory-external-
//! services standalone path (`AGENTS.md`'s dependency principle) still
//! serves traffic.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ConnectInfo;
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

#[derive(Debug, Clone)]
pub struct EddaKeyExtractor {
    /// `EDDA_TRUSTED_PROXIES` — the CIDRs a forwarding header is believed
    /// from. A header is only read when the *peer* IP falls inside one of
    /// these; empty means "no proxy in front," so headers are never read.
    trusted_proxies: Arc<[ipnet::IpNet]>,
}

impl KeyExtractor for EddaKeyExtractor {
    type Key = IpAddr;

    fn extract<B>(&self, req: &Request<B>) -> Result<Self::Key, GovernorError> {
        // The socket peer IP, from `into_make_service_with_connect_info`.
        let Some(peer_ip) = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
        else {
            // No `ConnectInfo` at all — one shared bucket, never a
            // per-request failure.
            return Ok(ANONYMOUS_BUCKET);
        };

        // Only a request that actually arrived from a configured proxy may
        // speak for a different client via a forwarding header.
        if self
            .trusted_proxies
            .iter()
            .any(|net| net.contains(&peer_ip))
        {
            if let Some(client_ip) = client_ip(req.headers()) {
                return Ok(client_ip);
            }
        }
        Ok(peer_ip)
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
/// the life of the process). Called once per [`crate::router`] call —
/// the composition root builds the router exactly once per process, so in
/// production that is one cleanup task for the life of the process.
pub fn layer(settings: &crate::config::RateLimitConfig) -> EddaGovernorLayer {
    build(
        settings.per_second,
        settings.burst,
        settings.trusted_proxies.as_slice().into(),
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
        settings.trusted_proxies.as_slice().into(),
    )
}

fn build(per_second: u64, burst: u32, trusted_proxies: Arc<[ipnet::IpNet]>) -> EddaGovernorLayer {
    let config = GovernorConfigBuilder::default()
        .per_second(per_second)
        .burst_size(burst)
        .key_extractor(EddaKeyExtractor { trusted_proxies })
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

    fn extractor(trusted_proxies: &[&str]) -> EddaKeyExtractor {
        EddaKeyExtractor {
            trusted_proxies: trusted_proxies
                .iter()
                .map(|cidr| cidr.parse::<ipnet::IpNet>().unwrap())
                .collect(),
        }
    }

    fn request(peer: Option<&str>, header: Option<(&'static str, &str)>) -> Request<()> {
        let mut req = Request::builder().body(()).unwrap();
        if let Some(peer) = peer {
            req.extensions_mut()
                .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        }
        if let Some((name, value)) = header {
            req.headers_mut()
                .insert(name, HeaderValue::from_str(value).unwrap());
        }
        req
    }

    #[test]
    fn keys_on_the_socket_peer_ip_by_default() {
        let req = request(Some("203.0.113.5:44321"), None);
        assert_eq!(
            extractor(&[]).extract(&req).unwrap(),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn a_direct_client_cannot_spoof_a_forwarding_header() {
        // Peer is not inside any trusted-proxy CIDR, so the header it sent
        // is ignored — it is keyed on its own peer IP.
        let req = request(
            Some("203.0.113.5:1"),
            Some(("x-forwarded-for", "198.51.100.9")),
        );
        assert_eq!(
            extractor(&["10.0.0.0/8"]).extract(&req).unwrap(),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn honours_the_forwarded_client_ip_from_a_trusted_proxy() {
        let req = request(
            Some("203.0.113.5:1"),
            Some(("x-forwarded-for", "198.51.100.9, 203.0.113.5")),
        );
        assert_eq!(
            extractor(&["203.0.113.0/24"]).extract(&req).unwrap(),
            "198.51.100.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn a_trusted_proxy_with_no_forwarding_header_is_keyed_on_the_proxy_peer_ip() {
        let req = request(Some("203.0.113.5:1"), None);
        assert_eq!(
            extractor(&["203.0.113.0/24"]).extract(&req).unwrap(),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn falls_into_one_shared_bucket_when_connect_info_is_absent() {
        let req = request(None, Some(("x-forwarded-for", "203.0.113.7")));
        assert_eq!(extractor(&[]).extract(&req).unwrap(), ANONYMOUS_BUCKET);
        assert_eq!(
            extractor(&["0.0.0.0/0"]).extract(&req).unwrap(),
            ANONYMOUS_BUCKET
        );
    }
}

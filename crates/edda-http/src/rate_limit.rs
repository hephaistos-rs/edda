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
//! `EddaKeyExtractor` below reads `X-Forwarded-For`/`X-Real-IP` instead —
//! correct for the common "self-hosted, reverse-proxied" deployment shape
//! (the proxy sets one of these) — and falls back to a single shared
//! bucket for direct, unproxied traffic rather than failing every request
//! outright, so the no-mandatory-external-services standalone deployment
//! path (`AGENTS.md`'s dependency principle) still starts and serves
//! traffic normally; it's simply coarser (every unidentified client
//! shares one budget) until a reverse proxy is added in front.

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
pub struct EddaKeyExtractor;

impl KeyExtractor for EddaKeyExtractor {
    type Key = IpAddr;

    fn extract<B>(&self, req: &Request<B>) -> Result<Self::Key, GovernorError> {
        Ok(client_ip(req.headers()).unwrap_or(ANONYMOUS_BUCKET))
    }

    fn key_name(&self, key: &Self::Key) -> Option<String> {
        Some(key.to_string())
    }

    fn name(&self) -> &'static str {
        "client-ip"
    }
}

/// `X-Forwarded-For` (its first, left-most hop — the original client, per
/// the header's own de-facto convention) then `X-Real-IP`, matching the
/// two proxy headers `tower_governor::key_extractor::SmartIpKeyExtractor`
/// itself checks first, before its `Forwarded`/`ConnectInfo` fallbacks
/// (neither reachable from this deployment — see this module's doc
/// comment). Either header is attacker-controlled unless a trusted
/// reverse proxy overwrites it before forwarding the request — the same
/// trust assumption every rate limiter keyed on these headers makes, not
/// specific to this implementation.
fn client_ip(headers: &HeaderMap) -> Option<IpAddr> {
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

/// Read from `EDDA_RATE_LIMIT_PER_SECOND`/`EDDA_RATE_LIMIT_BURST`
/// (deployment configuration, per `AGENTS.md`'s convention — never a
/// source change to retune), falling back to a default generous enough
/// for normal interactive use (loading a page that fans out to several
/// `/api/v1/` calls at once) while still bounding a single client's
/// sustained request rate.
fn env_setting(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&value| value > 0)
        .unwrap_or(default)
}

const DEFAULT_PER_SECOND: u64 = 5;
const DEFAULT_BURST_SIZE: u64 = 20;

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
pub fn layer() -> EddaGovernorLayer {
    let per_second = env_setting("EDDA_RATE_LIMIT_PER_SECOND", DEFAULT_PER_SECOND);
    let burst_size = env_setting("EDDA_RATE_LIMIT_BURST", DEFAULT_BURST_SIZE);

    let config = GovernorConfigBuilder::default()
        .per_second(per_second)
        .burst_size(burst_size as u32)
        .key_extractor(EddaKeyExtractor)
        .finish()
        .expect("EDDA_RATE_LIMIT_PER_SECOND/EDDA_RATE_LIMIT_BURST produce a valid governor config");

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
    fn the_key_extractor_never_errors_even_with_no_identifying_header() {
        let req = Request::builder().body(()).unwrap();
        assert_eq!(EddaKeyExtractor.extract(&req).unwrap(), ANONYMOUS_BUCKET);
    }
}

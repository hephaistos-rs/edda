//! SSRF mitigation for outgoing webhook targets: resolves a target URL's
//! host and validates every resolved address
//! against `edda_domain::is_blocked_ip`. Called independently at *both*
//! webhook-creation time (`webhook_server::create_webhook`) and delivery
//! time (`job_handlers::deliver_webhook`) — a target that resolves to a
//! public IP at creation and a private one by the time delivery actually
//! happens (DNS rebinding) is only caught because delivery re-resolves
//! and re-checks, rather than trusting a cached creation-time result.

use std::net::SocketAddr;

#[derive(Debug, thiserror::Error)]
pub enum SsrfError {
    #[error("the target URL must be http or https")]
    UnsupportedScheme,
    #[error("the target URL has no resolvable host")]
    NoHost,
    #[error("could not resolve the target host")]
    ResolutionFailed,
    #[error(
        "the target resolves to a private, loopback, link-local, or otherwise disallowed address"
    )]
    Blocked,
}

/// Validates `url` and returns one resolved `(host, addr)` pair a caller
/// can pin an HTTP client to via `reqwest::ClientBuilder::resolve` — that
/// pinning is what makes the delivery-time call actually meaningful:
/// letting the HTTP client re-resolve the host itself, after this
/// function already validated a (possibly different, by then) address,
/// would reopen exactly the rebinding gap this exists to close.
pub async fn resolve_and_check(url: &str) -> Result<(String, SocketAddr), SsrfError> {
    let parsed = reqwest::Url::parse(url).map_err(|_| SsrfError::NoHost)?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(SsrfError::UnsupportedScheme);
    }
    let host = parsed.host_str().ok_or(SsrfError::NoHost)?.to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or(SsrfError::UnsupportedScheme)?;

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|_| SsrfError::ResolutionFailed)?
        .collect();
    let Some(first) = addrs.first().copied() else {
        return Err(SsrfError::ResolutionFailed);
    };
    if addrs
        .iter()
        .any(|addr| edda_domain::is_blocked_ip(addr.ip()))
    {
        return Err(SsrfError::Blocked);
    }
    Ok((host, first))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_loopback_ip_literal_target_is_blocked_without_any_dns_lookup() {
        let err = resolve_and_check("http://127.0.0.1:9999/hook")
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::Blocked));
    }

    #[tokio::test]
    async fn a_private_ipv4_literal_target_is_blocked() {
        let err = resolve_and_check("http://10.0.0.5/hook").await.unwrap_err();
        assert!(matches!(err, SsrfError::Blocked));
    }

    #[tokio::test]
    async fn a_non_http_scheme_is_rejected() {
        let err = resolve_and_check("ftp://example.com/hook")
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::UnsupportedScheme));
    }

    #[tokio::test]
    async fn localhost_by_name_resolves_and_is_blocked_the_same_as_the_ip_literal() {
        // `localhost` resolves via the system resolver (no network access
        // needed — every OS answers this from `/etc/hosts`-equivalent
        // config), exercising the actual resolve-then-check path this
        // function is for, not just the loopback-IP-literal shortcut.
        let err = resolve_and_check("http://localhost:9999/hook")
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::Blocked));
    }
}

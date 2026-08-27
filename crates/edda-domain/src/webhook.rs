//! Webhooks: a repository-scoped subscription to a small, closed set of
//! domain events, delivered as an HMAC-signed HTTP POST. This module holds
//! the data shape and the one pure, security-relevant decision that
//! doesn't need any I/O to make: whether a resolved delivery-target IP
//! address is one Edda must refuse to connect to at all (`is_blocked_ip`).
//! Everything else — DNS resolution, the HTTP request itself, HMAC
//! signing with the (encrypted-at-rest) secret — is I/O and lives in
//! `edda-web`'s job handlers, not here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::ids::{RepositoryId, WebhookDeliveryId, WebhookId};

/// Deliberately a small, closed set — extended additively as real
/// consumers need more events, never a stringly-typed catch-all. Stored as
/// a JSON array column (`webhooks.events`), per this workspace's own
/// enum-representation rule (small/closed → `TEXT`+`CHECK`,
/// set-valued/extensible → `JSON`) — a webhook's event subscription is
/// exactly the set-valued case that rule calls out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEvent {
    PullRequestOpened,
    PullRequestMerged,
    IssueOpened,
    IssueCommented,
    Push,
}

impl WebhookEvent {
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            WebhookEvent::PullRequestOpened => "pull_request.opened",
            WebhookEvent::PullRequestMerged => "pull_request.merged",
            WebhookEvent::IssueOpened => "issue.opened",
            WebhookEvent::IssueCommented => "issue.commented",
            WebhookEvent::Push => "push",
        }
    }

    pub fn from_wire_str(value: &str) -> Option<Self> {
        match value {
            "pull_request.opened" => Some(WebhookEvent::PullRequestOpened),
            "pull_request.merged" => Some(WebhookEvent::PullRequestMerged),
            "issue.opened" => Some(WebhookEvent::IssueOpened),
            "issue.commented" => Some(WebhookEvent::IssueCommented),
            "push" => Some(WebhookEvent::Push),
            _ => None,
        }
    }
}

/// A repository's subscription to a target URL. The signing secret is
/// deliberately *not* a field here: it's shown once at creation (the same
/// "shown once, only ever handled again through a dedicated recovery path"
/// pattern already used for PATs), encrypted at rest (`edda_auth::
/// secret_box`), and only ever decrypted again inside the delivery job
/// handler that needs to sign an outgoing payload with it — a `Webhook`
/// value read for display/listing has no business carrying it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Webhook {
    pub id: WebhookId,
    pub repository_id: RepositoryId,
    pub target_url: String,
    pub events: Vec<WebhookEvent>,
    pub active: bool,
    pub created_at: i64,
}

impl Webhook {
    pub fn is_subscribed_to(&self, event: WebhookEvent) -> bool {
        self.active && self.events.contains(&event)
    }
}

/// One delivery attempt's record — this *is* the job-execution record,
/// modeled here because it's also directly user-visible ("recent
/// deliveries") and queried independently of the job queue's own
/// bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookDelivery {
    pub id: WebhookDeliveryId,
    pub webhook_id: WebhookId,
    pub event: WebhookEvent,
    pub payload: String,
    pub response_status: Option<i32>,
    pub attempt_count: i32,
    pub delivered_at: Option<i64>,
    pub created_at: i64,
}

/// Whether `ip` is a delivery target Edda must refuse — loopback,
/// link-local, private-CIDR, unspecified, multicast, CGNAT, and IPv6
/// unique-local/link-local equivalents, directly modeling Forgejo's
/// confirmed `ALLOWED_HOST_LIST` deny-by-default posture. Called *both* at
/// webhook-creation time and, independently, at delivery time on a fresh
/// resolution — a target that resolves to a public IP at creation and a
/// private one by the time delivery actually happens (DNS rebinding) must
/// be caught by the delivery-time call, not only the creation-time one;
/// see `edda_web`'s webhook-delivery job handler for where that second
/// call lives.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => is_blocked_ipv6(v6),
    }
}

fn is_blocked_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_loopback()
        || ip.is_link_local()
        || ip.is_private()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
    {
        return true;
    }
    // 100.64.0.0/10 — carrier-grade NAT (RFC 6598). Not classified by any
    // `std::net::Ipv4Addr` helper, so checked directly.
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
}

fn is_blocked_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_blocked_ipv4(v4);
    }
    let segments = ip.segments();
    // fe80::/10 — link-local.
    let is_link_local = (segments[0] & 0xffc0) == 0xfe80;
    // fc00::/7 — unique local addresses (the IPv6 analogue of RFC 1918).
    let is_unique_local = (segments[0] & 0xfe00) == 0xfc00;
    is_link_local || is_unique_local
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_event_round_trips_through_its_wire_string() {
        for event in [
            WebhookEvent::PullRequestOpened,
            WebhookEvent::PullRequestMerged,
            WebhookEvent::IssueOpened,
            WebhookEvent::IssueCommented,
            WebhookEvent::Push,
        ] {
            assert_eq!(
                WebhookEvent::from_wire_str(event.as_wire_str()),
                Some(event)
            );
        }
        assert_eq!(WebhookEvent::from_wire_str("bogus"), None);
    }

    #[test]
    fn an_inactive_or_unsubscribed_webhook_is_not_notified() {
        let webhook = Webhook {
            id: WebhookId::new(),
            repository_id: RepositoryId::new(),
            target_url: "https://example.com/hook".to_string(),
            events: vec![WebhookEvent::PullRequestMerged],
            active: true,
            created_at: 0,
        };
        assert!(webhook.is_subscribed_to(WebhookEvent::PullRequestMerged));
        assert!(!webhook.is_subscribed_to(WebhookEvent::IssueOpened));

        let inactive = Webhook {
            active: false,
            ..webhook
        };
        assert!(!inactive.is_subscribed_to(WebhookEvent::PullRequestMerged));
    }

    #[test]
    fn loopback_and_unspecified_v4_targets_are_blocked() {
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn private_cidr_v4_ranges_are_blocked() {
        assert!(is_blocked_ip("10.0.0.5".parse().unwrap()));
        assert!(is_blocked_ip("172.16.0.5".parse().unwrap()));
        assert!(is_blocked_ip("192.168.1.5".parse().unwrap()));
        assert!(is_blocked_ip("169.254.1.1".parse().unwrap()));
    }

    #[test]
    fn carrier_grade_nat_range_is_blocked() {
        assert!(is_blocked_ip("100.64.0.1".parse().unwrap()));
        assert!(is_blocked_ip("100.100.0.1".parse().unwrap()));
        // Just outside the /10 on either side must not be blocked by this
        // rule (they may or may not be public, but this specific rule
        // shouldn't over-match).
        assert!(!is_blocked_ip("100.63.255.255".parse().unwrap()));
        assert!(!is_blocked_ip("100.128.0.0".parse().unwrap()));
    }

    #[test]
    fn a_real_public_v4_address_is_allowed() {
        assert!(!is_blocked_ip("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn ipv6_loopback_link_local_and_unique_local_are_blocked() {
        assert!(is_blocked_ip("::1".parse().unwrap()));
        assert!(is_blocked_ip("fe80::1".parse().unwrap()));
        assert!(is_blocked_ip("fc00::1".parse().unwrap()));
        assert!(is_blocked_ip("fd12:3456:789a::1".parse().unwrap()));
    }

    #[test]
    fn an_ipv4_mapped_ipv6_loopback_is_blocked() {
        // ::ffff:127.0.0.1 — the IPv4-mapped form a rebinding attacker
        // could return from an AAAA record instead of an A one.
        assert!(is_blocked_ip("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn a_real_public_v6_address_is_allowed() {
        assert!(!is_blocked_ip(
            "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()
        ));
    }
}

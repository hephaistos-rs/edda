//! The actual `edda-jobs` handler *logic* — "send this webhook," "send
//! this email," "create this notification" — registered into a
//! `HandlerRegistry` by `main.rs`'s composition root. Defined here, not
//! inside `edda-jobs` itself, because these need `edda-auth` (secret
//! decryption, HMAC signing) and an HTTP client, which `edda-jobs`
//! deliberately never depends on — see that crate's own `Cargo.toml` doc
//! comment.

use std::time::Duration;

use lettre::{AsyncTransport, Tokio1Executor};

use edda_db::DbPool;
use edda_domain::{JobPayload, WebhookDeliveryId};

/// SMTP delivery, configured from `edda_http::config`'s `SmtpConfig`
/// (`EDDA_SMTP_URL`/`EDDA_SMTP_FROM`). Both unset (the default) is a
/// supported, first-class standalone configuration, not a degraded one —
/// `send_email` simply logs and no-ops rather than failing when this is
/// `None`, so nothing in this workspace *requires* SMTP to run
/// (`AGENTS.md`'s "optional but first-class" framing applied here exactly
/// as it already is to PostgreSQL/MySQL).
pub struct Mailer {
    transport: lettre::AsyncSmtpTransport<Tokio1Executor>,
    from: lettre::message::Mailbox,
}

impl Mailer {
    /// Builds a mailer from a validated `SmtpConfig`. Returns `Err` with a
    /// human-readable reason if the URL or From mailbox don't parse — the
    /// composition root surfaces that as a startup failure rather than
    /// silently disabling email.
    pub fn new(config: &edda_http::config::SmtpConfig) -> Result<Self, String> {
        let from: lettre::message::Mailbox = config
            .from
            .parse()
            .map_err(|e| format!("EDDA_SMTP_FROM is not a valid mailbox: {e}"))?;
        let transport = lettre::AsyncSmtpTransport::<Tokio1Executor>::from_url(&config.url)
            .map_err(|e| format!("EDDA_SMTP_URL is not a valid SMTP URL: {e}"))?
            .build();
        Ok(Self { transport, from })
    }

    async fn send(&self, to: &str, subject: &str, body_text: &str) -> Result<(), String> {
        let to_mailbox: lettre::message::Mailbox = to
            .parse()
            .map_err(|err: lettre::address::AddressError| err.to_string())?;
        let email = lettre::Message::builder()
            .from(self.from.clone())
            .to(to_mailbox)
            .subject(subject)
            .body(body_text.to_string())
            .map_err(|err| err.to_string())?;
        self.transport
            .send(email)
            .await
            .map(|_| ())
            .map_err(|err| err.to_string())
    }
}

pub async fn send_email(
    mailer: Option<std::sync::Arc<Mailer>>,
    payload: JobPayload,
) -> Result<(), String> {
    let JobPayload::SendEmail {
        to_email,
        subject,
        body_text,
    } = payload
    else {
        return Err("wrong payload kind routed to the send_email handler".to_string());
    };
    match mailer {
        Some(mailer) => mailer.send(&to_email, &subject, &body_text).await,
        None => {
            tracing::debug!(
                to = %to_email,
                "EDDA_SMTP_URL not configured — skipping email delivery (standalone mode)"
            );
            Ok(())
        }
    }
}

pub async fn create_notification(pool: DbPool, payload: JobPayload) -> Result<(), String> {
    let JobPayload::CreateNotification {
        user_id,
        kind,
        subject,
    } = payload
    else {
        return Err("wrong payload kind routed to the create_notification handler".to_string());
    };
    edda_db::NotificationRepo::insert_if_new(
        &pool,
        edda_domain::NotificationId::new(),
        user_id,
        kind,
        subject,
    )
    .await
    .map(|_| ())
    .map_err(|err| err.to_string())
}

/// The full delivery attempt: fetch the webhook + its decrypted secret,
/// sign the already-built payload, re-resolve and re-check the target
/// (`crate::ssrf::resolve_and_check` — independently of whatever check
/// ran at creation time, per that module's own doc comment), then POST
/// pinned to the checked address. Records one `WebhookDelivery` row per
/// execution (including retries) — real git hosts' own "recent
/// deliveries" views show each attempt separately too, not one row
/// mutated in place.
pub async fn deliver_webhook(pool: DbPool, payload: JobPayload) -> Result<(), String> {
    let JobPayload::DeliverWebhook {
        webhook_id,
        event,
        payload_json,
    } = payload
    else {
        return Err("wrong payload kind routed to the deliver_webhook handler".to_string());
    };

    let webhook = edda_db::WebhookRepo::find_by_id(&pool, webhook_id)
        .await
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "webhook no longer exists".to_string())?;
    if !webhook.is_subscribed_to(event) {
        // Unsubscribed or deactivated since this job was enqueued —
        // nothing to deliver, and not a failure of anything.
        return Ok(());
    }

    let ciphertext = edda_db::WebhookRepo::find_secret_ciphertext(&pool, webhook_id)
        .await
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "webhook secret missing".to_string())?;
    let secret = edda_auth::secret_box::decrypt(&ciphertext).map_err(|err| err.to_string())?;
    let signature = edda_auth::webhook_signing::sign(&secret, payload_json.as_bytes());

    let delivery_id = WebhookDeliveryId::new();
    edda_db::WebhookDeliveryRepo::insert(&pool, delivery_id, webhook_id, event, &payload_json)
        .await
        .map_err(|err| err.to_string())?;

    let (host, addr) = match crate::ssrf::resolve_and_check(&webhook.target_url).await {
        Ok(pair) => pair,
        Err(err) => {
            let _ =
                edda_db::WebhookDeliveryRepo::record_attempt(&pool, delivery_id, 1, None, false)
                    .await;
            return Err(err.to_string());
        }
    };

    let outcome = send_signed(
        &webhook.target_url,
        &host,
        addr,
        event,
        &signature,
        delivery_id,
        &payload_json,
    )
    .await;

    match outcome {
        Ok(status) => {
            let ok = (200..300).contains(&status);
            let _ = edda_db::WebhookDeliveryRepo::record_attempt(
                &pool,
                delivery_id,
                1,
                Some(status as i32),
                ok,
            )
            .await;
            if ok {
                Ok(())
            } else {
                Err(format!("target responded with status {status}"))
            }
        }
        Err(err) => {
            let _ =
                edda_db::WebhookDeliveryRepo::record_attempt(&pool, delivery_id, 1, None, false)
                    .await;
            Err(err)
        }
    }
}

/// The actual signed HTTP POST, pinned to an already-validated `addr` —
/// takes the address as a parameter rather than resolving `target_url`
/// itself, so the SSRF decision stays entirely in `deliver_webhook`/
/// `crate::ssrf` (this function has no path that could accidentally skip
/// it) and so this function's HTTP/signing mechanics are unit-testable
/// against a local mock server without needing to special-case a test
/// exemption in the SSRF gate itself.
async fn send_signed(
    target_url: &str,
    host: &str,
    addr: std::net::SocketAddr,
    event: edda_domain::WebhookEvent,
    signature: &str,
    delivery_id: WebhookDeliveryId,
    payload_json: &str,
) -> Result<u16, String> {
    let client = reqwest::Client::builder()
        .resolve(host, addr)
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| err.to_string())?;

    let response = client
        .post(target_url)
        .header("Content-Type", "application/json")
        .header("X-Edda-Event", event.as_wire_str())
        .header("X-Edda-Signature", signature)
        .header("X-Edda-Delivery", delivery_id.to_string())
        .body(payload_json.to_string())
        .send()
        .await
        .map_err(|err| err.to_string())?;
    Ok(response.status().as_u16())
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::routing::post;
    use axum::Router;

    fn set_test_key() {
        edda_auth::secret_box::init(Some([0x11; 32]));
    }

    #[derive(Clone, Default)]
    struct Captured(std::sync::Arc<tokio::sync::Mutex<Option<(HeaderMap, String)>>>);

    async fn capture_handler(
        State(captured): State<Captured>,
        headers: HeaderMap,
        body: String,
    ) -> &'static str {
        *captured.0.lock().await = Some((headers, body));
        "ok"
    }

    async fn spawn_capture_server() -> (std::net::SocketAddr, Captured) {
        let captured = Captured::default();
        let app = Router::new()
            .route("/hook", post(capture_handler))
            .with_state(captured.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral port");
        let addr = listener.local_addr().expect("resolve bound address");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        (addr, captured)
    }

    /// Exit criterion: "a webhook configured for `pull_request.merged`
    /// actually fires (with a valid HMAC signature)... verified by an
    /// integration test asserting the signature validates." `send_signed`
    /// is exactly the mechanics `deliver_webhook` uses once the SSRF gate
    /// has already approved a target — this drives it against a real
    /// local HTTP server and independently recomputes the HMAC the same
    /// way a real receiving webhook consumer would, over the real bytes
    /// received (not the bytes sent), so the assertion is meaningful even
    /// if serialization somehow drifted between signing and sending.
    #[tokio::test]
    async fn a_delivered_webhook_carries_a_signature_that_validates_against_the_real_secret() {
        let (addr, captured) = spawn_capture_server().await;
        let secret = b"a shared webhook secret";
        let payload_json = r#"{"action":"merged","pull_request":{"number":1}}"#;
        let signature = edda_auth::webhook_signing::sign(secret, payload_json.as_bytes());
        let delivery_id = WebhookDeliveryId::new();
        let target_url = format!("http://example-webhook-target.invalid:{}/hook", addr.port());

        let status = send_signed(
            &target_url,
            "example-webhook-target.invalid",
            addr,
            edda_domain::WebhookEvent::PullRequestMerged,
            &signature,
            delivery_id,
            payload_json,
        )
        .await
        .expect("delivery succeeds against the local mock server");
        assert_eq!(status, 200);

        let (headers, received_body) = captured
            .0
            .lock()
            .await
            .take()
            .expect("request was received");
        assert_eq!(received_body, payload_json);
        let received_signature = headers
            .get("x-edda-signature")
            .expect("signature header present")
            .to_str()
            .unwrap();
        // The receiving end's own verification: recompute HMAC over the
        // bytes it actually received and compare.
        let recomputed = edda_auth::webhook_signing::sign(secret, received_body.as_bytes());
        assert_eq!(received_signature, recomputed);

        // A tampered payload must not validate against the same
        // signature — proves this is a real signature check, not a
        // constant that always matches.
        let tampered = edda_auth::webhook_signing::sign(secret, b"tampered payload");
        assert_ne!(received_signature, tampered);

        assert_eq!(
            headers.get("x-edda-event").unwrap().to_str().unwrap(),
            "pull_request.merged"
        );
    }

    /// Exit criterion (the SSRF half): the delivery entrypoint itself —
    /// not just the isolated `crate::ssrf` unit tests — refuses a webhook
    /// whose target resolves to a loopback address, proving the real
    /// `deliver_webhook` call path actually invokes the check rather than
    /// merely having it available.
    #[tokio::test]
    async fn deliver_webhook_refuses_a_loopback_target_end_to_end() {
        set_test_key();
        let pool = edda_db::test_pool().await;
        let owner = edda_domain::UserId::new();
        edda_db::UserRepo::insert(&pool, owner, "alice", "alice@example.com", "x")
            .await
            .unwrap();
        let repository = edda_domain::Repository {
            id: edda_domain::RepositoryId::new(),
            owner: edda_domain::RepositoryOwner::User(owner),
            name: "demo".to_string(),
            description: None,
            visibility: edda_domain::Visibility::Public,
            forked_from: None,
        };
        edda_db::RepositoryRepo::insert_with_owner(&pool, &repository, owner)
            .await
            .unwrap();

        let secret = edda_auth::webhook_signing::generate_secret();
        let ciphertext =
            edda_auth::secret_box::encrypt(secret.as_bytes()).expect("test key installed");
        let webhook_id = edda_domain::WebhookId::new();
        edda_db::WebhookRepo::insert(
            &pool,
            webhook_id,
            repository.id,
            "http://127.0.0.1:9/hook",
            &ciphertext,
            &[edda_domain::WebhookEvent::PullRequestMerged],
        )
        .await
        .unwrap();

        let payload = JobPayload::DeliverWebhook {
            webhook_id,
            event: edda_domain::WebhookEvent::PullRequestMerged,
            payload_json: "{}".to_string(),
        };
        let err = deliver_webhook(pool.clone(), payload).await.unwrap_err();
        assert!(
            err.contains("disallowed") || err.contains("Blocked") || err.contains("private"),
            "expected an SSRF-blocked error, got: {err}"
        );

        // A delivery attempt was still recorded (as a failed one) — the
        // block happens after the delivery row exists, not silently.
        let deliveries = edda_db::WebhookDeliveryRepo::list_for_webhook(&pool, webhook_id)
            .await
            .unwrap();
        assert_eq!(deliveries.len(), 1);
        assert!(deliveries[0].delivered_at.is_none());
    }
}

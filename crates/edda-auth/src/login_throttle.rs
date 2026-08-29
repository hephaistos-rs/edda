//! Login brute-force throttle (S4). Every failed attempt bumps **two**
//! counters: one keyed on `(lower(email), client_ip)` and one account-wide
//! (`lower(email)` alone). The per-(account, IP) counter bites first for an
//! ordinary attacker; the account-wide one still bites when the attacker
//! rotates a spoofed `X-Forwarded-For` per request. A legitimate user
//! behind a different address, or a different account behind the same
//! address, is unaffected by the per-IP counter, and the account-wide lock
//! is deliberately brief.
//!
//! Policy: the first [`LOCK_THRESHOLD`] failures are free; after that each
//! further failure sets an exponentially growing lock window (`15s`,
//! `30s`, `60s`, … capped at [`MAX_LOCK_SECONDS`]). A successful login
//! clears both counters. Storage is `edda_db::LoginAttemptRepo`.

use std::time::{SystemTime, UNIX_EPOCH};

use edda_db::{DbError, LoginAttemptRepo};

/// Failures before any lock is applied.
const LOCK_THRESHOLD: i64 = 5;
/// The base window applied at the first over-threshold failure.
const BASE_LOCK_SECONDS: i64 = 15;
/// The lock window never grows past this.
const MAX_LOCK_SECONDS: i64 = 900;

#[derive(Debug, thiserror::Error)]
pub enum ThrottleError {
    #[error("too many failed sign-in attempts — try again in {retry_after_seconds}s")]
    LockedOut { retry_after_seconds: i64 },
    #[error(transparent)]
    Db(#[from] DbError),
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs() as i64
}

/// `lower(email) || '|' || client_ip` — the per-(account, IP) counter key.
/// An empty `client_ip` yields the account-wide key.
#[must_use]
pub fn attempt_key(email: &str, client_ip: &str) -> String {
    format!("{}|{}", email.trim().to_lowercase(), client_ip)
}

/// The counter keys a failure touches: always the account-wide one, plus
/// the per-IP one when a client IP is known (and distinct).
fn keys(email: &str, client_ip: &str) -> Vec<String> {
    let account_wide = attempt_key(email, "");
    if client_ip.is_empty() {
        vec![account_wide]
    } else {
        vec![account_wide, attempt_key(email, client_ip)]
    }
}

/// Fails with [`ThrottleError::LockedOut`] when either the account-wide or
/// the per-IP counter for `(email, ip)` is inside an active lock window;
/// otherwise `Ok(())` (the password check may proceed).
pub async fn check(
    pool: &edda_db::DbPool,
    email: &str,
    client_ip: &str,
) -> Result<(), ThrottleError> {
    let mut worst = 0i64;
    for key in keys(email, client_ip) {
        if let Some(attempt) = LoginAttemptRepo::current(pool, &key).await? {
            if let Some(locked_until) = attempt.locked_until {
                worst = worst.max(locked_until - now_unix());
            }
        }
    }
    if worst > 0 {
        return Err(ThrottleError::LockedOut {
            retry_after_seconds: worst,
        });
    }
    Ok(())
}

/// Records one failed attempt against both counters and, once either is
/// past the threshold, (re)arms its lock window.
pub async fn record_failure(
    pool: &edda_db::DbPool,
    email: &str,
    client_ip: &str,
) -> Result<(), ThrottleError> {
    for key in keys(email, client_ip) {
        let attempt = LoginAttemptRepo::record_failure(pool, &key, now_unix()).await?;
        if attempt.failure_count >= LOCK_THRESHOLD {
            // 0, 1, 2, … doublings of the base window, capped where the
            // doubled value would already exceed the ceiling anyway.
            let over = attempt.failure_count - LOCK_THRESHOLD;
            let steps = u32::try_from(over.clamp(0, 6)).unwrap_or(6);
            let window = (BASE_LOCK_SECONDS << steps).min(MAX_LOCK_SECONDS);
            LoginAttemptRepo::set_locked_until(pool, &key, Some(now_unix() + window)).await?;
        }
    }
    Ok(())
}

/// Clears both counters for `(email, ip)` — call after a completed login.
pub async fn record_success(
    pool: &edda_db::DbPool,
    email: &str,
    client_ip: &str,
) -> Result<(), ThrottleError> {
    for key in keys(email, client_ip) {
        LoginAttemptRepo::clear(pool, &key).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_first_failures_are_free_then_a_lock_arms_and_grows() {
        let pool = edda_db::test_pool().await;
        let (email, ip) = ("alice@example.com", "203.0.113.7");

        // Below the threshold: no lock.
        for _ in 0..LOCK_THRESHOLD - 1 {
            record_failure(&pool, email, ip).await.unwrap();
            check(&pool, email, ip).await.unwrap();
        }

        // Threshold failure arms the lock.
        record_failure(&pool, email, ip).await.unwrap();
        let err = check(&pool, email, ip).await.unwrap_err();
        let ThrottleError::LockedOut {
            retry_after_seconds,
        } = err
        else {
            panic!("expected LockedOut, got {err:?}");
        };
        assert!(retry_after_seconds > 0 && retry_after_seconds <= BASE_LOCK_SECONDS);

        // A success clears everything.
        record_success(&pool, email, ip).await.unwrap();
        check(&pool, email, ip).await.unwrap();
        assert!(LoginAttemptRepo::current(&pool, &attempt_key(email, ip))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn a_different_account_from_the_same_address_is_unaffected() {
        let pool = edda_db::test_pool().await;
        for _ in 0..LOCK_THRESHOLD + 2 {
            record_failure(&pool, "victim@example.com", "10.0.0.9")
                .await
                .unwrap();
        }
        // A bystander on the same IP can still sign in...
        check(&pool, "bystander@example.com", "10.0.0.9")
            .await
            .unwrap();
        // ...but the victim's account is locked from *any* address (the
        // account-wide counter), which is what defeats IP rotation.
        assert!(check(&pool, "victim@example.com", "10.0.0.9")
            .await
            .is_err());
        assert!(check(&pool, "victim@example.com", "10.0.0.42")
            .await
            .is_err());
    }
}

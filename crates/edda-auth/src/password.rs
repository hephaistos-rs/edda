//! Password hashing (Argon2id) with process-configurable cost parameters
//! and a timing-equalisation decoy for the unknown-user login path.
//!
//! The cost parameters come from `edda_app::config` (`EDDA_ARGON2_*`),
//! installed once at startup via [`configure`]; unset uses the `argon2`
//! crate's own defaults (19 MiB / t=2 / p=1). Hashing is CPU-bound and
//! must not run on an async worker — [`hash_password_async`] /
//! [`verify_password_async`] move it to `spawn_blocking`; the bare
//! [`hash_password`] / [`verify_password`] stay for tests and non-async
//! call sites.

use std::sync::OnceLock;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Version};

/// Argon2id cost parameters. [`Default`] mirrors `argon2::Params::DEFAULT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// Memory in KiB (`EDDA_ARGON2_MEMORY_KIB`).
    pub memory_kib: u32,
    /// Iterations / time cost (`EDDA_ARGON2_ITERATIONS`).
    pub iterations: u32,
    /// Degree of parallelism (`EDDA_ARGON2_PARALLELISM`).
    pub parallelism: u32,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
        }
    }
}

static PARAMS: OnceLock<Params> = OnceLock::new();

/// Installs the process's Argon2 cost parameters. Call once from the
/// composition root; the first call wins.
pub fn configure(params: Params) {
    let _ = PARAMS.set(params);
}

fn hasher() -> Argon2<'static> {
    let p = PARAMS.get().copied().unwrap_or_default();
    let params = argon2::Params::new(p.memory_kib, p.iterations, p.parallelism, None)
        .unwrap_or_else(|_| argon2::Params::default());
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(hasher()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    hasher()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// [`hash_password`] on a blocking thread — for async call sites.
pub async fn hash_password_async(password: String) -> Result<String, argon2::password_hash::Error> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .expect("the password-hashing task neither panics nor is cancelled")
}

/// [`verify_password`] on a blocking thread — for async call sites.
pub async fn verify_password_async(password: String, stored_hash: String) -> bool {
    tokio::task::spawn_blocking(move || verify_password(&password, &stored_hash))
        .await
        .unwrap_or(false)
}

/// Runs one Argon2 verification against a fixed decoy hash so the
/// unknown-user login path spends about as long as the known-user path,
/// closing the account-enumeration timing side channel (L8). The decoy is
/// computed once under the configured parameters and cached.
pub fn verify_dummy() {
    static DECOY: OnceLock<String> = OnceLock::new();
    let decoy = DECOY.get_or_init(|| {
        hash_password("edda-timing-equalisation-decoy").expect("hashing a fixed string never fails")
    });
    let _ = verify_password("not-the-decoy-password", decoy);
}

/// [`verify_dummy`] on a blocking thread — for async call sites.
pub async fn verify_dummy_async() {
    let _ = tokio::task::spawn_blocking(verify_dummy).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_verifies_against_its_own_hash_and_nothing_else() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("Tr0ub4dor&3", &hash));
    }

    #[test]
    fn verify_dummy_runs_without_panicking() {
        verify_dummy();
        verify_dummy();
    }

    #[test]
    fn custom_params_still_round_trip() {
        // `configure` is process-global and first-call-wins, so this test
        // only checks that a non-default `hasher()` produces usable hashes
        // via a direct construction, not via `configure`.
        let params = argon2::Params::new(8, 1, 1, None).unwrap();
        let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        let hash = a.hash_password(b"pw", &salt).unwrap().to_string();
        let parsed = PasswordHash::new(&hash).unwrap();
        assert!(a.verify_password(b"pw", &parsed).is_ok());
    }
}

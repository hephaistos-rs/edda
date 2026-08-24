//! The server's own SSH host key — the identity clients verify (and their
//! local `known_hosts` remembers) when they first connect. Generated once
//! and persisted to disk; regenerating it on every startup would change
//! the host key every restart, breaking every client's `known_hosts` entry
//! for no reason.

use std::path::Path;

use russh::keys::{Algorithm, PrivateKey};

/// Loads the host key at `path`, generating and persisting a fresh
/// Ed25519 key there if none exists yet.
pub fn load_or_generate(path: &Path) -> std::io::Result<PrivateKey> {
    if path.exists() {
        return PrivateKey::read_openssh_file(path).map_err(|err| {
            std::io::Error::other(format!("reading SSH host key at {}: {err}", path.display()))
        });
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .map_err(|err| std::io::Error::other(format!("generating SSH host key: {err}")))?;
    key.write_openssh_file(path, russh::keys::ssh_key::LineEnding::LF)
        .map_err(|err| {
            std::io::Error::other(format!("writing SSH host key to {}: {err}", path.display()))
        })?;
    tracing::info!(path = %path.display(), "generated a new SSH host key");
    Ok(key)
}

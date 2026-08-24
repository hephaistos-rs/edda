//! Git-over-SSH transport. Owns SSH-specific concerns only — server/session
//! lifecycle, public-key authentication, exec-command parsing, channel I/O
//! framing — and delegates every actual git operation to
//! `edda_git::protocol` (shared with `edda-http`'s bridge) and every
//! access decision to `edda_auth::AuthorizationService`. See
//! plan.local.md §17 Phase 2.

mod command;
mod handler;
mod host_key;
mod state;

#[cfg(test)]
mod tests;

pub use state::SshState;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use russh::server::{Config, Server as _};

use handler::Connection;

#[derive(Clone)]
struct SshServer {
    state: SshState,
}

impl russh::server::Server for SshServer {
    type Handler = Connection;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Connection {
        Connection::new(self.state.clone(), peer_addr)
    }

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        tracing::warn!(error = %error, "ssh session ended with an error");
    }
}

/// Binds `addr` and serves git-over-SSH until the process is asked to
/// shut down. `host_key_path` is where the server's persistent SSH host
/// key lives (generated once, on first run, if absent — see `host_key`'s
/// module doc).
pub async fn serve(
    state: SshState,
    addr: impl Into<SocketAddr>,
    host_key_path: &Path,
) -> std::io::Result<()> {
    let host_key = host_key::load_or_generate(host_key_path)?;

    let config = Arc::new(Config {
        keys: vec![host_key],
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(1),
        ..Default::default()
    });

    let mut server = SshServer { state };
    server.run_on_address(config, addr.into()).await
}

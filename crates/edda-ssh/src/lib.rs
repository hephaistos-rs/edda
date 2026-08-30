//! Git-over-SSH transport. Owns SSH-specific concerns only — server/session
//! lifecycle, public-key authentication, exec-command parsing, channel I/O
//! framing — and delegates every actual git operation to
//! `edda_git::protocol` (shared with `edda-app`'s bridge) and every
//! access decision to `edda_auth::AuthorizationService`.

mod command;
mod handler;
mod host_key;
mod state;

#[cfg(test)]
mod tests;

pub use state::SshState;

use std::future::Future;
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

/// Binds `addr` and serves git-over-SSH until `shutdown` resolves, then
/// drains: `russh`'s [`RunningServerHandle`](russh::server::RunningServerHandle)
/// stops the listener accepting new connections and the returned future
/// resolves once the sessions already running have finished — so an
/// in-flight `git clone`/`push` over SSH completes rather than being cut
/// when the process receives `SIGTERM`. `host_key_path` is where the
/// server's persistent SSH host key lives (generated once, on first run,
/// if absent — see `host_key`'s module doc).
pub async fn serve(
    state: SshState,
    addr: impl Into<SocketAddr>,
    host_key_path: &Path,
    shutdown: impl Future<Output = ()> + Send,
) -> std::io::Result<()> {
    let host_key = host_key::load_or_generate(host_key_path)?;

    let config = Arc::new(Config {
        keys: vec![host_key],
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(1),
        ..Default::default()
    });

    // `run_on_socket` borrows `server` and `listener` for the lifetime of
    // the returned `RunningServer` future; both are locals of this async
    // fn, which is itself the task the composition root spawns, so the
    // borrows are fine without an inner `tokio::spawn`. `RunningServer` is
    // `Unpin`, so `&mut running` works directly as a `select!` branch.
    let listener = tokio::net::TcpListener::bind(addr.into()).await?;
    let mut server = SshServer { state };
    let mut running = server.run_on_socket(config, &listener);
    let handle = running.handle();

    let shutdown = std::pin::pin!(shutdown);
    tokio::select! {
        result = &mut running => result,
        () = shutdown => {
            tracing::info!("git-over-SSH listener draining on shutdown signal");
            handle.shutdown("edda is shutting down".to_string());
            running.await
        }
    }
}

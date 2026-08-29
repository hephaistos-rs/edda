use std::collections::HashMap;
use std::net::SocketAddr;

use bytes::Bytes;
use russh::keys::PublicKey;
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId};

use edda_domain::{ActorContext, RepositoryId, UserId};
use edda_git::protocol;

use crate::state::SshState;

/// One SSH connection's channel-exec state — set once `exec_request` picks
/// a service and repository, then advanced by `data`/`channel_eof` as the
/// client sends its half of the git wire protocol.
enum ChannelState {
    /// A channel accepted for something other than a recognized git
    /// command (or not yet given an exec request at all) — no buffering,
    /// no further action.
    Idle,
    UploadPack {
        identity: String,
        buffer: Vec<u8>,
    },
    ReceivePack {
        identity: String,
        buffer: Vec<u8>,
        /// Resolved once, here, at command-open time (where `actor`/
        /// `repository` are both in scope) — see
        /// `AuthorizationService::resolve_receive_checks`'s own doc comment
        /// for why this resolution can't happen inside `edda-git` itself.
        checks: edda_git::ReceiveChecks,
        /// Carried through so `channel_eof` can hand the post-receive
        /// fan-out (`edda_jobs::record_push`) the repository and pusher
        /// without re-resolving them.
        repository_id: RepositoryId,
        pusher_id: Option<UserId>,
    },
}

pub struct Connection {
    state: SshState,
    peer_addr: Option<SocketAddr>,
    /// Set once `auth_publickey` succeeds — every later callback for this
    /// connection (there is exactly one identity per SSH connection, no
    /// re-authentication mid-session) reads this rather than re-deriving
    /// it.
    actor: Option<ActorContext>,
    channels: HashMap<ChannelId, ChannelState>,
}

impl Connection {
    pub(crate) fn new(state: SshState, peer_addr: Option<SocketAddr>) -> Self {
        Self {
            state,
            peer_addr,
            actor: None,
            channels: HashMap::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HandlerError {
    #[error(transparent)]
    Ssh(#[from] russh::Error),
}

/// Writes a `fatal: <message>\n` line to the channel's stderr, sets a
/// nonzero exit status, and closes it — matching how a real `git`
/// subprocess over SSH reports an application-level error (repository not
/// found, access denied, malformed request): the SSH `exec` request itself
/// still "succeeds" (a process genuinely ran), the failure is communicated
/// through the git-protocol-adjacent stderr/exit-status channel the `git`
/// CLI already knows how to surface to its own caller. Used for every
/// git-command failure *after* `exec_request` has accepted the channel —
/// never for the SSH-level authentication decision itself, which is
/// `auth_publickey`'s job alone.
fn fail_git_command(
    channel: ChannelId,
    session: &mut Session,
    message: &str,
) -> Result<(), HandlerError> {
    session.extended_data(channel, 1, format!("fatal: {message}\n"))?;
    session.exit_status_request(channel, 1)?;
    session.eof(channel)?;
    session.close(channel)?;
    Ok(())
}

fn succeed_git_command(
    channel: ChannelId,
    session: &mut Session,
    response: Vec<u8>,
) -> Result<(), HandlerError> {
    session.data(channel, Bytes::from(response))?;
    session.exit_status_request(channel, 0)?;
    session.eof(channel)?;
    session.close(channel)?;
    Ok(())
}

impl server::Handler for Connection {
    type Error = HandlerError;

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        // User keys first, so a key registered as both a user key and a
        // deploy key resolves to the user (matching `edda_auth::deploy_keys`'
        // own doc comment).
        if let Some(resolved) = edda_auth::ssh::authenticate(&self.state.pool, key).await {
            tracing::info!(user = %user, peer = ?self.peer_addr, resolved_user = %resolved.username, "ssh public-key authentication succeeded");
            self.actor = Some(ActorContext::User(resolved.id));
            return Ok(Auth::Accept);
        }
        if let Some(resolution) = edda_auth::deploy_keys::authenticate(&self.state.pool, key).await
        {
            tracing::info!(
                user = %user, peer = ?self.peer_addr,
                repository_id = %resolution.repository_id, read_only = resolution.read_only,
                "ssh deploy-key authentication succeeded"
            );
            self.actor = Some(ActorContext::DeployKey {
                repository_id: resolution.repository_id,
                read_only: resolution.read_only,
            });
            return Ok(Auth::Accept);
        }
        tracing::debug!(user = %user, peer = ?self.peer_addr, "ssh public-key authentication failed: no matching registered key");
        Ok(Auth::reject())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), ChannelState::Idle);
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // No shell, no arbitrary commands — only the two git services this
        // bridge exists to serve. Anything else is rejected outright at
        // the SSH-channel-request level (not even given the courtesy of a
        // git-shaped stderr message), since it was never a git command to
        // begin with.
        let Some(command) = crate::command::parse(data) else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        // `auth_publickey` always runs (and must succeed) before any
        // channel/exec callback — `russh` doesn't reach here otherwise —
        // so `self.actor` is always populated by this point.
        let Some(actor) = self.actor.clone() else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        let repository = match self
            .state
            .authz
            .repository_by_name(&command.owner, &command.name)
            .await
        {
            Ok(repository) => repository,
            Err(_) => {
                session.channel_success(channel)?;
                return fail_git_command(channel, session, "repository not found");
            }
        };

        let access_check = match command.service {
            crate::command::GitService::UploadPack => {
                self.state.authz.check_read(&actor, &repository).await
            }
            crate::command::GitService::ReceivePack => {
                self.state.authz.check_write(&actor, &repository).await
            }
        };
        if let Err(err) = access_check {
            session.channel_success(channel)?;
            // Same information-hiding rule as every other transport
            // (`edda_domain::AuthzError`'s doc comment): a `Forbidden`
            // still only ever says "not found" here too, since — unlike
            // HTTP's Basic-Auth retry affordance — there is no unauthenticated
            // "anonymous" SSH request to distinguish from an authenticated-
            // but-insufficient one; every SSH command already carries a
            // verified identity by the time it reaches this point.
            let _ = err;
            return fail_git_command(channel, session, "repository not found");
        }

        let identity = format!("{}/{}", command.owner, command.name);

        // Write the ref advertisement immediately — this is the first
        // thing a real `git-upload-pack`/`git-receive-pack` process does
        // upon starting, before reading anything from the client (unlike
        // HTTP, where the equivalent step is a separate `info/refs`
        // request; see `edda_git::protocol`'s module doc).
        let capabilities = match command.service {
            crate::command::GitService::UploadPack => protocol::UPLOAD_PACK_CAPABILITIES,
            crate::command::GitService::ReceivePack => protocol::RECEIVE_PACK_CAPABILITIES,
        };
        let advertisement = match protocol::build_ref_advertisement(
            self.state.store.as_ref(),
            &identity,
            capabilities,
        ) {
            Ok(advertisement) => advertisement,
            Err(err) => {
                session.channel_success(channel)?;
                return fail_git_command(channel, session, &err.to_string());
            }
        };

        session.channel_success(channel)?;
        session.data(channel, Bytes::from(advertisement))?;

        let next_state = match command.service {
            crate::command::GitService::UploadPack => ChannelState::UploadPack {
                identity,
                buffer: Vec::new(),
            },
            crate::command::GitService::ReceivePack => {
                let checks = self
                    .state
                    .authz
                    .resolve_receive_checks(&actor, &repository, self.state.max_repo_size_bytes)
                    .await
                    .map(|resolved| edda_git::ReceiveChecks {
                        blocked_ref_patterns: resolved.blocked_ref_patterns,
                        linear_history_ref_patterns: resolved.linear_history_ref_patterns,
                        signed_commit_ref_patterns: resolved.signed_commit_ref_patterns,
                        max_repo_bytes: resolved.max_repo_bytes,
                        current_repo_bytes: resolved.current_repo_bytes,
                    })
                    .unwrap_or_default();
                ChannelState::ReceivePack {
                    identity,
                    buffer: Vec::new(),
                    checks,
                    repository_id: repository.id,
                    pusher_id: actor.user_id(),
                }
            }
        };
        self.channels.insert(channel, next_state);
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Taken out of the map (not just borrowed) so the map itself is
        // free to mutate again below — `run_upload_pack` awaits, and this
        // handler must not hold a live borrow into `self.channels` across
        // that await point.
        let Some(mut state) = self.channels.remove(&channel) else {
            return Ok(());
        };

        match &mut state {
            ChannelState::Idle => {
                self.channels.insert(channel, state);
            }
            ChannelState::UploadPack { identity, buffer } => {
                buffer.extend_from_slice(data);
                if protocol::upload_pack_request_is_complete(buffer) {
                    let identity = identity.clone();
                    let body = Bytes::from(std::mem::take(buffer));
                    match protocol::run_upload_pack(self.state.store.as_ref(), &identity, body)
                        .await
                    {
                        Ok(response) => succeed_git_command(channel, session, response)?,
                        Err(err) => fail_git_command(channel, session, &err.to_string())?,
                    }
                    // Channel is done either way — not reinserted.
                } else {
                    self.channels.insert(channel, state);
                }
            }
            ChannelState::ReceivePack { buffer, .. } => {
                // Receive-pack has no "done" sentinel of its own to scan
                // for — the client signals "that's everything" by closing
                // its side of the channel, handled in `channel_eof`.
                buffer.extend_from_slice(data);
                self.channels.insert(channel, state);
            }
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(ChannelState::ReceivePack {
            identity,
            buffer,
            checks,
            repository_id,
            pusher_id,
        }) = self.channels.remove(&channel)
        {
            let body = Bytes::from(buffer);
            match protocol::run_receive_pack(
                self.state.store.as_ref(),
                &self.state.locks,
                &identity,
                body,
                checks,
            )
            .await
            {
                Ok(outcome) => {
                    if !outcome.applied.is_empty() {
                        let updated: Vec<(String, String, String)> = outcome
                            .applied
                            .iter()
                            .map(|r| (r.name.clone(), r.old.clone(), r.new.clone()))
                            .collect();
                        if let Err(err) = edda_jobs::record_push(
                            &self.state.pool,
                            repository_id,
                            pusher_id,
                            &updated,
                        )
                        .await
                        {
                            tracing::error!(error = %err, "failed to record the push for fan-out");
                        }
                    }
                    succeed_git_command(channel, session, outcome.response)?;
                }
                Err(err) => fail_git_command(channel, session, &err.to_string())?,
            }
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }
}

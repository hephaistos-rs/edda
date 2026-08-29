use edda_web::App;

#[cfg(feature = "server")]
mod jobs;
#[cfg(feature = "server")]
mod session_store;

/// Waits for either Ctrl-C or (on unix) SIGTERM — the two signals a process
/// manager / `docker stop` / an interactive terminal actually send.
#[cfg(feature = "server")]
async fn wait_for_shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        else {
            let _ = ctrl_c.await;
            return;
        };
        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}

/// The client (web) build launches normally. The server build assembles
/// its own axum router: Dioxus's SSR + static-asset router (no server
/// functions — those were removed in the Phase-4 cutover; the UI is a pure
/// `/api/v1` HTTP client now) merged with `edda_app::router`, which owns
/// the entire API, the git smart-HTTP bridge, and LFS. This function is
/// the workspace's one composition root: every other crate is wired
/// together here, and nowhere else.
#[cfg(feature = "server")]
fn main() {
    // Parse and validate every `EDDA_*` variable once, before anything
    // else runs. A misconfigured instance stops here with the *complete*
    // list of problems, printed plainly (no subscriber is installed yet).
    let settings = match edda_app::config::Settings::from_env() {
        Ok(settings) => std::sync::Arc::new(settings),
        Err(errors) => {
            eprint!("{errors}");
            std::process::exit(1);
        }
    };

    // Must run before `dioxus::server::serve(...)` — it installs a default
    // `tracing` subscriber of its own unless one is already set. See
    // `edda_telemetry`'s module docs for the full explanation.
    let telemetry_guard = edda_telemetry::init();

    // Install the at-rest encryption key set (or none). No lazy panic: if
    // it's absent, TOTP/webhook-secret features fail with a clear error
    // instead of aborting a request. The first entry is the primary; the
    // rest can still decrypt, so `edda-cli secrets rotate` can move blobs
    // onto a new primary.
    edda_auth::secret_box::init(
        settings.secret_keys.all(),
        settings.secret_keys.primary_id(),
    );
    if !settings.secret_keys.is_configured() {
        tracing::warn!(
            "EDDA_SECRET_KEYS is not set — TOTP (2FA) enrollment and creating webhooks with a \
             stored secret will be unavailable until it is configured"
        );
    }

    // Argon2 cost parameters (or the library defaults) — one place,
    // before any password is hashed.
    edda_auth::password::configure(settings.argon2.into_auth());

    // `dioxus::server::serve`'s callback can run more than once (dev-mode hot
    // reload re-invokes it to rebuild the router); the shutdown watcher below
    // must still only ever be spawned once, so the guard is shared behind a
    // lock rather than moved in directly.
    let telemetry_guard = std::sync::Arc::new(tokio::sync::Mutex::new(Some(telemetry_guard)));
    let shutdown_watcher_started = std::sync::Arc::new(std::sync::Once::new());
    let ssh_server_started = std::sync::Arc::new(std::sync::Once::new());
    let session_gc_started = std::sync::Arc::new(std::sync::Once::new());

    dioxus::server::serve(move || {
        let settings = settings.clone();
        let telemetry_guard = telemetry_guard.clone();
        let shutdown_watcher_started = shutdown_watcher_started.clone();
        let ssh_server_started = ssh_server_started.clone();
        let session_gc_started = session_gc_started.clone();
        async move {
            let pool = edda_db::pool(&settings.db.url, settings.db.pool_options()).await?;

            // Session cookies persist in the same configured database as
            // everything else, via a second small typed connection
            // `session_store::connect` opens alongside `pool`'s `AnyPool`
            // — see that module's doc comment for why
            // `tower-sessions-sqlx-store` can't share the `AnyPool`
            // directly.
            let session_store = session_store::connect(&pool, &settings.db.url).await?;
            // `SameSite=Lax`, not `tower-sessions`' own `Strict` default
            // (verified directly against a real instance, and found to
            // matter): the OAuth login/link flow (`edda-app`'s
            // `oauth_routes::begin`) stashes its CSRF token/nonce/PKCE
            // verifier in this exact session before redirecting to the
            // external provider, then
            // reads it back in `callback` once the provider redirects the
            // browser back — a genuine cross-site *top-level* navigation
            // the provider initiates. `SameSite=Strict` never attaches the
            // cookie to that request at all, so `callback` would always see
            // "no OAuth login is pending" and every real external-provider
            // login would fail outright. `Lax` still withholds the cookie
            // from the cross-site POST/subresource requests CSRF actually
            // relies on, so this doesn't weaken that protection — it only
            // permits the top-level-GET-navigation case `Strict` was
            // blocking unnecessarily.
            let session_layer = tower_sessions::SessionManagerLayer::new(session_store.clone())
                .with_same_site(tower_sessions::cookie::SameSite::Lax)
                // Rolling inactivity window (S10); the absolute ceiling is
                // enforced per-request in `edda-app`'s actor resolution.
                .with_expiry(tower_sessions::Expiry::OnInactivity(
                    tower_sessions::cookie::time::Duration::seconds(
                        settings.session.rolling_ttl_secs,
                    ),
                ));

            // GC expired session rows (S10) — `tower-sessions` only marks
            // them expired, it never deletes. Same `Once` guard as the
            // other background tasks, and for the same dev-hot-reload
            // reason.
            session_gc_started.call_once(|| {
                use tower_sessions::session_store::ExpiredDeletion;
                let store = session_store.clone();
                tokio::spawn(async move {
                    if let Err(err) = store
                        .continuously_delete_expired(tokio::time::Duration::from_secs(3600))
                        .await
                    {
                        tracing::warn!(error = %err, "session GC task stopped");
                    }
                });
            });

            let backend = edda_auth::Backend::new(pool.clone());
            let auth_layer =
                axum_login::AuthManagerLayerBuilder::new(backend.clone(), session_layer).build();

            let store: std::sync::Arc<dyn edda_git::store::RepoStore> = std::sync::Arc::new(
                edda_git::store::LocalFsStore::new(settings.git.repo_root.clone()),
            );
            let locks = std::sync::Arc::new(edda_git::LockRegistry::new());
            let authz = edda_auth::AuthorizationService::new(pool.clone());

            let state = edda_app::AppState {
                pool: pool.clone(),
                store: store.clone(),
                locks: locks.clone(),
                authz: authz.clone(),
                backend,
                config: edda_app::RuntimeConfig {
                    webauthn: settings.webauthn.clone().map(|w| w.into_auth()),
                    oidc: settings.oidc.clone().map(|o| o.into_auth()),
                    external_url: settings.http.external_url.clone(),
                    trusted_origins: settings.http.trusted_origins.clone(),
                    rate_limit: settings.rate_limit.clone(),
                    git_limits: settings.git.limits,
                    session: settings.session,
                },
            };
            let router = dioxus::server::router(App)
                .merge(edda_app::router(state))
                .layer(auth_layer);

            // The job poller: handler logic is registered here,
            // in the composition root, because it needs `edda-auth`
            // (secret decryption, HMAC signing) and an HTTP client —
            // `edda-jobs` itself deliberately depends on neither (see
            // that crate's own `Cargo.toml` doc comment).
            let mailer = match &settings.smtp {
                Some(smtp) => Some(std::sync::Arc::new(
                    jobs::Mailer::new(smtp).map_err(std::io::Error::other)?,
                )),
                None => {
                    tracing::info!(
                        "EDDA_SMTP_URL not set — email delivery (password reset, mention \
                         notifications) is disabled; in-app notifications still work"
                    );
                    None
                }
            };
            let mut handlers = edda_jobs::HandlerRegistry::new();
            handlers.register(edda_domain::JobKind::SendEmail, {
                let mailer = mailer.clone();
                move |payload| jobs::send_email(mailer.clone(), payload)
            });
            handlers.register(edda_domain::JobKind::CreateNotification, {
                let pool = pool.clone();
                move |payload| jobs::create_notification(pool.clone(), payload)
            });
            handlers.register(edda_domain::JobKind::DeliverWebhook, {
                let pool = pool.clone();
                move |payload| jobs::deliver_webhook(pool.clone(), payload)
            });
            edda_jobs::spawn_poller(
                pool.clone(),
                std::sync::Arc::new(handlers),
                edda_jobs::PollerConfig::default(),
            );

            // The event dispatcher: drains the `events` outbox (rows an
            // application service wrote in the same transaction as its
            // state change) into `jobs`. Separate task from the poller —
            // this one turns "what happened" into "what work," the poller
            // runs the work.
            edda_jobs::spawn_dispatcher(pool.clone(), edda_jobs::DispatcherConfig::default());

            // Same `Once`-guarded pattern as the shutdown watcher below,
            // and for the same reason: this callback can re-run on
            // dev-mode hot reload, and a second SSH listener must never
            // try to bind the same port again.
            ssh_server_started.call_once(|| {
                let ssh_state = edda_ssh::SshState {
                    pool,
                    store,
                    locks,
                    authz,
                };
                let ssh_bind = settings.ssh.bind;
                let host_key_path = settings.ssh.host_key_path.clone();
                tokio::spawn(async move {
                    tracing::info!(addr = %ssh_bind, "starting git-over-SSH listener");
                    if let Err(err) = edda_ssh::serve(ssh_state, ssh_bind, &host_key_path).await {
                        tracing::error!(error = %err, "git-over-SSH listener stopped");
                    }
                });
            });

            shutdown_watcher_started.call_once(|| {
                let telemetry_guard = telemetry_guard.clone();
                tokio::spawn(async move {
                    wait_for_shutdown_signal().await;
                    tracing::info!("shutdown signal received, flushing telemetry");
                    if let Some(guard) = telemetry_guard.lock().await.take() {
                        guard.shutdown().await;
                    }
                    std::process::exit(0);
                });
            });

            Ok(router)
        }
    });
}

#[cfg(not(feature = "server"))]
fn main() {
    dioxus::launch(App);
}

#[cfg(feature = "server")]
mod jobs;
#[cfg(feature = "server")]
mod session_store;

#[cfg(feature = "server")]
use std::process::ExitCode;
#[cfg(feature = "server")]
use std::sync::Arc;
#[cfg(feature = "server")]
use std::time::Duration;

#[cfg(feature = "server")]
use tokio_util::sync::CancellationToken;

/// A boxed error the composition root threads through `?` — the concrete
/// types (a DB error, an I/O error, …) are logged, never matched on.
#[cfg(feature = "server")]
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// How long `main` waits for the background tasks (poller, dispatcher,
/// scheduler, SSH listener) to drain after the HTTP server has stopped
/// before it gives up and returns anyway.
#[cfg(feature = "server")]
const SHUTDOWN_DRAIN_GRACE: Duration = Duration::from_secs(30);

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

/// The server build's entry point. It parses `Settings`, installs
/// telemetry / crypto / password config, builds a multi-threaded Tokio
/// runtime, and hands off to [`run`]. The exit code is the only thing
/// `main` itself decides — there is no `process::exit` anywhere in the
/// running tree; a `SIGTERM` unwinds [`run`] gracefully and control
/// returns here.
#[cfg(feature = "server")]
fn main() -> ExitCode {
    // Parse and validate every `EDDA_*` variable once, before anything
    // else runs. A misconfigured instance stops here with the *complete*
    // list of problems, printed plainly (no subscriber is installed yet).
    let settings = match edda_app::config::Settings::from_env() {
        Ok(settings) => Arc::new(settings),
        Err(errors) => {
            eprint!("{errors}");
            return ExitCode::FAILURE;
        }
    };

    // Installs a `tracing` subscriber (and, if configured, the OTel
    // exporter). Everything below logs through it.
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

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            tracing::error!(error = %err, "could not start the Tokio runtime");
            return ExitCode::FAILURE;
        }
    };

    let outcome = runtime.block_on(run(settings));

    // Flush spans/metrics while the runtime (and subscriber) are still
    // alive, whatever the outcome.
    runtime.block_on(telemetry_guard.shutdown());

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "edda exited with an error");
            ExitCode::FAILURE
        }
    }
}

/// The one composition root: every other crate is wired together here and
/// nowhere else. Builds `AppState`, starts the background tasks and the
/// git-over-SSH listener, and runs `axum::serve` — Dioxus's SSR + asset
/// router (via [`edda_web::ssr_router`], the only place `dioxus` is named)
/// merged with `edda_app::router` (the API, the git smart-HTTP bridge, and
/// LFS), wrapped in the session/auth layer.
///
/// The whole process shares one [`CancellationToken`]. `axum::serve` is
/// given `with_graceful_shutdown`: on `SIGTERM`/Ctrl-C it stops accepting
/// connections, lets in-flight requests finish, and returns; that also
/// cancels the token, so the poller/dispatcher/scheduler stop claiming and
/// drain their in-flight work and the SSH listener drains its live
/// sessions, all bounded by [`SHUTDOWN_DRAIN_GRACE`].
///
/// `into_make_service_with_connect_info` makes the real socket peer IP
/// available to the rate limiter (`edda_app::rate_limit`).
#[cfg(feature = "server")]
async fn run(settings: Arc<edda_app::config::Settings>) -> Result<(), BoxError> {
    let pool = edda_db::pool(&settings.db.url, settings.db.pool_options()).await?;

    // Session cookies persist in the same configured database as
    // everything else, via a second small typed connection
    // `session_store::connect` opens alongside `pool`'s `AnyPool` — see
    // that module's doc comment for why `tower-sessions-sqlx-store` can't
    // share the `AnyPool` directly.
    let session_store = session_store::connect(&pool, &settings.db.url).await?;
    // `SameSite=Lax`, not `tower-sessions`' own `Strict` default (verified
    // directly against a real instance, and found to matter): the OAuth
    // login/link flow (`edda-app`'s `oauth_routes::begin`) stashes its CSRF
    // token/nonce/PKCE verifier in this exact session before redirecting to
    // the external provider, then reads it back in `callback` once the
    // provider redirects the browser back — a genuine cross-site
    // *top-level* navigation the provider initiates. `SameSite=Strict`
    // never attaches the cookie to that request at all, so `callback` would
    // always see "no OAuth login is pending" and every real external-
    // provider login would fail outright. `Lax` still withholds the cookie
    // from the cross-site POST/subresource requests CSRF actually relies
    // on, so this doesn't weaken that protection — it only permits the
    // top-level-GET-navigation case `Strict` was blocking unnecessarily.
    let session_layer = tower_sessions::SessionManagerLayer::new(session_store.clone())
        .with_same_site(tower_sessions::cookie::SameSite::Lax)
        // Rolling inactivity window (S10); the absolute ceiling is enforced
        // per-request in `edda-app`'s actor resolution.
        .with_expiry(tower_sessions::Expiry::OnInactivity(
            tower_sessions::cookie::time::Duration::seconds(settings.session.rolling_ttl_secs),
        ));

    // The one shutdown signal, fanned out to every long-lived task below.
    let shutdown = CancellationToken::new();

    // GC expired session rows (S10) — `tower-sessions` only marks them
    // expired, it never deletes. A best-effort cleanup loop: it is
    // `abort`ed on shutdown rather than drained (there is nothing to lose
    // by cutting a delete sweep mid-pass).
    let session_gc = {
        use tower_sessions::session_store::ExpiredDeletion;
        let store = session_store.clone();
        tokio::spawn(async move {
            if let Err(err) = store
                .continuously_delete_expired(tokio::time::Duration::from_secs(3600))
                .await
            {
                tracing::warn!(error = %err, "session GC task stopped");
            }
        })
    };

    let backend = edda_auth::Backend::new(pool.clone());
    let auth_layer =
        axum_login::AuthManagerLayerBuilder::new(backend.clone(), session_layer).build();

    let store: Arc<dyn edda_git::store::RepoStore> = Arc::new(edda_git::store::LocalFsStore::new(
        settings.git.repo_root.clone(),
    ));
    let locks = Arc::new(edda_git::LockRegistry::new());
    let authz = edda_auth::AuthorizationService::new(pool.clone());

    // Seed the runtime `instance_settings` cache once, before the first
    // request: the environment baseline with any admin overrides already
    // stored in the database applied on top. The admin "save settings" path
    // swaps this `ArcSwap` wholesale later, no restart.
    let instance_settings_defaults = settings.registration.instance_settings_defaults();
    let instance_settings = edda_app::services::InstanceSettingsService::bootstrap(
        &pool,
        instance_settings_defaults.clone(),
    )
    .await;

    let state = edda_app::AppState {
        pool: pool.clone(),
        store: store.clone(),
        locks: locks.clone(),
        authz: authz.clone(),
        backend,
        config: edda_app::RuntimeConfig {
            webauthn: settings.webauthn.clone().map(|w| w.into_auth()),
            oidc: settings.oidc.clone(),
            external_url: settings.http.external_url.clone(),
            trusted_origins: settings.http.trusted_origins.clone(),
            rate_limit: settings.rate_limit.clone(),
            registration: settings.registration.policy.clone(),
            require_signin_to_view: settings.registration.require_signin_to_view,
            instance_settings_defaults,
            instance_settings,
            git_limits: settings.git.limits,
            session: settings.session,
            metrics_token: settings.metrics_token.clone(),
        },
    };

    // The job poller's handler logic is registered here, in the
    // composition root, because it needs `edda-auth` (secret decryption,
    // HMAC signing) and an HTTP client — `edda-jobs` itself deliberately
    // depends on neither (see that crate's own `Cargo.toml` doc comment).
    let mailer = match &settings.smtp {
        Some(smtp) => Some(Arc::new(
            jobs::Mailer::new(smtp).map_err(std::io::Error::other)?,
        )),
        None => {
            tracing::info!(
                "EDDA_SMTP_URL not set — email delivery (password reset, mention notifications) \
                 is disabled; in-app notifications still work"
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
    handlers.register(edda_domain::JobKind::UpdateRepoSize, {
        let pool = pool.clone();
        let store = store.clone();
        move |payload| jobs::update_repo_size(pool.clone(), store.clone(), payload)
    });
    handlers.register(edda_domain::JobKind::SyncReviewRequests, {
        let pool = pool.clone();
        let store = store.clone();
        move |payload| jobs::sync_review_requests(pool.clone(), store.clone(), payload)
    });
    handlers.register(edda_domain::JobKind::RunMaintenance, {
        let pool = pool.clone();
        let store = store.clone();
        move |payload| jobs::run_maintenance(pool.clone(), store.clone(), payload)
    });
    handlers.register(edda_domain::JobKind::RunRepoGc, {
        let pool = pool.clone();
        let store = store.clone();
        move |payload| jobs::run_repo_gc(pool.clone(), store.clone(), payload)
    });

    let poller = edda_jobs::spawn_poller(
        pool.clone(),
        Arc::new(handlers),
        edda_jobs::PollerConfig::default(),
        shutdown.clone(),
    );

    // The event dispatcher: drains the `events` outbox (rows an
    // application service wrote in the same transaction as its state
    // change) into `jobs`. Separate task from the poller — this one turns
    // "what happened" into "what work," the poller runs the work.
    let dispatcher = edda_jobs::spawn_dispatcher(
        pool.clone(),
        edda_jobs::DispatcherConfig::default(),
        shutdown.clone(),
    );

    // The maintenance scheduler (Phase 12): seeds the `scheduled_jobs`
    // rows, then every minute turns any due periodic task into a
    // `RunMaintenance` job for the poller.
    let scheduler = edda_jobs::spawn_scheduler(
        pool.clone(),
        edda_jobs::SchedulerConfig::default(),
        shutdown.clone(),
    );

    // The git-over-SSH listener. It drains the same way `axum::serve`
    // does: on cancellation it stops accepting and lets live sessions
    // (an in-flight `git clone`/`push`) finish.
    let ssh = {
        let ssh_state = edda_ssh::SshState {
            pool: pool.clone(),
            store: store.clone(),
            locks: locks.clone(),
            authz: authz.clone(),
            max_repo_size_bytes: settings
                .git
                .limits
                .max_repo_size_bytes
                .and_then(|bytes| i64::try_from(bytes).ok()),
        };
        let ssh_bind = settings.ssh.bind;
        let host_key_path = settings.ssh.host_key_path.clone();
        let ssh_shutdown = shutdown.clone();
        tokio::spawn(async move {
            tracing::info!(addr = %ssh_bind, "starting git-over-SSH listener");
            let drain = async move { ssh_shutdown.cancelled().await };
            if let Err(err) = edda_ssh::serve(ssh_state, ssh_bind, &host_key_path, drain).await {
                tracing::error!(error = %err, "git-over-SSH listener stopped");
            }
        })
    };

    // Dioxus SSR + assets, merged with the API/git/LFS router, wrapped in
    // the session/auth layer. This binary owns the serve loop.
    let app = edda_web::ssr_router()
        .merge(edda_app::router(state))
        .layer(auth_layer);

    let listener = tokio::net::TcpListener::bind(settings.http.bind).await?;
    tracing::info!(addr = %settings.http.bind, "HTTP listener up");

    let axum_shutdown = shutdown.clone();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        wait_for_shutdown_signal().await;
        tracing::info!("shutdown signal received — draining");
        axum_shutdown.cancel();
    })
    .await?;

    // `axum::serve` has returned: no new connections, in-flight requests
    // done. Make sure everything else sees the cancellation too (in case
    // `serve` returned for some reason other than the signal), then wait
    // for the background tasks to drain — bounded.
    shutdown.cancel();

    let drain = async {
        let _ = tokio::join!(poller, dispatcher, scheduler, ssh);
    };
    if tokio::time::timeout(SHUTDOWN_DRAIN_GRACE, drain)
        .await
        .is_err()
    {
        tracing::warn!("background tasks did not drain within the grace period; exiting anyway");
    }
    session_gc.abort();

    Ok(())
}

/// The wasm client build's entry point — just hydrates the UI. All Dioxus
/// details, this call included, live in `edda-web`.
#[cfg(not(feature = "server"))]
fn main() {
    edda_web::launch_client();
}

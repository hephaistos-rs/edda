//! The one place Edda's deployment configuration is read and validated.
//!
//! [`Settings::from_env`] parses every `EDDA_*` variable (plus `IP`/`PORT`)
//! **once**, at startup, into typed sub-structs, and returns *all* problems
//! at once rather than failing on the first. No other crate reads
//! `std::env` for configuration — lower crates (`edda-db`, `edda-git`,
//! `edda-auth`) take the resolved values as parameters. The boundary check
//! (`scripts/boundary-check.sh`) enforces this.
//!
//! Telemetry is the one documented exception: `edda-telemetry` still reads
//! the OpenTelemetry SDK's own `OTEL_*` variables (and `EDDA_LOG_FORMAT`)
//! directly — see `plan.local.md` §4.9. Everything else flows through here.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

/// One thing wrong with the environment. Carries the variable name so the
/// startup error can point at exactly what to fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub var: &'static str,
    pub problem: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.var, self.problem)
    }
}

/// The complete list of configuration problems, formatted as a block so a
/// misconfigured instance sees everything it needs to fix in one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigErrors(pub Vec<ConfigError>);

impl fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} configuration problem(s) — the server will not start:",
            self.0.len()
        )?;
        for e in &self.0 {
            writeln!(f, "  - {e}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigErrors {}

/// Error accumulator. Every getter records its own failure and returns a
/// fallback, so `from_env` can keep going and collect the rest.
struct Env {
    errors: Vec<ConfigError>,
}

impl Env {
    fn new() -> Self {
        Self { errors: Vec::new() }
    }

    fn fail(&mut self, var: &'static str, problem: impl Into<String>) {
        self.errors.push(ConfigError {
            var,
            problem: problem.into(),
        });
    }

    /// Present and non-blank, or `None`. Blank is treated as unset so an
    /// empty `EDDA_FOO=` in a compose file doesn't half-enable a feature.
    fn get(&self, var: &'static str) -> Option<String> {
        match std::env::var(var) {
            Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
            _ => None,
        }
    }

    /// Parse an optional var, falling back to `default`; a present-but-junk
    /// value is an error, not a silent fallback.
    fn parse_or<T>(&mut self, var: &'static str, default: T) -> T
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        match self.get(var) {
            None => default,
            Some(raw) => match raw.parse() {
                Ok(v) => v,
                Err(e) => {
                    self.fail(var, format!("invalid value {raw:?}: {e}"));
                    default
                }
            },
        }
    }
}

// --- sub-structs -----------------------------------------------------------

/// Where the HTTP server binds, and the URL the outside world reaches it
/// on (`EDDA_EXTERNAL_URL` — anchors OAuth redirect / WebAuthn origin /
/// CSRF-origin defaults).
#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub bind: SocketAddr,
    pub external_url: String,
    /// `EDDA_TRUSTED_ORIGINS` — a comma-separated list of extra
    /// `scheme://host[:port]` web origins a browser may send a
    /// credentialed, state-changing request from (for a split
    /// frontend/backend deployment). Same-origin and `external_url` are
    /// always trusted; this is empty for the ordinary single-origin
    /// deployment. See `crate::security::origin`.
    pub trusted_origins: Vec<String>,
}

/// Where the git-over-SSH listener binds, and where its persistent host
/// key lives (generated on first start).
#[derive(Debug, Clone)]
pub struct SshConfig {
    pub bind: SocketAddr,
    pub host_key_path: PathBuf,
}

/// The resolved database connection URL — `EDDA_DATABASE_URL` verbatim, or
/// a SQLite file under the data dir when unset (the zero-config default) —
/// plus the connection-pool tunables `edda_db::pool` needs.
#[derive(Debug, Clone)]
pub struct DbConfig {
    pub url: String,
    /// `EDDA_DB_MAX_CONNECTIONS` (default 10).
    pub max_connections: u32,
    /// `EDDA_DB_ACQUIRE_TIMEOUT_SECONDS` (default 30).
    pub acquire_timeout: Duration,
}

impl DbConfig {
    /// The shape `edda_db::pool` takes.
    #[must_use]
    pub fn pool_options(&self) -> edda_db::PoolOptions {
        edda_db::PoolOptions {
            max_connections: self.max_connections,
            acquire_timeout: self.acquire_timeout,
        }
    }
}

/// Where bare repositories live on disk (`{data_dir}/repos`), plus the
/// streamed-body size ceilings the git/LFS transfer paths enforce.
#[derive(Debug, Clone)]
pub struct GitConfig {
    pub repo_root: PathBuf,
    pub limits: GitLimits,
}

/// Hard ceilings the git smart-HTTP and Git LFS transfer paths enforce
/// **while the request body streams in** — a request over the limit is
/// aborted with `413 Payload Too Large` and nothing is written to disk.
/// Distinct from axum's `DefaultBodyLimit` (which the git/LFS routes
/// disable outright, since a real push/upload legitimately exceeds its
/// ~2 MiB default): these are Edda's own explicit, much larger, git-aware
/// caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GitLimits {
    /// `EDDA_GIT_MAX_PACK_BYTES` (default 2 GiB) — the largest
    /// `git-receive-pack` request body (the pack) a push may send.
    pub max_pack_bytes: u64,
    /// `EDDA_LFS_MAX_OBJECT_BYTES` (default 4 GiB) — the largest single
    /// Git LFS object an upload may send.
    pub max_lfs_object_bytes: u64,
}

impl Default for GitLimits {
    fn default() -> Self {
        Self {
            max_pack_bytes: 2 * 1024 * 1024 * 1024,
            max_lfs_object_bytes: 4 * 1024 * 1024 * 1024,
        }
    }
}

/// AES-256-GCM key material for at-rest secret encryption (TOTP shared
/// secrets, webhook signing secrets). Optional: an instance that never
/// enrolls 2FA or creates a webhook never needs it — but if
/// `EDDA_SECRET_KEYS` *is* set, every entry must be valid.
///
/// `EDDA_SECRET_KEYS` is a comma-separated list of `id:hex` entries (or a
/// single bare 64-hex key, which gets the id `default`). The **first**
/// entry is the primary: new ciphertext is encrypted under it and stamped
/// with its id. Every entry can decrypt, so rotation is: prepend a new
/// primary, run `edda-cli secrets rotate`, drop the old entry.
#[derive(Debug, Clone, Default)]
pub struct SecretKeys {
    /// `(id, key)` pairs in declared order; first = primary. Empty when
    /// `EDDA_SECRET_KEYS` is unset.
    entries: Vec<(String, [u8; 32])>,
}

impl SecretKeys {
    /// Every configured `(id, key)` pair — handed to
    /// `edda_auth::secret_box::init`.
    pub fn all(&self) -> Vec<(String, [u8; 32])> {
        self.entries.clone()
    }

    /// The id of the primary (first) key, if any.
    pub fn primary_id(&self) -> Option<String> {
        self.entries.first().map(|(id, _)| id.clone())
    }

    pub fn is_configured(&self) -> bool {
        !self.entries.is_empty()
    }
}

/// Argon2id password-hashing cost parameters (`EDDA_ARGON2_*`). `Default`
/// mirrors the `argon2` crate's own defaults (19 MiB / t=2 / p=1); raise
/// them for a host with spare CPU/RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Config {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
        }
    }
}

impl Argon2Config {
    pub fn into_auth(self) -> edda_auth::password::Params {
        edda_auth::password::Params {
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
        }
    }
}

/// WebAuthn relying-party identity plus two hardening toggles. `rp_id` /
/// `origin` are both-or-neither: one without the other is a configuration
/// error, since a mismatch fails every ceremony. `require_uv` /
/// `allow_cross_origin` are independent booleans, both defaulting off.
#[derive(Debug, Clone)]
pub struct WebauthnConfig {
    pub rp_id: String,
    pub origin: String,
    /// `EDDA_WEBAUTHN_REQUIRE_UV` — mandate the authenticator's
    /// user-verified flag (PIN/biometric) on every ceremony. Default false.
    pub require_uv: bool,
    /// `EDDA_WEBAUTHN_ALLOW_CROSS_ORIGIN` — permit a passkey prompt driven
    /// from a cross-origin `<iframe>` (`clientDataJSON.crossOrigin == true`).
    /// Default false.
    pub allow_cross_origin: bool,
}

impl WebauthnConfig {
    pub fn into_auth(self) -> edda_auth::webauthn::Config {
        edda_auth::webauthn::Config {
            rp_id: self.rp_id,
            origin: self.origin,
            require_uv: self.require_uv,
            allow_cross_origin: self.allow_cross_origin,
        }
    }
}

/// OIDC consumer-login credentials. All-four-or-none.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

impl OidcConfig {
    pub fn into_auth(self) -> edda_auth::oauth::Config {
        edda_auth::oauth::Config {
            issuer_url: self.issuer_url,
            client_id: self.client_id,
            client_secret: self.client_secret,
            redirect_url: self.redirect_url,
        }
    }
}

/// Outbound SMTP. Both-or-none; unset is a fully supported standalone mode
/// (email jobs log and no-op).
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub url: String,
    pub from: String,
}

/// Session lifetime (S10). `rolling` is the inactivity window fed to
/// `tower_sessions`' `Expiry::OnInactivity`; `absolute` is a hard ceiling
/// checked in the actor-resolution path (a session older than this is
/// treated as signed-out regardless of activity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionConfig {
    /// `EDDA_SESSION_ROLLING_TTL_SECONDS` (default 14 days).
    pub rolling_ttl_secs: i64,
    /// `EDDA_SESSION_ABSOLUTE_TTL_SECONDS` (default 90 days).
    pub absolute_ttl_secs: i64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            rolling_ttl_secs: 14 * 24 * 60 * 60,
            absolute_ttl_secs: 90 * 24 * 60 * 60,
        }
    }
}

/// Instance registration + privacy policy (Phase 9, H2/S3). The
/// `RegistrationPolicy` half (`EDDA_REGISTRATION_MODE`,
/// `EDDA_ALLOWED_EMAIL_DOMAINS`, `EDDA_REQUIRE_EMAIL_VERIFICATION`) is
/// consulted by `edda_auth::signup` and the push/create gate;
/// `require_signin_to_view` (`EDDA_REQUIRE_SIGNIN_VIEW`) makes the whole
/// instance private — an anonymous request gets 401 everywhere except
/// the login / health surface.
#[derive(Debug, Clone, Default)]
pub struct RegistrationConfig {
    pub policy: edda_domain::RegistrationPolicy,
    pub require_signin_to_view: bool,
}

/// Per-client token-bucket limits for the API surface (never the git or
/// LFS routes). Two buckets: a general one, and a stricter one applied to
/// just the auth endpoints (`/api/auth/*`, OAuth/WebAuthn begin+verify).
/// Defaults are generous enough for interactive use.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub per_second: u64,
    pub burst: u32,
    /// Stricter bucket for the auth endpoints (`EDDA_AUTH_RATE_LIMIT_*`).
    pub auth_per_second: u64,
    pub auth_burst: u32,
    /// `EDDA_TRUSTED_PROXIES` — CIDRs of reverse proxies whose
    /// `X-Forwarded-For` / `Forwarded` header may be trusted for the
    /// limiter key. Empty (the default) means forwarded headers are
    /// ignored entirely and every direct client shares one bucket. Peer-IP
    /// matching against these CIDRs needs `ConnectInfo` (Phase 13); for
    /// now a non-empty list is simply the signal to honour the leftmost
    /// forwarded hop.
    pub trusted_proxies: Vec<ipnet::IpNet>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_second: 5,
            burst: 20,
            auth_per_second: 1,
            auth_burst: 5,
            trusted_proxies: Vec::new(),
        }
    }
}

// --- top-level -----------------------------------------------------------

/// Everything the composition root needs to wire the process together,
/// validated. Build it once with [`Settings::from_env`].
#[derive(Debug, Clone)]
pub struct Settings {
    pub data_dir: PathBuf,
    pub http: HttpConfig,
    pub ssh: SshConfig,
    pub db: DbConfig,
    pub git: GitConfig,
    pub secret_keys: SecretKeys,
    pub argon2: Argon2Config,
    pub session: SessionConfig,
    pub registration: RegistrationConfig,
    pub webauthn: Option<WebauthnConfig>,
    pub oidc: Option<OidcConfig>,
    pub smtp: Option<SmtpConfig>,
    pub rate_limit: RateLimitConfig,
}

impl Settings {
    /// Parse and validate the whole environment. On failure the `Vec` holds
    /// *every* problem found, not just the first.
    pub fn from_env() -> Result<Settings, ConfigErrors> {
        let mut env = Env::new();

        let data_dir = env
            .get("EDDA_DATA_DIR")
            .map_or_else(|| PathBuf::from("./data"), PathBuf::from);
        // Repos, the SSH host key, and the zero-config SQLite file all live
        // here — create it now so every later step can assume it exists.
        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            env.fail(
                "EDDA_DATA_DIR",
                format!("could not create {data_dir:?}: {e}"),
            );
        }

        let ip: IpAddr = env.parse_or("IP", IpAddr::V4(Ipv4Addr::LOCALHOST));
        let http_port: u16 = env.parse_or("PORT", 8080);
        let ssh_port: u16 = env.parse_or("EDDA_SSH_PORT", 2222);

        let external_url = match env.get("EDDA_EXTERNAL_URL") {
            Some(u) if u.starts_with("http://") || u.starts_with("https://") => {
                u.trim_end_matches('/').to_string()
            }
            Some(u) => {
                env.fail(
                    "EDDA_EXTERNAL_URL",
                    format!("must start with http:// or https:// (got {u:?})"),
                );
                format!("http://{ip}:{http_port}")
            }
            None => format!("http://{ip}:{http_port}"),
        };

        let trusted_origins = match env.get("EDDA_TRUSTED_ORIGINS") {
            None => Vec::new(),
            Some(raw) => {
                let mut origins = Vec::new();
                for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    if entry.starts_with("http://") || entry.starts_with("https://") {
                        origins.push(entry.trim_end_matches('/').to_string());
                    } else {
                        env.fail(
                            "EDDA_TRUSTED_ORIGINS",
                            format!(
                                "each entry must start with http:// or https:// (got {entry:?})"
                            ),
                        );
                    }
                }
                origins
            }
        };

        let db_url = edda_db::effective_url(env.get("EDDA_DATABASE_URL").as_deref(), &data_dir);
        let db_max_connections = env.parse_or::<u32>("EDDA_DB_MAX_CONNECTIONS", 10);
        if db_max_connections == 0 {
            env.fail("EDDA_DB_MAX_CONNECTIONS", "must be greater than 0");
        }
        let db_acquire_timeout_secs = env.parse_or::<u64>("EDDA_DB_ACQUIRE_TIMEOUT_SECONDS", 30);
        if db_acquire_timeout_secs == 0 {
            env.fail("EDDA_DB_ACQUIRE_TIMEOUT_SECONDS", "must be greater than 0");
        }

        let secret_keys = parse_secret_keys(&mut env);
        let argon2 = parse_argon2(&mut env);
        let session = parse_session(&mut env);
        let registration = parse_registration(&mut env);
        let webauthn = parse_webauthn(&mut env);
        let oidc = parse_oidc(&mut env);
        let smtp = parse_smtp(&mut env);

        let rl_default = RateLimitConfig::default();
        let per_second = env.parse_or::<u64>("EDDA_RATE_LIMIT_PER_SECOND", rl_default.per_second);
        if per_second == 0 {
            env.fail("EDDA_RATE_LIMIT_PER_SECOND", "must be greater than 0");
        }
        let burst = env.parse_or::<u32>("EDDA_RATE_LIMIT_BURST", rl_default.burst);
        if burst == 0 {
            env.fail("EDDA_RATE_LIMIT_BURST", "must be greater than 0");
        }
        let auth_per_second = env.parse_or::<u64>(
            "EDDA_AUTH_RATE_LIMIT_PER_SECOND",
            rl_default.auth_per_second,
        );
        if auth_per_second == 0 {
            env.fail("EDDA_AUTH_RATE_LIMIT_PER_SECOND", "must be greater than 0");
        }
        let auth_burst = env.parse_or::<u32>("EDDA_AUTH_RATE_LIMIT_BURST", rl_default.auth_burst);
        if auth_burst == 0 {
            env.fail("EDDA_AUTH_RATE_LIMIT_BURST", "must be greater than 0");
        }
        let trusted_proxies = parse_trusted_proxies(&mut env);

        let default_git_limits = GitLimits::default();
        let max_pack_bytes =
            env.parse_or::<u64>("EDDA_GIT_MAX_PACK_BYTES", default_git_limits.max_pack_bytes);
        if max_pack_bytes == 0 {
            env.fail("EDDA_GIT_MAX_PACK_BYTES", "must be greater than 0");
        }
        let max_lfs_object_bytes = env.parse_or::<u64>(
            "EDDA_LFS_MAX_OBJECT_BYTES",
            default_git_limits.max_lfs_object_bytes,
        );
        if max_lfs_object_bytes == 0 {
            env.fail("EDDA_LFS_MAX_OBJECT_BYTES", "must be greater than 0");
        }

        if !env.errors.is_empty() {
            return Err(ConfigErrors(env.errors));
        }

        Ok(Settings {
            http: HttpConfig {
                bind: SocketAddr::new(ip, http_port),
                external_url,
                trusted_origins,
            },
            ssh: SshConfig {
                bind: SocketAddr::new(ip, ssh_port),
                host_key_path: data_dir.join("ssh_host_ed25519_key"),
            },
            db: DbConfig {
                url: db_url,
                max_connections: db_max_connections,
                acquire_timeout: Duration::from_secs(db_acquire_timeout_secs),
            },
            git: GitConfig {
                repo_root: data_dir.join("repos"),
                limits: GitLimits {
                    max_pack_bytes,
                    max_lfs_object_bytes,
                },
            },
            secret_keys,
            argon2,
            session,
            registration,
            webauthn,
            oidc,
            smtp,
            rate_limit: RateLimitConfig {
                per_second: per_second.max(1),
                burst: burst.max(1),
                auth_per_second: auth_per_second.max(1),
                auth_burst: auth_burst.max(1),
                trusted_proxies,
            },
            data_dir,
        })
    }
}

fn parse_secret_keys(env: &mut Env) -> SecretKeys {
    let Some(raw) = env.get("EDDA_SECRET_KEYS") else {
        return SecretKeys::default();
    };
    let items: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let mut entries: Vec<(String, [u8; 32])> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for item in &items {
        let (id, hex) = match item.split_once(':') {
            Some((id, hex)) => (id.trim().to_string(), hex.trim()),
            // A bare (id-less) 64-hex key is only accepted as the *sole*
            // entry — once there's more than one, ids are mandatory so
            // `decrypt` can tell them apart.
            None if items.len() == 1 => ("default".to_string(), item.trim()),
            None => {
                env.fail(
                    "EDDA_SECRET_KEYS",
                    "every entry must be `id:hex` when more than one key is listed",
                );
                continue;
            }
        };
        if id.is_empty() || id.len() > 32 {
            env.fail(
                "EDDA_SECRET_KEYS",
                format!("key id {id:?} must be 1-32 characters"),
            );
            continue;
        }
        if !seen.insert(id.clone()) {
            env.fail("EDDA_SECRET_KEYS", format!("duplicate key id {id:?}"));
            continue;
        }
        match decode_hex_32(hex) {
            Some(key) => entries.push((id, key)),
            None => env.fail(
                "EDDA_SECRET_KEYS",
                format!("key {id:?} must be a 64-character hex-encoded 32-byte value"),
            ),
        }
    }
    SecretKeys { entries }
}

fn parse_trusted_proxies(env: &mut Env) -> Vec<ipnet::IpNet> {
    let Some(raw) = env.get("EDDA_TRUSTED_PROXIES") else {
        return Vec::new();
    };
    let mut nets = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        // Accept a bare IP (treated as a /32 or /128) as well as a CIDR.
        let parsed = entry
            .parse::<ipnet::IpNet>()
            .or_else(|_| entry.parse::<std::net::IpAddr>().map(ipnet::IpNet::from));
        match parsed {
            Ok(net) => nets.push(net),
            Err(_) => env.fail(
                "EDDA_TRUSTED_PROXIES",
                format!("{entry:?} is not a valid IP address or CIDR"),
            ),
        }
    }
    nets
}

fn parse_registration(env: &mut Env) -> RegistrationConfig {
    let mode = match env.get("EDDA_REGISTRATION_MODE") {
        None => edda_domain::RegistrationMode::default(),
        Some(raw) => match edda_domain::RegistrationMode::parse(&raw) {
            Some(m) => m,
            None => {
                env.fail(
                    "EDDA_REGISTRATION_MODE",
                    format!("must be one of open, approval, closed (got {raw:?})"),
                );
                edda_domain::RegistrationMode::default()
            }
        },
    };
    let allowed_email_domains = env
        .get("EDDA_ALLOWED_EMAIL_DOMAINS")
        .map(|raw| {
            raw.split(',')
                .map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase())
                .filter(|d| !d.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let require_email_verification = env.parse_or::<bool>("EDDA_REQUIRE_EMAIL_VERIFICATION", false);
    let require_signin_to_view = env.parse_or::<bool>("EDDA_REQUIRE_SIGNIN_VIEW", false);

    RegistrationConfig {
        policy: edda_domain::RegistrationPolicy {
            mode,
            allowed_email_domains,
            require_email_verification,
        },
        require_signin_to_view,
    }
}

fn parse_session(env: &mut Env) -> SessionConfig {
    let d = SessionConfig::default();
    let rolling = env.parse_or::<i64>("EDDA_SESSION_ROLLING_TTL_SECONDS", d.rolling_ttl_secs);
    let absolute = env.parse_or::<i64>("EDDA_SESSION_ABSOLUTE_TTL_SECONDS", d.absolute_ttl_secs);
    if rolling <= 0 {
        env.fail("EDDA_SESSION_ROLLING_TTL_SECONDS", "must be greater than 0");
    }
    if absolute <= 0 {
        env.fail(
            "EDDA_SESSION_ABSOLUTE_TTL_SECONDS",
            "must be greater than 0",
        );
    }
    if rolling > 0 && absolute > 0 && absolute < rolling {
        env.fail(
            "EDDA_SESSION_ABSOLUTE_TTL_SECONDS",
            "must be at least EDDA_SESSION_ROLLING_TTL_SECONDS",
        );
    }
    SessionConfig {
        rolling_ttl_secs: rolling,
        absolute_ttl_secs: absolute,
    }
}

fn parse_argon2(env: &mut Env) -> Argon2Config {
    let d = Argon2Config::default();
    let memory_kib = env.parse_or::<u32>("EDDA_ARGON2_MEMORY_KIB", d.memory_kib);
    let iterations = env.parse_or::<u32>("EDDA_ARGON2_ITERATIONS", d.iterations);
    let parallelism = env.parse_or::<u32>("EDDA_ARGON2_PARALLELISM", d.parallelism);
    if iterations == 0 {
        env.fail("EDDA_ARGON2_ITERATIONS", "must be greater than 0");
    }
    if parallelism == 0 {
        env.fail("EDDA_ARGON2_PARALLELISM", "must be greater than 0");
    }
    // The argon2 spec requires m_cost >= 8 * p_cost.
    if parallelism > 0 && memory_kib < 8 * parallelism {
        env.fail(
            "EDDA_ARGON2_MEMORY_KIB",
            format!(
                "must be at least 8 * EDDA_ARGON2_PARALLELISM ({})",
                8 * parallelism
            ),
        );
    }
    Argon2Config {
        memory_kib,
        iterations,
        parallelism,
    }
}

fn parse_webauthn(env: &mut Env) -> Option<WebauthnConfig> {
    let require_uv = env.parse_or("EDDA_WEBAUTHN_REQUIRE_UV", false);
    let allow_cross_origin = env.parse_or("EDDA_WEBAUTHN_ALLOW_CROSS_ORIGIN", false);
    match (
        env.get("EDDA_WEBAUTHN_RP_ID"),
        env.get("EDDA_WEBAUTHN_ORIGIN"),
    ) {
        (None, None) => None,
        (Some(rp_id), Some(origin)) => Some(WebauthnConfig {
            rp_id,
            origin,
            require_uv,
            allow_cross_origin,
        }),
        (rp_id, _origin) => {
            let missing = if rp_id.is_none() {
                "EDDA_WEBAUTHN_RP_ID"
            } else {
                "EDDA_WEBAUTHN_ORIGIN"
            };
            env.fail(
                missing,
                "WebAuthn needs both EDDA_WEBAUTHN_RP_ID and EDDA_WEBAUTHN_ORIGIN, or neither",
            );
            None
        }
    }
}

fn parse_oidc(env: &mut Env) -> Option<OidcConfig> {
    let fields = [
        ("EDDA_OAUTH_ISSUER_URL", env.get("EDDA_OAUTH_ISSUER_URL")),
        ("EDDA_OAUTH_CLIENT_ID", env.get("EDDA_OAUTH_CLIENT_ID")),
        (
            "EDDA_OAUTH_CLIENT_SECRET",
            env.get("EDDA_OAUTH_CLIENT_SECRET"),
        ),
        (
            "EDDA_OAUTH_REDIRECT_URL",
            env.get("EDDA_OAUTH_REDIRECT_URL"),
        ),
    ];
    let set = fields.iter().filter(|(_, v)| v.is_some()).count();
    if set == 0 {
        return None;
    }
    if set < fields.len() {
        for (name, value) in &fields {
            if value.is_none() {
                env.fail(name, "all four EDDA_OAUTH_* variables must be set together");
            }
        }
        return None;
    }
    let [issuer_url, client_id, client_secret, redirect_url] =
        fields.map(|(_, v)| v.expect("checked all set above"));
    Some(OidcConfig {
        issuer_url,
        client_id,
        client_secret,
        redirect_url,
    })
}

fn parse_smtp(env: &mut Env) -> Option<SmtpConfig> {
    match (env.get("EDDA_SMTP_URL"), env.get("EDDA_SMTP_FROM")) {
        (None, None) => None,
        (Some(url), Some(from)) => Some(SmtpConfig { url, from }),
        (url, _from) => {
            let missing = if url.is_none() {
                "EDDA_SMTP_URL"
            } else {
                "EDDA_SMTP_FROM"
            };
            env.fail(
                missing,
                "email needs both EDDA_SMTP_URL and EDDA_SMTP_FROM, or neither",
            );
            None
        }
    }
}

/// Decode exactly 64 hex chars into 32 bytes.
fn decode_hex_32(input: &str) -> Option<[u8; 32]> {
    let input = input.trim();
    if input.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in input.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    // `std::env` is process-global; these tests mutate it, so they take a
    // shared lock and restore what they touched.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvScope<'a> {
        _guard: MutexGuard<'a, ()>,
        touched: Vec<&'static str>,
        /// A fresh temp dir `EDDA_DATA_DIR` points at, so `from_env`'s
        /// `create_dir_all` never touches the real `./data`.
        data_dir: PathBuf,
    }

    impl<'a> EnvScope<'a> {
        fn new() -> Self {
            let guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let data_dir = std::env::temp_dir().join(format!(
                "edda-config-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            // Clear every var from_env reads so one test can't leak into
            // the next (or pick up the developer's real shell).
            let mut scope = Self {
                _guard: guard,
                touched: Vec::new(),
                data_dir: data_dir.clone(),
            };
            for var in ALL_VARS {
                scope.unset(var);
            }
            scope.set("EDDA_DATA_DIR", data_dir.to_str().expect("utf-8 temp path"));
            scope
        }
        fn set(&mut self, var: &'static str, value: &str) {
            self.touched.push(var);
            std::env::set_var(var, value);
        }
        fn unset(&mut self, var: &'static str) {
            self.touched.push(var);
            std::env::remove_var(var);
        }
    }

    impl Drop for EnvScope<'_> {
        fn drop(&mut self) {
            for var in &self.touched {
                std::env::remove_var(var);
            }
            let _ = std::fs::remove_dir_all(&self.data_dir);
        }
    }

    const ALL_VARS: &[&str] = &[
        "EDDA_DATA_DIR",
        "EDDA_DATABASE_URL",
        "IP",
        "PORT",
        "EDDA_SSH_PORT",
        "EDDA_EXTERNAL_URL",
        "EDDA_TRUSTED_ORIGINS",
        "EDDA_SECRET_KEYS",
        "EDDA_WEBAUTHN_RP_ID",
        "EDDA_WEBAUTHN_ORIGIN",
        "EDDA_WEBAUTHN_REQUIRE_UV",
        "EDDA_WEBAUTHN_ALLOW_CROSS_ORIGIN",
        "EDDA_OAUTH_ISSUER_URL",
        "EDDA_OAUTH_CLIENT_ID",
        "EDDA_OAUTH_CLIENT_SECRET",
        "EDDA_OAUTH_REDIRECT_URL",
        "EDDA_SMTP_URL",
        "EDDA_SMTP_FROM",
        "EDDA_RATE_LIMIT_PER_SECOND",
        "EDDA_RATE_LIMIT_BURST",
        "EDDA_AUTH_RATE_LIMIT_PER_SECOND",
        "EDDA_AUTH_RATE_LIMIT_BURST",
        "EDDA_TRUSTED_PROXIES",
        "EDDA_ARGON2_MEMORY_KIB",
        "EDDA_ARGON2_ITERATIONS",
        "EDDA_ARGON2_PARALLELISM",
        "EDDA_SESSION_ROLLING_TTL_SECONDS",
        "EDDA_SESSION_ABSOLUTE_TTL_SECONDS",
        "EDDA_REGISTRATION_MODE",
        "EDDA_ALLOWED_EMAIL_DOMAINS",
        "EDDA_REQUIRE_EMAIL_VERIFICATION",
        "EDDA_REQUIRE_SIGNIN_VIEW",
        "EDDA_GIT_MAX_PACK_BYTES",
        "EDDA_LFS_MAX_OBJECT_BYTES",
    ];

    #[test]
    fn an_empty_environment_is_the_zero_config_default() {
        let scope = EnvScope::new();
        let s = Settings::from_env().expect("empty env is valid — SQLite default");
        assert!(s.db.url.starts_with("sqlite:"));
        assert_eq!(s.http.bind.port(), 8080);
        assert_eq!(s.ssh.bind.port(), 2222);
        assert_eq!(s.http.external_url, "http://127.0.0.1:8080");
        assert!(s.webauthn.is_none() && s.oidc.is_none() && s.smtp.is_none());
        assert!(!s.secret_keys.is_configured());
        assert_eq!(s.rate_limit.per_second, 5);
        assert_eq!(s.git.repo_root, scope.data_dir.join("repos"));
        assert_eq!(s.git.limits, GitLimits::default());
        assert_eq!(s.git.limits.max_pack_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(
            s.ssh.host_key_path,
            scope.data_dir.join("ssh_host_ed25519_key")
        );
    }

    #[test]
    fn git_transfer_limits_parse_and_reject_zero() {
        let mut scope = EnvScope::new();
        scope.set("EDDA_GIT_MAX_PACK_BYTES", "104857600");
        scope.set("EDDA_LFS_MAX_OBJECT_BYTES", "52428800");
        let s = Settings::from_env().expect("valid limits");
        assert_eq!(s.git.limits.max_pack_bytes, 100 * 1024 * 1024);
        assert_eq!(s.git.limits.max_lfs_object_bytes, 50 * 1024 * 1024);

        scope.set("EDDA_GIT_MAX_PACK_BYTES", "0");
        let errs = Settings::from_env().expect_err("zero is rejected");
        assert!(errs.0.iter().any(|e| e.var == "EDDA_GIT_MAX_PACK_BYTES"));
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let mut scope = EnvScope::new();
        scope.set("PORT", "not-a-port");
        scope.set("EDDA_SSH_PORT", "70000");
        scope.set("EDDA_SECRET_KEYS", "too-short");
        scope.set("EDDA_WEBAUTHN_RP_ID", "example.com"); // origin missing
        scope.set("EDDA_OAUTH_CLIENT_ID", "abc"); // three others missing
        scope.set("EDDA_EXTERNAL_URL", "example.com"); // no scheme

        let errs = Settings::from_env().expect_err("this env is broken six ways");
        let vars: Vec<_> = errs.0.iter().map(|e| e.var).collect();
        assert!(vars.contains(&"PORT"));
        assert!(vars.contains(&"EDDA_SSH_PORT"));
        assert!(vars.contains(&"EDDA_SECRET_KEYS"));
        assert!(vars.contains(&"EDDA_WEBAUTHN_ORIGIN"));
        assert!(vars.contains(&"EDDA_OAUTH_ISSUER_URL"));
        assert!(vars.contains(&"EDDA_EXTERNAL_URL"));
    }

    #[test]
    fn a_valid_full_configuration_parses() {
        let mut scope = EnvScope::new();
        scope.set("EDDA_DATABASE_URL", "postgres://u:p@db:5432/edda");
        scope.set("IP", "0.0.0.0");
        scope.set("PORT", "3000");
        scope.set("EDDA_EXTERNAL_URL", "https://git.example.com/");
        scope.set(
            "EDDA_SECRET_KEYS",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        scope.set("EDDA_WEBAUTHN_RP_ID", "example.com");
        scope.set("EDDA_WEBAUTHN_ORIGIN", "https://git.example.com");
        scope.set("EDDA_SMTP_URL", "smtp://localhost:25");
        scope.set("EDDA_SMTP_FROM", "Edda <no-reply@example.com>");
        scope.set("EDDA_RATE_LIMIT_PER_SECOND", "50");

        let s = Settings::from_env().expect("valid config");
        assert_eq!(s.db.url, "postgres://u:p@db:5432/edda");
        assert_eq!(s.http.bind.to_string(), "0.0.0.0:3000");
        assert_eq!(s.http.external_url, "https://git.example.com"); // trailing / trimmed
        assert!(s.secret_keys.is_configured());
        assert_eq!(s.webauthn.as_ref().unwrap().rp_id, "example.com");
        assert_eq!(s.smtp.as_ref().unwrap().from, "Edda <no-reply@example.com>");
        assert_eq!(s.rate_limit.per_second, 50);
    }

    #[test]
    fn a_multi_key_secret_key_list_parses_in_order_first_is_primary() {
        let mut scope = EnvScope::new();
        let k1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let k2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        assert_eq!(k1.len(), 64);
        scope.set("EDDA_SECRET_KEYS", &format!("v2:{k1}, v1:{k2}"));
        let s = Settings::from_env().expect("valid");
        assert!(s.secret_keys.is_configured());
        let all = s.secret_keys.all();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0, "v2");
        assert_eq!(all[1].0, "v1");
        assert_eq!(s.secret_keys.primary_id().as_deref(), Some("v2"));
    }

    #[test]
    fn a_malformed_or_duplicate_secret_key_entry_is_a_startup_error() {
        let mut scope = EnvScope::new();
        let k = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        // second entry is short, and a bare key alongside a named one.
        scope.set("EDDA_SECRET_KEYS", &format!("v2:{k},v1:dead"));
        let errs = Settings::from_env().expect_err("v1:dead is not 64 hex");
        assert!(errs.0.iter().any(|e| e.var == "EDDA_SECRET_KEYS"));

        scope.set("EDDA_SECRET_KEYS", &format!("v1:{k},v1:{k}"));
        let errs = Settings::from_env().expect_err("duplicate id");
        assert!(errs
            .0
            .iter()
            .any(|e| e.var == "EDDA_SECRET_KEYS" && e.problem.contains("duplicate")));
    }

    #[test]
    fn argon2_and_auth_rate_limit_knobs_parse_and_reject_bad_values() {
        let mut scope = EnvScope::new();
        scope.set("EDDA_ARGON2_MEMORY_KIB", "65536");
        scope.set("EDDA_ARGON2_ITERATIONS", "3");
        scope.set("EDDA_ARGON2_PARALLELISM", "2");
        scope.set("EDDA_AUTH_RATE_LIMIT_PER_SECOND", "2");
        scope.set("EDDA_AUTH_RATE_LIMIT_BURST", "8");
        scope.set("EDDA_TRUSTED_PROXIES", "10.0.0.0/8, 192.168.1.1");
        let s = Settings::from_env().expect("valid");
        assert_eq!(s.argon2.memory_kib, 65536);
        assert_eq!(s.argon2.parallelism, 2);
        assert_eq!(s.rate_limit.auth_per_second, 2);
        assert_eq!(s.rate_limit.trusted_proxies.len(), 2);

        // memory below 8*parallelism is rejected.
        scope.set("EDDA_ARGON2_MEMORY_KIB", "8");
        let errs = Settings::from_env().expect_err("m_cost < 8*p_cost");
        assert!(errs.0.iter().any(|e| e.var == "EDDA_ARGON2_MEMORY_KIB"));
    }

    #[test]
    fn a_bad_trusted_proxy_cidr_is_rejected() {
        let mut scope = EnvScope::new();
        scope.set("EDDA_TRUSTED_PROXIES", "not-an-ip");
        let errs = Settings::from_env().expect_err("bad cidr");
        assert!(errs.0.iter().any(|e| e.var == "EDDA_TRUSTED_PROXIES"));
    }

    #[test]
    fn registration_and_instance_privacy_knobs_parse() {
        let mut scope = EnvScope::new();

        // Default: wide open, not private.
        let s = Settings::from_env().expect("valid");
        assert_eq!(
            s.registration.policy.mode,
            edda_domain::RegistrationMode::Open
        );
        assert!(!s.registration.require_signin_to_view);
        assert!(s.registration.policy.allowed_email_domains.is_empty());

        scope.set("EDDA_REGISTRATION_MODE", "approval");
        scope.set("EDDA_ALLOWED_EMAIL_DOMAINS", "example.com, @Corp.Example ");
        scope.set("EDDA_REQUIRE_EMAIL_VERIFICATION", "true");
        scope.set("EDDA_REQUIRE_SIGNIN_VIEW", "true");
        let s = Settings::from_env().expect("valid");
        assert_eq!(
            s.registration.policy.mode,
            edda_domain::RegistrationMode::Approval
        );
        assert_eq!(
            s.registration.policy.allowed_email_domains,
            vec!["example.com".to_string(), "corp.example".to_string()]
        );
        assert!(s.registration.policy.require_email_verification);
        assert!(s.registration.require_signin_to_view);

        scope.set("EDDA_REGISTRATION_MODE", "halfway");
        let errs = Settings::from_env().expect_err("bad mode");
        assert!(errs.0.iter().any(|e| e.var == "EDDA_REGISTRATION_MODE"));
    }
}

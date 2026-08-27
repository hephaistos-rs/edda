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
/// CSRF-origin defaults in later phases).
#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub bind: SocketAddr,
    pub external_url: String,
}

/// Where the git-over-SSH listener binds, and where its persistent host
/// key lives (generated on first start).
#[derive(Debug, Clone)]
pub struct SshConfig {
    pub bind: SocketAddr,
    pub host_key_path: PathBuf,
}

/// The resolved database connection URL — `EDDA_DATABASE_URL` verbatim, or
/// a SQLite file under the data dir when unset (the zero-config default).
#[derive(Debug, Clone)]
pub struct DbConfig {
    pub url: String,
}

/// Where bare repositories live on disk (`{data_dir}/repos`).
#[derive(Debug, Clone)]
pub struct GitConfig {
    pub repo_root: PathBuf,
}

/// AES-256-GCM key material for at-rest secret encryption (TOTP shared
/// secrets, webhook signing secrets). Optional: an instance that never
/// enrolls 2FA or creates a webhook never needs it — but if
/// `EDDA_SECRET_KEYS` *is* set, it must be valid.
///
/// Format today is a single 64-hex key (optionally `id:hex`, id ignored
/// for now); Phase 8 turns the id into real key-rotation.
#[derive(Debug, Clone, Default)]
pub struct SecretKeys {
    primary: Option<[u8; 32]>,
}

impl SecretKeys {
    /// The key to encrypt new secrets with, if configured.
    pub fn primary(&self) -> Option<[u8; 32]> {
        self.primary
    }

    pub fn is_configured(&self) -> bool {
        self.primary.is_some()
    }
}

/// WebAuthn relying-party identity. Both-or-neither: one without the other
/// is a configuration error, since a mismatch fails every ceremony.
#[derive(Debug, Clone)]
pub struct WebauthnConfig {
    pub rp_id: String,
    pub origin: String,
}

impl WebauthnConfig {
    pub fn into_auth(self) -> edda_auth::webauthn::Config {
        edda_auth::webauthn::Config {
            rp_id: self.rp_id,
            origin: self.origin,
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

/// Per-client token-bucket limits for the API surface (never the git or
/// LFS routes). Defaults are generous enough for interactive use.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    pub per_second: u64,
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_second: 5,
            burst: 20,
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

        let db_url = edda_db::effective_url(env.get("EDDA_DATABASE_URL").as_deref(), &data_dir);

        let secret_keys = parse_secret_keys(&mut env);
        let webauthn = parse_webauthn(&mut env);
        let oidc = parse_oidc(&mut env);
        let smtp = parse_smtp(&mut env);

        let per_second = env.parse_or::<u64>("EDDA_RATE_LIMIT_PER_SECOND", 5);
        if per_second == 0 {
            env.fail("EDDA_RATE_LIMIT_PER_SECOND", "must be greater than 0");
        }
        let burst = env.parse_or::<u32>("EDDA_RATE_LIMIT_BURST", 20);
        if burst == 0 {
            env.fail("EDDA_RATE_LIMIT_BURST", "must be greater than 0");
        }

        if !env.errors.is_empty() {
            return Err(ConfigErrors(env.errors));
        }

        Ok(Settings {
            http: HttpConfig {
                bind: SocketAddr::new(ip, http_port),
                external_url,
            },
            ssh: SshConfig {
                bind: SocketAddr::new(ip, ssh_port),
                host_key_path: data_dir.join("ssh_host_ed25519_key"),
            },
            db: DbConfig { url: db_url },
            git: GitConfig {
                repo_root: data_dir.join("repos"),
            },
            secret_keys,
            webauthn,
            oidc,
            smtp,
            rate_limit: RateLimitConfig {
                per_second: per_second.max(1),
                burst: burst.max(1),
            },
            data_dir,
        })
    }
}

fn parse_secret_keys(env: &mut Env) -> SecretKeys {
    let Some(raw) = env.get("EDDA_SECRET_KEYS") else {
        return SecretKeys::default();
    };
    // Forward-compatible with the Phase-8 `id:hex,id:hex` format: take the
    // first entry, and the part after a `:` if present.
    let first = raw.split(',').next().unwrap_or(&raw).trim();
    let hex = first.rsplit(':').next().unwrap_or(first);
    match decode_hex_32(hex) {
        Some(key) => SecretKeys { primary: Some(key) },
        None => {
            env.fail(
                "EDDA_SECRET_KEYS",
                "must be a 64-character hex-encoded 32-byte key (optionally `id:hex`)",
            );
            SecretKeys::default()
        }
    }
}

fn parse_webauthn(env: &mut Env) -> Option<WebauthnConfig> {
    match (
        env.get("EDDA_WEBAUTHN_RP_ID"),
        env.get("EDDA_WEBAUTHN_ORIGIN"),
    ) {
        (None, None) => None,
        (Some(rp_id), Some(origin)) => Some(WebauthnConfig { rp_id, origin }),
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
        "EDDA_SECRET_KEYS",
        "EDDA_WEBAUTHN_RP_ID",
        "EDDA_WEBAUTHN_ORIGIN",
        "EDDA_OAUTH_ISSUER_URL",
        "EDDA_OAUTH_CLIENT_ID",
        "EDDA_OAUTH_CLIENT_SECRET",
        "EDDA_OAUTH_REDIRECT_URL",
        "EDDA_SMTP_URL",
        "EDDA_SMTP_FROM",
        "EDDA_RATE_LIMIT_PER_SECOND",
        "EDDA_RATE_LIMIT_BURST",
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
        assert_eq!(
            s.ssh.host_key_path,
            scope.data_dir.join("ssh_host_ed25519_key")
        );
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
    fn a_versioned_secret_key_entry_takes_the_hex_after_the_colon() {
        let mut scope = EnvScope::new();
        scope.set(
            "EDDA_SECRET_KEYS",
            "v2:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,v1:dead",
        );
        let s = Settings::from_env().expect("valid");
        assert!(s.secret_keys.is_configured());
    }
}

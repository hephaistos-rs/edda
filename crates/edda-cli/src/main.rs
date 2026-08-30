//! Instance administration CLI: a thin binary that talks to `edda-db` /
//! `edda-auth` directly, bypassing HTTP entirely — run from the same
//! host/container as the server, not a remote API client. It resolves the
//! database the exact same way the server does
//! (`EDDA_DATABASE_URL` / `EDDA_DATA_DIR` → `edda_db::effective_url`), so
//! it always points at whichever database the running instance uses.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use edda_db::{DbPool, UserRepo};
use edda_domain::UserId;

#[derive(Parser)]
#[command(
    name = "edda-cli",
    about = "Offline instance administration for an Edda server",
    version,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage user accounts.
    #[command(subcommand)]
    User(UserCommand),
    /// Secret-key maintenance.
    #[command(subcommand)]
    Secrets(SecretsCommand),
    /// Run health checks against the configured instance.
    Doctor,
    /// Write a portable backup (SQLite database + data directory) to a
    /// `.tar.gz`.
    Dump {
        /// Output path. Defaults to `edda-dump-<unixtime>.tar.gz` in the
        /// current directory.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Restore a backup produced by `dump`.
    Restore {
        /// The `.tar.gz` archive to restore.
        input: PathBuf,
        /// Overwrite a non-empty data directory / an existing database.
        #[arg(long)]
        force: bool,
    },
    /// Inspect repositories.
    #[command(subcommand)]
    Repo(RepoCommand),
}

#[derive(Subcommand)]
enum UserCommand {
    /// Create an account (a random password is assigned and never shown).
    Create {
        username: String,
        email: String,
        #[arg(long)]
        admin: bool,
    },
    /// List every account.
    List,
    /// Block the next sign-in for an account.
    Disable { username: String },
    /// Re-allow sign-in for a disabled account.
    Enable { username: String },
    /// Delete an account (fails if it still owns repositories).
    Delete { username: String },
}

#[derive(Subcommand)]
enum SecretsCommand {
    /// Re-encrypt every stored TOTP / webhook secret under the first
    /// entry of `EDDA_SECRET_KEYS`; run after prepending a new primary
    /// key, then drop the old entry.
    Rotate,
}

#[derive(Subcommand)]
enum RepoCommand {
    /// List every repository with its owner.
    List,
    /// Queue a garbage-collection pass for one repository (`owner/name`).
    /// The server's job poller runs it.
    Gc { repo: String },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

/// The `EDDA_DATA_DIR` the server would use (default `./data`), created if
/// missing.
fn data_dir() -> Result<PathBuf, String> {
    let dir = std::env::var("EDDA_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./data"));
    std::fs::create_dir_all(&dir)
        .map_err(|err| format!("could not create data dir {dir:?}: {err}"))?;
    Ok(dir)
}

async fn connect() -> Result<DbPool, String> {
    let url = edda_db::effective_url(
        std::env::var("EDDA_DATABASE_URL").ok().as_deref(),
        &data_dir()?,
    );
    // The CLI is short-lived and single-threaded in practice — the
    // default pool shape is plenty; it has no `Settings` to draw from.
    edda_db::pool(&url, edda_db::PoolOptions::default())
        .await
        .map_err(|err| format!("could not connect to the database: {err}"))
}

async fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::User(cmd) => user_command(&connect().await?, cmd).await,
        Command::Secrets(SecretsCommand::Rotate) => rotate_secrets(&connect().await?).await,
        Command::Doctor => doctor(&connect().await?, &data_dir()?).await,
        Command::Dump { out } => dump(&connect().await?, &data_dir()?, out).await,
        // `restore` lays down files; it never opens the database.
        Command::Restore { input, force } => restore(&data_dir()?, &input, force),
        Command::Repo(RepoCommand::List) => repo_list(&connect().await?).await,
        Command::Repo(RepoCommand::Gc { repo }) => repo_gc(&connect().await?, &repo).await,
    }
}

// ─────────────────────────────── users ───────────────────────────────

async fn user_command(pool: &DbPool, cmd: UserCommand) -> Result<(), String> {
    match cmd {
        UserCommand::Create {
            username,
            email,
            admin,
        } => create(pool, &username, &email, admin).await,
        UserCommand::List => list(pool).await,
        UserCommand::Disable { username } => set_disabled(pool, &username, true).await,
        UserCommand::Enable { username } => set_disabled(pool, &username, false).await,
        UserCommand::Delete { username } => delete(pool, &username).await,
    }
}

async fn create(pool: &DbPool, username: &str, email: &str, is_admin: bool) -> Result<(), String> {
    // An admin creating an account from the CLI bypasses the instance's
    // registration policy: the default policy (open, no verification)
    // makes the account immediately active.
    let outcome = edda_auth::signup(
        pool,
        &edda_domain::RegistrationPolicy::default(),
        username,
        email,
        &random_password(),
    )
    .await
    .map_err(|err| err.to_string())?;
    let user = outcome.user;
    if is_admin {
        UserRepo::set_admin(pool, user.id, true)
            .await
            .map_err(|err| err.to_string())?;
    }
    println!(
        "created user {username} ({email}){}",
        if is_admin { " [admin]" } else { "" }
    );
    println!(
        "no password was set — this account can only sign in via a password reset, \
         an SSH key, or another authentication method added from settings"
    );
    Ok(())
}

/// A freshly generated, never-displayed password — `user create`
/// deliberately doesn't accept one on the command line (it would land in
/// shell history and process listings).
fn random_password() -> String {
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn list(pool: &DbPool) -> Result<(), String> {
    let users = UserRepo::list_all(pool)
        .await
        .map_err(|err| err.to_string())?;
    if users.is_empty() {
        println!("no users");
        return Ok(());
    }
    for user in users {
        let admin = if user.is_admin { " [admin]" } else { "" };
        let status = if user.disabled_at.is_some() {
            " [disabled]"
        } else {
            ""
        };
        println!("{}\t{}{admin}{status}", user.username, user.email);
    }
    Ok(())
}

async fn find_user(pool: &DbPool, username: &str) -> Result<UserId, String> {
    UserRepo::find_by_username(pool, username)
        .await
        .map_err(|err| err.to_string())?
        .map(|user| user.id)
        .ok_or_else(|| format!("no such user: {username}"))
}

async fn set_disabled(pool: &DbPool, username: &str, disabled: bool) -> Result<(), String> {
    let id = find_user(pool, username).await?;
    UserRepo::set_disabled(pool, id, disabled)
        .await
        .map_err(|err| err.to_string())?;
    println!(
        "{username} is now {}",
        if disabled { "disabled" } else { "enabled" }
    );
    if disabled {
        println!(
            "note: an established session stays valid until it expires or is logged out — \
             disabling only blocks the *next* authentication attempt"
        );
    }
    Ok(())
}

async fn delete(pool: &DbPool, username: &str) -> Result<(), String> {
    let id = find_user(pool, username).await?;
    UserRepo::delete(pool, id)
        .await
        .map_err(|err| err.to_string())?;
    println!("deleted user {username}");
    println!(
        "note: an account that still owns repositories cannot be deleted — transfer or \
         delete those first"
    );
    Ok(())
}

// ────────────────────────────── secrets ──────────────────────────────

/// Re-encrypts every `secret_ciphertext` (TOTP + webhook) under the
/// current primary `EDDA_SECRET_KEYS` entry. Idempotent.
async fn rotate_secrets(pool: &DbPool) -> Result<(), String> {
    let (keys, primary_id) = parse_secret_keys()?;
    edda_auth::secret_box::init(keys, Some(primary_id.clone()));

    let secrets = edda_db::SecretRotationRepo::load_all(pool)
        .await
        .map_err(|err| err.to_string())?;
    if secrets.is_empty() {
        println!("no stored secrets to rotate");
        return Ok(());
    }
    let mut rotated = 0usize;
    for secret in &secrets {
        let reencrypted = edda_auth::secret_box::reencrypt(&secret.ciphertext)
            .map_err(|err| format!("{} {}: {err}", secret.kind, secret.id))?;
        edda_db::SecretRotationRepo::store(pool, secret, &reencrypted)
            .await
            .map_err(|err| err.to_string())?;
        rotated += 1;
    }
    println!("re-encrypted {rotated} secret(s) under key id {primary_id:?}");
    println!("older key ids can now be removed from EDDA_SECRET_KEYS");
    Ok(())
}

/// `(id, key)` pairs plus the primary id — what `secret_box::init` takes.
type ResolvedSecretKeys = (Vec<(String, [u8; 32])>, String);

/// The same `EDDA_SECRET_KEYS` shape `edda_app::config` parses: a
/// comma-separated list of `id:hex` (or a single bare 64-hex key, id
/// `default`), first entry primary.
fn parse_secret_keys() -> Result<ResolvedSecretKeys, String> {
    let raw = std::env::var("EDDA_SECRET_KEYS")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .ok_or("EDDA_SECRET_KEYS is not set — nothing to rotate to")?;
    let items: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let mut entries = Vec::new();
    for item in &items {
        let (id, hex) = match item.split_once(':') {
            Some((id, hex)) => (id.trim().to_string(), hex.trim()),
            None if items.len() == 1 => ("default".to_string(), item.trim()),
            None => return Err("every EDDA_SECRET_KEYS entry must be `id:hex`".to_string()),
        };
        let key = decode_hex_32(hex)
            .ok_or_else(|| format!("key {id:?} must be 64 hex characters (32 bytes)"))?;
        entries.push((id, key));
    }
    let primary_id = entries
        .first()
        .map(|(id, _)| id.clone())
        .ok_or("EDDA_SECRET_KEYS has no entries")?;
    Ok((entries, primary_id))
}

fn decode_hex_32(input: &str) -> Option<[u8; 32]> {
    let input = input.trim();
    if input.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in input.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

// ─────────────────────────────── doctor ──────────────────────────────

/// Health checks over what `edda-db` / `edda-auth` can see without HTTP:
/// database liveness, an orphan-row scan, `EDDA_SECRET_KEYS` parsing, the
/// data-directory footprint, and the dead-letter count. Prints a report
/// and exits non-zero if any check found a problem.
async fn doctor(pool: &DbPool, data_dir: &Path) -> Result<(), String> {
    let mut problems = 0usize;
    let mut check = |ok: bool, label: &str, detail: String| {
        println!("{} {label}: {detail}", if ok { "ok  " } else { "WARN" });
        if !ok {
            problems += 1;
        }
    };

    match edda_db::health(pool).await {
        Ok(()) => check(
            true,
            "database",
            format!("reachable ({:?})", pool.backend()),
        ),
        Err(err) => check(false, "database", err.to_string()),
    }

    match edda_db::EventRepo::fetch_unprocessed(pool, 1_000).await {
        Ok(events) => check(
            events.len() < 500,
            "outbox backlog",
            format!("{} unprocessed event(s)", events.len()),
        ),
        Err(err) => check(false, "outbox backlog", err.to_string()),
    }

    match edda_db::JobRepo::list_by_status(pool, edda_domain::JobStatus::Failed, 1_000).await {
        Ok(dead) => check(
            dead.is_empty(),
            "dead-letter queue",
            format!("{} dead job(s)", dead.len()),
        ),
        Err(err) => check(false, "dead-letter queue", err.to_string()),
    }

    match edda_db::RepositoryRepo::list_all(pool).await {
        Ok(repos) => check(true, "repositories", format!("{} row(s)", repos.len())),
        Err(err) => check(false, "repositories", err.to_string()),
    }

    match std::env::var("EDDA_SECRET_KEYS") {
        Err(_) => check(
            true,
            "EDDA_SECRET_KEYS",
            "not configured (optional — at-rest encryption disabled)".to_string(),
        ),
        Ok(_) => match parse_secret_keys() {
            Ok((keys, primary)) => check(
                true,
                "EDDA_SECRET_KEYS",
                format!("{} key(s), primary {primary:?}", keys.len()),
            ),
            Err(err) => check(false, "EDDA_SECRET_KEYS", err),
        },
    }

    let (bytes, files) = dir_footprint(data_dir);
    check(
        true,
        "data directory",
        format!(
            "{files} file(s), {bytes} byte(s) under {}",
            data_dir.display()
        ),
    );

    if problems == 0 {
        println!("\nall checks passed");
        Ok(())
    } else {
        Err(format!("{problems} check(s) reported a problem"))
    }
}

/// `(total bytes, file count)` under `root`, recursive; symlinks not
/// followed.
fn dir_footprint(root: &Path) -> (u64, u64) {
    let mut bytes = 0;
    let mut files = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                bytes += meta.len();
                files += 1;
            }
        }
    }
    (bytes, files)
}

// ────────────────────────── dump / restore ───────────────────────────

const DB_BASENAME: &str = "edda.db";

/// Bundles a consistent SQLite snapshot plus the `data/` tree into a
/// `.tar.gz`. SQLite only — for PostgreSQL / MySQL this refuses and
/// points at `pg_dump` / `mysqldump`.
async fn dump(pool: &DbPool, data_dir: &Path, out: Option<PathBuf>) -> Result<(), String> {
    if pool.backend() != edda_db::Backend::Sqlite {
        return Err(
            "dump supports the SQLite backend only — use pg_dump / mysqldump for \
             PostgreSQL / MySQL (the data/ tree can still be tar'd separately)"
                .to_string(),
        );
    }
    let out = out.unwrap_or_else(|| PathBuf::from(format!("edda-dump-{}.tar.gz", now_unix())));
    if out.exists() {
        return Err(format!("{} already exists", out.display()));
    }

    // A defragmented, point-in-time copy of the database — safe to take
    // while the server is running.
    let staged_db = std::env::temp_dir().join(format!(
        "edda-dump-{}-{}.db",
        std::process::id(),
        now_unix()
    ));
    let _ = std::fs::remove_file(&staged_db);
    edda_db::backup_sqlite(pool, &staged_db)
        .await
        .map_err(|err| format!("VACUUM INTO failed: {err}"))?;

    let file =
        std::fs::File::create(&out).map_err(|err| format!("create {}: {err}", out.display()))?;
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    builder
        .append_path_with_name(&staged_db, DB_BASENAME)
        .map_err(|err| format!("archiving the database: {err}"))?;
    // Everything under data/ except the live database files (the staged
    // copy above is the authoritative one).
    append_data_dir(&mut builder, data_dir).map_err(|err| format!("archiving data/: {err}"))?;
    let encoder = builder
        .into_inner()
        .map_err(|err| format!("finishing the tar stream: {err}"))?;
    encoder
        .finish()
        .map_err(|err| format!("finishing the gzip stream: {err}"))?;
    let _ = std::fs::remove_file(&staged_db);

    println!("wrote {}", out.display());
    Ok(())
}

fn append_data_dir<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    data_dir: &Path,
) -> std::io::Result<()> {
    let mut stack = vec![data_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // The live SQLite files change under us; the staged copy is in
            // the archive already.
            if dir == data_dir
                && (name == DB_BASENAME || name.starts_with(&format!("{DB_BASENAME}-")))
            {
                continue;
            }
            let rel = path
                .strip_prefix(data_dir)
                .expect("walked path is under data_dir");
            let archived = Path::new("data").join(rel);
            if entry.file_type()?.is_dir() {
                stack.push(path);
            } else {
                builder.append_path_with_name(&path, &archived)?;
            }
        }
    }
    Ok(())
}

/// Unpacks a `dump` archive: the `edda.db` entry becomes
/// `<data_dir>/edda.db`, the `data/` entries land under `<data_dir>`.
/// Refuses a non-empty target unless `--force`.
fn restore(data_dir: &Path, input: &Path, force: bool) -> Result<(), String> {
    let db_path = data_dir.join(DB_BASENAME);
    let target_populated = db_path.exists()
        || std::fs::read_dir(data_dir)
            .map(|mut it| it.next().is_some())
            .unwrap_or(false);
    if target_populated && !force {
        return Err(format!(
            "{} is not empty — pass --force to overwrite",
            data_dir.display()
        ));
    }

    let file =
        std::fs::File::open(input).map_err(|err| format!("open {}: {err}", input.display()))?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let mut restored_db = false;
    for entry in archive.entries().map_err(|err| err.to_string())? {
        let mut entry = entry.map_err(|err| err.to_string())?;
        let path = entry.path().map_err(|err| err.to_string())?.into_owned();
        let dest = if path == Path::new(DB_BASENAME) {
            restored_db = true;
            db_path.clone()
        } else if let Ok(rel) = path.strip_prefix("data") {
            data_dir.join(rel)
        } else {
            // An unexpected entry — skip it rather than write outside the
            // data directory.
            continue;
        };
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        entry.unpack(&dest).map_err(|err| err.to_string())?;
    }
    if !restored_db {
        return Err("the archive contained no edda.db entry — is it an edda dump?".to_string());
    }
    println!("restored into {}", data_dir.display());
    println!("start the server pointed at this data directory (SQLite backend)");
    Ok(())
}

// ──────────────────────────────── repo ───────────────────────────────

async fn repo_list(pool: &DbPool) -> Result<(), String> {
    let repos = edda_db::RepositoryRepo::list_all_with_owner_username(pool)
        .await
        .map_err(|err| err.to_string())?;
    if repos.is_empty() {
        println!("no repositories");
        return Ok(());
    }
    for (repo, owner) in repos {
        let visibility = if repo.is_private() {
            "private"
        } else {
            "public"
        };
        println!("{owner}/{}\t{visibility}", repo.name);
    }
    Ok(())
}

async fn repo_gc(pool: &DbPool, spec: &str) -> Result<(), String> {
    let (owner, name) = spec
        .split_once('/')
        .ok_or("expected an `owner/name` repository")?;
    let repo = edda_db::RepositoryRepo::find_by_owner_username_and_name(pool, owner, name)
        .await
        .map_err(|err| err.to_string())?
        .ok_or_else(|| format!("no such repository: {spec}"))?;
    edda_db::JobRepo::enqueue(
        pool,
        edda_domain::JobId::new(),
        &edda_domain::JobPayload::RunRepoGc {
            repository_id: repo.id,
        },
        now_unix(),
        5,
    )
    .await
    .map_err(|err| err.to_string())?;
    println!("queued a gc for {spec}; the server's job poller will run it");
    Ok(())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

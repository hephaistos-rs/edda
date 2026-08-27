//! Instance administration CLI: a thin binary that talks to `edda-db`/
//! `edda-auth` directly, bypassing HTTP entirely — run from the same
//! host/container as the server, not a remote API client. Connects via
//! the exact same `EDDA_DATABASE_URL`/`EDDA_DATA_DIR` resolution the
//! server uses (`edda_db::effective_url`), so this points at whichever
//! database the running server itself uses.

use std::process::ExitCode;

use edda_db::UserRepo;
use edda_domain::UserId;

fn print_usage() {
    eprintln!(
        "usage: edda-cli user <create|list|disable|enable|delete> [args...]\n\
         \n\
         edda-cli user create <username> <email> [--admin]\n\
         edda-cli user list\n\
         edda-cli user disable <username>\n\
         edda-cli user enable <username>\n\
         edda-cli user delete <username>"
    );
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &[String]) -> Result<(), String> {
    // The same `EDDA_DATABASE_URL` / `EDDA_DATA_DIR` resolution the server
    // uses (`edda_db::effective_url`), so this points at whichever database
    // the running instance does. As a binary entry point, reading the
    // environment directly here is allowed (`edda-http::config` is the
    // server's equivalent; a shared `Settings` is a later phase).
    let data_dir = std::env::var("EDDA_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("./data"));
    std::fs::create_dir_all(&data_dir)
        .map_err(|err| format!("could not create data dir {data_dir:?}: {err}"))?;
    let url = edda_db::effective_url(
        std::env::var("EDDA_DATABASE_URL").ok().as_deref(),
        &data_dir,
    );
    // The CLI is short-lived and single-threaded in practice — the default
    // pool shape is more than enough; it has no `Settings` to draw from.
    let pool = edda_db::pool(&url, edda_db::PoolOptions::default())
        .await
        .map_err(|err| format!("could not connect to the database: {err}"))?;

    match args {
        [subcommand, rest @ ..] if subcommand == "user" => user_command(&pool, rest).await,
        _ => {
            print_usage();
            Err("no subcommand given".to_string())
        }
    }
}

async fn user_command(pool: &edda_db::DbPool, args: &[String]) -> Result<(), String> {
    match args {
        [action, username, email, rest @ ..] if action == "create" => {
            let is_admin = rest.iter().any(|arg| arg == "--admin");
            create(pool, username, email, is_admin).await
        }
        [action] if action == "list" => list(pool).await,
        [action, username] if action == "disable" => set_disabled(pool, username, true).await,
        [action, username] if action == "enable" => set_disabled(pool, username, false).await,
        [action, username] if action == "delete" => delete(pool, username).await,
        _ => {
            print_usage();
            Err("unrecognized `user` invocation".to_string())
        }
    }
}

async fn create(
    pool: &edda_db::DbPool,
    username: &str,
    email: &str,
    is_admin: bool,
) -> Result<(), String> {
    let user = edda_auth::signup(pool, username, email, &random_password())
        .await
        .map_err(|err| err.to_string())?;
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
         an SSH key, or another authentication method added from settings; \
         use the web UI's signup flow instead if you need one set now"
    );
    Ok(())
}

/// A freshly generated, never-displayed password — `edda-cli user create`
/// deliberately doesn't prompt for or accept one on the command line (a
/// password passed as a CLI argument ends up in shell history and process
/// listings, a real credential-leak vector this avoids entirely rather
/// than working around).
fn random_password() -> String {
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn list(pool: &edda_db::DbPool) -> Result<(), String> {
    let users = UserRepo::list_all(pool)
        .await
        .map_err(|err| err.to_string())?;
    if users.is_empty() {
        println!("no users");
        return Ok(());
    }
    for user in users {
        let admin_tag = if user.is_admin { " [admin]" } else { "" };
        let status = if user.disabled_at.is_some() {
            " [disabled]"
        } else {
            ""
        };
        println!("{}\t{}{admin_tag}{status}", user.username, user.email);
    }
    Ok(())
}

async fn find_user(pool: &edda_db::DbPool, username: &str) -> Result<UserId, String> {
    UserRepo::find_by_username(pool, username)
        .await
        .map_err(|err| err.to_string())?
        .map(|user| user.id)
        .ok_or_else(|| format!("no such user: {username}"))
}

async fn set_disabled(
    pool: &edda_db::DbPool,
    username: &str,
    disabled: bool,
) -> Result<(), String> {
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
            "note: any session this account already established stays valid until it expires \
             or is logged out — disabling only prevents the *next* authentication attempt \
             (password, token, SSH key, or OAuth)"
        );
    }
    Ok(())
}

async fn delete(pool: &edda_db::DbPool, username: &str) -> Result<(), String> {
    let id = find_user(pool, username).await?;
    UserRepo::delete(pool, id)
        .await
        .map_err(|err| err.to_string())?;
    println!("deleted user {username}");
    println!(
        "note: repositories this account owned are NOT deleted — ownership transfer or \
         deletion of those repositories is a separate, deliberate action, not a side effect \
         of removing the account"
    );
    Ok(())
}

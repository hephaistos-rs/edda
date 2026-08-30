//! Phase 12: the `doctor` / `dump` / `restore` / `repo` subcommands,
//! exercised by spawning the real compiled `edda-cli` binary — the same
//! subprocess approach `disable_blocks_login.rs` uses.

use std::path::{Path, PathBuf};
use std::process::Command;

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "edda-cli-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `(success, stdout, stderr)` from `edda-cli` run against `data_dir`
/// (SQLite under it).
fn run(data_dir: &Path, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_edda-cli"))
        .args(args)
        .env("EDDA_DATA_DIR", data_dir)
        .env_remove("EDDA_DATABASE_URL")
        .env_remove("EDDA_SECRET_KEYS")
        .output()
        .expect("failed to run edda-cli");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn doctor_passes_on_a_fresh_instance_and_repo_list_is_empty() {
    let data_dir = scratch("doctor");

    let (ok, stdout, stderr) = run(&data_dir, &["doctor"]);
    assert!(ok, "doctor failed:\n{stdout}\n{stderr}");
    assert!(stdout.contains("all checks passed"), "{stdout}");
    assert!(stdout.contains("database: reachable"), "{stdout}");

    let (ok, stdout, _) = run(&data_dir, &["repo", "list"]);
    assert!(ok);
    assert!(stdout.contains("no repositories"), "{stdout}");

    let _ = std::fs::remove_dir_all(&data_dir);
}

#[test]
fn dump_then_restore_round_trips_the_database_and_data_tree() {
    let source = scratch("dump-src");

    // Seed an account and a stray data file.
    let (ok, out, err) = run(&source, &["user", "create", "alice", "alice@example.com"]);
    assert!(ok, "user create failed:\n{out}\n{err}");
    std::fs::create_dir_all(source.join("repos/alice")).unwrap();
    std::fs::write(source.join("repos/alice/marker"), b"hello").unwrap();

    let archive = scratch("dump-out").join("backup.tar.gz");
    let (ok, out, err) = run(&source, &["dump", "--out", archive.to_str().unwrap()]);
    assert!(ok, "dump failed:\n{out}\n{err}");
    assert!(archive.exists());

    // Restore into a pristine directory.
    let target = scratch("dump-tgt");
    let (ok, out, err) = run(&target, &["restore", archive.to_str().unwrap()]);
    assert!(ok, "restore failed:\n{out}\n{err}");
    assert!(target.join("edda.db").exists(), "the database was restored");
    assert_eq!(
        std::fs::read(target.join("repos/alice/marker")).unwrap(),
        b"hello",
        "the data tree was restored"
    );

    // The restored database still lists the account.
    let (ok, stdout, _) = run(&target, &["user", "list"]);
    assert!(ok);
    assert!(stdout.contains("alice\talice@example.com"), "{stdout}");

    // A second restore over a populated directory needs --force.
    let (ok, _, err) = run(&target, &["restore", archive.to_str().unwrap()]);
    assert!(!ok);
    assert!(err.contains("--force"), "{err}");
    let (ok, _, err) = run(&target, &["restore", archive.to_str().unwrap(), "--force"]);
    assert!(ok, "forced restore failed:\n{err}");

    for dir in [&source, &target, archive.parent().unwrap()] {
        let _ = std::fs::remove_dir_all(dir);
    }
}

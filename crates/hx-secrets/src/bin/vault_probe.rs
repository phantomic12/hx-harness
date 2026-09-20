//! The second process.
//!
//! This binary exists for one reason: the vault's cross-process behaviour is the property under
//! test, and a second `Vault` handle inside the test process cannot hold it. Two handles in one
//! process share the file cache, the umask, the open-file table and the memory that already holds
//! the derived key — so every question worth asking here ("can a stranger read this?", "did that
//! stranger's create wipe it?", "what does a writer's save look like from outside?") is answered by
//! the test's own assumptions instead of by the vault. `tests/vault_process.rs` spawns this binary,
//! named by `env!("CARGO_BIN_EXE_hx-vault-probe")` so it is the artefact that same `cargo test`
//! invocation just built — never a stale copy from `target/`.
//!
//! It is a probe, not a product entry point: no CLI in `apps/` calls it and no release packaging
//! ships it. The passphrase arrives through the environment rather than `argv` so that a test run
//! does not put one in `ps`, and every command except `get` prints only counts — never a value,
//! never a secret name.
//!
//! Exit codes: `0` when the vault answered; `1` when it refused (no vault, wrong passphrase,
//! refusing to overwrite) with the reason on stderr, which never carries a secret value; `2` for a
//! usage mistake, so a broken test invocation cannot be mistaken for a security refusal.

use hx_secrets::vault::{KdfParams, Vault};
use std::process::ExitCode;

/// The passphrase for the vault this run touches. Named so the test can set it per process.
const PASSPHRASE_ENV: &str = "HX_VAULT_PROBE_PASSPHRASE";

enum Failure {
    /// The vault answered with a refusal. This is a result, not a crash.
    Refused(String),
    /// The probe was called wrongly. A different exit code on purpose: a test that cannot tell
    /// "the vault refused" from "I invoked the probe wrong" would report the second as the first.
    Usage(String),
}

use Failure::{Refused, Usage};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(Refused(reason)) => {
            eprintln!("{reason}");
            ExitCode::from(1)
        }
        Err(Usage(reason)) => {
            eprintln!("{reason}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), Failure> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: hx-vault-probe <create|put|get|count|watch> <path> [args...] \
                 (passphrase in HX_VAULT_PROBE_PASSPHRASE)";

    let command = args.first().ok_or_else(|| Usage(usage.to_string()))?;
    let path = args.get(1).ok_or_else(|| Usage(usage.to_string()))?;

    // An *absent* passphrase is not an empty one. Guessing here would report "unlocked" for a vault
    // this process never opened, which is the failure mode the whole test file is about. An
    // explicitly empty passphrase is passed through instead, so the test can watch the vault
    // itself refuse it.
    let passphrase = std::env::var(PASSPHRASE_ENV).map_err(|_| {
        Refused(format!(
            "{PASSPHRASE_ENV} is not set; refusing to guess a passphrase"
        ))
    })?;

    match command.as_str() {
        "create" => {
            // `default-kdf` builds the vault at the real Argon2id cost rather than the test
            // parameters, so one test can prove the shipped cost is the one that works.
            let kdf = match args.get(2).map(String::as_str) {
                None => KdfParams::for_tests(),
                Some("default-kdf") => KdfParams::default(),
                Some(other) => return Err(Usage(format!("unknown create option {other:?}"))),
            };
            match Vault::create_at(path, &passphrase, kdf) {
                Ok(_) => Ok(()),
                Err(e) => Err(Refused(e.to_string())),
            }
        }
        "put" => {
            let name = args.get(2).ok_or_else(|| Usage(usage.to_string()))?;
            let value = args.get(3).ok_or_else(|| Usage(usage.to_string()))?;
            let mut vault =
                Vault::open_at(path, &passphrase).map_err(|e| Refused(e.to_string()))?;
            vault.put(name.as_str(), value.as_str());
            vault.save_to(path).map_err(|e| Refused(e.to_string()))
        }
        "get" => {
            let name = args.get(2).ok_or_else(|| Usage(usage.to_string()))?;
            let vault = Vault::open_at(path, &passphrase).map_err(|e| Refused(e.to_string()))?;
            let secret = vault.get(name).map_err(|e| Refused(e.to_string()))?;
            // The one command that prints a value, and only because a test needs to see that the
            // value survived a round trip through a second process.
            println!("{}", secret.expose());
            Ok(())
        }
        "count" => {
            let vault = Vault::open_at(path, &passphrase).map_err(|e| Refused(e.to_string()))?;
            println!("entries={}", vault.len());
            Ok(())
        }
        "watch" => {
            // Open the vault over and over and report the *smallest* entry count seen, so a
            // transient empty or unreadable state cannot hide behind a healthy final read. Every
            // iteration is a count, never a sleep: the assertion is on opens, not on elapsed time.
            let iterations: u32 = args
                .get(2)
                .ok_or_else(|| Usage(usage.to_string()))?
                .parse()
                .map_err(|_| Usage("watch needs an iteration count".to_string()))?;
            let mut opens = 0u32;
            let mut min_entries = usize::MAX;
            for _ in 0..iterations {
                let vault = Vault::open_at(path, &passphrase)
                    .map_err(|e| Refused(format!("open {opens} failed: {e}")))?;
                min_entries = min_entries.min(vault.len());
                opens += 1;
            }
            println!("opens={opens} min_entries={min_entries}");
            Ok(())
        }
        other => Err(Usage(format!("unknown command {other:?}\n{usage}"))),
    }
}

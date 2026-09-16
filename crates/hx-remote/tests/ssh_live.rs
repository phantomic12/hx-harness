//! Integration tests against a **real** SSH server.
//!
//! These are the tests `TESTING.md` said did not exist. Everything else in this crate is an
//! in-process unit test; nothing here has a fake, so a protocol mistake — a wrong cipher
//! negotiation, a misread channel message, a wrong exit-status path — fails here and nowhere else.
//!
//! They are `#[ignore]`d because they need a machine. Run them explicitly:
//!
//! ```console
//! $ HX_SSH_TEST_HOST=10.0.0.5 \
//!   HX_SSH_TEST_USER=deploy \
//!   HX_SSH_TEST_KEY=~/.ssh/id_ed25519 \
//!   cargo test -p hx-remote --test ssh_live -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Optional: `HX_SSH_TEST_PORT` (default 22).
//!
//! Every test uses its own `known_hosts` in a temp directory, so running them never writes to the
//! developer's `~/.ssh/known_hosts` and never depends on what happened to be in it.

use hx_core::ids::HostId;
use hx_remote::{Host, HostKeyPolicy, KnownHosts, RemoteOs, SshAuth, SshHost};
use hx_secrets::Secret;

struct Target {
    host: String,
    port: u16,
    user: String,
    key: Secret,
}

/// The machine to test against, or `None` when the environment does not name one.
fn target() -> Option<Target> {
    let host = std::env::var("HX_SSH_TEST_HOST").ok()?;
    let user = std::env::var("HX_SSH_TEST_USER").ok()?;
    let key_path = std::env::var("HX_SSH_TEST_KEY").ok()?;
    let port = std::env::var("HX_SSH_TEST_PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(22);

    // `~/...` is expanded here rather than shell-expanded, so the documented invocation works
    // when the test is started from an editor or a CI job that never saw a shell.
    let path = match key_path.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", std::env::var("HOME").unwrap_or_default()),
        None => key_path,
    };

    let pem = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("HX_SSH_TEST_KEY={path} could not be read: {err}"));

    Some(Target {
        host,
        port,
        user,
        key: Secret::new(pem),
    })
}

fn auth(target: &Target) -> SshAuth {
    SshAuth::Key {
        private_key_pem: Secret::new(target.key.expose().to_string()),
        passphrase: None,
    }
}

macro_rules! skip_without_a_host {
    () => {
        match target() {
            Some(target) => target,
            None => {
                eprintln!(
                    "skipped: set HX_SSH_TEST_HOST, HX_SSH_TEST_USER and HX_SSH_TEST_KEY to run \
                     this against a real machine"
                );
                return;
            }
        }
    };
}

#[ignore = "requires a real SSH host (HX_SSH_TEST_HOST, HX_SSH_TEST_USER, HX_SSH_TEST_KEY)"]
#[tokio::test]
async fn connects_probes_the_far_end_and_records_its_key() {
    let target = skip_without_a_host!();
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("known_hosts");

    let host = SshHost::connect(
        HostId::from("hst_live"),
        &target.host,
        target.port,
        &target.user,
        &auth(&target),
        &HostKeyPolicy::tofu_at(&store),
    )
    .await
    .expect("connect to the test host");

    // Capabilities come from probing the far end over the connection that was just made, so this
    // is evidence the exec path works, not evidence of a `uname` we ran locally.
    assert_eq!(host.caps().os, RemoteOs::Linux, "{:?}", host.caps());
    assert!(host.caps().home_dir.is_some(), "{:?}", host.caps());
    assert!(host.describe().starts_with("ssh "), "{}", host.describe());

    let recorded = std::fs::read_to_string(&store).unwrap();
    assert!(
        recorded.starts_with(&format!("{} ssh-", target.host)),
        "the first connection must be recorded in the trust store: {recorded}"
    );
}

#[ignore = "requires a real SSH host (HX_SSH_TEST_HOST, HX_SSH_TEST_USER, HX_SSH_TEST_KEY)"]
#[tokio::test]
async fn a_second_connection_is_verified_against_what_the_first_one_recorded() {
    let target = skip_without_a_host!();
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("known_hosts");

    for attempt in 0..2 {
        SshHost::connect(
            HostId::from("hst_live"),
            &target.host,
            target.port,
            &target.user,
            &auth(&target),
            &HostKeyPolicy::tofu_at(&store),
        )
        .await
        .unwrap_or_else(|err| panic!("attempt {attempt} failed: {err}"));
    }

    // One line, not two: the second connection matched instead of appending another pin.
    let recorded = std::fs::read_to_string(&store).unwrap();
    assert_eq!(
        recorded.lines().count(),
        1,
        "a verified reconnect must not re-record the key: {recorded}"
    );
}

#[ignore = "requires a real SSH host (HX_SSH_TEST_HOST, HX_SSH_TEST_USER, HX_SSH_TEST_KEY)"]
#[tokio::test]
async fn strict_refuses_a_host_that_is_not_pinned_yet() {
    let target = skip_without_a_host!();
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("known_hosts");

    let from = std::time::Instant::now();
    let err = SshHost::connect(
        HostId::from("hst_live"),
        &target.host,
        target.port,
        &target.user,
        &auth(&target),
        &HostKeyPolicy::Strict {
            known_hosts: KnownHosts::at(&store),
        },
    )
    .await
    .expect_err("strict must refuse an unknown host");

    let message = err.to_string();
    // Printed rather than only asserted: the wording is the operator-facing part of this feature,
    // and seeing it is how a manual run is worth more than a green tick.
    eprintln!("strict refusal: {message}");
    assert!(
        message.contains("refused to connect"),
        "the refusal has to be reported as a refusal, not as an unreachable host: {message}"
    );
    assert!(message.contains("strict"), "{message}");
    assert!(!store.exists(), "a refusal must not write a trust entry");

    // It refused during key exchange, before authentication was attempted. A refused host must
    // not be a slow failure.
    assert!(
        from.elapsed() < std::time::Duration::from_secs(30),
        "refusal took {:?}",
        from.elapsed()
    );
}

#[ignore = "requires a real SSH host (HX_SSH_TEST_HOST, HX_SSH_TEST_USER, HX_SSH_TEST_KEY)"]
#[tokio::test]
async fn a_server_whose_key_changed_is_refused() {
    let target = skip_without_a_host!();
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("known_hosts");

    // Stand in for the attacker: a real ed25519 key that is *not* the one this server presents,
    // written into the trust store exactly where a previous connection would have put it.
    //
    // This is the whole point of the exercise. Before host key verification, this connection
    // succeeded and the substituted key was used.
    const OTHER_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
    std::fs::write(&store, format!("{} ssh-ed25519 {OTHER_KEY}\n", target.host)).unwrap();

    let err = SshHost::connect(
        HostId::from("hst_live"),
        &target.host,
        target.port,
        &target.user,
        &auth(&target),
        &HostKeyPolicy::tofu_at(&store),
    )
    .await
    .expect_err("a changed host key must be refused");

    let message = err.to_string();
    eprintln!("changed-key refusal: {message}");
    assert!(
        message.contains("does not match"),
        "the error must name the change: {message}"
    );
    assert!(message.contains(OTHER_KEY), "{message}");

    // And the pinned key is still the pinned key: a refused connection must not overwrite the
    // record, or the next attempt would accept the substitution.
    let recorded = std::fs::read_to_string(&store).unwrap();
    assert_eq!(
        recorded,
        format!("{} ssh-ed25519 {OTHER_KEY}\n", target.host)
    );
}

#[ignore = "requires a real SSH host (HX_SSH_TEST_HOST, HX_SSH_TEST_USER, HX_SSH_TEST_KEY)"]
#[tokio::test]
async fn executes_writes_reads_and_lists_over_the_connection() {
    let target = skip_without_a_host!();
    let dir = tempfile::tempdir().unwrap();

    let host = SshHost::connect(
        HostId::from("hst_live"),
        &target.host,
        target.port,
        &target.user,
        &auth(&target),
        &HostKeyPolicy::tofu_at(dir.path().join("known_hosts")),
    )
    .await
    .expect("connect to the test host");

    // A directory nobody else will be using, keyed by this process so a concurrent run cannot
    // collide with it.
    let work = format!("/tmp/hx-live-{}", std::process::id());

    let made = host
        .exec(
            &format!("mkdir -p {work}"),
            std::time::Duration::from_secs(30),
        )
        .await
        .expect("mkdir");
    assert!(made.success(), "mkdir failed: {made:?}");

    // --- exec, including the exit status path ------------------------------------------------
    let echoed = host
        .exec(
            "echo hx-live; echo to-stderr >&2",
            std::time::Duration::from_secs(30),
        )
        .await
        .expect("exec");
    assert!(echoed.success(), "{echoed:?}");
    assert_eq!(echoed.stdout.trim(), "hx-live");
    assert_eq!(echoed.stderr.trim(), "to-stderr");

    let failed = host
        .exec("exit 7", std::time::Duration::from_secs(30))
        .await
        .expect("exec");
    assert_eq!(
        failed.exit_code,
        Some(7),
        "the exit status must survive: {failed:?}"
    );
    assert!(!failed.success());

    // --- write then read, binary-safe ---------------------------------------------------------
    let path = format!("{work}/bytes.bin");
    // Not valid UTF-8, and not valid text: a `cat`-based transfer silently mangles this.
    let payload: Vec<u8> = vec![0x00, 0xff, 0xfe, 0x80, b'h', b'x', 0x0a, 0x00];

    host.write_file(&path, &payload).await.expect("write_file");
    let read_back = host.read_file(&path).await.expect("read_file");
    assert_eq!(
        read_back, payload,
        "the file did not survive the round trip"
    );

    // --- list --------------------------------------------------------------------------------
    let entries = host.list_dir(&work).await.expect("list_dir");
    let listed = entries
        .iter()
        .find(|entry| entry.name == "bytes.bin")
        .unwrap_or_else(|| panic!("bytes.bin missing from {entries:?}"));
    assert!(!listed.is_dir);
    assert_eq!(listed.size, payload.len() as u64);
    assert_eq!(listed.path, path);

    // --- a missing directory is an error, not an empty list -----------------------------------
    let missing = host.list_dir(&format!("{work}/nope")).await;
    assert!(
        missing.is_err(),
        "a missing directory listed as {missing:?}"
    );

    // Clean up after ourselves, one file and one directory at a time.
    let cleaned = host
        .exec(
            &format!("rm -f {path} && rmdir {work}"),
            std::time::Duration::from_secs(30),
        )
        .await
        .expect("cleanup");
    assert!(cleaned.success(), "cleanup failed: {cleaned:?}");
}

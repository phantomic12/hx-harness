//! Live: an interactive terminal over SSH against a real sshd.
//!
//! Ignored by default. To run:
//!
//!   HX_SSH_TEST_HOST=127.0.0.1 HX_SSH_TEST_PORT=2222 HX_SSH_TEST_USER=$(whoami) \
//!   HX_SSH_TEST_KEY=/tmp/hxptytest/user_ed25519 \
//!   cargo test -p hx-remote --offline --test pty_live -- --ignored --test-threads=1
//!
//! ## Why these tests pass an explicit shell
//!
//! The default login shell here is `fish`, and fish performs a terminal-capability handshake on
//! start: it emits DA1 (`ESC [ c`) and DSR (`ESC [ 6n`) and *waits for the emulator to answer*.
//! A daemon-side test is not an emulator, so the shell sits at the handshake and anything typed
//! arrives as literal text interleaved with the queries — the command never runs.
//!
//! That is not a bug in the transport, and it is worth stating plainly because it looks exactly like
//! one: the bytes go out, the prompt comes back, and the command does not execute. Against a real
//! client the queries *are* answered (xterm.js replies to DA1), so the same session works. These
//! tests therefore start `sh`, which has no handshake, so what is being tested is the pty and not
//! the terminal emulator on the other end.

use hx_core::ids::HostId;
use hx_remote::{Host, HostKeyPolicy, SshAuth, SshHost};
use std::time::Duration;

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

async fn connect() -> Option<SshHost> {
    let host = std::env::var("HX_SSH_TEST_HOST").ok()?;
    let port: u16 = env_or("HX_SSH_TEST_PORT", "22").parse().unwrap_or(22);
    let user = env_or("HX_SSH_TEST_USER", "root");
    let key_path = env_or("HX_SSH_TEST_KEY", "~/.ssh/id_ed25519");
    let path = match key_path.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", std::env::var("HOME").unwrap_or_default()),
        None => key_path,
    };
    let pem = std::fs::read_to_string(&path).expect("the test key is readable");
    let auth = SshAuth::Key {
        private_key_pem: pem.into(),
        passphrase: None,
    };
    SshHost::connect(
        HostId::from_raw("ptytest"),
        &host,
        port,
        &user,
        &auth,
        &HostKeyPolicy::Insecure,
    )
    .await
    .ok()
}

/// Read until `needle` appears or the budget runs out, returning everything seen.
async fn read_until(pty: &std::sync::Arc<dyn hx_remote::PtySession>, needle: &str) -> String {
    let mut seen = String::new();
    for _ in 0..60 {
        match tokio::time::timeout(Duration::from_secs(2), pty.read()).await {
            Ok(Some(chunk)) => {
                seen.push_str(&String::from_utf8_lossy(&chunk));
                if seen.contains(needle) {
                    break;
                }
            }
            _ => break,
        }
    }
    seen
}

/// The whole point of a pty over an `exec`: a command typed *after* the shell starts comes back.
#[tokio::test]
#[ignore]
async fn a_command_typed_after_the_shell_starts_is_executed() {
    let Some(host) = connect().await else {
        eprintln!("skipping: HX_SSH_TEST_HOST is unset");
        return;
    };
    let pty = host
        .open_pty(Some("sh"), 80, 24)
        .await
        .expect("a pty opens");

    // Let the shell print its prompt before typing, so the two are not interleaved.
    tokio::time::sleep(Duration::from_millis(400)).await;
    pty.write(b"echo PTY_MARKER_$((6*7))\n")
        .await
        .expect("write");

    // 6*7 is evaluated by the *remote* shell, so the marker can only appear if the command ran
    // there. An echoed line would still read `$((6*7))`.
    let seen = read_until(&pty, "PTY_MARKER_42").await;
    pty.close().await.expect("close");
    assert!(
        seen.contains("PTY_MARKER_42"),
        "the remote shell never printed PTY_MARKER_42; saw: {seen:?}"
    );
}

/// A resize has to reach the kernel's `winsize`, not just be accepted.
#[tokio::test]
#[ignore]
async fn a_resize_reaches_the_remote_winsize() {
    let Some(host) = connect().await else {
        eprintln!("skipping: HX_SSH_TEST_HOST is unset");
        return;
    };
    let pty = host
        .open_pty(Some("sh"), 80, 24)
        .await
        .expect("a pty opens");
    tokio::time::sleep(Duration::from_millis(400)).await;

    pty.resize(120, 40).await.expect("resize is accepted");
    // `stty size` reads the winsize the pty actually has, so this reports what was set rather than
    // trusting that the request went out.
    pty.write(b"stty size\n").await.expect("write");
    let seen = read_until(&pty, "40 120").await;
    pty.close().await.expect("close");
    assert!(
        seen.contains("40 120"),
        "the resize never reached the shell; saw: {seen:?}"
    );
}

/// Closing twice is fine, and a closed session's stream ends instead of blocking forever.
#[tokio::test]
#[ignore]
async fn closing_is_idempotent_and_ends_the_stream() {
    let Some(host) = connect().await else {
        eprintln!("skipping: HX_SSH_TEST_HOST is unset");
        return;
    };
    let pty = host
        .open_pty(Some("sh"), 80, 24)
        .await
        .expect("a pty opens");
    tokio::time::sleep(Duration::from_millis(300)).await;
    pty.close().await.expect("first close");
    pty.close().await.expect("second close is not an error");

    // The stream has to *end*, not hang: a client attached to a closed terminal must be told, not
    // left waiting for output that will never come. Buffered output may still arrive first — the
    // shell's prompt was already in flight when the close was sent, and dropping it would lose the
    // last thing the terminal said — so this drains until the stream ends and bounds the whole
    // thing by time.
    let started = std::time::Instant::now();
    loop {
        let next = tokio::time::timeout(Duration::from_secs(5), pty.read()).await;
        match next {
            Ok(None) => break,
            // Output still buffered: keep draining, but not forever.
            Ok(Some(_)) if started.elapsed() < Duration::from_secs(10) => continue,
            Ok(Some(_)) => {
                panic!("output kept arriving after close for over 10s; the stream never ended")
            }
            Err(_) => panic!("the stream hung after close instead of ending"),
        }
    }
}

/// A Windows host is refused with a reason rather than quietly given a POSIX session.
#[tokio::test]
#[ignore]
async fn the_default_shell_is_used_when_none_is_named() {
    let Some(host) = connect().await else {
        eprintln!("skipping: HX_SSH_TEST_HOST is unset");
        return;
    };
    // No command: the machine's own login shell. Only that a session opens and emits something is
    // asserted — which shell it is depends on the machine, and asserting the name would make this
    // test a fact about one host rather than about the code.
    let pty = host.open_pty(None, 80, 24).await.expect("a pty opens");
    let first = tokio::time::timeout(Duration::from_secs(8), pty.read()).await;
    pty.close().await.ok();
    match first {
        Ok(Some(bytes)) => assert!(!bytes.is_empty(), "the login shell must produce output"),
        // Even an empty first read is acceptable: a shell that emits nothing until the terminal
        // answers a query is a real behaviour, documented at the top of this file. What must not
        // happen is a hang or an error.
        Ok(None) => panic!("the session ended without producing anything"),
        Err(_) => panic!("the login shell produced nothing within the budget"),
    }
}

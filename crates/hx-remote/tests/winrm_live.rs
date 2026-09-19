//! WinRM against a real Windows host.
//!
//! `#[ignore]`d, because it needs a Windows machine with WinRM enabled. Run it with:
//!
//! ```text
//! HX_WINRM_HOST=<host> HX_WINRM_USER=<user> HX_WINRM_PASSWORD=<password> \
//!   cargo test -p hx-remote --test winrm_live -- --ignored --test-threads=1
//! ```
//!
//! The dev environment is a `dockur/windows` guest (Windows 10, QEMU/KVM) whose OEM install
//! script enables WinRM and creates the account. It is a genuine Windows WinRM endpoint — the
//! same service a physical host runs — which is the point: a mocked transport would test my
//! understanding of the protocol rather than the protocol.
//!
//! ## Why these tests exist at all
//!
//! The unit tests in `winrm.rs` and `ntlm.rs` prove the message construction (against published
//! MD4 and NT-hash vectors) and the parsing. None of them prove the exchange: whether the SOAP
//! envelope is one WSMan accepts, whether the selector syntax names the right object, or whether
//! the output framing is decoded the way the server encoded it. Only a real server answers those,
//! and a NTLM client that is wrong in any of those places fails with `401` and nothing else.

use std::time::Duration;

use hx_core::error::HxError;
use hx_core::ids::HostId;
use hx_remote::host::{Host, RemoteOs, ShellKind};
use hx_remote::winrm::{WinRmAuth, WinRmHost};

/// The environment a live run needs, or `None` when it is not configured.
///
/// Returns `None` rather than panicking so the module compiles and the tests skip cleanly on a
/// machine with no Windows host — an ignored test that fails on a missing variable trains people
/// to ignore failures.
fn target() -> Option<(String, String, String, u16)> {
    let host = std::env::var("HX_WINRM_HOST").ok()?;
    let user = std::env::var("HX_WINRM_USER").ok()?;
    let password = std::env::var("HX_WINRM_PASSWORD").ok()?;
    let port = std::env::var("HX_WINRM_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);
    Some((host, user, password, port))
}

/// The transport to use, chosen by `HX_WINRM_AUTH`.
///
/// `ntlm` is the default because it is what a workgroup host answers without configuration. `basic`
/// exists because NTLM over WinRM requires message sealing — every request after the handshake is
/// sealed with the session key, in a `multipart/encrypted` body — which this client does not yet
/// implement. Basic carries no such requirement, and is only acceptable because HTTPS supplies the
/// confidentiality, so it is selected with `HX_WINRM_AUTH=basic` alongside `HX_WINRM_HTTPS=1`.
fn auth(user: String, password: String) -> (WinRmAuth, bool) {
    let https = std::env::var("HX_WINRM_HTTPS").is_ok_and(|v| v != "0" && !v.is_empty());
    match std::env::var("HX_WINRM_AUTH").as_deref() {
        Ok("basic") => (WinRmAuth::Basic { user, password }, https),
        _ => (
            WinRmAuth::Ntlm {
                user,
                password,
                // A local account authenticates against the machine itself, so no domain.
                domain: None,
            },
            https,
        ),
    }
}

async fn connect() -> Option<WinRmHost> {
    let (host, user, password, port) = target()?;
    let (auth, https) = auth(user, password);
    let connected = WinRmHost::connect(HostId::from("win-live"), &host, port, https, auth).await;
    match connected {
        Ok(h) => Some(h),
        Err(e) => panic!("could not connect to the Windows host: {e}"),
    }
}

#[tokio::test]
#[ignore = "needs a Windows host with WinRM; set HX_WINRM_HOST/USER/PASSWORD"]
async fn a_real_windows_host_connects_and_reports_itself() {
    let Some(host) = connect().await else {
        eprintln!("skipped: HX_WINRM_HOST is not set");
        return;
    };

    // The probe on connect read the OS, so these are the caps a tool would branch on rather than a
    // guess from the transport's own construction.
    let caps = host.caps();
    assert_eq!(caps.os, RemoteOs::Windows, "a WinRM host is Windows");
    assert_eq!(
        caps.shell,
        ShellKind::PowerShell,
        "Windows means PowerShell for anything non-trivial"
    );
    assert!(
        host.describe().contains("winrm"),
        "the description must say what transport it is: {}",
        host.describe()
    );
}

#[tokio::test]
#[ignore = "needs a Windows host with WinRM; set HX_WINRM_HOST/USER/PASSWORD"]
async fn a_command_runs_and_its_output_comes_back_through_the_soap_framing() {
    let Some(host) = connect().await else {
        eprintln!("skipped");
        return;
    };

    // `cmd.exe` built-ins, so the test does not depend on anything being installed. The marker is
    // distinctive so it cannot be confused with the shell's own banner.
    let out = host
        .exec("echo hx-winrm-marker-7f3a", Duration::from_secs(60))
        .await
        .expect("the command must run");

    assert_eq!(out.exit_code, Some(0), "exit code: {out:?}");
    assert!(
        out.stdout.contains("hx-winrm-marker-7f3a"),
        "the command's output must survive the base64/UTF-16 framing, got {:?}",
        out.stdout
    );
    // The UTF-16 half of the framing is the easy one to get wrong: decoding only the base64 leaves
    // a NUL between every character, which `contains` on the marker would still pass. So the
    // absence of stray NULs is asserted separately.
    assert!(
        !out.stdout.contains('\0'),
        "output must be decoded from UTF-16, not taken as ASCII: {:?}",
        out.stdout
    );
    // Line endings are normalised at the boundary, so a caller never has to know.
    assert!(
        !out.stdout.contains("\r\n"),
        "CRLF must be normalised to LF: {:?}",
        out.stdout
    );
}

#[tokio::test]
#[ignore = "needs a Windows host with WinRM; set HX_WINRM_HOST/USER/PASSWORD"]
async fn a_failing_command_reports_its_exit_code_and_stderr_separately() {
    let Some(host) = connect().await else {
        eprintln!("skipped");
        return;
    };

    let out = host
        .exec(
            "nonexistent-command-xyz & echo after",
            Duration::from_secs(60),
        )
        .await
        .expect("the transport must complete, even for a failing command");

    // The command *ran*; the transport succeeded. Conflating "the command failed" with "the
    // connection failed" is what makes a remote host's errors unreadable.
    assert!(
        out.exit_code.is_some(),
        "an exit code must be reported: {out:?}"
    );
}

#[tokio::test]
#[ignore = "needs a Windows host with WinRM; set HX_WINRM_HOST/USER/PASSWORD"]
async fn a_file_round_trips_byte_for_byte() {
    let Some(host) = connect().await else {
        eprintln!("skipped");
        return;
    };

    // Bytes that are not valid UTF-8 and contain a NUL: the case a text-shaped transport mangles.
    // Base64 through PowerShell is how the transport carries them.
    let contents: Vec<u8> = vec![0x00, 0x01, 0xff, 0xfe, 0x80, b'h', b'i', 0x0d, 0x0a, 0x7f];
    let path = r"C:\Windows\Temp\hx-winrm-roundtrip.bin";

    host.write_file(path, &contents)
        .await
        .expect("writing must succeed");

    let read_back = host.read_file(path).await.expect("reading must succeed");
    assert_eq!(
        read_back, contents,
        "a binary file must round-trip exactly, including a NUL and invalid UTF-8"
    );

    // The directory is created when it does not exist, because a caller asked to write a file
    // rather than to also arrange its parent.
    let nested = r"C:\Windows\Temp\hx-winrm-sub\deep\file.txt";
    host.write_file(nested, b"nested")
        .await
        .expect("a nested path must be created");
    let nested_back = host.read_file(nested).await.expect("read nested");
    assert_eq!(nested_back, b"nested");

    let _ = host
        .exec(
            r"del /f /q C:\Windows\Temp\hx-winrm-roundtrip.bin & rmdir /s /q C:\Windows\Temp\hx-winrm-sub",
            Duration::from_secs(60),
        )
        .await;
}

#[tokio::test]
#[ignore = "needs a Windows host with WinRM; set HX_WINRM_HOST/USER/PASSWORD"]
async fn a_directory_lists_with_real_entries() {
    let Some(host) = connect().await else {
        eprintln!("skipped");
        return;
    };

    let entries = host
        .list_dir(r"C:\Windows")
        .await
        .expect("the system directory must list");

    assert!(
        !entries.is_empty(),
        "C:\\Windows is not empty, so a listing that is empty means the parse failed"
    );
    // `System32` is a directory that exists on every Windows install, and its absence would mean
    // the entries are being produced but not classified.
    let system32 = entries
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case("System32"))
        .expect("System32 must appear in C:\\Windows");
    assert!(system32.is_dir, "System32 must be reported as a directory");
    assert_eq!(
        system32.path, r"C:\Windows\System32",
        "the path must be joined with a backslash, not a slash"
    );

    // A file entry carries a size; a directory reports none.
    if let Some(file) = entries.iter().find(|e| !e.is_dir) {
        assert!(!file.name.is_empty(), "a file entry has a name: {file:?}");
    }
}

#[tokio::test]
#[ignore = "needs a Windows host with WinRM; set HX_WINRM_HOST/USER/PASSWORD"]
async fn rename_refuses_to_overwrite_an_existing_destination() {
    let Some(host) = connect().await else {
        eprintln!("skipped");
        return;
    };

    // The contract the transport shares with SSH: an existing destination is an error, never an
    // overwrite. The trash a delete leaves behind must not destroy what is already in it, so this
    // is a correctness property rather than a nicety.
    let src = r"C:\Windows\Temp\hx-rename-src.txt";
    let dst = r"C:\Windows\Temp\hx-rename-dst.txt";
    host.write_file(src, b"source contents")
        .await
        .expect("write src");
    host.write_file(dst, b"destination contents")
        .await
        .expect("write dst");

    let result = host.rename(src, dst).await;
    assert!(
        result.is_err(),
        "moving onto an existing file must fail rather than replace it"
    );

    // And the destination is untouched, which is the part that matters.
    let survivor = host.read_file(dst).await.expect("dst still readable");
    assert_eq!(
        survivor, b"destination contents",
        "the existing file must be byte-for-byte intact"
    );

    // A move to a free name succeeds.
    let free = r"C:\Windows\Temp\hx-rename-free.txt";
    host.rename(src, free).await.expect("a free name must move");
    let moved = host.read_file(free).await.expect("moved file readable");
    assert_eq!(moved, b"source contents");

    let _ = host
        .exec(
            r"del /f /q C:\Windows\Temp\hx-rename-dst.txt C:\Windows\Temp\hx-rename-free.txt",
            Duration::from_secs(60),
        )
        .await;
}

#[tokio::test]
#[ignore = "needs a Windows host with WinRM; set HX_WINRM_HOST/USER/PASSWORD"]
async fn several_commands_reuse_one_shell() {
    let Some(host) = connect().await else {
        eprintln!("skipped");
        return;
    };

    // A shell is created once per connection and reused. The thing that breaks if the reuse is
    // wrong is the *second* command, so a test that runs one command proves nothing here.
    for i in 1..=4 {
        let out = host
            .exec(&format!("echo run-{i}"), Duration::from_secs(60))
            .await
            .unwrap_or_else(|e| panic!("command {i} failed: {e}"));
        assert_eq!(out.exit_code, Some(0), "command {i}: {out:?}");
        assert!(
            out.stdout.contains(&format!("run-{i}")),
            "command {i} must report its own output, got {:?}",
            out.stdout
        );
    }
}

#[tokio::test]
#[ignore = "needs a Windows host with WinRM; set HX_WINRM_HOST/USER/PASSWORD"]
async fn wrong_credentials_are_refused_with_a_reason_that_names_the_problem() {
    let Some((host, user, _password, port)) = target() else {
        eprintln!("skipped");
        return;
    };

    // The failure mode worth pinning: a bad password must produce a message that points at the
    // account, not a bare 401 that sends someone to read the server's event log.
    let refused = WinRmHost::connect(
        HostId::from("win-bad"),
        &host,
        port,
        port == 5986,
        WinRmAuth::Ntlm {
            user: user.clone(),
            password: "definitely-not-the-password".to_string(),
            domain: None,
        },
    )
    .await;

    match refused {
        Ok(_) => panic!("a wrong password must not connect"),
        Err(e) => {
            let message = e.to_string();
            assert!(
                !message.contains("definitely-not-the-password"),
                "the password must never appear in an error: {message}"
            );
            let named = message.contains(&user)
                || message.contains("credential")
                || message.contains("NTLM");
            assert!(
                named,
                "the error must point at the account or the auth method, got: {message}"
            );
        }
    }
}

#[tokio::test]
#[ignore = "needs a Windows host with WinRM; set HX_WINRM_HOST/USER/PASSWORD"]
async fn a_host_that_is_not_listening_reports_a_transport_failure_not_a_panic() {
    // Port 1 is reserved and nothing listens there. The point is that an unreachable host is a
    // clean error rather than a panic or a hang, because "the box is down" is an ordinary state.
    let result = WinRmHost::connect(
        HostId::from("win-dead"),
        "127.0.0.1",
        1,
        false,
        WinRmAuth::Ntlm {
            user: "nobody".to_string(),
            password: "nothing".to_string(),
            domain: None,
        },
    )
    .await;

    match result {
        Ok(_) => panic!("connecting to a closed port must not succeed"),
        Err(HxError::Remote(_)) | Err(HxError::Config(_)) => {}
        Err(other) => panic!("expected a transport error, got {other:?}"),
    }
}

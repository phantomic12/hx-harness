//! Connecting to machines, and adapting to what they actually are.
//!
//! ## The problem this crate exists to solve
//!
//! "Support Windows, macOS and Linux" is usually implemented as a pile of `if cfg!(windows)`
//! checks that interrogate the *local* platform — which is exactly wrong, because the interesting
//! case is a Linux daemon driving a Windows box. The remote platform is a runtime property of
//! each connection, not a compile-time property of the binary.
//!
//! So every host is probed once on connect and reports a [`HostCaps`]. Tool implementations read
//! those caps to decide whether to emit `/bin/sh` or `powershell.exe`, whether there is `ssh` for
//! a jump host, and whether to expect `\r\n` line endings. Guessing is what produces the classic
//! "works on my machine, `uname: not found` on the build box" outcome.
//!
//! ## Layers
//!
//! - [`Host`] — the trait every transport implements.
//! - [`LocalHost`] — the machine the daemon runs on.
//! - [`known_hosts`] — the trust store that decides whether a host key may be accepted.
//! - [`sftp`] — a minimal SFTP v3 client carried over a russh channel.
//!
//! ## What is landed, and what is not
//!
//! Landed: the trait, the platform capability probing, the local host, the SSH transport over
//! `russh`, host key verification against `known_hosts`, and the approval-gated command runner.
//!
//! Not landed, and deliberately not stubbed with a type that pretends to work:
//!
//! - `WinRMHost` — for the Hyper-V boxes that cannot do SSH (NTLM via a jump host). M4.
//! - Host certificates. A server presenting one is refused rather than trusted on the strength
//!   of a `@cert-authority` line.
//!
//! ## What the tests here do and do not prove
//!
//! They prove the pure logic: capability parsing, path translation, command wrapping, risk
//! classification, output bounding, `known_hosts` parsing and its verdicts, the host key policy,
//! and an approval round-trip driven against the local host.
//!
//! They do **not** prove that an SSH connection to a second machine works. That needs a real key
//! and a real host. `SshHost` compiles and its parsing logic is tested, but its handshake has
//! never been executed against a server — it is listed as unverified in `TESTING.md`.

pub mod host;
pub mod known_hosts;
pub mod local;
pub mod ntlm;
pub mod runner;
pub mod sftp;
pub mod ssh;
pub mod winrm;

pub use host::{
    powershell_quote, shell_quote, ExecOutput, Host, HostCaps, PtySession, RemoteEntry, RemoteOs,
    ShellKind,
};
pub use known_hosts::{HostKeyVerdict, KnownHosts};
pub use local::LocalHost;
pub use sftp::{SftpAvailability, SftpSession};
pub use ssh::{HostKeyDecision, HostKeyPolicy, SshAuth, SshHost, SshPty};
pub use winrm::{WinRmAuth, WinRmHost};

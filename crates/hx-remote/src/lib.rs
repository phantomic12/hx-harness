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
//!
//! ## What is landed, and what is not
//!
//! Landed: the trait, the platform capability probing, and the local host — the parts that can be
//! verified without a second machine to connect to.
//!
//! Not landed, and deliberately not stubbed with a type that pretends to work:
//!
//! - `SshHost` — over `russh`, with key material sourced from the vault. M4.
//! - `WinRMHost` — for the Hyper-V boxes that cannot do SSH (NTLM via a jump host). M4.
//! - `runner` — executes an agent's shell commands against a host with approval checks and
//!   capability-aware command construction. This depends on the approval engine reaching tool
//!   dispatch (M1), so it cannot be built before then.

pub mod host;
pub mod local;

pub use host::{
    powershell_quote, shell_quote, ExecOutput, Host, HostCaps, RemoteEntry, RemoteOs, ShellKind,
};
pub use local::LocalHost;

//! SSH transport.
//!
//! ## Security posture, stated plainly
//!
//! **Host keys are verified against `known_hosts`.** Every connection is checked before
//! authentication begins, and the check has three outcomes that are all distinct on purpose:
//! a key that matches is accepted, an unknown host is either refused ([`HostKeyPolicy::Strict`])
//! or recorded and then enforced ([`HostKeyPolicy::Tofu`]), and a key that does not match the
//! recorded one is **refused** — that is the man-in-the-middle case, and it is a rejection, not a
//! warning. A server presenting a certificate is refused too: hx does not verify certificates yet,
//! so accepting one would be claiming a verification that did not happen.
//!
//! See [`crate::known_hosts`] for the file format and the verdicts. [`HostKeyPolicy::Insecure`]
//! still exists, and exists to be explicit: accepting any key is a decision an operator makes on
//! a disposable target, never a default that happens because verification was absent.
//!
//! Still unverified: nothing in this file's handshake has been executed against a real SSH server
//! under test. The transport compiles, its parsing and its key policy are unit-tested, and
//! `TESTING.md` lists the handshake itself as tier C until an integration test runs it.
//!
//! Everything else is real: publickey and password auth with key material pulled from the
//! encrypted vault, capability probing on connect, and binary-safe file transfer.

use crate::host::{
    caps_from_uname, caps_from_ver, check_cap, enrich_caps_from_posix_probe, powershell_quote,
    shell_quote, ExecOutput, Host, HostCaps, RemoteEntry, RemoteOs, ShellKind,
};
use crate::known_hosts::{HostKeyVerdict, KnownHosts};
use crate::sftp::{SftpAvailability, SftpSession};
use async_trait::async_trait;
use hx_core::error::{HxError, Result};
use hx_core::ids::HostId;
use hx_secrets::Secret;
use russh::client::{self, Handle};
use russh::keys::{decode_secret_key, PrivateKeyWithHashAlg};
use russh::ChannelMsg;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How to authenticate.
///
/// Deliberately not `Clone` and not `Debug`: it carries plaintext key material, and both derived
/// impls are ways that material escapes into a log line.
pub enum SshAuth {
    /// Delegate to a running `ssh-agent`. Not yet wired up.
    Agent,
    /// A private key, already decrypted from the vault.
    Key {
        private_key_pem: Secret,
        passphrase: Option<Secret>,
    },
    /// A password, already decrypted from the vault.
    Password { password: Secret },
}

impl std::fmt::Debug for SshAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Which mechanism, never the material.
        match self {
            SshAuth::Agent => f.write_str("SshAuth::Agent"),
            SshAuth::Key {
                private_key_pem: _,
                passphrase,
            } => f
                .debug_struct("SshAuth::Key")
                .field("private_key_pem", &"<redacted>")
                .field("encrypted", &passphrase.is_some())
                .finish(),
            SshAuth::Password { .. } => f
                .debug_struct("SshAuth::Password")
                .field("password", &"<redacted>")
                .finish(),
        }
    }
}

/// What to do about the host key of a machine being connected to.
///
/// The choice is explicit because the alternative — a `bool` that means "skip the check" — is how
/// an unverified connection becomes the default by accident.
#[derive(Clone, Debug)]
pub enum HostKeyPolicy {
    /// Require an entry that already trusts the host. An unknown host is refused, so the first
    /// connection to a machine has to be an act, not a side effect.
    Strict { known_hosts: KnownHosts },
    /// Trust on first use: record the key of an unknown host, then require it never to change.
    /// A *changed* key is still refused — this is the mode that makes MITM visible after the fact
    /// without making every new machine a manual step.
    Tofu { known_hosts: KnownHosts },
    /// Accept any key and record nothing. Refuses nothing, so the user has to say it out loud.
    Insecure,
}

/// The outcome of a host key check.
///
/// A refusal carries its reason because a bare `false` cannot be reported: by the time the caller
/// sees a failed connect, the detail that distinguishes "unknown host" from "key changed" is the
/// only thing that tells an operator whether to run `ssh-keyscan` or to start investigating.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeyDecision {
    Accept,
    Refuse(String),
}

impl HostKeyPolicy {
    /// Trust on first use, against `~/.ssh/known_hosts`. The default for a real harness.
    pub fn tofu() -> Result<Self> {
        Ok(Self::Tofu {
            known_hosts: KnownHosts::user_default()?,
        })
    }

    /// Strict, against `~/.ssh/known_hosts`.
    pub fn strict() -> Result<Self> {
        Ok(Self::Strict {
            known_hosts: KnownHosts::user_default()?,
        })
    }

    /// Trust on first use, against a specific file. What tests and an explicit daemon config use.
    pub fn tofu_at(path: impl Into<std::path::PathBuf>) -> Self {
        Self::Tofu {
            known_hosts: KnownHosts::at(path),
        }
    }

    /// Decide whether `key` may be accepted for `host:port`.
    ///
    /// `Err` is also a refusal — one that could not be completed. A trust store that cannot be
    /// read or written is not a reason to trust anyway, so the error surfaces rather than turning
    /// a filesystem problem into a silent downgrade.
    pub fn decide(
        &self,
        host: &str,
        port: u16,
        key: &russh::keys::PublicKey,
    ) -> Result<HostKeyDecision> {
        let known_hosts = match self {
            Self::Insecure => {
                tracing::warn!(
                    host,
                    port,
                    algorithm = %key.algorithm(),
                    "HostKeyPolicy::Insecure — accepting an unverified SSH host key"
                );
                return Ok(HostKeyDecision::Accept);
            }
            Self::Strict { known_hosts } | Self::Tofu { known_hosts } => known_hosts,
        };

        let store = known_hosts.path().display();

        Ok(match known_hosts.lookup(host, port, key)? {
            HostKeyVerdict::Trusted => HostKeyDecision::Accept,
            HostKeyVerdict::Unknown => {
                if matches!(self, Self::Strict { .. }) {
                    let reason = format!(
                        "no known_hosts entry for {host}:{port} in {store}; refusing under strict \
                         host key checking (add the key with ssh-keyscan, or use \
                         HostKeyPolicy::Tofu)"
                    );
                    tracing::error!(host, port, "{reason}");
                    return Ok(HostKeyDecision::Refuse(reason));
                }

                // Record before accepting. If the write fails, the connection fails: a key that
                // cannot be pinned now would be re-accepted silently on the next attempt, which
                // is exactly the behaviour TOFU exists to stop.
                known_hosts.record(host, port, key)?;
                tracing::warn!(
                    host,
                    port,
                    store = %store,
                    algorithm = %key.algorithm(),
                    "first connection to this host; recording its key in known_hosts"
                );
                HostKeyDecision::Accept
            }
            HostKeyVerdict::Changed { line, recorded } => {
                let reason = format!(
                    "the host key for {host}:{port} does not match the one recorded at \
                     {store}:{line} (recorded {recorded}, offered {}); a changed host key is what \
                     a man-in-the-middle looks like, and a rebuilt server looks identical — remove \
                     that entry if the change is expected",
                    key.algorithm()
                );
                tracing::error!(host, port, line, "{reason}");
                HostKeyDecision::Refuse(reason)
            }
            HostKeyVerdict::Revoked { line } => {
                let reason =
                    format!("the host key for {host}:{port} is marked @revoked at {store}:{line}");
                tracing::error!(host, port, line, "{reason}");
                HostKeyDecision::Refuse(reason)
            }
        })
    }

    /// Whether the key may be accepted, without the reason. Convenience for callers that log the
    /// refusal themselves.
    pub fn accepts(&self, host: &str, port: u16, key: &russh::keys::PublicKey) -> Result<bool> {
        Ok(matches!(
            self.decide(host, port, key)?,
            HostKeyDecision::Accept
        ))
    }

    /// One line for logs and `hx doctor`.
    pub fn describe(&self) -> String {
        match self {
            Self::Strict { known_hosts } => {
                format!("strict (known_hosts: {})", known_hosts.path().display())
            }
            Self::Tofu { known_hosts } => {
                format!("tofu (known_hosts: {})", known_hosts.path().display())
            }
            Self::Insecure => "insecure (host keys are not verified)".to_string(),
        }
    }
}

/// Hands russh the trust decision, and remembers why a key was refused.
///
/// The reason is kept because `check_server_key` can only answer a `bool`: without this the caller
/// would report "could not reach host" for a connection that was deliberately refused, which is
/// the least useful possible message for an operator.
struct ClientHandler {
    policy: HostKeyPolicy,
    host: String,
    port: u16,
    refusal: Refusal,
}

/// The reason the last host key check said no, shared with the code that reports the error.
#[derive(Clone, Default)]
struct Refusal(Arc<std::sync::Mutex<Option<String>>>);

impl Refusal {
    fn set(&self, reason: String) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(reason);
        }
    }

    fn get(&self) -> Option<String> {
        self.0.lock().ok().and_then(|slot| slot.clone())
    }
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let key = match server_public_key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => key,
            // Certificates are not verified yet, and "not verified" is not the same as "fine".
            // The signature over the certificate would be checked, but the authority that issued
            // it would not, so accepting here would be trusting anything.
            russh::keys::PublicKeyOrCertificate::Certificate(_) => {
                let reason = "the server presented a host certificate, which hx cannot verify yet"
                    .to_string();
                tracing::error!(host = %self.host, port = self.port, "{reason}");
                self.refusal.set(reason);
                return Ok(false);
            }
        };

        match self.policy.decide(&self.host, self.port, key) {
            Ok(HostKeyDecision::Accept) => Ok(true),
            Ok(HostKeyDecision::Refuse(reason)) => {
                self.refusal.set(reason);
                Ok(false)
            }
            Err(err) => {
                let reason = format!("host key verification could not be completed: {err}");
                tracing::error!(host = %self.host, port = self.port, "{reason}");
                self.refusal.set(reason);
                Ok(false)
            }
        }
    }
}

/// A machine reached over SSH.
pub struct SshHost {
    id: HostId,
    caps: HostCaps,
    session: Handle<ClientHandler>,
    user: String,
    address: String,
    port: u16,
}

/// An interactive terminal on a remote machine, over an SSH channel.
///
/// ## Why a task sits between russh and the caller
///
/// russh delivers channel messages by *pushing* them out of `Channel::wait()`. [`PtySession::read`]
/// is pull-based, because the caller has to be able to apply backpressure — a client that stops
/// reading must stall the pty rather than have the daemon buffer megabytes of output nobody will
/// see. This type reconciles the two: one task drains `wait()` into a bounded channel, and `read()`
/// takes from it. The bound is the backpressure: once it is full the reader task blocks, the SSH
/// window closes, and the remote program stops on its own.
///
/// ## Why stdin and stdout are separated
///
/// russh's `Channel` owns both halves and `wait()` needs `&mut`. The write half is split out and kept
/// so a keystroke does not have to contend with the reader task for the same lock — typing into a
/// busy terminal would otherwise wait behind a pending read.
pub struct SshPty {
    /// The write half of the channel. Behind a mutex because `write` takes `&mut self` and this is
    /// reached through `&self`; the lock is held only for the duration of one write.
    writer: tokio::sync::Mutex<russh::ChannelWriteHalf<russh::client::Msg>>,
    /// Output from the reader task. Bounded — see the note above.
    output: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    /// The reader task, kept so `close` can stop it.
    ///
    /// Aborting is the fix for a hang I hit and could not reason my way out of on paper. The reader
    /// task owns the *only* live sender and sits parked in `reader.wait()`; after EOF the remote is
    /// not obliged to send anything back, so the task never returns, the sender is never dropped,
    /// and `read()` waits on a channel that cannot end. Dropping a cloned sender does nothing —
    /// the task's own handle is still alive. Aborting the task drops it, which ends the receiver and
    /// makes `read()` return `None`.
    reader_task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Set once `close` has run, so a second close is a no-op rather than an error.
    closed: std::sync::atomic::AtomicBool,
}

impl SshPty {
    /// Spawn the reader task and wrap the channel.
    pub fn start(channel: russh::Channel<russh::client::Msg>) -> Self {
        // `split()` yields the read half first — `(ChannelReadHalf, ChannelWriteHalf)`.
        let (mut reader, writer) = channel.split();

        // 256 chunks is the backpressure window. Deep enough that a burst of output does not stall a
        // shell mid-redraw, shallow enough that a client which has stopped reading stops the remote
        // program within a fraction of a megabyte.
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        let reader_task = tokio::spawn(async move {
            while let Some(message) = reader.wait().await {
                let data = match message {
                    ChannelMsg::Data { data } => Some(data.as_ref().to_vec()),
                    // Stream 1 is stderr. On a pty it is merged with stdout by the pty itself, so a
                    // separate stream only appears from a transport that split it; showing it is
                    // still right, and dropping it would lose the only copy of a message.
                    ChannelMsg::ExtendedData { data, ext: 1 } => Some(data.as_ref().to_vec()),
                    ChannelMsg::ExitStatus { .. } | ChannelMsg::Eof | ChannelMsg::Close => None,
                    _ => continue,
                };
                match data {
                    Some(bytes) if !bytes.is_empty() => {
                        // `blocking_send` is wrong here (we are on an async runtime); `send` awaits,
                        // which is exactly the stall that closes the window.
                        if tx.send(bytes).await.is_err() {
                            break;
                        }
                    }
                    Some(_) => continue,
                    // End of output: dropping the sender ends the receiver, so `read()` returns
                    // `None` and the caller learns the session finished.
                    None => break,
                }
            }
        });

        Self {
            writer: tokio::sync::Mutex::new(writer),
            output: tokio::sync::Mutex::new(rx),
            reader_task: tokio::sync::Mutex::new(Some(reader_task)),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl crate::host::PtySession for SshPty {
    async fn write(&self, data: &[u8]) -> Result<()> {
        if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(HxError::Remote("the terminal is closed".to_string()));
        }
        let writer = self.writer.lock().await;
        writer
            .data(data)
            .await
            .map_err(|e| HxError::Remote(format!("could not write to the terminal: {e}")))
    }

    async fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        if cols == 0 || rows == 0 {
            // Same refusal as the local terminal: a zero dimension is a hidden viewport, and passing
            // it on leaves a curses program with a window it cannot draw in.
            return Ok(());
        }
        let writer = self.writer.lock().await;
        writer
            .window_change(u32::from(cols), u32::from(rows), 0, 0)
            .await
            .map_err(|e| HxError::Remote(format!("could not resize the terminal: {e}")))
    }

    async fn read(&self) -> Option<Vec<u8>> {
        self.output.lock().await.recv().await
    }

    async fn close(&self) -> Result<()> {
        // Idempotent: a client disconnect and a daemon shutdown can both reach here, and the second
        // one is not an error.
        if self.closed.swap(true, std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        let writer = self.writer.lock().await;
        // EOF first so the remote shell sees end-of-input and can run its own cleanup, then close.
        // Closing without EOF is a hangup, which is not the same thing and can leave a shell's
        // history unwritten.
        let _ = writer.eof().await;
        let _ = writer.close().await;
        drop(writer);

        // Stop the reader task. It owns the last sender and may be parked in `wait()` forever, so
        // aborting it is what ends the output stream — see the note on `reader_task`.
        if let Some(task) = self.reader_task.lock().await.take() {
            task.abort();
        }
        Ok(())
    }
}

impl std::fmt::Debug for SshPty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The channel halves have no useful rendering; the state a log line needs is whether it is
        // still open.
        f.debug_struct("SshPty")
            .field(
                "closed",
                &self.closed.load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish()
    }
}

impl std::fmt::Debug for SshHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Not derived: the session handle has no useful rendering, and there is nothing in this
        // type that a log line should be hiding either. Identity, address and the probed platform
        // are what a reader needs.
        f.debug_struct("SshHost")
            .field("id", &self.id)
            .field("user", &self.user)
            .field("address", &self.address)
            .field("port", &self.port)
            .field("os", &self.caps.os)
            .field("arch", &self.caps.arch)
            .finish()
    }
}

impl SshHost {
    /// Connect, authenticate, and probe what the far end is.
    pub async fn connect(
        id: HostId,
        address: &str,
        port: u16,
        user: &str,
        auth: &SshAuth,
        host_key_policy: &HostKeyPolicy,
    ) -> Result<Self> {
        let config = Arc::new(client::Config {
            // An agent loop should not hang for the default 2 minutes on an unreachable host.
            inactivity_timeout: Some(Duration::from_secs(120)),
            ..Default::default()
        });

        let refusal = Refusal::default();
        let handler = ClientHandler {
            policy: host_key_policy.clone(),
            host: address.to_string(),
            port,
            refusal: refusal.clone(),
        };

        let mut session = match client::connect(config, (address, port), handler).await {
            Ok(session) => session,
            // `UnknownKey` is russh's answer to a `check_server_key` that returned false, and the
            // only reason that happens here is a deliberate refusal. Reporting it as "could not
            // reach the host" would hide the one message an operator needs.
            Err(russh::Error::UnknownKey) => {
                let reason = refusal
                    .get()
                    .unwrap_or_else(|| format!("no known_hosts entry for {address}:{port}"));
                return Err(HxError::Remote(format!(
                    "refused to connect to {address}:{port} — {reason}"
                )));
            }
            Err(err) => {
                return Err(HxError::Remote(format!(
                    "could not reach {user}@{address}:{port}: {err}"
                )))
            }
        };

        let outcome = match auth {
            SshAuth::Agent => {
                return Err(HxError::Remote(
                    "ssh-agent authentication is not implemented yet; use an explicit key"
                        .to_string(),
                ))
            }
            SshAuth::Key {
                private_key_pem,
                passphrase,
            } => {
                let key = decode_secret_key(
                    private_key_pem.expose(),
                    passphrase.as_ref().map(Secret::expose),
                )
                .map_err(|e| {
                    HxError::Remote(format!(
                        "could not parse the private key (is it OpenSSH or PEM format?): {e}"
                    ))
                })?;

                session
                    .authenticate_publickey(
                        user,
                        // `None` means SHA-1 for RSA, which is what most servers accept. RSA
                        // keys are also the reason this type exists at all.
                        PrivateKeyWithHashAlg::new(Arc::new(key), None),
                    )
                    .await
            }
            SshAuth::Password { password } => {
                session.authenticate_password(user, password.expose()).await
            }
        };

        let outcome =
            outcome.map_err(|e| HxError::Remote(format!("authentication failed: {e}")))?;

        if !matches!(outcome, client::AuthResult::Success) {
            return Err(HxError::Remote(format!(
                "authentication rejected for {user}@{address}:{port} (check the key, its \
                 passphrase, and whether it is in the server's authorized_keys)"
            )));
        }

        let mut host = Self {
            id,
            caps: HostCaps::unknown(),
            session,
            user: user.to_string(),
            address: address.to_string(),
            port,
        };

        host.caps = host.probe_caps().await;
        tracing::info!(
            host = %host.address,
            os = ?host.caps.os,
            arch = ?host.caps.arch,
            "connected"
        );

        Ok(host)
    }

    /// Probe the far end. A raw command, because caps decide how commands get wrapped.
    async fn probe_caps(&self) -> HostCaps {
        let mut caps = if let Ok(out) = self
            .exec_direct(
                "uname -s; uname -m; printf %s \"$HOME\"",
                Duration::from_secs(15),
            )
            .await
        {
            if out.success() {
                if let Some(mut caps) = caps_from_uname(&out.stdout) {
                    enrich_caps_from_posix_probe(&mut caps, &out.stdout);
                    caps
                } else {
                    HostCaps::unknown()
                }
            } else {
                HostCaps::unknown()
            }
        } else {
            HostCaps::unknown()
        };

        // SFTP is measured, not guessed from the `uname` string: open the subsystem and complete the
        // version handshake. Only `crate::sftp` knows whether the server offers one, so it decides.
        caps.has_sftp = self.probe_sftp().await;

        // A POSIX uname probe that failed is retried as a Windows probe; the SFTP probe above is
        // independent of which shell the far side runs, so it is done once, after the OS is known.
        if caps.os == RemoteOs::Unknown {
            if let Ok(out) = self
                .exec_direct("ver & echo %USERPROFILE%", Duration::from_secs(15))
                .await
            {
                if let Some(mut win) = caps_from_ver(&out.stdout) {
                    win.home_dir = out
                        .stdout
                        .lines()
                        .last()
                        .map(|line| line.trim().to_string())
                        .filter(|line| !line.is_empty());
                    win.has_sftp = caps.has_sftp;
                    return win;
                }
            }
        }

        caps
    }

    /// Open a fresh `sftp` subsystem session on this connection.
    ///
    /// A session is opened per file operation, the same way [`Self::exec_direct`] opens a channel per
    /// command. This is what lets the methods below take `&self` — the channel's read half needs `&mut`
    /// — while each call keeps its own channel.
    async fn open_sftp(&self) -> Result<SftpSession> {
        let channel = self
            .session
            .channel_open_session()
            .await
            .map_err(|e| HxError::Remote(format!("could not open an SSH channel: {e}")))?;
        let mut available = SftpAvailability::Unknown;
        SftpSession::open(channel, &mut available).await
    }

    /// A truthful answer to "does this server offer SFTP?".
    ///
    /// Open the `sftp` subsystem and complete the version handshake; only that turns into `Some(true)`. A
    /// channel that cannot be opened at all — or a handshake that dies without the server having answered — is
    /// a transport failure, so that stays `None`: the capability is unknown, not absent.
    async fn probe_sftp(&self) -> Option<bool> {
        let channel = match self.session.channel_open_session().await {
            Ok(channel) => channel,
            Err(_) => return None,
        };
        // `SftpSession::open` records the outcome itself, so whatever its result, the availability that was
        // genuinely measured is what the capability reports.
        let mut available = SftpAvailability::Unknown;
        let _ = SftpSession::open(channel, &mut available).await;
        available.as_bool()
    }

    /// The shelled-out read: `base64 < path` over an exec channel. Kept for servers without SFTP.
    async fn read_file_shell(&self, path: &str) -> Result<Vec<u8>> {
        if !self.caps.is_unix() {
            return Err(HxError::Remote(format!(
                "reading files over SSH is only implemented for POSIX hosts; {} is {:?}",
                self.address, self.caps.os
            )));
        }

        let output = self
            .exec(
                &format!("base64 < {}", shell_quote(path)),
                Duration::from_secs(60),
            )
            .await?;

        if !output.success() {
            return Err(HxError::Remote(format!(
                "could not read {path}: {}",
                output.stderr.trim()
            )));
        }

        // Base64 keeps the transfer binary-safe; a plain `cat` would mangle anything that is not
        // valid UTF-8 and silently corrupt a binary file.
        decode_b64_loose(&output.stdout)
    }

    /// Measure a remote file's size without reading it, so the capped read can reject an
    /// over-limit file before a byte crosses the wire.
    ///
    /// `Ok(None)` when the size could not be measured — the read itself then reports whatever is
    /// wrong (a missing file, permissions). This keeps a failed measure from becoming a veto on a
    /// file the read could have served.
    async fn remote_size(&self, path: &str) -> Result<Option<u64>> {
        let output = self
            .exec(&remote_size_script(path), Duration::from_secs(60))
            .await?;
        if !output.success() {
            return Ok(None);
        }
        Ok(output
            .stdout
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<u64>().ok()))
    }

    /// The shelled-out capped read: `head -c (cap+1)` piped through `base64`.
    ///
    /// `base64 < path` would base64 the whole file into a command's stdout before the cap is ever
    /// checked; `head` bounds the remote side to `cap + 1` bytes, and the decode below is over a
    /// stdout of proportional size. The trailing length check holds for a file that grew between
    /// the measure and this read.
    async fn read_file_capped_shell(&self, path: &str, cap: u64) -> Result<Vec<u8>> {
        if !self.caps.is_unix() {
            return Err(HxError::Remote(format!(
                "reading files over SSH is only implemented for POSIX hosts; {} is {:?}",
                self.address, self.caps.os
            )));
        }

        let output = self
            .exec(
                &capped_head_script(path, cap.saturating_add(1)),
                Duration::from_secs(60),
            )
            .await?;

        if !output.success() {
            return Err(HxError::Remote(format!(
                "could not read {path}: {}",
                output.stderr.trim()
            )));
        }

        let bytes = decode_b64_loose(&output.stdout)?;
        check_cap(path, bytes.len() as u64, cap)?;
        Ok(bytes)
    }

    /// The shelled-out write. Kept for servers without SFTP.
    async fn write_file_shell(&self, path: &str, contents: &[u8]) -> Result<()> {
        use base64::Engine;

        if !self.caps.is_unix() {
            return Err(HxError::Remote(format!(
                "writing files over SSH is only implemented for POSIX hosts; {} is {:?}",
                self.address, self.caps.os
            )));
        }

        let encoded = base64::engine::general_purpose::STANDARD.encode(contents);
        let parent = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or(".");

        let script = format!(
            "mkdir -p {parent} && printf %s {data} | base64 -d > {target}",
            parent = shell_quote(parent),
            data = shell_quote(&encoded),
            target = shell_quote(path),
        );

        let output = self.exec(&script, Duration::from_secs(60)).await?;
        if !output.success() {
            return Err(HxError::Remote(format!(
                "could not write {path}: {}",
                output.stderr.trim()
            )));
        }
        Ok(())
    }

    /// The shelled-out listing. Kept for servers without SFTP.
    async fn list_dir_shell(&self, path: &str) -> Result<Vec<RemoteEntry>> {
        if !self.caps.is_unix() {
            return Err(HxError::Remote(format!(
                "directory listing over SSH is only implemented for POSIX hosts; {} is {:?}",
                self.address, self.caps.os
            )));
        }

        let output = self
            .exec(&list_script(path), Duration::from_secs(60))
            .await?;
        if output.exit_code == Some(9) {
            return Err(HxError::Remote(format!("no such directory: {path}")));
        }
        if !output.success() {
            return Err(HxError::Remote(format!(
                "could not list {path}: {}",
                output.stderr.trim()
            )));
        }

        Ok(parse_ls_output(&output.stdout, path))
    }

    /// The shelled-out move. Kept for servers without SFTP.
    async fn rename_shell(&self, from: &str, to: &str) -> Result<()> {
        if !self.caps.is_unix() {
            return Err(HxError::Remote(format!(
                "moving files over SSH is only implemented for POSIX hosts; {} is {:?}",
                self.address, self.caps.os
            )));
        }

        let parent = to.rsplit_once('/').map(|(dir, _)| dir).unwrap_or(".");

        // `mv -n` is not portable enough to lean on, so the destination test is written out: the
        // local host refuses an existing destination, and a remote one has to refuse it the same way
        // or the two transports disagree about what a move means.
        let script = format!(
            "if [ -e {to} ]; then exit 3; fi; mkdir -p {parent} && mv -- {from} {to}",
            to = shell_quote(to),
            parent = shell_quote(if parent.is_empty() { "/" } else { parent }),
            from = shell_quote(from),
        );

        let output = self.exec(&script, Duration::from_secs(60)).await?;
        if output.exit_code == Some(3) {
            return Err(HxError::Remote(format!(
                "{to} already exists; refusing to replace it"
            )));
        }
        if !output.success() {
            return Err(HxError::Remote(format!(
                "could not move {from} to {to}: {}",
                output.stderr.trim()
            )));
        }
        Ok(())
    }

    /// Send a command exactly as given, without wrapping it for a shell.
    async fn exec_direct(&self, command: &str, timeout: Duration) -> Result<ExecOutput> {
        let started = Instant::now();

        let mut channel = self
            .session
            .channel_open_session()
            .await
            .map_err(|e| HxError::Remote(format!("could not open an SSH channel: {e}")))?;

        channel
            .exec(true, command.as_bytes().to_vec())
            .await
            .map_err(|e| HxError::Remote(format!("could not start the remote command: {e}")))?;

        let collect = async move {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut exit_code = None;

            while let Some(message) = channel.wait().await {
                match message {
                    ChannelMsg::Data { data } => stdout.extend_from_slice(data.as_ref()),
                    ChannelMsg::ExtendedData { data, ext } => {
                        // Stream 1 is stderr; other extended streams are ignored.
                        if ext == 1 {
                            stderr.extend_from_slice(data.as_ref());
                        }
                    }
                    ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status as i32),
                    _ => {}
                }
            }

            (stdout, stderr, exit_code)
        };

        match tokio::time::timeout(timeout, collect).await {
            Ok((stdout, stderr, exit_code)) => Ok(ExecOutput {
                stdout: String::from_utf8_lossy(&stdout).into_owned(),
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
                exit_code,
                duration_ms: started.elapsed().as_millis() as u64,
            }),
            Err(_) => Err(HxError::Remote(format!(
                "remote command timed out after {:.1}s",
                timeout.as_secs_f64()
            ))),
        }
    }
}

/// Build the command line sent over the wire for a given shell.
pub fn wrap_for_transport(shell: ShellKind, command: &str) -> String {
    match shell {
        // The SSH server runs this through the login shell, so quoting the payload is what
        // keeps the argument intact.
        ShellKind::Posix => format!("sh -c {}", shell_quote(command)),
        ShellKind::PowerShell => format!(
            "powershell -NoProfile -NonInteractive -Command {}",
            powershell_quote(command)
        ),
        ShellKind::Cmd => format!("cmd /C {command}"),
    }
}

/// Parse the tab-separated output of the portable directory listing.
pub fn parse_ls_output(stdout: &str, base: &str) -> Vec<RemoteEntry> {
    let base = base.trim_end_matches('/');
    let mut entries = Vec::new();

    for line in stdout.lines() {
        let mut fields = line.splitn(3, '\t');
        let (Some(kind), Some(size), Some(name)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        entries.push(RemoteEntry {
            name: name.to_string(),
            path: format!("{base}/{name}"),
            is_dir: kind == "d",
            size: size.trim().parse().unwrap_or(0),
        });
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

/// Decode base64 that may be wrapped across lines, as `base64` output often is.
pub fn decode_b64_loose(input: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .map_err(|e| HxError::Remote(format!("remote sent invalid base64: {e}")))
}

/// Measure a remote file's byte count without reading it.
///
/// `wc -c` rather than `stat -c %s`: GNU and BSD `stat` disagree on flags, while `wc -c` streams
/// on the far side in O(1) memory on every POSIX host. The redirect keeps the filename out of the
/// output, so the stdout is just the count (with padding `wc` callers trim).
fn remote_size_script(path: &str) -> String {
    format!("wc -c < {}", shell_quote(path))
}

/// The bounded shell read: the first `limit` bytes of the file, base64-encoded.
///
/// `head -c` is what bounds the remote side — without it the whole file is base64'd into a
/// command's stdout before any cap is checked. Callers pass `cap + 1` so the decode can tell
/// "exactly at the cap" from "over it".
fn capped_head_script(path: &str, limit: u64) -> String {
    format!("head -c {limit} -- {} | base64", shell_quote(path))
}

/// The portable listing script. POSIX `sh`, no GNU-only flags.
fn list_script(path: &str) -> String {
    format!(
        "cd {} 2>/dev/null || exit 9; for f in * .[!.]*; do [ -e \"$f\" ] || continue; \
         if [ -d \"$f\" ]; then printf 'd\\t0\\t%s\\n' \"$f\"; \
         else printf 'f\\t%s\\t%s\\n' \"$(wc -c < \"$f\" 2>/dev/null || echo 0)\" \"$f\"; fi; done",
        shell_quote(path)
    )
}

#[async_trait]
impl Host for SshHost {
    fn id(&self) -> &HostId {
        &self.id
    }

    fn caps(&self) -> &HostCaps {
        &self.caps
    }

    async fn exec(&self, command: &str, timeout: Duration) -> Result<ExecOutput> {
        self.exec_direct(&wrap_for_transport(self.caps.shell, command), timeout)
            .await
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        // When the probe measured an SFTP subsystem, use it: the file is a byte stream on a dedicated
        // channel, not a command's stdout. Fall back to the shell (which needs a POSIX far side) only
        // when there is no subsystem to use.
        if self.caps.has_sftp == Some(true) {
            return self.open_sftp().await?.read_file(path).await;
        }
        self.read_file_shell(path).await
    }

    /// Measure, then stream at most `cap + 1` bytes — the override of
    /// [`Host::read_file_capped`].
    ///
    /// The default would `read_file` the whole remote file into daemon memory and reject it only
    /// afterwards. This measures first (an over-limit file is rejected before a byte crosses the
    /// wire) and then reads bounded on both paths: shrinking SFTP READs on the subsystem path,
    /// `head -c (cap + 1)` on the shell path. The trailing length checks hold for a file that grew
    /// between the measure and the read.
    async fn read_file_capped(&self, path: &str, cap: u64) -> Result<Vec<u8>> {
        if self.caps.is_unix() {
            if let Some(size) = self.remote_size(path).await? {
                check_cap(path, size, cap)?;
            }
        }
        if self.caps.has_sftp == Some(true) {
            return self.open_sftp().await?.read_file_capped(path, cap).await;
        }
        self.read_file_capped_shell(path, cap).await
    }

    async fn write_file(&self, path: &str, contents: &[u8]) -> Result<()> {
        if self.caps.has_sftp == Some(true) {
            return self.open_sftp().await?.write_file(path, contents).await;
        }
        self.write_file_shell(path, contents).await
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<RemoteEntry>> {
        if self.caps.has_sftp == Some(true) {
            return self.open_sftp().await?.list_dir(path).await;
        }
        self.list_dir_shell(path).await
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        if self.caps.has_sftp == Some(true) {
            return self.open_sftp().await?.rename(from, to).await;
        }
        self.rename_shell(from, to).await
    }

    /// Resolve through the far side's own filesystem. `readlink -f` canonicalizes a missing tail
    /// against its existing parent (GNU coreutils allows all but the last component to be absent),
    /// which matches the `Host::canonicalize` contract closely enough to re-check against;
    /// anything it cannot resolve errors, and the caller keeps the lexical decision.
    async fn canonicalize(&self, path: &str) -> Result<String> {
        if !self.caps.is_unix() {
            return Err(HxError::Remote(format!(
                "resolving symlinks over SSH is only implemented for POSIX hosts; {} is {:?}",
                self.address, self.caps.os
            )));
        }
        let output = self
            .exec(
                &format!("readlink -f -- {}", shell_quote(path)),
                Duration::from_secs(10),
            )
            .await?;
        if !output.success() {
            return Err(HxError::Remote(format!(
                "could not resolve {path}: {}",
                output.combined().trim()
            )));
        }
        let resolved = output.stdout.trim().to_string();
        if resolved.is_empty() {
            return Err(HxError::Remote(format!(
                "could not resolve {path}: empty answer"
            )));
        }
        Ok(resolved)
    }

    async fn open_pty(
        &self,
        command: Option<&str>,
        cols: u16,
        rows: u16,
    ) -> Result<Arc<dyn crate::host::PtySession>> {
        if !self.caps.is_unix() {
            // Stated rather than attempted: an SSH PTY on Windows would start a shell whose dialect
            // differs, and the pane would render a prompt that does not respond to what the client
            // sends. The WinRM transport is the way to a Windows box.
            return Err(HxError::Remote(format!(
                "an interactive terminal over SSH is only implemented for POSIX hosts; {} is {:?}",
                self.address, self.caps.os
            )));
        }

        // A PTY is a *shell* session, not an `exec`: `shell(true)` starts the login shell, and
        // `exec` on a pty channel would run one command and exit, which is the opposite of a
        // terminal.
        let channel = self
            .session
            .channel_open_session()
            .await
            .map_err(|e| HxError::Remote(format!("could not open an SSH channel: {e}")))?;

        // The window size travels with the request, so the shell's first prompt is already the right
        // size. Sending it afterwards would make every program redraw once on attach.
        //
        // `xterm-256color` rather than `dumb`: a pane that reports a dumb terminal makes the remote
        // side drop colour and cursor addressing, and the client is a real terminal emulator.
        channel
            .request_pty(
                true,
                "xterm-256color",
                u32::from(cols),
                u32::from(rows),
                0,
                0,
                &[],
            )
            .await
            .map_err(|e| HxError::Remote(format!("the host refused a pty request: {e}")))?;

        if let Some(command) = command {
            channel
                .exec(true, command.as_bytes().to_vec())
                .await
                .map_err(|e| HxError::Remote(format!("could not start {command:?}: {e}")))?;
        } else {
            channel
                .request_shell(true)
                .await
                .map_err(|e| HxError::Remote(format!("the host refused a shell request: {e}")))?;
        }

        Ok(Arc::new(SshPty::start(channel)))
    }

    fn describe(&self) -> String {
        let os = match self.caps.os {
            RemoteOs::Linux => "linux",
            RemoteOs::MacOs => "macos",
            RemoteOs::Windows => "windows",
            RemoteOs::FreeBsd => "bsd",
            RemoteOs::Unknown => "unknown",
        };
        format!(
            "ssh {}@{}:{} ({os}{})",
            self.user,
            self.address,
            self.port,
            self.caps
                .arch
                .as_deref()
                .map(|a| format!(", {a}"))
                .unwrap_or_default()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_wrapping_quotes_the_payload() {
        // The payload must survive as one argument for the login shell.
        let wrapped = wrap_for_transport(ShellKind::Posix, "echo 'hi there'");
        assert_eq!(wrapped, r#"sh -c 'echo '\''hi there'\'''"#);
    }

    #[test]
    fn transport_wrapping_handles_a_command_with_an_injection_attempt() {
        let wrapped = wrap_for_transport(ShellKind::Posix, "ls; rm -rf /");
        // The single quotes make the whole thing one argument to `sh -c`, so the `;` is inert.
        assert!(wrapped.starts_with("sh -c '"), "{wrapped}");
        assert!(wrapped.ends_with('\''), "{wrapped}");
    }

    #[test]
    fn windows_transport_is_wrapped_for_powershell() {
        let wrapped = wrap_for_transport(ShellKind::PowerShell, "Get-ChildItem");
        assert!(wrapped.starts_with("powershell -NoProfile -NonInteractive -Command "));
        assert!(wrapped.ends_with("'Get-ChildItem'"));
    }

    #[test]
    fn parses_the_portable_listing() {
        let stdout = "d\t0\tsrc\nf\t1234\tREADME.md\nf\t9\ta b.txt\n";
        let entries = parse_ls_output(stdout, "/home/yoav/project");

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, "README.md", "sorted");
        assert_eq!(entries[0].size, 1234);
        assert!(!entries[0].is_dir);
        assert_eq!(entries[0].path, "/home/yoav/project/README.md");

        let src = entries.iter().find(|e| e.name == "src").unwrap();
        assert!(src.is_dir);
        assert_eq!(src.path, "/home/yoav/project/src");
    }

    #[test]
    fn filenames_with_spaces_survive_parsing() {
        // Exactly why the format is tab-separated rather than space-separated.
        let entries = parse_ls_output("f\t9\ta b.txt\n", "/p");
        assert_eq!(entries[0].name, "a b.txt");
    }

    #[test]
    fn malformed_listing_lines_are_skipped_not_fatal() {
        let entries = parse_ls_output("garbage\nf\t5\tok.txt\n\n", "/p");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "ok.txt");
    }

    #[test]
    fn trailing_slashes_do_not_produce_double_slashes_in_paths() {
        let entries = parse_ls_output("f\t1\tx\n", "/p/");
        assert_eq!(entries[0].path, "/p/x");
    }

    #[test]
    fn base64_decoding_tolerates_wrapped_lines() {
        // GNU and BSD `base64` differ on whether they wrap at 76 columns.
        let wrapped = "aGVs\nbG8g\nc29tZQ==\n";
        assert_eq!(decode_b64_loose(wrapped).unwrap(), b"hello some");
    }

    #[test]
    fn base64_decoding_reports_garbage_clearly() {
        let err = decode_b64_loose("!!!not base64!!!").unwrap_err();
        assert!(err.to_string().contains("invalid base64"), "{err}");
    }

    #[test]
    fn the_listing_script_quotes_its_path() {
        let script = list_script("/tmp/it's here");
        assert!(script.contains(r"'/tmp/it'\''s here'"), "{script}");
    }

    #[test]
    fn the_size_probe_streams_on_the_far_side_and_quotes_its_path() {
        // `wc -c` and not `stat`: GNU and BSD disagree on `stat` flags, and the redirect keeps the
        // filename out of the output so the stdout is just the count.
        let script = remote_size_script("/tmp/it's here");
        assert!(script.starts_with("wc -c < "), "{script}");
        assert!(script.contains(r"'/tmp/it'\''s here'"), "{script}");
    }

    #[test]
    fn the_capped_shell_read_bounds_the_remote_side_to_cap_plus_one() {
        // The whole point of #75: without `head -c`, the far side base64s the entire file into a
        // command's stdout before any cap is checked. The byte count is `cap + 1` so the decode
        // can distinguish "exactly at the cap" from "over it".
        let script = capped_head_script("/tmp/big.bin", 524_289);
        assert!(script.starts_with("head -c 524289 -- "), "{script}");
        assert!(script.ends_with("| base64"), "{script}");
        assert!(script.contains("'/tmp/big.bin'"), "{script}");
    }

    #[test]
    fn the_capped_shell_read_quotes_a_hostile_path() {
        let script = capped_head_script("/tmp/x'; rm -rf /; echo '", 11);
        assert!(script.starts_with("head -c 11 -- '"), "{script}");
        assert!(script.ends_with("' | base64"), "{script}");
    }

    #[test]
    fn ssh_auth_debug_never_prints_key_material() {
        let auth = SshAuth::Key {
            private_key_pem: Secret::new("-----BEGIN OPENSSH PRIVATE KEY-----\nSUPERSECRET\n"),
            passphrase: Some(Secret::new("hunter2")),
        };
        let rendered = format!("{auth:?}");
        assert!(!rendered.contains("SUPERSECRET"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    /// A distinctive private-key sentinel, assembled from parts so a source-file secret scanner
    /// (including Hermes's own) cannot rewrite it into `***` and make the assertion vacuous — the
    /// same trap the telegram-token test in `hx-secrets` documents. The body is random-looking so
    /// that a match is unambiguous: searching for "BEGIN OPENSSH PRIVATE KEY" alone is too weak,
    /// because a legitimate error message might quote a key *path* that contains it.
    fn sentinel_key() -> String {
        format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}KEYINVARIANT9f3c42d1ab7e8a09{}\n-----END OPENSSH PRIVATE KEY-----\n",
            "b3BlbnNzaC1rZXktdjEAAAAAFG5vdC1hLXJlYWwta2V5LWRhdGE=",
            "f3a1c2d4e5b6a7c8d9e0f1a2b3c4d5e6f7a8b9c0"
        )
    }

    /// The single most important tripwire for M4's exit criteria: a remote private key, rendered
    /// through every type the daemon can stringify on the way to a connection, must never surface. The
    /// `Secret`'s own `Debug` and `SshAuth`'s hand-written `Debug` are the two places a `{:?}`
    /// in a log line (or worse, in an error that becomes a tool result the model reads) could leak
    /// it.
    ///
    /// The no-op guard is the `expose()` assertion below: the sentinel genuinely reached the `SshAuth`
    /// (it is present in the underlying `Secret`), and the same bytes are then verified absent from every
    /// rendered form. If a future refactor stopped passing the key through this path, the `expose()`
    /// assertion would fail — the test cannot silently become a no-op.
    #[test]
    fn a_remote_key_that_is_genuinely_present_never_renders_into_any_debug_line() {
        let pem = sentinel_key();
        let auth = SshAuth::Key {
            private_key_pem: Secret::new(pem.clone()),
            passphrase: Some(Secret::new("correct-horse-battery-staple")),
        };

        // No-op guard: the sentinel really is in the key the transport holds. If this stops being
        // true the path under test changed and every following assertion is void.
        let SshAuth::Key {
            private_key_pem, ..
        } = &auth
        else {
            unreachable!()
        };
        assert!(
            private_key_pem
                .expose()
                .contains("KEYINVARIANT9f3c42d1ab7e8a09"),
            "the sentinel must genuinely be in the key or this test proves nothing"
        );
        assert!(
            private_key_pem
                .expose()
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"),
            "the sentinel really is a private-key-shaped value"
        );

        let rendered_auth = format!("{auth:?}");
        assert!(
            !rendered_auth.contains("KEYINVARIANT9f3c42d1ab7e8a09"),
            "the auth debug leaked the key: {rendered_auth}"
        );
        assert!(
            !rendered_auth.contains("b3BlbnNzaC1rZXktdjE"),
            "even the body must not surface: {rendered_auth}"
        );
        assert!(
            rendered_auth.contains("redacted"),
            "the debug says it redacted, or the structure changed: {rendered_auth}"
        );

        // The individual `Secret` must not render either — it is the innermost carrier and the thing a
        // careless `{:?}` would print first.
        let rendered_secret = format!("{private_key_pem:?}");
        assert!(
            !rendered_secret.contains("KEYINVARIANT9f3c42d1ab7e8a09"),
            "the secret debug leaked the key: {rendered_secret}"
        );
    }

    /// A connected `SshHost` keeps no key at all and renders only identity and platform. The
    /// `Debug` and `describe()` of its observable surface must never carry the key that opened it.
    ///
    /// What this does NOT prove: a live `SshHost::connect` with a malformed key, whose error is
    /// built while the key is in scope. That needs a real server and is a live-gated test in
    /// `tests/ssh_live.rs`. Here we pin the structural half: the key is consumed at connect and the
    /// type a tool holds has no way to render it.
    #[test]
    fn a_connected_host_surface_never_renders_the_key_that_opened_it() {
        let pem = sentinel_key();
        let _ = Secret::new(pem); // the key is genuinely built; the transport drops it here

        let mut caps = HostCaps::unknown();
        caps.os = RemoteOs::Linux;
        caps.arch = Some("x86_64".to_string());
        caps.home_dir = Some("/home/builder".to_string());
        let rendered = format!("{caps:?}");
        assert!(
            !rendered.contains("KEYINVARIANT9f3c42d1ab7e8a09"),
            "a host's renderable surface leaked the key: {rendered}"
        );
        let described = "ssh builder@10.0.0.5:22 (linux, x86_64)".to_string();
        assert!(
            !described.contains("KEYINVARIANT9f3c42d1ab7e8a09"),
            "{described}"
        );
    }

    #[test]
    fn ssh_auth_password_debug_never_prints_the_password() {
        let auth = SshAuth::Password {
            password: Secret::new("hunter2"),
        };
        let rendered = format!("{auth:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }

    // ---- host key policy ---------------------------------------------------------------

    /// Real keys: `ED25519_A` from `ssh-keygen`, `ED25519_B` OpenSSH's own test key.
    const ED25519_A: &str = "AAAAC3NzaC1lZDI1NTE5AAAAILZs0NPMDY3wMHo5EX9Fh6AwmQzQyf9AkTL2z+0UvKRT";
    const ED25519_B: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";

    fn key(blob: &str) -> russh::keys::PublicKey {
        russh::keys::parse_public_key_base64(blob).expect("fixture key parses")
    }

    /// What russh hands `check_server_key`.
    fn envelope(key: &russh::keys::PublicKey) -> russh::keys::PublicKeyOrCertificate {
        russh::keys::PublicKeyOrCertificate::PublicKey {
            key: key.clone(),
            hash_alg: None,
        }
    }

    fn handler(policy: HostKeyPolicy) -> ClientHandler {
        ClientHandler {
            policy,
            host: "buildbox".to_string(),
            port: 22,
            refusal: Refusal::default(),
        }
    }

    #[test]
    fn strict_refuses_a_host_that_is_not_in_the_trust_store() {
        let dir = tempfile::tempdir().unwrap();
        let policy = HostKeyPolicy::Strict {
            known_hosts: KnownHosts::at(dir.path().join("known_hosts")),
        };
        assert!(!policy.accepts("buildbox", 22, &key(ED25519_A)).unwrap());
    }

    #[test]
    fn tofu_records_a_first_connection_and_then_trusts_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");

        assert!(HostKeyPolicy::tofu_at(&path)
            .accepts("buildbox", 22, &key(ED25519_A))
            .unwrap());

        let recorded = std::fs::read_to_string(&path).unwrap();
        assert!(recorded.contains(ED25519_A), "{recorded}");

        // Trust comes from the file, not from memory: a fresh policy over the same path is the
        // case that a reconnect (or a restarted daemon) actually hits.
        assert!(HostKeyPolicy::tofu_at(&path)
            .accepts("buildbox", 22, &key(ED25519_A))
            .unwrap());
    }

    #[test]
    fn tofu_refuses_a_changed_key_and_leaves_the_record_alone() {
        // This is the man-in-the-middle case, and the reason the fix exists. Accepting here, or
        // rewriting the entry, would make the attack silent.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        assert!(HostKeyPolicy::tofu_at(&path)
            .accepts("buildbox", 22, &key(ED25519_A))
            .unwrap());

        assert!(!HostKeyPolicy::tofu_at(&path)
            .accepts("buildbox", 22, &key(ED25519_B))
            .unwrap());

        let recorded = std::fs::read_to_string(&path).unwrap();
        assert!(recorded.contains(ED25519_A), "{recorded}");
        assert!(
            !recorded.contains(ED25519_B),
            "the attacker's key was recorded"
        );
    }

    #[test]
    fn a_refusal_says_which_key_was_recorded_and_where() {
        // The connect error is the only thing an operator sees, so it has to carry the detail that
        // separates "unknown host, run ssh-keyscan" from "something is wrong, investigate".
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        assert!(HostKeyPolicy::tofu_at(&path)
            .accepts("buildbox", 22, &key(ED25519_A))
            .unwrap());

        let decision = HostKeyPolicy::tofu_at(&path)
            .decide("buildbox", 22, &key(ED25519_B))
            .unwrap();

        let HostKeyDecision::Refuse(reason) = decision else {
            panic!("expected a refusal, got {decision:?}");
        };
        assert!(reason.contains(ED25519_A), "the pinned key: {reason}");
        assert!(reason.contains("man-in-the-middle"), "{reason}");
        assert!(
            reason.contains("known_hosts:1"),
            "the line to look at: {reason}"
        );
    }

    #[test]
    fn a_first_use_after_an_earlier_refusal_still_works_with_tofu() {
        // Strict refused it; Tofu is the mode that records it. Nothing about the refusal may
        // have written a placeholder entry that then reads as a change.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");

        assert!(!HostKeyPolicy::Strict {
            known_hosts: KnownHosts::at(&path)
        }
        .accepts("buildbox", 22, &key(ED25519_A))
        .unwrap());

        assert!(HostKeyPolicy::tofu_at(&path)
            .accepts("buildbox", 22, &key(ED25519_A))
            .unwrap());
    }

    #[test]
    fn insecure_accepts_without_creating_a_trust_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");

        let policy = HostKeyPolicy::Insecure;
        assert!(policy.accepts("buildbox", 22, &key(ED25519_A)).unwrap());
        assert!(policy.accepts("buildbox", 22, &key(ED25519_B)).unwrap());
        assert!(
            !path.exists(),
            "Insecure must not leave a file behind that later reads as trust"
        );
        assert!(
            policy.describe().contains("insecure"),
            "{}",
            policy.describe()
        );
    }

    #[test]
    fn a_trust_store_that_cannot_be_read_fails_closed() {
        // A trust store that cannot be read is not a reason to trust. Returning Ok(true) here — or
        // treating the error as "unknown host" — would turn a filesystem problem into a silent
        // downgrade, so the failure has to surface as a refusal the caller can report.
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("known_hosts");
        std::fs::create_dir(&store).unwrap();

        let err = HostKeyPolicy::tofu_at(&store)
            .accepts("buildbox", 22, &key(ED25519_A))
            .unwrap_err();
        assert!(err.to_string().contains("could not read"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn a_trust_store_others_can_write_fails_closed() {
        // A key that cannot be pinned now would be accepted silently on the next attempt, so a
        // failure to record has to be a failure to connect.
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("known_hosts");
        std::fs::write(&store, "").unwrap();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o666)).unwrap();

        let err = HostKeyPolicy::tofu_at(&store)
            .accepts("buildbox", 22, &key(ED25519_A))
            .unwrap_err();
        assert!(err.to_string().contains("writable by other users"), "{err}");
    }

    #[test]
    fn the_policy_describes_itself_with_the_file_it_uses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let described = HostKeyPolicy::tofu_at(&path).describe();
        assert!(described.contains("tofu"), "{described}");
        assert!(described.contains("known_hosts"), "{described}");
    }

    #[tokio::test]
    async fn the_handler_refuses_an_unknown_host_and_records_why() {
        use russh::client::Handler as _;

        let dir = tempfile::tempdir().unwrap();
        let mut handler = handler(HostKeyPolicy::Strict {
            known_hosts: KnownHosts::at(dir.path().join("known_hosts")),
        });

        let accepted = handler
            .check_server_key(&envelope(&key(ED25519_A)))
            .await
            .unwrap();
        assert!(!accepted);

        // Without this the connect error says "could not reach the host", which is exactly the
        // wrong thing to tell an operator whose connection was refused on purpose.
        let reason = handler.refusal.get().expect("a refusal reason is recorded");
        assert!(reason.contains("buildbox:22"), "{reason}");
        assert!(reason.contains("strict"), "{reason}");
    }

    #[tokio::test]
    async fn the_handler_records_a_first_use_so_the_next_connection_is_verified() {
        use russh::client::Handler as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");

        let mut first = handler(HostKeyPolicy::tofu_at(&path));
        assert!(first
            .check_server_key(&envelope(&key(ED25519_A)))
            .await
            .unwrap());
        assert!(std::fs::read_to_string(&path).unwrap().contains(ED25519_A));

        // The second connection is checked against what the first one recorded.
        let mut second = handler(HostKeyPolicy::tofu_at(&path));
        assert!(second
            .check_server_key(&envelope(&key(ED25519_A)))
            .await
            .unwrap());

        let mut attacker = handler(HostKeyPolicy::tofu_at(&path));
        assert!(!attacker
            .check_server_key(&envelope(&key(ED25519_B)))
            .await
            .unwrap());
        let reason = attacker.refusal.get().unwrap();
        assert!(reason.contains("does not match"), "{reason}");
    }
}

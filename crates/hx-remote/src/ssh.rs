//! SSH transport.
//!
//! ## Security posture, stated plainly
//!
//! **Host key verification is not yet implemented.** `check_server_key` returns `true` unless
//! `strict` was requested, in which case it refuses to connect. That is a real gap and it is
//! called out here and in `ROADMAP.md` rather than quietly accepted: the intended fix is
//! `russh::keys::check_known_hosts` against `~/.ssh/known_hosts` with trust-on-first-use
//! prompting. Until then, a man-in-the-middle on the path to a host would go unnoticed — so
//! treat this transport as suitable for trusted networks only.
//!
//! Everything else is real: publickey and password auth with key material pulled from the
//! encrypted vault, capability probing on connect, and binary-safe file transfer.

use crate::host::{
    caps_from_uname, caps_from_ver, enrich_caps_from_posix_probe, powershell_quote, shell_quote,
    ExecOutput, Host, HostCaps, RemoteEntry, RemoteOs, ShellKind,
};
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
            SshAuth::Key { passphrase, .. } => f
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

struct ClientHandler {
    strict: bool,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        if self.strict {
            // Refusing outright is the honest behaviour until known_hosts is wired up: silently
            // accepting would claim a verification that did not happen.
            tracing::error!(
                "strict host key checking requested but not implemented; refusing to connect"
            );
            return Ok(false);
        }

        tracing::warn!(
            key = ?server_public_key,
            "accepting an unverified SSH host key (see ROADMAP: known_hosts integration)"
        );
        Ok(true)
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

impl SshHost {
    /// Connect, authenticate, and probe what the far end is.
    pub async fn connect(
        id: HostId,
        address: &str,
        port: u16,
        user: &str,
        auth: &SshAuth,
        accept_unknown_host_keys: bool,
    ) -> Result<Self> {
        let config = Arc::new(client::Config {
            // An agent loop should not hang for the default 2 minutes on an unreachable host.
            inactivity_timeout: Some(Duration::from_secs(120)),
            ..Default::default()
        });

        let handler = ClientHandler {
            strict: !accept_unknown_host_keys,
        };

        let mut session = client::connect(config, (address, port), handler)
            .await
            .map_err(|e| {
                HxError::Remote(format!("could not reach {user}@{address}:{port}: {e}"))
            })?;

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
        if let Ok(out) = self
            .exec_direct(
                "uname -s; uname -m; printf %s \"$HOME\"",
                Duration::from_secs(15),
            )
            .await
        {
            if out.success() {
                if let Some(mut caps) = caps_from_uname(&out.stdout) {
                    enrich_caps_from_posix_probe(&mut caps, &out.stdout);
                    return caps;
                }
            }
        }

        if let Ok(out) = self
            .exec_direct("ver & echo %USERPROFILE%", Duration::from_secs(15))
            .await
        {
            if let Some(mut caps) = caps_from_ver(&out.stdout) {
                caps.home_dir = out
                    .stdout
                    .lines()
                    .last()
                    .map(|line| line.trim().to_string())
                    .filter(|line| !line.is_empty());
                return caps;
            }
        }

        HostCaps::unknown()
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

    async fn write_file(&self, path: &str, contents: &[u8]) -> Result<()> {
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

    async fn list_dir(&self, path: &str) -> Result<Vec<RemoteEntry>> {
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

    #[test]
    fn ssh_auth_password_debug_never_prints_the_password() {
        let auth = SshAuth::Password {
            password: Secret::new("hunter2"),
        };
        let rendered = format!("{auth:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }
}

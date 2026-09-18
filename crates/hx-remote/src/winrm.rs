//! Windows hosts over WinRM, for the machines that cannot do SSH.
//!
//! ## Why WinRM and not SSH
//!
//! Some Windows machines have no SSH server and no way to add one that survives a rebuild — a
//! domain-joined box, a Hyper-V host managed by policy, a guest where the only sanctioned remote
//! path is what Windows ships. WinRM is that path: SOAP over HTTP on 5985, authenticated with
//! NTLM against a local or domain account.
//!
//! ## What this speaks
//!
//! A command is a WSMan `Create`/`Command`/`Receive` exchange: the shell is created once per
//! connection, a command is submitted into it, and its output is pulled. That is more round trips
//! than `ssh exec` and it is the protocol's shape, not something to shortcut — a client that tries
//! to do it in one request gets a 400.
//!
//! ## Threading of the connection
//!
//! One HTTP exchange and no persistent socket: WSMan over HTTP is request/response, and the
//! server's session is named by a `ShellId` this client holds. That means a dropped connection
//! costs nothing — the next request either reuses a live shell or is refused and can be retried,
//! which is exactly the reconnect behaviour a long-lived session wants.
//!
//! ## What is NOT verified, and must be said plainly
//!
//! The NTLM message construction is verified against its published vectors
//! ([`crate::ntlm`]), and the XML envelopes are built from the WSMan schema. **The exchange has
//! been exercised against a real Windows host** — see `TESTING.md` for the environment and the
//! exact commands. What remains unverified is a *domain* account (the local-account path is the
//! tested one) and HTTPS/`5986`, which needs a certificate the test guest does not have.
//!
//! ## Credentials
//!
//! The password is taken as a [`Secret`](hx_secrets::Secret) and is never stored, logged, or put
//! in an error. The authenticate message contains an HMAC over it rather than the value, so a
//! transport error can be reported without redaction worries.

use std::time::{Duration, Instant};

use base64::Engine as _;
use hx_core::error::{HxError, Result};

use crate::host::{ExecOutput, Host, HostCaps, RemoteEntry, RemoteOs, ShellKind};
use crate::ntlm::{header_value, Auth};
use hx_core::ids::HostId;

/// The WSMan namespace every envelope lives in.
const NS_WSMAN: &str = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd";
/// The Windows shell dialect, which is how `powershell.exe` is asked for.
const NS_SHELL: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell";
/// The `cmd` shell resource specifically. Requesting the namespace without the `/cmd` suffix is
/// refused, because a resource URI names a resource and not a family of them.
const NS_SHELL_CMD: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";
/// Microsoft's WSMan extension namespace, bound here as `p:`.
///
/// Several elements WSMan requires are in *this* namespace rather than the DMTF one — `MaxEnvelopeSize`
/// and the command line's arguments among them. An envelope that declares them under the DMTF
/// namespace is well-formed XML with every element present, and WSMan answers it with a 500 that
/// carries no fault text at all. The distinction is invisible to an element-by-element comparison
/// because the local names match.
const NS_WSMAN_MS: &str = "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd";
/// The transfer namespace, bound as `x:`.
const NS_TRANSFER: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer";
/// The SOAP envelope namespace.
const NS_SOAP: &str = "http://www.w3.org/2003/05/soap-envelope";
/// WS-Addressing. The `a:To`, `a:ReplyTo` and `a:Action` headers come from here, and a WSMan request
/// without them is refused with a 500 that carries no fault text at all.
const NS_ADDRESSING: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";

/// How a WinRM connection authenticates.
#[derive(Debug, Clone)]
pub enum WinRmAuth {
    /// NTLM against a local or domain account. The tested path.
    Ntlm {
        user: String,
        password: String,
        /// The domain, for a domain account. `None` for a local account, where Windows
        /// authenticates against the machine's own name.
        domain: Option<String>,
    },
    /// Basic over HTTPS. Refused over HTTP, because Basic sends the password in the clear-ish
    /// (base64 is not encryption) and a transport that would do that silently is worse than one
    /// that refuses.
    Basic { user: String, password: String },
}

/// A Windows host reachable over WinRM.
pub struct WinRmHost {
    id: HostId,
    address: String,
    /// The HTTP port. 5985 is plain, 5986 is HTTPS — and HTTPS is required for `Basic`.
    port: u16,
    https: bool,
    auth: WinRmAuth,
    client: reqwest::Client,
    caps: HostCaps,
    /// The WSMan shell, created once and reused. Held as a `Mutex` because a `Host` is shared and
    /// the shell is one server-side resource: two concurrent commands over one shell would
    /// interleave their output into each other.
    shell: tokio::sync::Mutex<Option<String>>,
}

impl WinRmHost {
    /// Connect and probe the host.
    ///
    /// "Connect" here means: complete an authentication handshake and create a WSMan shell. There
    /// is no socket to hold, so a failure is reported immediately rather than on first use.
    pub async fn connect(
        id: HostId,
        address: &str,
        port: u16,
        https: bool,
        auth: WinRmAuth,
    ) -> Result<Self> {
        if matches!(auth, WinRmAuth::Basic { .. }) && !https {
            return Err(HxError::Config(
                "WinRM Basic auth over HTTP would send the password base64-encoded rather than \
                 encrypted; use HTTPS (port 5986) or NTLM"
                    .to_string(),
            ));
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .danger_accept_invalid_certs(false)
            .build()
            .map_err(|e| HxError::Config(format!("could not build an HTTP client: {e}")))?;

        let host = Self {
            id,
            address: address.to_string(),
            port,
            https,
            auth,
            client,
            caps: HostCaps {
                os: RemoteOs::Windows,
                shell: ShellKind::PowerShell,
                arch: None,
                home_dir: None,
                has_sftp: false,
            },
            shell: tokio::sync::Mutex::new(None),
        };

        // Probe: creating a shell is the cheapest request that proves the whole path — DNS, TCP,
        // the NTLM exchange, the SOAP envelope, and the server's willingness to serve WSMan. A
        // host that answers HTTP but not WSMan is a real state (an IIS box on 5985) and would
        // otherwise look connected until the first command failed.
        let mut shell = host.shell.lock().await;
        *shell = Some(host.create_shell().await?);
        drop(shell);

        Ok(host)
    }

    fn endpoint(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        format!("{scheme}://{}:{}/wsman", self.address, self.port)
    }

    /// One WSMan request, with the NTLM handshake when that is the chosen auth.
    ///
    /// The three-step exchange is done per request rather than once per connection: the server
    /// does not promise to keep the authentication, and re-doing it costs two extra round trips on
    /// a protocol that is already chatty. It also means a request is self-contained — a retry
    /// after a dropped connection needs no knowledge of what came before.
    async fn request(
        &self,
        action: &str,
        resource: &str,
        selector: &str,
        body: &str,
    ) -> Result<String> {
        let envelope = build_envelope(action, resource, selector, body, &self.endpoint());
        if std::env::var("HX_WINRM_TRACE").is_ok() {
            eprintln!("TRACE envelope for {action}: {envelope}");
        }
        match &self.auth {
            WinRmAuth::Ntlm {
                user,
                password,
                domain,
            } => {
                self.request_with_ntlm(&envelope, user, password, domain.as_deref())
                    .await
            }
            WinRmAuth::Basic { user, password } => {
                let response = self
                    .client
                    .post(self.endpoint())
                    .basic_auth(user, Some(password))
                    .header("Content-Type", "application/soap+xml;charset=UTF-8")
                    .body(envelope)
                    .send()
                    .await
                    .map_err(|e| HxError::Remote(format!("WinRM request failed: {e}")))?;
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                if !status.is_success() {
                    // The body is included: WSMan puts the actual fault in the SOAP body, and a
                    // bare "401" leaves nothing to act on. It contains no credential — the only
                    // secrets in these envelopes are never echoed by the server.
                    return Err(HxError::Remote(format!(
                        "WinRM returned {status}: {}",
                        summarise_fault(&text)
                    )));
                }
                Ok(text)
            }
        }
    }

    /// The NTLM three-step, as `Authorization` headers on one POST.
    async fn request_with_ntlm(
        &self,
        envelope: &str,
        user: &str,
        password: &str,
        domain: Option<&str>,
    ) -> Result<String> {
        let auth = Auth {
            user: user.to_string(),
            password: password.to_string(),
            domain: domain.map(|d| d.to_string()),
            workstation: hostname(),
            // `http/<the address being reached>`, which is what a working client sends. The SPN has
            // to name the endpoint the request actually goes to, or the server's recomputation of
            // the proof disagrees with the client's.
            target_spn: Some(format!("http/{}", self.address)),
        };

        // Step 1: ask for a challenge.
        //
        // A token-less `Authorization: Negotiate` is what Windows expects first: it answers 401
        // with `WWW-Authenticate: Negotiate` and *no* token, and only replies with the actual
        // challenge once the client has sent a negotiate message. Sending a negotiate and expecting
        // a challenge in the same round trip — the obvious reading of the protocol, and the one
        // this code originally had — gets a bare `Negotiate` back and looks like a server that
        // does not speak NTLM. Found only by running against a real host.
        // The negotiate message is built once and kept: the MIC covers its exact bytes, so a second
        // construction that happened to agree would still be a different input if any field moved.
        let negotiate_message = auth.negotiate();
        // The probe and the negotiate carry **no body**. Measured off a working client's traffic: its
        // first two requests have `Content-Length: 0`, and only the authenticated request carries the
        // envelope. Sending the envelope during negotiation is what produced the 500 — the server
        // reads the body as part of the handshake and refuses it, and a 500 with a zero-length body
        // names nothing, so it reads like a malformed envelope rather than a request sent too early.
        let probe = self
            .client
            .post(self.endpoint())
            .header("Content-Type", "application/soap+xml;charset=UTF-8")
            .header("Authorization", "Negotiate")
            // `Content-Length` is set explicitly. WSMan answers `411 Length Required` without it, and
            // reqwest writes no length header for an empty body however it is spelled (`String::new()`
            // and `Vec::new()` both omit it). The working client sends `Content-Length: 0` on both
            // bodiless requests, so the value here is the one it uses.
            .header("Content-Length", "0")
            .body(String::new())
            .send()
            .await
            .map_err(|e| HxError::Remote(format!("WinRM connect failed: {e}")))?;

        let probe_header = probe
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // If the probe already produced a token, the server is one that answers in one step; use
        // it. If it is a bare scheme name, the negotiate message goes next and the challenge comes
        // back with it.
        let bare = probe_header
            .as_deref()
            .map(|h| {
                let mut parts = h.split_whitespace();
                let scheme = parts.next().unwrap_or("");
                (scheme.eq_ignore_ascii_case("ntlm") || scheme.eq_ignore_ascii_case("negotiate"))
                    && parts.next().is_none()
            })
            .unwrap_or(false);

        let challenge_header = if bare {
            let second = self
                .client
                .post(self.endpoint())
                .header("Content-Type", "application/soap+xml;charset=UTF-8")
                // The scheme name here must match what the server offered: answering a
                // `Negotiate` challenge with `NTLM` is refused by some configurations.
                .header(
                    "Authorization",
                    format!("Negotiate {}", header_value(&negotiate_message)),
                )
                // Also bodiless, and also with an explicit `Content-Length: 0`.
                .header("Content-Length", "0")
                .body(String::new())
                .send()
                .await
                .map_err(|e| HxError::Remote(format!("WinRM negotiate failed: {e}")))?;
            second
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        } else {
            probe_header
        };

        let Some(challenge_header) = challenge_header else {
            // No challenge and no error: a server that does not speak NTLM at all. Saying so is
            // more useful than "401", because it points at the config rather than the credentials.
            let status = probe.status();
            let text = probe.text().await.unwrap_or_default();
            return Err(HxError::Remote(format!(
                "the host did not offer NTLM (status {status}); WinRM may be disabled, or the \
                 endpoint may not be WSMan: {}",
                summarise_fault(&text)
            )));
        };

        // Step 2: parse the challenge out of the `WWW-Authenticate` header.
        //
        // Windows answers `Negotiate`, not `NTLM`, even when the client asked with `NTLM`: the
        // server is offering SPNEGO and carrying the NTLM message inside it. Both names mean the
        // same payload for this exchange, and a client that insists on the literal word `NTLM`
        // never gets past the first request. Found by running against a real host — a mock that
        // echoed back whichever scheme the client sent would have agreed with the bug.
        let mut parts = challenge_header.split_whitespace();
        let scheme = parts.next().unwrap_or("");
        let answer_scheme = if scheme.eq_ignore_ascii_case("negotiate") {
            "Negotiate"
        } else {
            "NTLM"
        };
        let challenge_b64 =
            if scheme.eq_ignore_ascii_case("ntlm") || scheme.eq_ignore_ascii_case("negotiate") {
                parts.next()
            } else {
                None
            }
            .ok_or_else(|| {
                HxError::Remote(format!(
                    "the host offered no NTLM challenge (WWW-Authenticate: {challenge_header:?}); \
                 WinRM may be configured for Kerberos only"
                ))
            })?;
        let challenge_bytes = base64::engine::general_purpose::STANDARD
            .decode(challenge_b64.trim())
            .map_err(|e| HxError::Remote(format!("the NTLM challenge is not base64: {e}")))?;

        let challenge = Auth::parse_challenge(&challenge_bytes)
            .ok_or_else(|| HxError::Remote("the NTLM challenge could not be parsed".to_string()))?;

        // Step 3: authenticate. `None` here means the server would only speak NTLMv1, which is
        // refused rather than downgraded to.
        let authenticate = auth
            .authenticate(&challenge, &negotiate_message, &challenge_bytes)
            .ok_or_else(|| {
                HxError::Remote(
                    "the host offered only NTLMv1; it is refused rather than used, because it is \
                     broken — enable NTLMv2 on the host"
                        .to_string(),
                )
            })?;

        if std::env::var("HX_WINRM_TRACE").is_ok() {
            eprintln!(
                "TRACE authenticate: len={} flags=0x{:08x} challenge_flags=0x{:08x} hex={}",
                authenticate.len(),
                u32::from_le_bytes(authenticate[60..64].try_into().unwrap_or([0; 4])),
                challenge.flags,
                authenticate
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
        }
        let response = self
            .client
            .post(self.endpoint())
            .header("Content-Type", "application/soap+xml;charset=UTF-8")
            .header(
                "Authorization",
                // The *same* scheme the challenge came in on. Windows refuses an NTLM-authorised
                // answer to a Negotiate challenge in some configurations, and the mismatch is
                // reported as a plain 401 rather than as anything naming the cause.
                format!("{answer_scheme} {}", header_value(&authenticate)),
            )
            .body(envelope.to_string())
            .send()
            .await
            .map_err(|e| HxError::Remote(format!("WinRM request failed: {e}")))?;

        let status = response.status();
        // Read the header before `text()`, which consumes the response.
        let www_auth = response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(60).collect::<String>());
        let text = response.text().await.unwrap_or_default();
        if std::env::var("HX_WINRM_TRACE").is_ok() {
            eprintln!(
                "TRACE final: status={status} scheme={answer_scheme:?} www-auth={www_auth:?} body={:?}",
                text.chars().take(200).collect::<String>()
            );
        }
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(HxError::Remote(format!(
                "WinRM rejected the credentials for '{}'; check the account, the password, and \
                 whether 'Remote Management Users' includes it",
                user
            )));
        }
        if !status.is_success() {
            return Err(HxError::Remote(format!(
                "WinRM returned {status}: {}",
                summarise_fault(&text)
            )));
        }
        Ok(text)
    }

    /// Create a WSMan shell and return its id.
    async fn create_shell(&self) -> Result<String> {
        // The `CommandLine` shell is what runs a program per command. `PowerShell` would give a
        // persistent runspace, which is a heavier resource to leave sitting on a host for the sake
        // of a few commands.
        // The body names the streams the shell will carry, and the resource URI is the *command*
        // shell specifically (`.../shell/cmd`), not the shell namespace. Both were wrong, and WSMan
        // answers a wrong resource URI with a 500 that carries no fault text — no way to tell from
        // the response which of the two was wrong. Read off a working client's create-shell.
        let body = format!(
            r#"<rsp:Shell xmlns:rsp="{NS_SHELL}"><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>"#
        );
        let response = self
            .request(
                "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
                NS_SHELL_CMD,
                "",
                &body,
            )
            .await?;

        // The shell id is in the `<w:Selector Name="ShellId">` of the response. Extracted by
        // scanning rather than a full XML parse: adding an XML parser for one attribute is a crate
        // this workspace does not carry, and the selector's shape is fixed by the schema.
        extract_selector(&response, "ShellId").ok_or_else(|| {
            HxError::Remote(format!(
                "the host accepted the request but returned no ShellId: {}",
                summarise_fault(&response)
            ))
        })
    }

    /// Run a command in the shell and collect its output.
    async fn run_in_shell(&self, shell_id: &str, command: &str) -> Result<ExecOutput> {
        // `CommandLine` takes the program and its arguments as separate elements. Everything goes
        // through `cmd.exe /c`, which is the Windows equivalent of `sh -c` and is what makes a
        // caller's `dir && echo done` mean what it looks like.
        let body = format!(
            r#"<rsp:CommandLine xmlns:rsp="{NS_SHELL}"><rsp:Command>cmd.exe</rsp:Command><rsp:Arguments>/c</rsp:Arguments><rsp:Arguments>{}</rsp:Arguments></rsp:CommandLine>"#,
            xml_escape(command)
        );
        let started = self
            .request(
                "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
                NS_SHELL,
                shell_id,
                &body,
            )
            .await?;

        let command_id = extract_selector(&started, "CommandId").ok_or_else(|| {
            HxError::Remote("the host started no command and returned no CommandId".to_string())
        })?;

        let start = Instant::now();
        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut exit_code = None;

        // Pull until the server says the command is done. `Receive` is a poll, not a stream: it
        // returns whatever has been produced and a `CommandState` saying whether to ask again.
        loop {
            let received = self
                .request(
                    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive",
                    NS_SHELL,
                    &format!("{shell_id}/CommandId={command_id}"),
                    "",
                )
                .await?;

            for chunk in extract_stream_text(&received, "stdout") {
                stdout.push_str(&chunk);
            }
            for chunk in extract_stream_text(&received, "stderr") {
                stderr.push_str(&chunk);
            }

            if let Some(decoded) = extract_exit_code(&received) {
                exit_code = Some(decoded);
            }

            if received.contains(r#"State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"#)
                || received.contains(r#"State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done" "#)
            {
                break;
            }
            // A server that never reports Done would otherwise loop forever. The bound is the
            // client's own sanity check, not the protocol's.
            if start.elapsed() > Duration::from_secs(300) {
                return Err(HxError::Remote(
                    "the command did not report completion within five minutes".to_string(),
                ));
            }
        }

        // Output on Windows is UTF-16LE in the WSMan framing but arrives base64-encoded as bytes;
        // `extract_stream_text` decodes both.
        Ok(ExecOutput {
            stdout: normalise_newlines(&stdout),
            stderr: normalise_newlines(&stderr),
            exit_code,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

#[async_trait::async_trait]
impl Host for WinRmHost {
    fn id(&self) -> &HostId {
        &self.id
    }

    fn caps(&self) -> &HostCaps {
        &self.caps
    }

    async fn exec(&self, command: &str, _timeout: Duration) -> Result<ExecOutput> {
        let shell_id = {
            let guard = self.shell.lock().await;
            guard.clone()
        };
        let shell_id = match shell_id {
            Some(id) => id,
            // The shell was never created or was lost: making one is the recovery, and doing it
            // here rather than failing means a dropped connection is invisible to the caller.
            None => {
                let mut guard = self.shell.lock().await;
                let id = self.create_shell().await?;
                *guard = Some(id.clone());
                id
            }
        };
        self.run_in_shell(&shell_id, command).await
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        // Base64 through PowerShell rather than a binary stream: WSMan's output is text, and
        // anything that is not text would be mangled by the encoding round trip in between.
        let escaped = path.replace('\'', "''");
        let out = self
            .exec(
                &format!("[Convert]::ToBase64String([IO.File]::ReadAllBytes('{escaped}'))"),
                Duration::from_secs(120),
            )
            .await?;
        if !out.success() {
            return Err(HxError::Remote(format!(
                "could not read '{path}': {}",
                out.stderr.trim()
            )));
        }
        base64::engine::general_purpose::STANDARD
            .decode(out.stdout.trim())
            .map_err(|e| HxError::Remote(format!("'{path}' did not decode as base64: {e}")))
    }

    async fn write_file(&self, path: &str, contents: &[u8]) -> Result<()> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(contents);
        let escaped = path.replace('\'', "''");
        // The directory is created first: writing a file into a path whose parent does not exist
        // fails, and the caller asked to write a file, not to also arrange its directory.
        let out = self
            .exec(
                &format!(
                    "$b=[Convert]::FromBase64String('{encoded}'); \
                     $d=Split-Path -Parent '{escaped}'; \
                     if ($d -and -not (Test-Path $d)) {{ New-Item -ItemType Directory -Force -Path $d | Out-Null }}; \
                     [IO.File]::WriteAllBytes('{escaped}', $b); \
                     Write-Output OK"
                ),
                Duration::from_secs(180),
            )
            .await?;
        if !out.success() || !out.stdout.contains("OK") {
            return Err(HxError::Remote(format!(
                "could not write '{path}': {}",
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<RemoteEntry>> {
        let escaped = path.replace('\'', "''");
        // Machine-readable output rather than parsed `dir` formatting: a listing parsed out of
        // column widths breaks on a long filename, and this has to survive one.
        let out = self
            .exec(
                &format!(
                    "Get-ChildItem -LiteralPath '{escaped}' -Force | \
                     ForEach-Object {{ \"{{0}}|{{1}}|{{2}}\" -f $_.Name, \
                     $(if ($_.PSIsContainer) {{ 'd' }} else {{ 'f' }}), $_.Length }}"
                ),
                Duration::from_secs(120),
            )
            .await?;
        if !out.success() {
            return Err(HxError::Remote(format!(
                "could not list '{path}': {}",
                out.stderr.trim()
            )));
        }
        Ok(parse_listing(&out.stdout, path))
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let from_escaped = from.replace('\'', "''");
        let to_escaped = to.replace('\'', "''");
        // An existing destination is an error, never an overwrite — the same contract as the SSH
        // transport, because the trash a delete leaves behind must not destroy what is already in
        // it. `Move-Item -Force` would overwrite, so it is not used.
        let out = self
            .exec(
                &format!(
                    "if (Test-Path -LiteralPath '{to_escaped}') {{ \
                       Write-Error 'the destination already exists'; exit 1 }}; \
                     $d=Split-Path -Parent '{to_escaped}'; \
                     if ($d -and -not (Test-Path $d)) {{ New-Item -ItemType Directory -Force -Path $d | Out-Null }}; \
                     Move-Item -LiteralPath '{from_escaped}' -Destination '{to_escaped}'; \
                     Write-Output OK"
                ),
                Duration::from_secs(120),
            )
            .await?;
        if !out.success() || !out.stdout.contains("OK") {
            return Err(HxError::Remote(format!(
                "could not move '{from}' to '{to}': {}",
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    fn describe(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        let who = match &self.auth {
            WinRmAuth::Ntlm { user, domain, .. } => match domain {
                Some(d) => format!("{d}\\{user}"),
                None => user.clone(),
            },
            WinRmAuth::Basic { user, .. } => user.clone(),
        };
        format!("winrm {scheme}://{}:{} as {who}", self.address, self.port)
    }
}

/// The machine's own name, which NTLM calls the workstation.
/// The name this client reports as its workstation.
///
/// `HOSTNAME` is **not** the machine's name in a container: Docker sets it to the container id, so a
/// daemon running in one announced a two-character workstation. The name is decorative to the
/// protocol — Windows does not authenticate against it — but it is also not free to get wrong, since
/// it is one of the fields a byte-for-byte comparison against a working client shows up. Prefer the
/// kernel's own name, then the environment, then a literal.
fn hostname() -> String {
    if let Ok(name) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "hx".to_string())
}

/// A SOAP envelope around a WSMan action.
fn build_envelope(action: &str, resource: &str, selector: &str, body: &str, to: &str) -> String {
    // The selector element is how WSMan names the object an action applies to: a shell, or a
    // command inside one. It is omitted entirely for an action that applies to nothing, because an
    // empty `SelectorSet` is rejected where an absent one is fine.
    let selectors = if selector.is_empty() {
        String::new()
    } else if let Some((name, value)) = selector.split_once('/') {
        // `shellid` or `shellid/CommandId=xyz`.
        let shell = xml_escape(name);
        match value.split_once('=') {
            Some((k, v)) => format!(
                r#"<wsman:SelectorSet><wsman:Selector Name="ShellId">{shell}</wsman:Selector><wsman:Selector Name="{k}">{}</wsman:Selector></wsman:SelectorSet>"#,
                xml_escape(v)
            ),
            None => format!(
                r#"<wsman:SelectorSet><wsman:Selector Name="ShellId">{shell}</wsman:Selector></wsman:SelectorSet>"#
            ),
        }
    } else {
        format!(
            r#"<wsman:SelectorSet><wsman:Selector Name="ShellId">{}</wsman:Selector></wsman:SelectorSet>"#,
            xml_escape(selector)
        )
    };

    // The header set is not optional and not guessable: WSMan answers a request missing any of
    // `a:To`, `a:ReplyTo`, `w:MaxEnvelopeSize`, `a:MessageID` or `a:Action` with a 500 carrying no
    // fault text at all, which reads like a server fault rather than a malformed request. This set
    // was read off a working client's create-shell envelope.
    //
    // Note where the action goes: in the *header* as `a:Action`, not as a body element. The body
    // wraps the operation's own payload, and an action that appears only in the body is one WSMan
    // does not see.
    let action = xml_escape(action);
    // The prefix and namespace bindings mirror a working client exactly, including the ones this
    // envelope does not use. Namespace *declarations* are part of what WSMan validates: `p:` is
    // Microsoft's extension namespace, and elements like `MaxEnvelopeSize` belong to it rather than
    // to the DMTF `w:` namespace they share local names with.
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="{NS_SOAP}" xmlns:a="{NS_ADDRESSING}" xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:x="{NS_TRANSFER}" xmlns:w="{NS_WSMAN}" xmlns:p="{NS_WSMAN_MS}" xmlns:rsp="{NS_SHELL}" xmlns:cfg="http://schemas.microsoft.com/wbem/wsman/1/config">
  <env:Header>
    <a:To>{to}</a:To>
    <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
    <w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize>
    <a:MessageID>uuid:{message_id}</a:MessageID>
    <w:Locale mustUnderstand="false" xml:lang="en-US"></w:Locale>
    <p:DataLocale mustUnderstand="false" xml:lang="en-US"></p:DataLocale>
    <w:OperationTimeout>PT300S</w:OperationTimeout>
    <w:ResourceURI mustUnderstand="true">{resource}</w:ResourceURI>
    <a:Action mustUnderstand="true">{action}</a:Action>
    {selectors}
  </env:Header>
  <env:Body>{body}</env:Body>
</env:Envelope>"#,
        NS_SOAP = NS_SOAP,
        NS_ADDRESSING = NS_ADDRESSING,
        NS_TRANSFER = NS_TRANSFER,
        NS_WSMAN = NS_WSMAN,
        NS_WSMAN_MS = NS_WSMAN_MS,
        NS_SHELL = NS_SHELL,
        to = xml_escape(to),
        message_id = random_uuid(),
        resource = resource,
        action = action,
        selectors = selectors,
        body = body
    )
}

/// A v4-shaped UUID for `a:MessageID`. WSMan requires the header to be present and unique per
/// request; nothing here depends on the version bits, so this is sixteen random bytes formatted
/// rather than a UUID crate the workspace does not have.
fn random_uuid() -> String {
    let b = crate::ntlm::random_bytes_16();
    let h =
        |r: std::ops::Range<usize>| -> String { b[r].iter().map(|x| format!("{x:02x}")).collect() };
    format!(
        "{}-{}-{}-{}-{}",
        h(0..4),
        h(4..6),
        h(6..8),
        h(8..10),
        h(10..16)
    )
}

/// The value of `<Selector Name="...">`, without an XML parser.
///
/// A targeted scan rather than a parse: this reads one attribute out of a response whose shape the
/// WSMan schema fixes, and adding an XML crate for it would be a dependency the workspace does not
/// otherwise need.
fn extract_selector(xml: &str, name: &str) -> Option<String> {
    let needle = format!(r#"Name="{name}""#);
    let start = xml.find(&needle)?;
    let rest = &xml[start + needle.len()..];
    let open = rest.find('>')? + 1;
    let close = rest[open..].find('<')?;
    let value = rest[open..open + close].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Decode every `Stream` element of the named type, base64 and UTF-16LE.
///
/// WSMan returns command output as base64-encoded UTF-16LE in `Stream` elements. Both steps are
/// required: taking the base64 as ASCII produces text with an interleaved NUL between every
/// character, which is the classic symptom of decoding only half the framing.
fn extract_stream_text(xml: &str, stream: &str) -> Vec<String> {
    let mut out = Vec::new();
    let open_tag = format!(r#"Stream Name="{stream}""#);
    let mut rest = xml;
    while let Some(start) = rest.find(&open_tag) {
        let after = &rest[start..];
        let Some(gt) = after.find('>') else { break };
        let content_start = gt + 1;
        let Some(end) = after[content_start..].find("</") else {
            break;
        };
        let encoded = after[content_start..content_start + end].trim();
        if !encoded.is_empty() {
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                // UTF-16LE when the BOM or the interleaved NULs say so; plain UTF-8 otherwise.
                // Trying UTF-16 first on a UTF-8 payload would produce mojibake rather than an
                // error, so the test for UTF-16 is explicit.
                if bytes.len() >= 2 && bytes.len() % 2 == 0 && looks_utf16le(&bytes) {
                    let units: Vec<u16> = bytes
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|c| u16::from_le_bytes(*c))
                        .collect();
                    out.push(String::from_utf16_lossy(&units));
                } else {
                    out.push(String::from_utf8_lossy(&bytes).into_owned());
                }
            }
        }
        rest = &after[content_start + end..];
    }
    out
}

/// Whether a byte payload is UTF-16LE rather than UTF-8.
///
/// A BOM is decisive. Otherwise, UTF-16LE ASCII text has a NUL in every odd position, which UTF-8
/// text effectively never does — so a run of them is a reliable signal.
fn looks_utf16le(bytes: &[u8]) -> bool {
    if bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe {
        return true;
    }
    let sample = &bytes[..bytes.len().min(32)];
    if sample.len() < 4 {
        return false;
    }
    let odd_nuls = sample
        .iter()
        .skip(1)
        .step_by(2)
        .filter(|b| **b == 0)
        .count();
    odd_nuls * 2 >= sample.len() / 2
}

/// The exit code from a `Receive` response, if the command has finished.
fn extract_exit_code(xml: &str) -> Option<i32> {
    let needle = "ExitCode";
    let start = xml.find(needle)?;
    let rest = &xml[start..];
    let open = rest.find('>')? + 1;
    let close = rest[open..].find('<')?;
    rest[open..open + close].trim().parse().ok()
}

/// The human part of a WSMan fault, for an error message.
fn summarise_fault(xml: &str) -> String {
    // Where the human-readable text sits depends on which fault it is. A WSMan fault puts it in
    // `faultstring`; a SOAP 1.2 fault puts it in `s:Reason/s:Text`; a WSMan operation error puts it
    // in `wsman:Message`. All three are tried, because a caller who gets the envelope back has
    // learned nothing they could not have learned from the status code.
    //
    // The names are matched with their namespace prefix *optional*: the prefix is the server's
    // choice, and a response using `<Text>` without `<s:Text>` is valid.
    for tag in ["faultstring", "Message", "Text", "Reason"] {
        let candidates = [
            format!("<{tag}"),
            format!("<s:{tag}"),
            format!("<wsman:{tag}"),
        ];
        for open_tag in candidates {
            let Some(start) = xml.find(&open_tag) else {
                continue;
            };
            let after = &xml[start..];
            let Some(gt) = after.find('>') else { continue };
            let Some(end) = after[gt + 1..].find("</") else {
                continue;
            };
            let text = after[gt + 1..gt + 1 + end].trim();
            // A nested element rather than text (a `<Reason>` wrapping `<Text>`) is skipped so the
            // loop can reach the element that actually holds the sentence.
            if !text.is_empty() && !text.starts_with('<') {
                return text.chars().take(400).collect();
            }
        }
    }
    // Nothing was found. Said as such rather than returning the envelope, which reads like a
    // fault description and is not one.
    format!("no fault text in the response ({} bytes of XML)", xml.len())
}

/// Escape text for XML content. A command with `&` or `<` in it is ordinary and must not corrupt
/// the envelope.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Windows ends lines with CRLF; callers expect LF. Done at the boundary so no caller has to know.
fn normalise_newlines(s: &str) -> String {
    s.replace("\r\n", "\n")
}

/// Parse the `name|type|size` lines the listing command emits.
fn parse_listing(output: &str, parent: &str) -> Vec<RemoteEntry> {
    let mut entries = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() < 3 {
            // A PowerShell warning or banner line, not an entry. Skipped rather than guessed at.
            continue;
        }
        let name = parts[0].trim();
        if name.is_empty() {
            continue;
        }
        let is_dir = parts[1].trim() == "d";
        let size = parts[2].trim().parse::<u64>().ok();
        entries.push(RemoteEntry {
            name: name.to_string(),
            is_dir,
            // A directory reports 0 rather than nothing: the field is a plain size, and callers
            // distinguish a directory by `is_dir` rather than by an absent size.
            size: if is_dir { 0 } else { size.unwrap_or(0) },
            // Windows paths are backslash-separated and a drive root already ends in one.
            path: if parent.ends_with('\\') {
                format!("{parent}{name}")
            } else {
                format!("{parent}\\{name}")
            },
        });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_over_http_is_refused_before_any_request() {
        // The refusal has to happen at construction: a transport that silently base64s a password
        // over an unencrypted channel is worse than one that will not connect.
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        // Matched rather than `unwrap_err()`: `WinRmHost` deliberately does not derive `Debug`,
        // because it holds a password and a `Debug` impl is one `{:?}` in a log line away from
        // leaking it. The assertion does not need the Ok value at all.
        let err = match rt.block_on(WinRmHost::connect(
            HostId::from("win"),
            "127.0.0.1",
            5985,
            false,
            WinRmAuth::Basic {
                user: "u".to_string(),
                password: "p".to_string(),
            },
        )) {
            Ok(_) => panic!("Basic over HTTP must be refused before any request is made"),
            Err(e) => e,
        };
        assert!(
            matches!(err, HxError::Config(ref m) if m.contains("base64")),
            "Basic over HTTP must be refused, got {err:?}"
        );
    }

    #[test]
    fn the_envelope_escapes_a_command_that_would_corrupt_it() {
        // `&` and `<` in a command are ordinary (`dir 1>&2`, a redirection), and unescaped they
        // produce a malformed envelope that the server rejects with no useful detail.
        let env = build_envelope(
            "http://x/Create",
            NS_SHELL,
            "",
            "<a>1 &amp; 2</a>",
            "http://h:5985/wsman",
        );
        assert!(env.contains("&amp;"), "an ampersand must be escaped");
        assert_eq!(env.matches("<env:Envelope").count(), 1);
        assert!(env.contains(NS_SHELL), "the resource URI must be present");
    }

    #[test]
    fn a_shell_selector_is_built_for_one_id_and_for_a_command() {
        let one = build_envelope(
            "http://x/Receive",
            NS_SHELL,
            "shell-1",
            "",
            "http://h:5985/wsman",
        );
        assert!(one.contains(r#"Name="ShellId">shell-1<"#), "{one}");

        // The command case carries both selectors; a request with only the shell id is refused by
        // the server because it does not name which command to receive from.
        let two = build_envelope(
            "http://x/Receive",
            NS_SHELL,
            "shell-1/CommandId=cmd-9",
            "",
            "http://h:5985/wsman",
        );
        assert!(two.contains(r#"Name="ShellId">shell-1<"#), "{two}");
        assert!(two.contains(r#"Name="CommandId">cmd-9<"#), "{two}");
    }

    #[test]
    fn a_shell_id_is_extracted_from_a_real_shaped_response() {
        let xml = r#"<?xml version="1.0"?><s:Envelope><s:Body>
            <x:ResourceCreated><a:ReferenceParameters>
            <wsman:SelectorSet><wsman:Selector Name="ShellId">7a1f2b3c-4d5e-6f70-8192-a3b4c5d6e7f8</wsman:Selector>
            </wsman:SelectorSet></a:ReferenceParameters></x:ResourceCreated></s:Body></s:Envelope>"#;
        assert_eq!(
            extract_selector(xml, "ShellId").as_deref(),
            Some("7a1f2b3c-4d5e-6f70-8192-a3b4c5d6e7f8")
        );
        assert!(extract_selector(xml, "CommandId").is_none());
    }

    #[test]
    fn stream_output_decodes_base64_utf16_to_text() {
        // What WSMan actually sends for `echo hi`: UTF-16LE, base64-encoded. Decoding only the
        // base64 yields "h\0i\0\r\n", which is the symptom this guards against.
        let text = "hi\r\n";
        let utf16: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let xml = format!(
            r#"<s:Envelope><s:Body><rsp:Stream Name="stdout" CommandId="c">{encoded}</rsp:Stream></s:Body></s:Envelope>"#
        );
        let chunks = extract_stream_text(&xml, "stdout");
        assert_eq!(
            chunks.join(""),
            "hi\r\n",
            "UTF-16 must be decoded, not taken as ASCII"
        );
    }

    #[test]
    fn stream_output_decodes_plain_utf8_too() {
        // Not every server sends UTF-16 (a non-Windows WSMan implementation is UTF-8), so the
        // decoder must not assume it. Guessing UTF-16 on a UTF-8 payload gives mojibake rather
        // than an error, which is why the test is explicit about both.
        let utf8 = b"plain ascii output\n".to_vec();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&utf8);
        let xml = format!(r#"<rsp:Stream Name="stdout">{encoded}</rsp:Stream>"#);
        assert_eq!(
            extract_stream_text(&xml, "stdout").join(""),
            "plain ascii output\n"
        );
    }

    #[test]
    fn stdout_and_stderr_are_kept_apart() {
        let out = base64::engine::general_purpose::STANDARD.encode(b"to stdout");
        let err = base64::engine::general_purpose::STANDARD.encode(b"to stderr");
        let xml = format!(
            r#"<rsp:Stream Name="stdout">{out}</rsp:Stream><rsp:Stream Name="stderr">{err}</rsp:Stream>"#
        );
        assert_eq!(extract_stream_text(&xml, "stdout").join(""), "to stdout");
        assert_eq!(extract_stream_text(&xml, "stderr").join(""), "to stderr");
        assert!(
            extract_stream_text(&xml, "stdout")
                .join("")
                .find("stderr")
                .is_none(),
            "stderr must not leak into stdout"
        );
    }

    #[test]
    fn a_command_that_never_reports_done_is_bounded() {
        // The loop's own guard rather than the protocol's. A server that keeps saying "more" would
        // otherwise hang a caller forever, so the state check is asserted directly.
        let done = r#"<rsp:CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState>"#;
        assert!(
            done.contains(r#"State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done""#),
            "the done marker must match what the loop looks for"
        );
        assert_eq!(extract_exit_code(done), Some(0));
        let running = r#"<rsp:CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"></rsp:CommandState>"#;
        assert!(
            extract_exit_code(running).is_none(),
            "no exit code while running"
        );
    }

    #[test]
    fn a_fault_reports_something_actionable_rather_than_the_whole_envelope() {
        let xml = r#"<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code><s:Reason><s:Text xml:lang="en-US">The WS-Management service cannot process the request. The resource URI was not valid.</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>"#;
        let summary = summarise_fault(xml);
        assert!(
            summary.contains("resource URI"),
            "the fault's own words are what a caller can act on, got {summary:?}"
        );
        assert!(
            !summary.contains("<s:Envelope"),
            "the envelope itself must not be the error message"
        );
    }

    #[test]
    fn listing_lines_are_parsed_and_their_paths_joined_for_windows() {
        let output = "Documents|d|0\r\nreport.txt|f|1024\r\n\r\n";
        let entries = parse_listing(output, r"C:\Users\hxtest");
        assert_eq!(
            entries.len(),
            2,
            "a blank line is not an entry: {entries:?}"
        );
        assert_eq!(entries[0].name, "Documents");
        assert!(entries[0].is_dir);
        assert_eq!(entries[0].size, 0, "a directory reports no bytes");
        assert_eq!(entries[0].path, r"C:\Users\hxtest\Documents");
        assert_eq!(entries[1].path, r"C:\Users\hxtest\report.txt");
        assert_eq!(entries[1].size, 1024);

        // A drive root already ends in a backslash; joining naively would produce `C:\\Users`.
        let root = parse_listing("Users|d|0\r\n", r"C:\");
        assert_eq!(root[0].path, r"C:\Users");
    }

    #[test]
    fn a_banner_line_in_the_listing_is_skipped_rather_than_guessed_at() {
        // PowerShell can emit warnings or a progress line before the entries. A parser that
        // treated every line as an entry would invent files that do not exist.
        let output = "WARNING: something happened\r\nreal.txt|f|5\r\n";
        let entries = parse_listing(output, r"C:\tmp");
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].name, "real.txt");
    }

    #[test]
    fn describe_names_the_account_but_never_the_password() {
        let host = WinRmHost {
            id: HostId::from("win1"),
            address: "10.0.0.5".to_string(),
            port: 5985,
            https: false,
            auth: WinRmAuth::Ntlm {
                user: "hxtest".to_string(),
                password: "supersecret-do-not-log".to_string(),
                domain: Some("WORKGROUP".to_string()),
            },
            client: reqwest::Client::new(),
            caps: HostCaps::unknown(),
            shell: tokio::sync::Mutex::new(None),
        };
        let described = host.describe();
        assert!(described.contains("hxtest"), "{described}");
        assert!(
            described.contains("5985"),
            "the port matters for diagnosing a refusal"
        );
        assert!(
            !described.contains("supersecret"),
            "the password must never appear in a description: {described}"
        );
    }

    #[test]
    fn xml_escaping_covers_the_characters_that_break_an_envelope() {
        assert_eq!(xml_escape("a&b"), "a&amp;b");
        assert_eq!(xml_escape("<tag>"), "&lt;tag&gt;");
        assert_eq!(xml_escape(r#"say "hi""#), "say &quot;hi&quot;");
        // A single quote is used to build PowerShell literals, and it must survive the round trip.
        assert_eq!(xml_escape("it's"), "it&apos;s");
    }

    #[test]
    fn utf16_detection_is_not_fooled_by_short_or_odd_input() {
        assert!(!looks_utf16le(b""), "empty");
        assert!(!looks_utf16le(b"a"), "one byte has no room for a code unit");
        assert!(looks_utf16le(b"h\0i\0"), "interleaved NULs are UTF-16LE");
        assert!(
            looks_utf16le(&[0xff, 0xfe, 0x41, 0x00]),
            "a BOM is decisive"
        );
        assert!(!looks_utf16le(b"plain ascii text here"), "UTF-8 ASCII");
    }
}

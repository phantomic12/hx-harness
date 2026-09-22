//! The [`Host`] trait, runtime capability detection, and safe command construction.

use async_trait::async_trait;
use hx_core::config::HostKind;
use hx_core::error::{HxError, Result};
use hx_core::ids::HostId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// What the far end is running.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteOs {
    Linux,
    MacOs,
    Windows,
    FreeBsd,
    Unknown,
}

/// Which shell to build command lines for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellKind {
    /// `sh -c`. Correct choice on Linux, macOS, and BSDs.
    Posix,
    /// `powershell -Command`.
    PowerShell,
    /// `cmd /C`.
    Cmd,
}

impl ShellKind {
    /// Quote one argument for this shell.
    pub fn quote(self, arg: &str) -> String {
        match self {
            ShellKind::Posix => shell_quote(arg),
            ShellKind::PowerShell => powershell_quote(arg),
            // `cmd` has no escape for `"` inside a quoted string, so the best that can be done
            // is wrap and reject embedded quotes at the call site. Documented rather than
            // silently mangled.
            ShellKind::Cmd => format!("\"{}\"", arg.replace('"', "").replace('\\', "\\\\")),
        }
    }

    /// The argv used to run a command line under this shell.
    pub fn wrap(self, command_line: &str) -> Vec<String> {
        match self {
            ShellKind::Posix => vec!["sh".into(), "-c".into(), command_line.into()],
            ShellKind::PowerShell => vec![
                "powershell".into(),
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                command_line.into(),
            ],
            ShellKind::Cmd => vec!["cmd".into(), "/C".into(), command_line.into()],
        }
    }

    /// Join two commands so the second runs only when the first succeeded.
    ///
    /// This is per-shell because `&&` is not universal. Windows PowerShell 5.1 — what `powershell`
    /// resolves to on every Windows host without PowerShell 7 installed — rejects it outright with
    /// `The token '&&' is not a valid statement separator in this version`, so a `cd <dir> && <cmd>`
    /// built for a POSIX shell fails before the command is ever reached. That is what broke every
    /// `workdir`-qualified command on Windows, in tests and in production alike.
    ///
    /// - POSIX `sh` uses `&&`.
    /// - `cmd.exe` uses `&&`.
    /// - PowerShell separates statements with `;`, and gates the second on the first with `if`.
    pub fn chain(self, first: &str, second: &str) -> String {
        match self {
            ShellKind::Posix | ShellKind::Cmd => format!("{first} && {second}"),
            // `;` alone runs the second statement whatever happened to the first, which is not the
            // same thing: a `cd` into a directory that does not exist must not then run the command
            // in the daemon's own working directory. `$?` is checked instead, so the second
            // statement is skipped on failure exactly as `&&` would skip it.
            ShellKind::PowerShell => {
                format!("{first}; if ($? -eq $true) {{ {second} }}")
            }
        }
    }
}

/// Wrap an argument in single quotes for a POSIX shell.
///
/// Single quotes suppress every expansion, so the only character needing care is `'` itself,
/// which is closed, escaped, and reopened. Getting this wrong is how an argument containing
/// `; rm -rf ~` becomes a command.
pub fn shell_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', r"'\''"))
}

/// Wrap an argument in single quotes for PowerShell, where the escape is a doubled quote.
pub fn powershell_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "''"))
}

/// What a host turned out to be, probed once on connect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCaps {
    pub os: RemoteOs,
    pub shell: ShellKind,
    /// `uname -m`-style architecture, when known.
    pub arch: Option<String>,
    pub home_dir: Option<String>,
    /// Whether an SFTP subsystem is available for copying files.
    ///
    /// `None` means **unknown**, and that is still an honest answer from *some* transports: the
    /// capability parsers for `uname`/`cmd ver` say nothing about which SSH subsystems a server
    /// offers, so on their own they would leave this unmeasured. `SshHost` therefore measures it on
    /// connect — it opens the `sftp` subsystem and completes the version handshake (see
    /// [`crate::sftp`]) — so for an `SshHost` this is `Some(true)` when the server answered,
    /// `Some(false)` when it declined, and only `None` when the transport itself fell over before the
    /// server could answer. This field was a `bool` hard-coded to `true` by both parsers, which the
    /// host route then handed to clients as though it had been measured — a capability report that no
    /// code ever checked, on the one question (can I copy files?) a client would act on. `false`
    /// would have been just as wrong in the other direction, so the field said what was true: nobody
    /// had looked. Now the one transport that can look, does.
    pub has_sftp: Option<bool>,
}

impl HostCaps {
    pub fn unknown() -> Self {
        Self {
            os: RemoteOs::Unknown,
            // POSIX is the safer default: it is the majority case, and a wrong guess fails
            // loudly on Windows rather than silently doing something unexpected.
            shell: ShellKind::Posix,
            arch: None,
            home_dir: None,
            has_sftp: None,
        }
    }

    pub fn is_unix(&self) -> bool {
        matches!(
            self.os,
            RemoteOs::Linux | RemoteOs::MacOs | RemoteOs::FreeBsd
        )
    }
}

/// Parse the output of `uname -s` (or the first token of `uname -a`).
pub fn caps_from_uname(stdout: &str) -> Option<HostCaps> {
    let first = stdout.split_whitespace().next()?;
    let os = match first {
        "Linux" => RemoteOs::Linux,
        "Darwin" => RemoteOs::MacOs,
        "FreeBSD" | "OpenBSD" | "NetBSD" => RemoteOs::FreeBsd,
        // `uname` existing at all with an unrecognised value still means a POSIX box.
        "SunOS" | "AIX" | "HP-UX" => RemoteOs::Unknown,
        _ => return None,
    };

    Some(HostCaps {
        os,
        shell: ShellKind::Posix,
        arch: None,
        home_dir: None,
        // Nothing here has asked the server what subsystems it offers.
        has_sftp: None,
    })
}

/// Parse the output of `cmd /C ver`, which looks like
/// `Microsoft Windows [Version 10.0.19045.3803]`.
pub fn caps_from_ver(stdout: &str) -> Option<HostCaps> {
    let lower = stdout.to_ascii_lowercase();
    if !lower.contains("windows") {
        return None;
    }
    Some(HostCaps {
        os: RemoteOs::Windows,
        // PowerShell is present on every supported Windows and is dramatically easier to build
        // correct command lines for than `cmd`.
        shell: ShellKind::PowerShell,
        arch: None,
        home_dir: None,
        // Not checked; see the field's note.
        has_sftp: None,
    })
}

/// The result of running a command somewhere.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    /// `None` when the transport could not report one (some SSH servers, killed processes).
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    /// Whether either stream hit [`MAX_EXEC_STREAM_BYTES`] and lost its middle. The strings
    /// already carry a `... [N bytes omitted] ...` notice; this flag is for machine consumers
    /// (`read_file` over a shell fallback decodes stdout as base64) that must fail loudly on
    /// truncation rather than decode a hole as data. Defaulted so older payloads still parse.
    #[serde(default)]
    pub truncated: bool,
}

impl ExecOutput {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }

    /// Stdout and stderr merged, for feeding to a model.
    pub fn combined(&self) -> String {
        match (self.stdout.is_empty(), self.stderr.is_empty()) {
            (false, true) => self.stdout.clone(),
            (true, false) => self.stderr.clone(),
            (false, false) => format!("{}\n{}", self.stdout.trim_end(), self.stderr),
            (true, true) => String::new(),
        }
    }

    /// A bounded rendering suitable for a tool result.
    pub fn bounded(&self, max_chars: usize) -> String {
        let body = self.combined();
        let code = match self.exit_code {
            Some(0) => String::new(),
            Some(c) => format!("\n[exit status {c}]"),
            None => "\n[exit status unknown]".to_string(),
        };
        format!("{}{}", truncate_middle(&body, max_chars), code)
    }
}

/// Trim the middle out of an over-long string, keeping both ends.
///
/// The tail is kept deliberately: build errors, test summaries and stack traces all live at the
/// *end* of output, so a naive head-truncation throws away precisely the part that matters.
/// Character-based, so multi-byte output is never split mid-character.
pub fn truncate_middle(text: &str, max_chars: usize) -> String {
    const NOTICE_RESERVE: usize = 48;

    let total = text.chars().count();
    if total <= max_chars {
        return text.to_string();
    }
    if max_chars <= NOTICE_RESERVE + 8 {
        return text.chars().take(max_chars).collect();
    }

    let budget = max_chars - NOTICE_RESERVE;
    let head_chars = budget * 3 / 5;
    let tail_chars = budget - head_chars;

    let head: String = text.chars().take(head_chars).collect();
    let tail: String = text.chars().skip(total - tail_chars).collect();

    let omitted = total - head_chars - tail_chars;
    format!("{head}\n\n... [{omitted} characters omitted] ...\n\n{tail}")
}

/// Hard byte ceiling for one captured output stream of [`Host::exec`].
///
/// WHY a fixed constant rather than the runner's `max_output_chars`: that bound truncates the
/// *display* after the bytes are already resident, so it cannot bound memory. This one bounds
/// the *read*, per stream, on every transport. 256 KiB per stream (512 KiB per command) stays
/// small even with concurrent execs, while dwarfing the 8 000-char display budget the runner
/// renders — so a bounded stream still carries far more than any tool result shows.
pub const MAX_EXEC_STREAM_BYTES: usize = 256 * 1024;

/// A bounded byte accumulator for command output.
///
/// WHY this exists: every `Host::exec` used to collect the child's full stdout and stderr into
/// memory before returning. `yes` produces ~1-4 GB/s, so tens of gigabytes could land in daemon
/// memory long before any timeout fired. This keeps the first and the last bytes (a byte-level
/// mirror of the head+tail promise [`truncate_middle`] makes for display) plus a dropped-byte
/// counter, and never retains more than the cap — no matter how much the command emits.
///
/// The caller must keep *reading* into it until EOF: stopping early leaves the pipe full, which
/// blocks the child and deadlocks the exec. Every transport below drains to EOF and lets the
/// excess fall on the floor, so the process stays alive and consumable while memory stays flat.
#[derive(Debug)]
pub struct BoundedOutput {
    head_cap: usize,
    tail_cap: usize,
    head: Vec<u8>,
    tail: std::collections::VecDeque<u8>,
    /// Bytes seen after the head filled — the tail holds the last `tail_cap` of these.
    post_head_seen: u64,
}

impl BoundedOutput {
    /// An accumulator capped at [`MAX_EXEC_STREAM_BYTES`].
    pub fn new() -> Self {
        Self::with_cap(MAX_EXEC_STREAM_BYTES)
    }

    /// An accumulator capped at `cap` bytes, for tests and callers with their own budget.
    pub fn with_cap(cap: usize) -> Self {
        // Tiny caps cannot hold both ends; keep everything in the head rather than a
        // zero-length tail that would discard the whole stream.
        let (head_cap, tail_cap) = if cap <= 64 {
            (cap, 0)
        } else {
            let head_cap = cap * 3 / 5;
            (head_cap, cap - head_cap)
        };
        Self {
            head_cap,
            tail_cap,
            head: Vec::new(),
            tail: std::collections::VecDeque::new(),
            post_head_seen: 0,
        }
    }

    /// Feed raw bytes — the SSH/local path, where output arrives as byte chunks.
    pub fn push_bytes(&mut self, mut chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        if self.head.len() < self.head_cap {
            let room = self.head_cap - self.head.len();
            let n = room.min(chunk.len());
            self.head.extend_from_slice(&chunk[..n]);
            chunk = &chunk[n..];
            if chunk.is_empty() {
                return;
            }
        }
        self.post_head_seen += chunk.len() as u64;
        if self.tail_cap == 0 {
            return;
        }
        self.tail.extend(chunk.iter().copied());
        let excess = self.tail.len().saturating_sub(self.tail_cap);
        if excess > 0 {
            self.tail.drain(..excess);
        }
    }

    /// Feed decoded text — the WinRM path, where chunks arrive as strings.
    pub fn push_str(&mut self, chunk: &str) {
        self.push_bytes(chunk.as_bytes());
    }

    /// Bytes retained right now. Never exceeds the cap.
    pub fn retained_len(&self) -> usize {
        self.head.len() + self.tail.len()
    }

    /// Bytes dropped from the middle so far.
    pub fn dropped_bytes(&self) -> u64 {
        self.post_head_seen.saturating_sub(self.tail.len() as u64)
    }

    /// Whether any output was dropped.
    pub fn is_truncated(&self) -> bool {
        self.dropped_bytes() > 0
    }

    /// The retained output with a dropped-byte notice spliced into the middle, mirroring the
    /// `... [N omitted] ...` shape [`truncate_middle`] produces for display.
    pub fn finish(self) -> String {
        let dropped = self.dropped_bytes();
        if dropped == 0 {
            let mut all = self.head;
            all.extend(self.tail);
            return String::from_utf8_lossy(&all).into_owned();
        }
        let head = String::from_utf8_lossy(&self.head).into_owned();
        let tail: Vec<u8> = self.tail.into_iter().collect();
        let tail = String::from_utf8_lossy(&tail).into_owned();
        format!("{head}\n\n... [{dropped} bytes omitted] ...\n\n{tail}")
    }
}

impl Default for BoundedOutput {
    fn default() -> Self {
        Self::new()
    }
}

/// Drain an async pipe to EOF into a bounded accumulator.
///
/// Returns promptly on a missing pipe; the loop otherwise reads until EOF so the writer is
/// never blocked on a full pipe, however much it emits. Memory stays under `cap` throughout.
pub async fn drain_pipe_bounded<R>(pipe: Option<R>, cap: usize) -> BoundedOutput
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut out = BoundedOutput::with_cap(cap);
    let Some(mut pipe) = pipe else { return out };
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 32 * 1024];
    loop {
        match pipe.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => out.push_bytes(&buf[..n]),
            Err(_) => break,
        }
    }
    out
}

/// One directory entry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RemoteEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
}

/// A PTY attached to a machine, from either side of the transport.
///
/// Deliberately not `async fn exec` with a shell: an interactive terminal is a *stream*, not a
/// request. Input arrives when the person types, output when the program prints, and the two are not
/// related in time. A trait method that promised a reply could not express that.
///
/// The separation is what makes one route serve both a local and a remote terminal: the daemon's
/// terminal pane already speaks this shape against a `portable-pty` master, and `SshHost` speaks it
/// against an SSH channel. Neither side needs to know which it has.
#[async_trait]
pub trait PtySession: Send + Sync {
    /// Type at the terminal. Bytes, not a string: a terminal is 8-bit clean, and a paste of UTF-8
    /// must not be re-encoded on the way through.
    async fn write(&self, data: &[u8]) -> Result<()>;

    /// Tell the far side the window changed, so a full-screen program redraws.
    async fn resize(&self, cols: u16, rows: u16) -> Result<()>;

    /// The next chunk of output, or `None` once the session has ended.
    ///
    /// Pulled rather than pushed: a subscriber that cannot keep up must be able to apply backpressure
    /// instead of having bytes accumulate in the transport. The caller owns the buffering decision,
    /// which is what lets it keep the scrollback the pane needs.
    async fn read(&self) -> Option<Vec<u8>>;

    /// End the session. Idempotent: closing twice is not an error, because both a client disconnect
    /// and a shutdown may race to do it.
    async fn close(&self) -> Result<()>;
}

/// A machine the daemon can run commands on.
///
/// Every method takes what it needs explicitly so implementations stay stateless with respect to
/// the caller — connection pooling, if any, is the implementation's business.
#[async_trait]
pub trait Host: Send + Sync {
    fn id(&self) -> &HostId;

    /// What this machine is. Populated once at connect; cheap to read thereafter.
    fn caps(&self) -> &HostCaps;

    /// Run a command line under the host's shell.
    async fn exec(&self, command: &str, timeout: Duration) -> Result<ExecOutput>;

    /// Open an interactive terminal on this machine.
    ///
    /// `command` is the shell to start. `None` asks for the machine's own default, which is the
    /// right answer for a login shell and the wrong one to guess from the outside: on a POSIX host
    /// that is `$SHELL` or `sh`, and on Windows it is PowerShell because that is what the rest of the
    /// transport already builds command lines for.
    ///
    /// Returns an error rather than a degenerate session when the transport cannot do it — a
    /// `PtySession` that silently never produced output would look like a hung machine.
    async fn open_pty(
        &self,
        command: Option<&str>,
        cols: u16,
        rows: u16,
    ) -> Result<Arc<dyn PtySession>>;

    async fn read_file(&self, path: &str) -> Result<Vec<u8>>;

    /// Read a file with a hard byte cap, for surfaces that serve what they read.
    ///
    /// WHY a second method rather than a cap on [`Host::read_file`]: the agent loop already bounds
    /// reads at its own layer (and reports them as failed tool calls, not errors), while the HTTP
    /// surface must refuse with a 413 before a multi-gigabyte file becomes a multi-gigabyte
    /// response. The default implementation reads then rejects, which bounds the *answer* on every
    /// transport; transports that can bound the read itself (local, ssh, winrm) override it —
    /// measure first, reject, and stream at most `cap + 1` bytes so a file that grows between the
    /// measure and the read, or reports no size at all (`/dev/zero`, a pipe), still cannot push more
    /// than `cap + 1` bytes into memory.
    async fn read_file_capped(&self, path: &str, cap: u64) -> Result<Vec<u8>> {
        let bytes = self.read_file(path).await?;
        let size = bytes.len() as u64;
        if size > cap {
            return Err(HxError::TooLarge {
                what: path.to_string(),
                size,
                limit: cap,
            });
        }
        Ok(bytes)
    }

    async fn write_file(&self, path: &str, contents: &[u8]) -> Result<()>;

    async fn list_dir(&self, path: &str) -> Result<Vec<RemoteEntry>>;

    /// Resolve `path` to the absolute physical location the host would open, symlinks settled.
    ///
    /// WHY this is on the host rather than in `hx-core`: only the machine that owns the
    /// filesystem can resolve its links — the daemon canonicalizing an SSH path against its own
    /// disk would compare the wrong tree and either deny legitimate access or, worse, allow an
    /// escape it cannot see. The agent loop calls this after the lexical capability check and
    /// re-checks the answer against the token, so a path that *reads* as inside the grant but
    /// *opens* as outside it is refused with `SymlinkEscape`.
    ///
    /// Contract, kept identical across implementations:
    /// - existing paths resolve fully (links, `.`, `..` collapsed);
    /// - not-yet-existing paths (write/create targets) resolve through the nearest existing
    ///   ancestor with the missing tail joined back on, so creates stay checkable;
    /// - `Err` **only** when this transport cannot resolve at all (never for a merely missing
    ///   file). Callers treat `Err` as "resolution unavailable" and keep the lexical decision —
    ///   a documented residual risk for those transports, not a per-file veto an attacker could
    ///   trigger with a dangling link.
    async fn canonicalize(&self, path: &str) -> Result<String> {
        let _ = path;
        Err(HxError::Remote(
            "this host cannot resolve symlinks; containment is lexical only".to_string(),
        ))
    }

    /// Move a file or directory within the host, creating the destination's parent directory.
    ///
    /// A transport operation rather than a command the caller composes: the trash a `delete` leaves
    /// behind has to be created and moved into, and a tool that built `mv …` itself would be a tool
    /// that needs a POSIX shell on a machine it is not allowed to assume one on. An existing
    /// destination is an **error, never an overwrite** — a delete picks a free name, and the one
    /// thing a trash must not do is destroy the file already sitting in it.
    async fn rename(&self, from: &str, to: &str) -> Result<()>;

    /// A one-line description for status output.
    fn describe(&self) -> String;
}

/// Reject a measured file size over `cap` with the [`HxError::TooLarge`] the capped routes map
/// to 413.
///
/// One shared gate so every transport reports the same error for the same over-limit file: the
/// local, ssh, and winrm capped reads all measure first and call this before streaming a byte.
pub(crate) fn check_cap(what: &str, size: u64, cap: u64) -> Result<()> {
    if size > cap {
        return Err(HxError::TooLarge {
            what: what.to_string(),
            size,
            limit: cap,
        });
    }
    Ok(())
}

/// Read `uname -s`-style output into caps, falling back to the Windows probe.
pub fn detect_caps_from_probes(uname: Option<&str>, ver: Option<&str>) -> HostCaps {
    if let Some(out) = uname {
        if let Some(caps) = caps_from_uname(out) {
            return caps;
        }
    }
    if let Some(out) = ver {
        if let Some(caps) = caps_from_ver(out) {
            return caps;
        }
    }
    HostCaps::unknown()
}

/// The command used to probe a POSIX host.
pub fn posix_probe_command() -> &'static str {
    "uname -s; uname -m; printf %s \"$HOME\""
}

/// The command used to probe a Windows host.
pub fn windows_probe_command() -> &'static str {
    "ver & echo %USERPROFILE%"
}

/// Fill in arch and home from the remaining lines of the POSIX probe.
pub fn enrich_caps_from_posix_probe(caps: &mut HostCaps, stdout: &str) {
    let mut lines = stdout.lines();
    let _os = lines.next();
    if let Some(arch) = lines.next() {
        let arch = arch.trim();
        if !arch.is_empty() {
            caps.arch = Some(arch.to_string());
        }
    }
    if let Some(home) = lines.next() {
        let home = home.trim();
        if !home.is_empty() {
            caps.home_dir = Some(home.to_string());
        }
    }
}

/// Config-level host kind, for reporting.
pub fn kind_of(caps: &HostCaps) -> HostKind {
    match caps.os {
        RemoteOs::Windows => HostKind::Winrm,
        _ => HostKind::Ssh,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- capability detection ----

    #[test]
    fn uname_recognises_the_three_platforms_we_care_about() {
        assert_eq!(caps_from_uname("Linux\n").unwrap().os, RemoteOs::Linux);
        assert_eq!(caps_from_uname("Darwin\n").unwrap().os, RemoteOs::MacOs);
        assert_eq!(caps_from_uname("FreeBSD").unwrap().os, RemoteOs::FreeBsd);
    }

    #[test]
    fn uname_handles_the_full_form() {
        let caps = caps_from_uname("Linux host 6.8.0-generic #1 SMP x86_64 GNU/Linux").unwrap();
        assert_eq!(caps.os, RemoteOs::Linux);
        assert_eq!(caps.shell, ShellKind::Posix);
    }

    #[test]
    fn a_capability_probe_does_not_claim_sftp_it_never_checked() {
        // The bug this pins: both parsers hard-coded `has_sftp: true`, and the host route handed
        // that to clients as though it had been measured. A `uname` string says nothing about which
        // SSH subsystems the server offers, so the honest answer is "unknown" — `false` would be
        // just as wrong in the other direction.
        assert_eq!(
            caps_from_uname("Linux host 6.8.0-generic #1 SMP x86_64 GNU/Linux")
                .unwrap()
                .has_sftp,
            None
        );
        assert_eq!(
            caps_from_ver("Microsoft Windows [Version 10.0.19045.3803]")
                .unwrap()
                .has_sftp,
            None
        );
        // And the default caps are as unmeasured as the parsed ones.
        assert_eq!(HostCaps::unknown().has_sftp, None);
    }

    #[test]
    fn uname_rejects_things_that_are_not_uname_output() {
        // A shell error message must not be mistaken for a platform.
        assert!(caps_from_uname("uname: not found").is_none());
        assert!(caps_from_uname("").is_none());
        assert!(caps_from_uname("'uname' is not recognized as an internal command").is_none());
    }

    #[test]
    fn ver_recognises_windows_and_prefers_powershell() {
        let caps = caps_from_ver("Microsoft Windows [Version 10.0.19045.3803]").unwrap();
        assert_eq!(caps.os, RemoteOs::Windows);
        assert_eq!(
            caps.shell,
            ShellKind::PowerShell,
            "powershell is present on all supported Windows and quotes correctly"
        );
    }

    #[test]
    fn ver_rejects_non_windows_output() {
        assert!(caps_from_ver("Linux").is_none());
    }

    #[test]
    fn unknown_caps_default_to_posix_rather_than_guessing_wildly() {
        let caps = HostCaps::unknown();
        assert_eq!(caps.os, RemoteOs::Unknown);
        assert_eq!(caps.shell, ShellKind::Posix);
        assert!(!caps.is_unix(), "unknown is not unix");
    }

    #[test]
    fn probe_falls_back_from_uname_to_ver() {
        // A Windows host where `uname` returned an error string.
        let caps = detect_caps_from_probes(
            Some("'uname' is not recognized"),
            Some("Microsoft Windows [Version 10.0.22631.0]"),
        );
        assert_eq!(caps.os, RemoteOs::Windows);
    }

    #[test]
    fn probe_yields_unknown_when_nothing_answers() {
        assert_eq!(detect_caps_from_probes(None, None).os, RemoteOs::Unknown);
        assert_eq!(
            detect_caps_from_probes(Some(""), Some("")).os,
            RemoteOs::Unknown
        );
    }

    #[test]
    fn posix_probe_supplies_arch_and_home() {
        let mut caps = HostCaps::unknown();
        enrich_caps_from_posix_probe(&mut caps, "Linux\nx86_64\n/home/yoav\n");
        assert_eq!(caps.arch.as_deref(), Some("x86_64"));
        assert_eq!(caps.home_dir.as_deref(), Some("/home/yoav"));
    }

    #[test]
    fn an_empty_home_is_not_recorded_as_a_value() {
        let mut caps = HostCaps::unknown();
        enrich_caps_from_posix_probe(&mut caps, "Linux\naarch64\n\n");
        assert_eq!(caps.home_dir, None);
        assert_eq!(caps.arch.as_deref(), Some("aarch64"));
    }

    // ---- quoting ----

    #[test]
    fn shell_quote_neutralises_embedded_quotes_and_metacharacters() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("a; rm -rf ~"), "'a; rm -rf ~'");
        assert_eq!(shell_quote("$(whoami)"), "'$(whoami)'");
        assert_eq!(shell_quote("`id`"), "'`id`'");
    }

    #[test]
    fn shell_quote_survives_the_classic_injection_attempt() {
        // The whole point: this must be one opaque argument, not two commands.
        let quoted = shell_quote("x'; rm -rf /; echo '");
        assert!(quoted.starts_with('\''));
        assert!(quoted.ends_with('\''));
        // Every embedded quote is escaped as '\'' — there is no bare trailing quote.
        assert_eq!(quoted, r"'x'\''; rm -rf /; echo '\'''");
    }

    #[test]
    fn powershell_quote_doubles_rather_than_escapes() {
        assert_eq!(powershell_quote("it's"), "'it''s'");
        assert_eq!(powershell_quote("plain"), "'plain'");
    }

    #[test]
    fn cmd_quoting_strips_embedded_quotes_because_there_is_no_escape() {
        // Documented limitation: `cmd` cannot express a literal `"` inside quotes.
        assert_eq!(ShellKind::Cmd.quote("a\"b"), "\"ab\"");
    }

    // ---- shell wrapping ----

    #[test]
    fn shells_wrap_command_lines_correctly() {
        assert_eq!(
            ShellKind::Posix.wrap("echo hi"),
            vec!["sh", "-c", "echo hi"]
        );
        assert_eq!(
            ShellKind::PowerShell.wrap("Get-ChildItem"),
            vec![
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-ChildItem"
            ]
        );
        assert_eq!(ShellKind::Cmd.wrap("dir"), vec!["cmd", "/C", "dir"]);
    }

    #[test]
    fn powershell_is_invoked_non_interactively() {
        // Otherwise a prompt can hang the daemon forever.
        let argv = ShellKind::PowerShell.wrap("x");
        assert!(argv.contains(&"-NonInteractive".to_string()));
        assert!(argv.contains(&"-NoProfile".to_string()));
    }

    // ---- output handling ----

    #[test]
    fn success_only_when_exit_code_is_zero() {
        let mut out = ExecOutput {
            stdout: "x".into(),
            stderr: String::new(),
            exit_code: Some(0),
            duration_ms: 1,
            truncated: false,
        };
        assert!(out.success());
        out.exit_code = Some(1);
        assert!(!out.success());
        out.exit_code = None;
        assert!(!out.success(), "unknown status must not read as success");
    }

    #[test]
    fn combined_merges_streams_without_stray_blank_lines() {
        let out = ExecOutput {
            stdout: "out\n".into(),
            stderr: "err\n".into(),
            exit_code: Some(1),
            duration_ms: 1,
            truncated: false,
        };
        assert_eq!(out.combined(), "out\nerr\n");

        let only_err = ExecOutput {
            stdout: String::new(),
            stderr: "err".into(),
            exit_code: Some(1),
            duration_ms: 1,
            truncated: false,
        };
        assert_eq!(only_err.combined(), "err");
    }

    #[test]
    fn short_output_is_untouched() {
        assert_eq!(truncate_middle("hello", 100), "hello");
        assert_eq!(truncate_middle("", 100), "");
    }

    #[test]
    fn long_output_keeps_the_tail_because_errors_live_there() {
        let text = format!("{}{}", "a".repeat(5000), "FAILED at the end");
        let out = truncate_middle(&text, 500);
        assert!(out.chars().count() <= 500, "got {}", out.chars().count());
        assert!(
            out.ends_with("FAILED at the end"),
            "the tail carries the diagnosis and must survive"
        );
        assert!(out.contains("characters omitted"));
    }

    #[test]
    fn truncation_is_character_safe() {
        // Multi-byte characters must never be split. Rust guarantees `&str` is valid UTF-8, so
        // the real assertion is that no code point was cut in half — which would surface as a
        // replacement character — and that the surviving payload is intact.
        let text = "é".repeat(4000);
        let out = truncate_middle(&text, 300);
        assert!(out.chars().count() <= 300);
        assert!(
            !out.contains('\u{FFFD}'),
            "a replacement character means a code point was split"
        );

        let payload: String = out.chars().filter(|c| !c.is_ascii()).collect();
        assert!(
            payload.chars().all(|c| c == 'é'),
            "the non-ASCII payload must survive unmangled, got {payload:?}"
        );
    }

    #[test]
    fn a_tiny_budget_degrades_to_a_head_truncation() {
        let out = truncate_middle(&"x".repeat(1000), 10);
        assert_eq!(out.chars().count(), 10);
    }

    #[test]
    fn bounded_output_appends_the_exit_status_only_when_nonzero() {
        let ok = ExecOutput {
            stdout: "fine".into(),
            stderr: String::new(),
            exit_code: Some(0),
            duration_ms: 1,
            truncated: false,
        };
        assert_eq!(ok.bounded(1000), "fine");

        let bad = ExecOutput {
            stdout: "boom".into(),
            stderr: String::new(),
            exit_code: Some(127),
            duration_ms: 1,
            truncated: false,
        };
        assert!(bad.bounded(1000).contains("[exit status 127]"));
    }

    #[test]
    fn host_kind_maps_windows_to_winrm_for_reporting() {
        let mut caps = HostCaps::unknown();
        caps.os = RemoteOs::Windows;
        assert_eq!(kind_of(&caps), HostKind::Winrm);
        caps.os = RemoteOs::Linux;
        assert_eq!(kind_of(&caps), HostKind::Ssh);
    }

    // ---- capped reads ----

    #[test]
    fn an_over_limit_size_is_rejected_with_its_measurements() {
        // The contract every capped transport shares: over the cap is `TooLarge` carrying the
        // measured size and the cap, so the routes map it to 413 with a message the caller can act
        // on. Exactly at the cap is allowed — the limit is a size, not an off-by-one.
        let err = check_cap("/tmp/big.bin", 1025, 1024).unwrap_err();
        match err {
            HxError::TooLarge { what, size, limit } => {
                assert_eq!(what, "/tmp/big.bin");
                assert_eq!(size, 1025);
                assert_eq!(limit, 1024);
            }
            other => panic!("wrong error: {other:?}"),
        }
        assert!(check_cap("/tmp/exact.bin", 1024, 1024).is_ok());
        assert!(check_cap("/tmp/small.bin", 3, 1024).is_ok());
    }

    // ---- bounded output ----

    #[test]
    fn a_short_stream_passes_through_untouched() {
        let mut out = BoundedOutput::with_cap(1024);
        out.push_bytes(b"hello");
        out.push_str(" world");
        assert!(!out.is_truncated());
        assert_eq!(out.dropped_bytes(), 0);
        assert_eq!(out.finish(), "hello world");
    }

    #[test]
    fn a_huge_stream_never_retains_more_than_the_cap() {
        // 10 MiB through a 4 KiB cap, in pipe-sized chunks — the `yes`-scale shape.
        let cap = 4096;
        let mut out = BoundedOutput::with_cap(cap);
        let chunk = vec![b'x'; 8192];
        let total = 10 * 1024 * 1024;
        let mut pushed = 0;
        while pushed < total {
            out.push_bytes(&chunk);
            pushed += chunk.len();
            assert!(
                out.retained_len() <= cap,
                "retained {} exceeds cap {cap}",
                out.retained_len()
            );
        }
        assert!(out.is_truncated());
        assert_eq!(out.dropped_bytes(), (total - cap) as u64);
        let text = out.finish();
        assert!(text.contains("bytes omitted"), "{text:?}");
        assert!(
            text.len() <= cap + 128,
            "finished text {} exceeds cap {cap} + notice slack",
            text.len()
        );
    }

    #[test]
    fn a_truncated_stream_keeps_its_head_and_its_tail() {
        let cap = 1000;
        let mut out = BoundedOutput::with_cap(cap);
        // Distinct head/middle/tail markers so each region is identifiable.
        out.push_str(&"H".repeat(600));
        out.push_str(&"M".repeat(5000));
        out.push_str(&"T".repeat(400));
        assert!(out.is_truncated());
        let text = out.finish();
        assert!(text.starts_with(&"H".repeat(600)), "head must survive");
        assert!(text.ends_with(&"T".repeat(400)), "tail must survive");
        assert!(!text.contains('M'), "the middle must be gone, not kept");
        assert!(text.contains("bytes omitted"));
    }

    #[test]
    fn tiny_caps_keep_what_fits_without_panicking() {
        let mut out = BoundedOutput::with_cap(8);
        out.push_bytes(b"0123456789abcdef");
        assert!(out.retained_len() <= 8);
        assert!(!out.finish().is_empty());
    }

    #[tokio::test]
    async fn draining_a_pipe_stays_bounded_and_reaches_eof() {
        // A `duplex` pipe stands in for the child-process pipe: the writer emits 4 MiB while the
        // drain reads, so a bounded-but-blocking reader would deadlock here. The drain must
        // consume everything (writer finishes) while retaining at most the cap.
        let (mut writer, reader) = tokio::io::duplex(32 * 1024);
        let total = 4 * 1024 * 1024;
        let writer_task = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let chunk = vec![b'y'; 8192];
            let mut written = 0;
            while written < total {
                writer.write_all(&chunk).await.unwrap();
                written += chunk.len();
            }
            writer.shutdown().await.unwrap();
        });
        let out = drain_pipe_bounded(Some(reader), 4096).await;
        writer_task.await.unwrap();
        assert!(out.is_truncated());
        assert_eq!(out.dropped_bytes(), (total - 4096) as u64);
        assert!(out.retained_len() <= 4096);
    }
}

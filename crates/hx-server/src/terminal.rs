//! A server-side terminal: a real PTY that outlives any one client, with scrollback kept in `hxd`.
//!
//! Why the daemon owns this rather than each client: M2's honest claim is that two clients can
//! attach to *one* session and see the same bytes. That only holds if the process and the output
//! live somewhere other than a client. A browser tab closing, a TUI reconnecting, a laptop lid
//! shutting — none of those may kill the shell or lose what it printed. So the PTY and its
//! scrollback are owned here, and clients attach and detach.
//!
//! ## What a client sees
//!
//! On attach, the client is sent the retained scrollback first (so a fresh terminal is not blank
//! and a reattaching one does not see a gap), then live output. Keystrokes and resizes come back as
//! [`TerminalInput`]. Detaching is not an event the terminal observes: the shell keeps running.
//!
//! ## Scrollback is bounded
//!
//! [`SCROLLBACK_BYTES`] caps what is retained, trimmed on write. An unbounded buffer fed by
//! `yes` is a memory leak with extra steps, and a terminal is exactly the kind of place a runaway
//! program sends infinite output. The cap is on *bytes*, not lines, because one line can be
//! arbitrarily long and a line-counting cap would let a single `printf` past it.
//!
//! ## Bytes, not `String`
//!
//! Output is passed through as raw bytes and base64-encoded on the wire. A terminal is byte-
//! oriented: escape sequences, partial UTF-8 sequences split across reads, and binary that a
//! program legitimately prints all have to survive. Decoding to `String` here would replace
//! anything malformed and corrupt the stream a terminal is meant to interpret verbatim.

// The Unix-only helpers below are dead code on a host with no PTY, which is expected: they
// implement a feature that platform does not have. Allowing it once here is clearer than
// guarding two dozen small items — and CI runs clippy with `-D warnings`, so a stray warning
// is a build failure on Windows and macOS.
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::collections::HashMap;
#[cfg(unix)]
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use hx_core::error::{HxError, Result};
#[cfg(unix)]
use nix::pty::{openpty, OpenptyResult};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};
#[cfg(unix)]
use tokio::sync::broadcast;

/// How much terminal output is retained for a client that attaches late or reattaches.
///
/// 256 KiB is roughly a few thousand lines of ordinary shell output — enough that reattaching shows
/// recent history, small enough that a runaway producer cannot exhaust memory.
pub const SCROLLBACK_BYTES: usize = 256 * 1024;

/// A client's message to its terminal.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum TerminalInput {
    /// Bytes typed at the terminal. Base64 because input is bytes too: a paste may contain
    /// anything, and a control character must not have to be representable as text to be sent.
    Input { data: String },
    /// The client's viewport changed; the shell needs to know so `vim` and friends redraw.
    Resize { cols: u16, rows: u16 },
}

/// A terminal's message to an attached client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum TerminalOutput {
    /// Terminal bytes, base64-encoded.
    Output { data: String },
    /// Sent once on attach, before any live output: what the terminal printed before this client
    /// arrived. Delivered as its own frame so a client can tell "history" from "live" and a
    /// reattaching client can decide whether to clear first.
    Scrollback { data: String },
    /// The shell exited; the terminal is over and no further output will come.
    Exited { code: Option<i32> },
}

/// Encode terminal bytes for the wire.
pub fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decode terminal bytes from the wire.
pub fn decode(data: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| HxError::Config(format!("terminal data is not valid base64: {e}")))
}

/// A bounded byte buffer that keeps the *most recent* bytes, trimming the oldest.
///
/// A plain `Vec<u8>` with a cap, not a ring buffer: trimming happens on write and reads are whole-
/// buffer, so the extra bookkeeping a ring would need buys nothing and gives more room to get the
/// wrap-around wrong. Output arrives in the tens of KiB at most, so the copy on trim is not hot.
#[derive(Debug, Default)]
#[cfg(unix)]
struct Scrollback {
    bytes: Vec<u8>,
}

#[cfg(unix)]
impl Scrollback {
    fn push(&mut self, chunk: &[u8]) {
        self.bytes.extend_from_slice(chunk);
        if self.bytes.len() > SCROLLBACK_BYTES {
            // Drop from the front, and drop the whole excess at once rather than one byte per
            // write. Trimming to exactly the cap on every write would make a producer that always
            // exceeds it copy the entire buffer each time.
            let excess = self.bytes.len() - SCROLLBACK_BYTES;
            self.bytes.drain(..excess);
        }
    }

    fn snapshot(&self) -> &[u8] {
        &self.bytes
    }
}

/// One terminal: the PTY, its scrollback, and the broadcast of its output.
///
/// Unix-only. A PTY is a Unix device; on a host without one there is nothing honest to return, so
/// [`Terminals`] reports that rather than pretending a terminal exists.
#[cfg(unix)]
pub struct Terminal {
    /// The master side of the PTY. Writing here is typing; reading here is what the shell printed.
    ///
    /// Held for the terminal's life. When it closes, the shell sees end-of-input.
    master: Mutex<OwnedFd>,
    scrollback: Mutex<Scrollback>,
    /// Output broadcast to attached clients. `broadcast` because several clients attach to one
    /// terminal and all must see the same bytes; a client that falls behind is told it lagged
    /// rather than silently skipping output.
    output: broadcast::Sender<TerminalOutput>,
    /// The child's process id, for signalling. The child itself is reaped by the reader task.
    child_pid: Option<i32>,
}

#[cfg(unix)]
impl Terminal {
    /// The retained scrollback, for a client attaching now.
    pub fn scrollback(&self) -> Vec<u8> {
        self.scrollback
            .lock()
            .expect("scrollback mutex is never poisoned by a panic-free push")
            .snapshot()
            .to_vec()
    }

    /// Subscribe to live output. Call *before* reading [`Terminal::scrollback`] to avoid a gap:
    /// output produced between the snapshot and the subscription would otherwise be lost.
    pub fn subscribe(&self) -> broadcast::Receiver<TerminalOutput> {
        self.output.subscribe()
    }

    /// Type at the terminal.
    pub fn write(&self, data: &[u8]) -> Result<()> {
        let master = self
            .master
            .lock()
            .map_err(|_| HxError::Sandbox("terminal master lock is poisoned".to_string()))?;
        let mut file =
            std::fs::File::from(master.try_clone().map_err(|e| {
                HxError::Sandbox(format!("could not duplicate the pty master: {e}"))
            })?);
        file.write_all(data)
            .map_err(|e| HxError::Sandbox(format!("could not write to the terminal: {e}")))
    }

    /// Resize the terminal, so a full-screen program redraws to the client's viewport.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        if cols == 0 || rows == 0 {
            // A zero dimension is what a hidden or unmounted viewport reports. Passing it on would
            // make the kernel reject the winsize or, worse, leave the shell with a 0x0 window that
            // breaks every curses program until the next resize.
            return Ok(());
        }
        let master = self
            .master
            .lock()
            .map_err(|_| HxError::Sandbox("terminal master lock is poisoned".to_string()))?;
        let winsize = libc_winsize(cols, rows);
        // SAFETY: `master` is an owned, open fd for the duration of the call, and `TIOCSWINSZ`
        // takes a pointer to a winsize we have just built on the stack for exactly this purpose.
        let rc = unsafe { libc_ioctl_tiocswinsz(master.as_raw_fd(), &winsize) };
        if rc != 0 {
            return Err(HxError::Sandbox(format!(
                "could not resize the terminal to {cols}x{rows}: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}

/// Start a terminal running `shell`, with output broadcast and retained.
///
/// The shell is spawned on a PTY's *slave* side and the master is kept here. A task reads the master
/// and publishes what it gets; the child is reaped on exit and an [`TerminalOutput::Exited`] is
/// broadcast last, so a client learns the shell ended rather than seeing the stream simply stop —
/// "no more output" and "the shell died" are different things to render.
#[cfg(unix)]
pub fn spawn(shell: &str, args: &[String], cols: u16, rows: u16) -> Result<Arc<Terminal>> {
    // `openpty` takes nix's own `Winsize`; the hand-rolled one below is for the `TIOCSWINSZ` ioctl
    // on a resize, which has no safe wrapper here.
    let window = nix::pty::Winsize {
        ws_row: rows.max(1),
        ws_col: cols.max(1),
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let OpenptyResult { master, slave } = openpty(Some(&window), None)
        .map_err(|e| HxError::Sandbox(format!("could not open a pty: {e}")))?;

    let slave_raw = slave.as_raw_fd();
    let mut command = std::process::Command::new(shell);
    command.args(args);
    // The child must be a session leader with the slave as its controlling terminal, or job
    // control, `Ctrl-C` and full-screen programs do not work: signals are delivered to the
    // foreground *process group*, which only exists once the pty is controlling.
    //
    // All of the child's setup lives in one `pre_exec`: calling it twice would silently discard
    // the first closure, and the session — and so job control — would be quietly missing.
    //
    // The stdio wiring happens in the *child*, in `pre_exec` below. Doing it here would `dup2` over
    // the daemon's own descriptors: the parent's stdout and stderr are the process's, not the
    // shell's, and clobbering them makes the daemon (or a test runner) die with no output at all.
    //
    // The child must also close the master, or it holds the terminal open and a shell that exits
    // never produces end-of-file on the master — the reader would wait forever on a dead shell.
    let master_raw = master.as_raw_fd();
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(move || {
            // `setsid` gives the child a new session with no controlling terminal, which
            // `TIOCSCTTY` then claims. Without the detach first, the child would inherit the
            // daemon's session and `TIOCSCTTY` would fail.
            if libc_setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc_ioctl_tiocsctty(slave_raw) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            for fd in 0..=2 {
                if libc_dup2(slave_raw, fd) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // Drop the master and the original slave descriptor: the child talks to the terminal
            // only through the three standard descriptors just wired to it.
            libc_close(master_raw);
            libc_close(slave_raw);
            Ok(())
        });
    }

    let child = command
        .spawn()
        .map_err(|e| HxError::Sandbox(format!("could not start '{shell}': {e}")))?;
    // The child holds its own descriptors now; the parent must close the slave or the master never
    // reports end-of-file when the shell exits and the reader would hang forever.
    drop(slave);
    let child_pid = child.id() as i32;

    let (output, _) = broadcast::channel(1024);
    let terminal = Arc::new(Terminal {
        master: Mutex::new(master),
        scrollback: Mutex::new(Scrollback::default()),
        output: output.clone(),
        child_pid: Some(child_pid),
    });

    // The reader owns the child so it can reap it; the daemon must not leave a zombie for every
    // shell a client ever opened.
    let reader_terminal = Arc::clone(&terminal);
    let reader_output = output;
    let master_fd = reader_terminal
        .master
        .lock()
        .map_err(|_| HxError::Sandbox("terminal master lock is poisoned".to_string()))?
        .try_clone()
        .map_err(|e| HxError::Sandbox(format!("could not duplicate the pty master: {e}")))?;

    // A dedicated OS thread, not `spawn_blocking`: a terminal's reader blocks for as long as the
    // shell lives, which is the lifetime of the daemon — not a bounded piece of work owed back to
    // the async runtime — and a blocking read must not occupy a runtime worker. A plain thread also
    // makes the terminal usable outside a runtime, which is what its own tests need.
    std::thread::Builder::new()
        .name("hx-pty-reader".to_string())
        .spawn(move || {
            let mut reader = std::fs::File::from(master_fd);
            let mut buf = [0u8; 8192];
            let mut child = child;
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let chunk = &buf[..n];
                        // Retained before broadcast: a client that attaches while this is in flight
                        // reads the scrollback and then subscribes, so anything retained here is
                        // visible to it either way. Publishing first would leave a window where the
                        // bytes are live but not yet in the snapshot.
                        if let Ok(mut sb) = reader_terminal.scrollback.lock() {
                            sb.push(chunk);
                        }
                        // A send error means no client is attached, which is normal: the terminal
                        // outlives its clients by design. The bytes are still retained.
                        let _ = reader_output.send(TerminalOutput::Output {
                            data: encode(chunk),
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    // EIO on a pty master means the slave side closed — the shell exited. Treating it
                    // as a read failure would report an error for the ordinary end of a terminal.
                    Err(_) => break,
                }
            }
            let code = child.wait().ok().and_then(|s| s.code());
            let _ = reader_output.send(TerminalOutput::Exited { code });
        })
        .map_err(|e| HxError::Sandbox(format!("could not start the terminal reader: {e}")))?;

    Ok(terminal)
}

/// Every live terminal, by id.
///
/// A terminal is keyed by an opaque id rather than by session: a session may have more than one
/// shell (a build in one, an editor in another), and the terminal must be reachable by a client
/// that reconnects without knowing anything about the session.
#[cfg(unix)]
#[derive(Default)]
pub struct Terminals {
    inner: Mutex<HashMap<String, Arc<Terminal>>>,
}

/// The terminal registry on a host with no PTY.
///
/// The type still exists, and says why it cannot do anything, because the daemon's state holds it
/// unconditionally: removing it would push this platform difference up into every caller. `create`
/// and `attach` fail with a reason that names the limit rather than a panic or a silent no-op — a
/// terminal that appears to start and then produces nothing is worse than being told it will not.
#[cfg(not(unix))]
#[derive(Default)]
pub struct Terminals;

#[cfg(not(unix))]
impl Terminals {
    pub fn new() -> Self {
        Self
    }

    /// Always fails: there is no PTY to spawn a shell on.
    pub fn create(
        &self,
        _id: &str,
        _shell: &str,
        _args: &[String],
        _cols: u16,
        _rows: u16,
    ) -> Result<()> {
        Err(HxError::Sandbox(
            "terminals need a PTY, which this platform does not have".to_string(),
        ))
    }

    /// Always reports the terminal as absent, for the same reason.
    pub fn get(&self, _id: &str) -> Option<Arc<Terminal>> {
        None
    }

    /// No terminals can exist here, so there are none to list.
    pub fn ids(&self) -> Vec<String> {
        Vec::new()
    }

    /// Nothing can have been registered, so there is nothing to remove.
    pub fn remove(&self, _id: &str) -> bool {
        false
    }
}

/// The terminal on a host with no PTY: a type that exists so callers compile, and that cannot be
/// constructed, because there is never one to hand back.
#[cfg(not(unix))]
#[derive(Debug)]
pub struct Terminal {
    _private: (),
}

#[cfg(unix)]
impl Terminals {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a terminal and register it under `id`.
    pub fn create(
        &self,
        id: &str,
        shell: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| HxError::Sandbox("terminal registry lock is poisoned".to_string()))?;
        if inner.contains_key(id) {
            return Err(HxError::Config(format!(
                "a terminal '{id}' already exists: attaching is the way to reach it, not creating \
                 a second one under the same name"
            )));
        }
        let terminal = spawn(shell, args, cols, rows)?;
        inner.insert(id.to_string(), terminal);
        Ok(())
    }

    /// The terminal with this id, if it is live.
    pub fn get(&self, id: &str) -> Option<Arc<Terminal>> {
        self.inner.lock().ok()?.get(id).cloned()
    }

    /// Ids of the live terminals.
    pub fn ids(&self) -> Vec<String> {
        self.inner
            .lock()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Remove a terminal from the registry. The shell is not killed here: its master fd closes when
    /// the last `Arc` drops, which sends the shell `SIGHUP` the way a real terminal closing does.
    pub fn remove(&self, id: &str) -> bool {
        self.inner
            .lock()
            .map(|mut m| m.remove(id).is_some())
            .unwrap_or(false)
    }
}

#[cfg(unix)]
impl Terminal {
    /// The child's pid, for a caller that wants to signal it.
    pub fn child_pid(&self) -> Option<i32> {
        self.child_pid
    }
}

// The ioctl and libc calls a PTY needs, declared here rather than pulled from a bindings crate:
// four symbols, all stable ABI on Linux, and the roadmap's own preference is a self-contained
// service over a dependency that has to be vendored.
#[repr(C)]
#[derive(Clone, Copy)]
struct Winsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

fn libc_winsize(cols: u16, rows: u16) -> Winsize {
    Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

// `TIOCSCTTY` and `TIOCSWINSZ` are **not** the same number on every Unix, and the ioctl request
// encodes the argument's size and direction, so a wrong value is not a near miss: the kernel rejects
// it with `Inappropriate ioctl for device` and the shell never starts. These were the Linux values
// for every platform, which is why macOS failed with
// `could not start '/bin/sh': Inappropriate ioctl for device (os error 25)`.
//
// Linux reaches these numbers through `arch/*/mod.rs` in the `libc` crate, and they really do differ
// by architecture: `0x540E` on x86 and arm, `0x5480` on MIPS, `0x80087467` for a resize on
// powerpc/mips. BSD and macOS share one encoding (`_IOW`/`_IO` from `<sys/ioccom.h>`), which is what
// the `0x2000_...`/`0x8008_...` forms below are.
//
// Verified against the `libc` crate's own per-target constants rather than from memory. If a target is
// ever added here, take its values from that crate or the platform header, not by copying a neighbour.

/// The `ioctl` request to make the tty a controlling terminal.
///
/// Linux x86 and arm use `0x540E`; MIPS uses `0x5480`.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    not(any(target_arch = "mips", target_arch = "mips64"))
))]
const TIOCSCTTY: u64 = 0x540E;
/// The `ioctl` request to set the terminal window size.
///
/// Linux: x86/arm is `0x5414`, but MIPS and PowerPC encode the size into the request, so the `libc`
/// crate's values for those are used rather than assumed.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    not(any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "powerpc",
        target_arch = "powerpc64"
    ))
))]
const TIOCSWINSZ: u64 = 0x5414;

// Linux on architectures that encode the size into the request.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "mips", target_arch = "mips64")
))]
const TIOCSCTTY: u64 = 0x5480;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "powerpc",
        target_arch = "powerpc64"
    )
))]
const TIOCSWINSZ: u64 = 0x80087467;

// BSD and macOS: `_IO('t', 97)` and `_IOW('t', 103, struct winsize)` from `<sys/ioccom.h>`. The
// values match the `libc` crate's `freebsdlike`/`netbsdlike`/`apple` definitions.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const TIOCSCTTY: u64 = 0x20007461;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const TIOCSWINSZ: u64 = 0x80087467;

// The ioctl helpers are Unix-only: they reference the per-platform request constants above, and on a
// platform with no PTY neither the constants nor the calls exist. Guarding them here is what keeps
// Windows compiling — without it the constants are absent and these two functions fail to resolve.
#[cfg(unix)]
unsafe fn libc_ioctl_tiocswinsz(fd: i32, ws: &Winsize) -> i32 {
    unsafe extern "C" {
        fn ioctl(fd: i32, request: u64, ...) -> i32;
    }
    unsafe { ioctl(fd, TIOCSWINSZ, ws as *const Winsize) }
}

#[cfg(unix)]
unsafe fn libc_ioctl_tiocsctty(fd: i32) -> i32 {
    unsafe extern "C" {
        fn ioctl(fd: i32, request: u64, ...) -> i32;
    }
    unsafe { ioctl(fd, TIOCSCTTY, 0i32) }
}

#[cfg(unix)]
unsafe fn libc_setsid() -> i32 {
    unsafe extern "C" {
        fn setsid() -> i32;
    }
    unsafe { setsid() }
}

unsafe fn libc_close(fd: i32) -> i32 {
    unsafe extern "C" {
        fn close(fd: i32) -> i32;
    }
    unsafe { close(fd) }
}

#[cfg(unix)]
unsafe fn libc_dup2(oldfd: i32, newfd: i32) -> i32 {
    unsafe extern "C" {
        fn dup2(oldfd: i32, newfd: i32) -> i32;
    }
    unsafe { dup2(oldfd, newfd) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A few tests in this module are about the wire format rather than the PTY, so they run
    // everywhere: `encode`/`decode` are unguarded precisely because a client needs them on any
    // platform. The rest drive `Scrollback` and `Terminals`, which only exist where a PTY does.
    #[cfg(unix)]
    #[test]
    fn scrollback_keeps_only_the_most_recent_bytes() {
        let mut sb = Scrollback::default();
        // More than the cap, so the trim runs and the oldest bytes are the ones dropped.
        sb.push(&vec![b'a'; SCROLLBACK_BYTES]);
        sb.push(b"RECENT");
        assert_eq!(sb.snapshot().len(), SCROLLBACK_BYTES);
        assert!(
            sb.snapshot().ends_with(b"RECENT"),
            "the newest bytes must survive the trim"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_single_write_larger_than_the_cap_is_trimmed_not_kept() {
        // The case a line-counting cap would miss: one enormous write.
        let mut sb = Scrollback::default();
        sb.push(&vec![b'x'; SCROLLBACK_BYTES * 2]);
        assert_eq!(sb.snapshot().len(), SCROLLBACK_BYTES);
    }

    #[test]
    fn terminal_bytes_survive_a_round_trip_that_is_not_valid_utf8() {
        // A terminal must pass bytes it cannot interpret as text — a partial UTF-8 sequence split
        // across reads, or binary a program legitimately prints.
        let raw = vec![0xff, 0xfe, 0x00, 0x1b, 0x5b, 0x33, 0x31, 0x6d];
        let decoded = decode(&encode(&raw)).expect("base64 must round-trip arbitrary bytes");
        assert_eq!(decoded, raw);
    }

    #[cfg(unix)]
    #[test]
    fn a_zero_dimension_resize_is_ignored_rather_than_applied() {
        // A hidden viewport reports 0x0; applying it leaves the shell in a state every curses
        // program renders wrong until something resizes it again.
        let OpenptyResult { master, slave } = openpty(None, None).expect("openpty");
        drop(slave);
        let terminal = Terminal {
            master: Mutex::new(master),
            scrollback: Mutex::new(Scrollback::default()),
            output: broadcast::channel(4).0,
            child_pid: None,
        };
        assert!(terminal.resize(0, 24).is_ok());
        assert!(terminal.resize(80, 0).is_ok());
    }

    #[test]
    fn decoding_something_that_is_not_base64_is_an_error_not_a_panic() {
        let err = decode("not base64!!").unwrap_err();
        assert!(matches!(err, HxError::Config(_)));
    }

    #[cfg(unix)]
    #[test]
    fn a_terminal_id_cannot_be_reused_while_it_is_live() {
        let terminals = Terminals::new();
        terminals
            .create("t1", "/bin/sh", &[], 80, 24)
            .expect("a shell must start");
        let err = terminals.create("t1", "/bin/sh", &[], 80, 24).unwrap_err();
        assert!(
            matches!(err, HxError::Config(ref m) if m.contains("already exists")),
            "a second terminal under one id must be refused, got {err:?}"
        );
        assert!(terminals.remove("t1"));
        assert!(terminals.get("t1").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn an_unknown_terminal_is_absent_rather_than_created_on_the_way_in() {
        let terminals = Terminals::new();
        assert!(terminals.get("nope").is_none());
        assert!(terminals.ids().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_real_shell_prints_and_its_output_is_retained() {
        // The end-to-end proof at the unit level: start a real shell, run a real command, and see
        // its bytes come back through the same path a client would read them.
        let terminals = Terminals::new();
        terminals
            .create("t", "/bin/sh", &[], 80, 24)
            .expect("a shell must start");
        let terminal = terminals.get("t").expect("the shell is registered");
        let mut rx = terminal.subscribe();

        terminal
            .write(b"echo hx-pty-marker\n")
            .expect("writing to the pty must work");

        let mut seen = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            match rx.try_recv() {
                Ok(TerminalOutput::Output { data }) => {
                    seen.extend_from_slice(&decode(&data).expect("output is base64"));
                    if String::from_utf8_lossy(&seen).contains("hx-pty-marker") {
                        break;
                    }
                }
                Ok(_) => {}
                // Nothing yet: yield rather than spin, the shell needs to be scheduled.
                Err(broadcast::error::TryRecvError::Empty) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => panic!("the output stream must not close while the shell lives: {e}"),
            }
        }
        let text = String::from_utf8_lossy(&seen);
        assert!(
            text.contains("hx-pty-marker"),
            "the command's output must reach an attached reader, saw {text:?}"
        );
        // And it is in the scrollback a later client would be sent.
        let retained = String::from_utf8_lossy(&terminal.scrollback()).into_owned();
        assert!(
            retained.contains("hx-pty-marker"),
            "output must be retained for a client that attaches later, saw {retained:?}"
        );
        terminals.remove("t");
    }

    #[cfg(unix)]
    #[test]
    fn two_readers_on_one_terminal_see_the_same_bytes() {
        // M2's actual claim, at the level of the terminal: not one client, two.
        let terminals = Terminals::new();
        terminals
            .create("t", "/bin/sh", &[], 80, 24)
            .expect("a shell");
        let terminal = terminals.get("t").expect("registered");
        let mut a = terminal.subscribe();
        let mut b = terminal.subscribe();

        terminal.write(b"echo shared-bytes\n").expect("write");

        let collect = |rx: &mut broadcast::Receiver<TerminalOutput>| {
            let mut out = Vec::new();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while std::time::Instant::now() < deadline {
                if let Ok(TerminalOutput::Output { data }) = rx.try_recv() {
                    out.extend_from_slice(&decode(&data).expect("base64"));
                    if String::from_utf8_lossy(&out).contains("shared-bytes") {
                        break;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            out
        };
        let seen_a = collect(&mut a);
        let seen_b = collect(&mut b);
        assert!(String::from_utf8_lossy(&seen_a).contains("shared-bytes"));
        assert!(
            String::from_utf8_lossy(&seen_b).contains("shared-bytes"),
            "both attached clients must receive the terminal's output"
        );
        terminals.remove("t");
    }
}

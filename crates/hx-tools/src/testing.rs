//! Test doubles shared by this crate's unit tests.
//!
//! Deliberately a real implementation of [`hx_remote::Host`] rather than a mock library: a host is
//! not that large a trait, and an in-memory filesystem makes it possible to assert what a tool
//! *did* (which bytes were written, which command ran) instead of only what it returned.

use async_trait::async_trait;
use hx_core::error::{HxError, Result};
use hx_core::ids::HostId;
use hx_remote::host::{ExecOutput, HostCaps, RemoteEntry, RemoteOs, ShellKind};
use hx_remote::{Host, PtySession};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A boundary that records what it was asked to run.
///
/// `docs/approvals.md` §4's tests need a confined run without a container engine: the facts under test are
/// *where* the command went and what the tool reported, not whether Docker works, and a test that needed
/// Docker would be `#[ignore]`d and therefore not run in CI. The real boundary is exercised by
/// `hx-sandbox`'s live suite and by the daemon's adapter.
pub struct FakeSandbox {
    /// Every `(command, workdir)` this boundary was asked for, in order.
    pub runs: Mutex<Vec<(String, Option<String>)>>,
    /// What to answer. `Err` is a boundary that cannot be entered.
    response: Mutex<Result<ExecOutput, String>>,
    /// What `describe()` says — the line a transcript shows.
    pub label: String,
}

impl Default for FakeSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeSandbox {
    /// A boundary that accepts everything and answers with no output.
    pub fn new() -> Self {
        Self {
            runs: Mutex::new(Vec::new()),
            response: Mutex::new(Ok(ExecOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: Some(0),
                duration_ms: 1,
                truncated: false,
            })),
            label: "sandbox fake (l2, for tests)".to_string(),
        }
    }

    /// A boundary whose entry fails — an engine that is gone, a mount that disappeared.
    pub fn unavailable(reason: &str) -> Self {
        let sandbox = Self::new();
        *sandbox.response.lock().unwrap() = Err(reason.to_string());
        sandbox
    }

    /// A boundary that answers with this output.
    pub fn answering(stdout: &str, exit_code: i32) -> Self {
        let sandbox = Self::new();
        *sandbox.response.lock().unwrap() = Ok(ExecOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: Some(exit_code),
            duration_ms: 3,
            truncated: false,
        });
        sandbox
    }

    /// Every command this boundary was asked to run, with the directory it was given.
    pub fn runs(&self) -> Vec<(String, Option<String>)> {
        self.runs.lock().unwrap().clone()
    }
}

#[async_trait]
impl crate::tool::SandboxExec for FakeSandbox {
    async fn exec(&self, command: &str, workdir: Option<&str>) -> Result<ExecOutput> {
        self.runs
            .lock()
            .unwrap()
            .push((command.to_string(), workdir.map(str::to_string)));
        match self.response.lock().unwrap().clone() {
            Ok(output) => Ok(output),
            Err(reason) => Err(HxError::Sandbox(reason)),
        }
    }

    fn describe(&self) -> String {
        self.label.clone()
    }
}

/// A host with an in-memory filesystem and a scripted command runner.
pub struct FakeHost {
    id: HostId,
    /// What this machine is, mutable so a test can describe a host the tool must refuse — no home
    /// directory, no trash, a Windows shell.
    pub caps: HostCaps,
    pub files: Mutex<BTreeMap<String, Vec<u8>>>,
    /// Directories, so that a listing can contain something that is not a file.
    ///
    /// Tracked separately because an empty directory is exactly the case a listing has to get right:
    /// "move this tree to the trash" is a question about a directory whose contents may be nothing
    /// at all, and the count in the prompt has to be able to say zero.
    pub dirs: Mutex<BTreeSet<String>>,
    /// Every command line this host was asked to run, in order.
    pub commands: Mutex<Vec<String>>,
    /// Every directory this host was asked to list, in order.
    ///
    /// Recorded because a measurement is *work*: the prompt for a deletion is built from a directory
    /// walk, and "was that walk done at all" is a question a test has to be able to ask.
    pub listings: Mutex<Vec<String>>,
    /// What `exec` returns. `None` means "succeed with empty output".
    pub exec_response: Mutex<Option<ExecOutput>>,
    /// Every pty this host has opened, in order.
    ///
    /// Held so a test can reach into the session the server opened and assert on what the client
    /// actually sent it — `written()` and `resizes()` are the interesting ones.
    pub ptys: Mutex<Vec<FakePty>>,
    /// Symlinks, as link path -> target path. Resolution is longest-prefix, like the kernel's,
    /// so tests can stage the exact escape shape (`/ws/link` -> `/etc`) and assert the loop
    /// refuses it.
    pub symlinks: Mutex<BTreeMap<String, String>>,
}

impl FakeHost {
    pub fn unix() -> Self {
        Self {
            id: HostId::from("hst_fake"),
            caps: HostCaps {
                os: RemoteOs::Linux,
                shell: ShellKind::Posix,
                arch: Some("x86_64".to_string()),
                home_dir: Some("/home/agent".to_string()),
                has_sftp: None,
            },
            files: Mutex::new(BTreeMap::new()),
            dirs: Mutex::new(BTreeSet::new()),
            commands: Mutex::new(Vec::new()),
            listings: Mutex::new(Vec::new()),
            exec_response: Mutex::new(None),
            ptys: Mutex::new(Vec::new()),
            symlinks: Mutex::new(BTreeMap::new()),
        }
    }

    /// The pty opened most recently, if any.
    pub fn last_pty(&self) -> Option<FakePty> {
        self.ptys.lock().unwrap().last().cloned()
    }

    pub fn windows() -> Self {
        let mut host = Self::unix();
        host.caps.os = RemoteOs::Windows;
        host.caps.shell = ShellKind::PowerShell;
        host
    }

    pub fn with_file(self, path: &str, contents: &str) -> Self {
        self.ensure_parents(path);
        self.files
            .lock()
            .unwrap()
            .insert(path.to_string(), contents.as_bytes().to_vec());
        self
    }

    /// Declare a directory, which is how a listing ends up containing something that is not a file.
    pub fn with_dir(self, path: &str) -> Self {
        self.ensure_parents(path);
        self.dirs
            .lock()
            .unwrap()
            .insert(path.trim_end_matches('/').to_string());
        self
    }

    /// A directory exists because something is in it. Declaring the parents here is what makes a
    /// listing of a tree look like a filesystem rather than like a flat map of paths.
    fn ensure_parents(&self, path: &str) {
        let mut dirs = self.dirs.lock().unwrap();
        let mut current = String::new();
        for segment in path.trim_end_matches('/').split('/') {
            if current.is_empty() && segment.is_empty() {
                continue;
            }
            current = format!("{current}/{segment}");
            // The last segment is the thing itself, not a parent of it.
            if current.trim_end_matches('/') == path.trim_end_matches('/') {
                break;
            }
            dirs.insert(current.clone());
        }
    }

    pub fn with_exec_output(self, stdout: &str, stderr: &str, exit_code: Option<i32>) -> Self {
        *self.exec_response.lock().unwrap() = Some(ExecOutput {
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            exit_code,
            duration_ms: 3,
            truncated: false,
        });
        self
    }

    /// Stage a symlink: `link` resolves to `target`, longest-prefix wins, like the kernel.
    pub fn with_symlink(self, link: &str, target: &str) -> Self {
        self.symlinks
            .lock()
            .unwrap()
            .insert(link.to_string(), target.to_string());
        self
    }

    /// Follow staged links, longest-prefix-first, with a cycle guard. A link cycle resolves to
    /// wherever the guard stops — tests stage acyclic links; this just must not hang on a typo.
    fn resolve_links(&self, path: &str) -> String {
        let mut current = path.to_string();
        for _ in 0..16 {
            let links = self.symlinks.lock().unwrap();
            let mut best: Option<(String, String)> = None;
            for (link, target) in links.iter() {
                let covers = current == *link || current.starts_with(&format!("{link}/"));
                if covers && best.as_ref().is_none_or(|(b, _)| link.len() > b.len()) {
                    best = Some((link.clone(), target.clone()));
                }
            }
            drop(links);
            match best {
                Some((link, target)) => {
                    let rest = current[link.len()..].trim_start_matches('/');
                    current = if rest.is_empty() {
                        target
                    } else {
                        format!("{}/{}", target.trim_end_matches('/'), rest)
                    };
                }
                None => break,
            }
        }
        current
    }

    /// Collapse `.`, `..` and duplicate separators lexically — the fake filesystem has no kernel
    /// to ask, so normalization stands in for it.
    fn normalize_lexical(path: &str) -> String {
        let absolute = path.starts_with('/');
        let mut parts: Vec<&str> = Vec::new();
        for segment in path.split('/') {
            match segment {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                s => parts.push(s),
            }
        }
        let joined = parts.join("/");
        if absolute {
            format!("/{joined}")
        } else {
            joined
        }
    }

    pub fn file(&self, path: &str) -> Option<String> {
        self.files
            .lock()
            .unwrap()
            .get(path)
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
    }

    pub fn commands(&self) -> Vec<String> {
        self.commands.lock().unwrap().clone()
    }

    /// Every directory this host was asked to list, in order. See [`FakeHost::listings`].
    pub fn listings(&self) -> Vec<String> {
        self.listings.lock().unwrap().clone()
    }
}

#[async_trait]
impl Host for FakeHost {
    fn id(&self) -> &HostId {
        &self.id
    }

    fn caps(&self) -> &HostCaps {
        &self.caps
    }

    async fn exec(&self, command: &str, _timeout: Duration) -> Result<ExecOutput> {
        self.commands.lock().unwrap().push(command.to_string());
        if let Some(response) = self.exec_response.lock().unwrap().clone() {
            return Ok(response);
        }
        Ok(ExecOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(0),
            duration_ms: 1,
            truncated: false,
        })
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        // Links resolve before the lookup, like the kernel: a test that stages an escape reads
        // through it, which is what makes the agent-level re-check test meaningful.
        let resolved = self.resolve_links(path);
        self.files
            .lock()
            .unwrap()
            .get(&resolved)
            .cloned()
            .ok_or_else(|| HxError::Remote(format!("no such file: {path}")))
    }

    async fn write_file(&self, path: &str, contents: &[u8]) -> Result<()> {
        let resolved = self.resolve_links(path);
        self.files
            .lock()
            .unwrap()
            .insert(resolved, contents.to_vec());
        Ok(())
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<RemoteEntry>> {
        self.listings.lock().unwrap().push(path.to_string());
        let prefix = format!("{}/", path.trim_end_matches('/'));
        let mut entries: Vec<RemoteEntry> = Vec::new();

        for (name, contents) in self.files.lock().unwrap().iter() {
            if let Some(rest) = name.strip_prefix(&prefix) {
                if !rest.is_empty() && !rest.contains('/') {
                    entries.push(RemoteEntry {
                        name: rest.to_string(),
                        path: name.clone(),
                        is_dir: false,
                        size: contents.len() as u64,
                    });
                }
            }
        }

        for name in self.dirs.lock().unwrap().iter() {
            if let Some(rest) = name.strip_prefix(&prefix) {
                if !rest.is_empty() && !rest.contains('/') {
                    entries.push(RemoteEntry {
                        name: rest.to_string(),
                        path: name.clone(),
                        is_dir: true,
                        size: 0,
                    });
                }
            }
        }

        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    /// Resolve staged links plus lexical normalization — the fake stand-in for the kernel's
    /// answer, so the agent's canonical re-check is testable without a real filesystem.
    async fn canonicalize(&self, path: &str) -> Result<String> {
        Ok(Self::normalize_lexical(&self.resolve_links(path)))
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let from = from.trim_end_matches('/');
        let to = to.trim_end_matches('/');

        {
            let files = self.files.lock().unwrap();
            let dirs = self.dirs.lock().unwrap();
            if files.contains_key(to) || dirs.contains(to) {
                return Err(HxError::Remote(format!(
                    "{to} already exists; refusing to replace it"
                )));
            }
        }

        // A directory is its prefix, so one rule moves both kinds of thing.
        let under = |name: &str| name == from || name.starts_with(&format!("{from}/"));
        let renamed = |name: &str| format!("{to}{}", &name[from.len()..]);

        let mut moved_files = 0usize;
        {
            let mut files = self.files.lock().unwrap();
            let mut kept = BTreeMap::new();
            for (name, contents) in std::mem::take(&mut *files) {
                if under(&name) {
                    moved_files += 1;
                    kept.insert(renamed(&name), contents);
                } else {
                    kept.insert(name, contents);
                }
            }
            *files = kept;
        }

        let mut moved_dirs = 0usize;
        {
            let mut dirs = self.dirs.lock().unwrap();
            let mut kept = BTreeSet::new();
            for name in std::mem::take(&mut *dirs) {
                if under(&name) {
                    moved_dirs += 1;
                    kept.insert(renamed(&name));
                } else {
                    kept.insert(name);
                }
            }
            *dirs = kept;
        }

        if moved_files == 0 && moved_dirs == 0 {
            return Err(HxError::Remote(format!("no such file: {from}")));
        }

        // `rename(2)` creates nothing on the way, but the host contract says the destination's
        // parent is created, and the trash a delete invents depends on that.
        self.ensure_parents(to);
        Ok(())
    }

    async fn open_pty(
        &self,
        command: Option<&str>,
        cols: u16,
        rows: u16,
    ) -> Result<Arc<dyn PtySession>> {
        // A working pty, so the layer above can be tested without a transport. It echoes what is
        // written, which is enough to prove a client's bytes arrive and the reply is routed back.
        let session = FakePty::new(command, cols, rows);
        self.ptys.lock().unwrap().push(session.clone());
        Ok(Arc::new(session))
    }

    fn describe(&self) -> String {
        format!("fake ({:?})", self.caps.os)
    }
}

/// A pty that remembers what it was asked and replays what it is given.
///
/// Deliberately simple: an echo, an optional opening line, and a record of writes and resizes. The
/// point is to exercise the wiring above the transport, not to pretend to be a shell.
#[derive(Clone)]
pub struct FakePty {
    inner: Arc<FakePtyInner>,
}

struct FakePtyInner {
    command: Option<String>,
    cols: std::sync::atomic::AtomicU16,
    rows: std::sync::atomic::AtomicU16,
    /// Bytes a client has written, in order.
    written: Mutex<Vec<u8>>,
    /// Resizes, in order.
    resizes: Mutex<Vec<(u16, u16)>>,
    /// Output waiting to be read.
    pending: Mutex<std::collections::VecDeque<Vec<u8>>>,
    closed: std::sync::atomic::AtomicBool,
}

impl FakePty {
    fn new(command: Option<&str>, cols: u16, rows: u16) -> Self {
        let pending = std::collections::VecDeque::new();
        Self {
            inner: Arc::new(FakePtyInner {
                command: command.map(str::to_string),
                cols: std::sync::atomic::AtomicU16::new(cols),
                rows: std::sync::atomic::AtomicU16::new(rows),
                written: Mutex::new(Vec::new()),
                resizes: Mutex::new(Vec::new()),
                pending: Mutex::new(pending),
                closed: std::sync::atomic::AtomicBool::new(false),
            }),
        }
    }

    /// The command the pty was opened with, if any.
    pub fn command(&self) -> Option<String> {
        self.inner.command.clone()
    }

    /// Everything a client has written so far.
    pub fn written(&self) -> Vec<u8> {
        self.inner.written.lock().unwrap().clone()
    }

    /// Every resize, in order.
    pub fn resizes(&self) -> Vec<(u16, u16)> {
        self.inner.resizes.lock().unwrap().clone()
    }

    /// Whether `close` has run.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Queue output for the next `read`.
    pub fn push_output(&self, bytes: &[u8]) {
        self.inner.pending.lock().unwrap().push_back(bytes.to_vec());
    }
}

#[async_trait]
impl PtySession for FakePty {
    async fn write(&self, data: &[u8]) -> Result<()> {
        if self.inner.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(HxError::Remote("the session is closed".to_string()));
        }
        let mut written = self.inner.written.lock().unwrap();
        written.extend_from_slice(data);
        // Echo, like a real pty does: a test can then assert on one stream rather than two.
        let mut pending = self.inner.pending.lock().unwrap();
        pending.push_back(data.to_vec());
        Ok(())
    }

    async fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        if self.inner.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(HxError::Remote("the session is closed".to_string()));
        }
        self.inner
            .cols
            .store(cols, std::sync::atomic::Ordering::SeqCst);
        self.inner
            .rows
            .store(rows, std::sync::atomic::Ordering::SeqCst);
        self.inner.resizes.lock().unwrap().push((cols, rows));
        Ok(())
    }

    async fn read(&self) -> Option<Vec<u8>> {
        // A closed session ends: `None` rather than a wait, which is what a client needs in order to
        // stop reading instead of hanging.
        if self.inner.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return None;
        }
        loop {
            if let Some(chunk) = self.inner.pending.lock().unwrap().pop_front() {
                return Some(chunk);
            }
            if self.inner.closed.load(std::sync::atomic::Ordering::SeqCst) {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn close(&self) -> Result<()> {
        self.inner
            .closed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// A host whose every operation fails, for the paths where the transport is the problem.
///
/// Otherwise described as an ordinary POSIX machine with a home directory: a failure test that also
/// tripped a capability check would be testing the wrong refusal.
pub struct BrokenHost {
    id: HostId,
    caps: HostCaps,
}

impl BrokenHost {
    pub fn new() -> Self {
        let mut caps = HostCaps::unknown();
        caps.os = RemoteOs::Linux;
        caps.home_dir = Some("/home/agent".to_string());
        Self {
            id: HostId::from("hst_broken"),
            caps,
        }
    }
}

impl Default for BrokenHost {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Host for BrokenHost {
    fn id(&self) -> &HostId {
        &self.id
    }

    fn caps(&self) -> &HostCaps {
        &self.caps
    }

    async fn exec(&self, _command: &str, _timeout: Duration) -> Result<ExecOutput> {
        Err(HxError::Remote("connection reset".to_string()))
    }

    async fn read_file(&self, _path: &str) -> Result<Vec<u8>> {
        Err(HxError::Remote("connection reset".to_string()))
    }

    async fn write_file(&self, _path: &str, _contents: &[u8]) -> Result<()> {
        Err(HxError::Remote("connection reset".to_string()))
    }

    async fn list_dir(&self, _path: &str) -> Result<Vec<RemoteEntry>> {
        Err(HxError::Remote("connection reset".to_string()))
    }

    async fn rename(&self, _from: &str, _to: &str) -> Result<()> {
        Err(HxError::Remote("connection reset".to_string()))
    }

    async fn open_pty(
        &self,
        _command: Option<&str>,
        _cols: u16,
        _rows: u16,
    ) -> Result<Arc<dyn PtySession>> {
        // A pty on a broken host fails like everything else on it. Returning a session that never
        // produced output would be the worse answer: it looks like a hung machine rather than a
        // dead one.
        Err(HxError::Remote("connection reset".to_string()))
    }

    fn describe(&self) -> String {
        "broken".to_string()
    }
}

#[cfg(test)]
mod pty_tests {
    use super::*;

    #[tokio::test]
    async fn a_fake_pty_records_what_a_client_sent() {
        let host = FakeHost::unix();
        let pty = host.open_pty(Some("sh"), 80, 24).await.unwrap();
        pty.write(b"ls -la\n").await.unwrap();
        let fake = host.last_pty().expect("the pty was recorded");
        assert_eq!(fake.written(), b"ls -la\n");
        assert_eq!(fake.command().as_deref(), Some("sh"));
    }

    #[tokio::test]
    async fn a_fake_pty_echoes_so_the_round_trip_can_be_asserted() {
        let host = FakeHost::unix();
        let pty = host.open_pty(Some("sh"), 80, 24).await.unwrap();
        pty.write(b"hello").await.unwrap();
        // A real pty echoes input; matching that means the layer above can be tested on one stream.
        assert_eq!(pty.read().await, Some(b"hello".to_vec()));
    }

    #[tokio::test]
    async fn a_fake_pty_records_resizes_in_order() {
        let host = FakeHost::unix();
        let pty = host.open_pty(Some("sh"), 80, 24).await.unwrap();
        pty.resize(120, 40).await.unwrap();
        pty.resize(100, 30).await.unwrap();
        let fake = host.last_pty().unwrap();
        assert_eq!(fake.resizes(), vec![(120, 40), (100, 30)]);
    }

    #[tokio::test]
    async fn a_closed_pty_ends_and_refuses_further_writes() {
        let host = FakeHost::unix();
        let pty = host.open_pty(Some("sh"), 80, 24).await.unwrap();
        pty.close().await.unwrap();
        // Closing twice is not an error: a disconnect and a shutdown may both try.
        pty.close().await.unwrap();
        assert!(host.last_pty().unwrap().is_closed());
        // A closed session ends the stream rather than waiting for output that will never come.
        assert_eq!(pty.read().await, None);
        // And writing to it fails rather than silently succeeding.
        assert!(pty.write(b"x").await.is_err());
    }

    #[tokio::test]
    async fn a_broken_host_refuses_to_open_a_pty() {
        let host = BrokenHost::new();
        // The refusal has to come from the transport, not from a session that never says anything:
        // a silent session reads as a hung machine, which is a different and worse report.
        match host.open_pty(None, 80, 24).await {
            Ok(_) => panic!("a broken host must not hand back a pty"),
            Err(err) => assert!(err.to_string().contains("connection reset"), "{err}"),
        }
    }
}

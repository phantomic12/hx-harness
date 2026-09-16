//! Test doubles shared by this crate's unit tests.
//!
//! Deliberately a real implementation of [`hx_remote::Host`] rather than a mock library: a host is
//! not that large a trait, and an in-memory filesystem makes it possible to assert what a tool
//! *did* (which bytes were written, which command ran) instead of only what it returned.

use async_trait::async_trait;
use hx_core::error::{HxError, Result};
use hx_core::ids::HostId;
use hx_remote::host::{ExecOutput, HostCaps, RemoteEntry, RemoteOs, ShellKind};
use hx_remote::Host;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::Duration;

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
                has_sftp: false,
            },
            files: Mutex::new(BTreeMap::new()),
            dirs: Mutex::new(BTreeSet::new()),
            commands: Mutex::new(Vec::new()),
            listings: Mutex::new(Vec::new()),
            exec_response: Mutex::new(None),
        }
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
        });
        self
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
        })
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        self.files
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| HxError::Remote(format!("no such file: {path}")))
    }

    async fn write_file(&self, path: &str, contents: &[u8]) -> Result<()> {
        self.files
            .lock()
            .unwrap()
            .insert(path.to_string(), contents.to_vec());
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

    fn describe(&self) -> String {
        format!("fake ({:?})", self.caps.os)
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

    fn describe(&self) -> String {
        "broken".to_string()
    }
}

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
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

/// A host with an in-memory filesystem and a scripted command runner.
pub struct FakeHost {
    id: HostId,
    caps: HostCaps,
    pub files: Mutex<BTreeMap<String, Vec<u8>>>,
    /// Every command line this host was asked to run, in order.
    pub commands: Mutex<Vec<String>>,
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
            commands: Mutex::new(Vec::new()),
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
        self.files
            .lock()
            .unwrap()
            .insert(path.to_string(), contents.as_bytes().to_vec());
        self
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
        let prefix = format!("{}/", path.trim_end_matches('/'));
        let files = self.files.lock().unwrap();
        let entries: Vec<RemoteEntry> = files
            .iter()
            .filter(|(name, _)| name.starts_with(&prefix) && !name[prefix.len()..].contains('/'))
            .map(|(name, contents)| RemoteEntry {
                name: name[prefix.len()..].to_string(),
                path: name.clone(),
                is_dir: false,
                size: contents.len() as u64,
            })
            .collect();
        Ok(entries)
    }

    fn describe(&self) -> String {
        format!("fake ({:?})", self.caps.os)
    }
}

/// A host whose every operation fails, for the paths where the transport is the problem.
pub struct BrokenHost {
    id: HostId,
    caps: HostCaps,
}

impl BrokenHost {
    pub fn new() -> Self {
        Self {
            id: HostId::from("hst_broken"),
            caps: HostCaps::unknown(),
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

    fn describe(&self) -> String {
        "broken".to_string()
    }
}

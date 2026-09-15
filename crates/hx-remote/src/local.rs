//! The machine the daemon itself runs on.

use crate::host::{
    caps_from_uname, caps_from_ver, enrich_caps_from_posix_probe, posix_probe_command,
    windows_probe_command, ExecOutput, Host, HostCaps, RemoteEntry, RemoteOs, ShellKind,
};
use async_trait::async_trait;
use hx_core::error::{HxError, Result};
use hx_core::ids::HostId;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

/// The local machine, driven through `std::process` rather than a shell round-trip.
pub struct LocalHost {
    id: HostId,
    caps: HostCaps,
}

impl LocalHost {
    /// Probe this machine and build a handle to it.
    pub async fn detect(id: HostId) -> Result<Self> {
        Ok(Self {
            id,
            caps: detect_local_caps().await,
        })
    }

    /// Build with caps supplied, so tests and callers on an exotic platform can skip probing.
    pub fn with_caps(id: HostId, caps: HostCaps) -> Self {
        Self { id, caps }
    }
}

async fn detect_local_caps() -> HostCaps {
    if let Some(stdout) = run_probe("sh", &["-c", posix_probe_command()]).await {
        if let Some(mut caps) = caps_from_uname(&stdout) {
            enrich_caps_from_posix_probe(&mut caps, &stdout);
            return caps;
        }
    }

    if let Some(stdout) = run_probe("cmd", &["/C", windows_probe_command()]).await {
        if let Some(mut caps) = caps_from_ver(&stdout) {
            caps.arch = std::env::var("PROCESSOR_ARCHITECTURE").ok();
            caps.home_dir = std::env::var("USERPROFILE").ok();
            return caps;
        }
    }

    // Neither probe answered. Keep whatever we know about the process we are running in, which
    // is strictly better than `Unknown` and costs nothing.
    let mut caps = HostCaps::unknown();
    caps.home_dir = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok());
    caps
}

async fn run_probe(program: &str, args: &[&str]) -> Option<String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .ok()?;
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[async_trait]
impl Host for LocalHost {
    fn id(&self) -> &HostId {
        &self.id
    }

    fn caps(&self) -> &HostCaps {
        &self.caps
    }

    async fn exec(&self, command: &str, timeout: Duration) -> Result<ExecOutput> {
        let argv = self.caps.shell.wrap(command);
        let (program, args) = argv
            .split_first()
            .ok_or_else(|| HxError::Remote("shell produced an empty argv".to_string()))?;

        let child = tokio::process::Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Critical: a timed-out command must actually die. Without this, `sleep 10000` would
            // outlive the timeout and keep holding whatever it holds.
            .kill_on_drop(true)
            .spawn()?;

        let started = Instant::now();

        match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(Ok(output)) => Ok(ExecOutput {
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                exit_code: output.status.code(),
                duration_ms: started.elapsed().as_millis() as u64,
            }),
            Ok(Err(err)) => Err(HxError::Remote(format!("failed to run command: {err}"))),
            Err(_) => Err(HxError::Remote(format!(
                "command timed out after {:.1}s",
                timeout.as_secs_f64()
            ))),
        }
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        tokio::fs::read(path)
            .await
            .map_err(|e| HxError::Remote(format!("could not read {path}: {e}")))
    }

    async fn write_file(&self, path: &str, contents: &[u8]) -> Result<()> {
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    HxError::Remote(format!("could not create {}: {e}", parent.display()))
                })?;
            }
        }
        tokio::fs::write(path, contents)
            .await
            .map_err(|e| HxError::Remote(format!("could not write {path}: {e}")))
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<RemoteEntry>> {
        let mut reader = tokio::fs::read_dir(path)
            .await
            .map_err(|e| HxError::Remote(format!("could not list {path}: {e}")))?;

        let mut entries = Vec::new();
        while let Some(entry) = reader
            .next_entry()
            .await
            .map_err(|e| HxError::Remote(format!("error reading {path}: {e}")))?
        {
            // `metadata` follows symlinks; a dangling link should not abort the whole listing.
            let meta = match entry.metadata().await {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            entries.push(RemoteEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                path: entry.path().to_string_lossy().into_owned(),
                is_dir: meta.is_dir(),
                size: meta.len(),
            });
        }

        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
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
            "local ({os}, {} shell)",
            match self.caps.shell {
                ShellKind::Posix => "posix",
                ShellKind::PowerShell => "powershell",
                ShellKind::Cmd => "cmd",
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> LocalHost {
        // Fixed caps keep these tests about process handling, not platform probing.
        LocalHost::with_caps(
            HostId::from_raw("local"),
            HostCaps {
                os: RemoteOs::Linux,
                shell: ShellKind::Posix,
                arch: None,
                home_dir: None,
                has_sftp: false,
            },
        )
    }

    #[tokio::test]
    async fn runs_a_command_and_captures_stdout() {
        let out = host()
            .exec("echo hello world", Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(out.stdout.trim(), "hello world");
        assert!(out.success());
    }

    #[tokio::test]
    async fn a_nonzero_exit_is_reported_not_raised() {
        // A failing command is data the agent needs, not an exception that hides the output.
        let out = host()
            .exec("echo problem >&2; exit 3", Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(out.exit_code, Some(3));
        assert!(!out.success());
        assert_eq!(out.stderr.trim(), "problem");
    }

    #[tokio::test]
    async fn both_streams_are_kept_separate() {
        let out = host()
            .exec("echo out; echo err >&2", Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(out.stdout.trim(), "out");
        assert_eq!(out.stderr.trim(), "err");
    }

    #[tokio::test]
    async fn the_current_directory_is_the_daemons_working_directory() {
        // Documented behaviour, and the reason sandboxes exist: a local shell inherits whatever
        // the daemon had. Callers that care must `cd` explicitly.
        let out = host().exec("pwd", Duration::from_secs(10)).await.unwrap();
        assert!(out.success());
        assert!(!out.stdout.trim().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_hanging_command_is_killed_at_the_timeout() {
        let err = host()
            .exec("sleep 30", Duration::from_millis(150))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
    }

    #[tokio::test]
    async fn writes_then_reads_back_a_file_creating_parents() {
        let dir = std::env::temp_dir().join(format!("hx-test-{}", std::process::id()));
        let path = dir.join("nested").join("file.txt");
        let path_str = path.to_string_lossy().into_owned();

        host().write_file(&path_str, b"payload").await.unwrap();
        let back = host().read_file(&path_str).await.unwrap();
        assert_eq!(back, b"payload");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn listing_a_missing_directory_is_an_error_not_a_panic() {
        let err = host()
            .list_dir("/definitely/not/here/hx")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("could not list"), "{err}");
    }

    #[tokio::test]
    async fn lists_a_directory_sorted_with_sizes() {
        let dir = std::env::temp_dir().join(format!("hx-list-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.txt"), b"x").unwrap();
        std::fs::write(dir.join("a.txt"), b"yy").unwrap();

        let entries = host().list_dir(&dir.to_string_lossy()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a.txt", "b.txt"], "sorted for stable output");
        assert_eq!(entries[0].size, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn describe_names_the_platform_and_shell() {
        assert_eq!(host().describe(), "local (linux, posix shell)");
    }
}

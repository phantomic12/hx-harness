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

/// Move `from` to `to` where a hard link cannot be made, keeping the "never replace" contract.
///
/// A cross-device move cannot be a link, and `rename(2)` would replace silently. The destination is
/// therefore created with `create_new` — which is atomic, and fails when the destination exists — and
/// the bytes are copied into it. On a failed copy the partial destination is removed, so a caller
/// never sees a truncated file at a path that was meant to hold a complete move.
async fn copy_without_replacing(from: &str, to: &str, link_error: std::io::Error) -> Result<()> {
    let mut source = tokio::fs::File::open(from)
        .await
        .map_err(|e| HxError::Remote(format!("could not read {from} to move it to {to}: {e}")))?;

    // `create_new` is the atomic part: it is the only way to get a destination another process
    // cannot have created in the meantime.
    let mut destination = match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)
        .await
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(HxError::Remote(format!(
                "{to} already exists; refusing to replace it"
            )));
        }
        Err(e) => {
            return Err(HxError::Remote(format!(
                "could not create {to} (the move from {from} cannot be a link here: {link_error}): {e}"
            )));
        }
    };

    if let Err(e) = tokio::io::copy(&mut source, &mut destination).await {
        drop(destination);
        // Removed rather than left behind: a partial file at a path the caller believes holds a
        // complete move is worse than no file, which at least reports the failure.
        let _ = tokio::fs::remove_file(to).await;
        return Err(HxError::Remote(format!(
            "could not copy {from} to {to}: {e}"
        )));
    }

    if let Err(e) = tokio::fs::remove_file(from).await {
        return Err(HxError::Remote(format!(
            "copied {from} to {to}, but could not remove the original: {e}"
        )));
    }
    Ok(())
}

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

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        if let Some(parent) = Path::new(to).parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    HxError::Remote(format!("could not create {}: {e}", parent.display()))
                })?;
            }
        }

        // `rename(2)` replaces an existing destination silently, so the refusal has to be atomic —
        // a check-then-rename lets another process create the destination in the window between the
        // two, and the rename then overwrites it.
        //
        // `link(2)` refuses when the destination exists, and the kernel does that test and the
        // creation in one step, so there is no window. The second step is `remove_file(from)`, which
        // is what turns the hard link into a move: the destination is already durable at that point,
        // so a failure there leaves the data at *both* paths rather than losing it.
        match tokio::fs::hard_link(from, to).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(HxError::Remote(format!(
                    "{to} already exists; refusing to replace it"
                )));
            }
            Err(e) => {
                // A cross-device move cannot be a hard link, and the no-replace property has to be
                // kept, so the destination is created exclusively instead and the source copied in.
                return copy_without_replacing(from, to, e).await;
            }
        }

        if let Err(e) = tokio::fs::remove_file(from).await {
            return Err(HxError::Remote(format!(
                "moved {from} to {to}, but could not remove the original: {e}"
            )));
        }
        Ok(())
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

    #[tokio::test]
    async fn a_rename_never_replaces_an_existing_destination() {
        // The contract is "refuse", and the reason it must be atomic rather than a check-then-move is
        // that the check is not a promise: another process can create the destination in between, and
        // a `rename(2)` would then overwrite it silently. This asserts the refusal and, more
        // importantly, that the destination is untouched afterwards.
        let dir = tempdir();
        let from = dir.join("src.txt");
        let to = dir.join("dst.txt");
        tokio::fs::write(&from, b"source contents").await.unwrap();
        tokio::fs::write(&to, b"existing contents").await.unwrap();

        let refused = host()
            .rename(&from.to_string_lossy(), &to.to_string_lossy())
            .await;
        assert!(
            refused.is_err(),
            "moving onto an existing destination must be refused"
        );
        let message = format!("{:?}", refused.unwrap_err());
        assert!(
            message.contains("already exists"),
            "the refusal must say why: {message}"
        );

        // The whole point: the existing file is intact, not overwritten.
        assert_eq!(
            tokio::fs::read(&to).await.unwrap(),
            b"existing contents",
            "the destination must be untouched by a refused move"
        );
        // And the source is still where it was, because nothing moved.
        assert_eq!(
            tokio::fs::read(&from).await.unwrap(),
            b"source contents",
            "a refused move must leave the source in place"
        );
    }

    #[tokio::test]
    async fn a_rename_to_a_free_name_moves_the_file() {
        let dir = tempdir();
        let from = dir.join("src.txt");
        let to = dir.join("moved.txt");
        tokio::fs::write(&from, b"payload").await.unwrap();

        host()
            .rename(&from.to_string_lossy(), &to.to_string_lossy())
            .await
            .expect("a free destination must move");

        assert_eq!(tokio::fs::read(&to).await.unwrap(), b"payload");
        assert!(
            !from.exists(),
            "a completed move must not leave the source behind"
        );
    }

    /// A scratch directory that removes itself, so a failing assertion cannot leave files behind.
    fn tempdir() -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "hx-local-rename-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn join(&self, name: &str) -> std::path::PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

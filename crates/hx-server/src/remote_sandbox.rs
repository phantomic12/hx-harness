//! The adapter that lets a sandbox profile name a *remote* Docker host.
//!
//! `hx-sandbox`'s [`RemoteSandboxRuntime`] reaches a far daemon through a tiny one-method
//! [`RemoteCommandRunner`] trait, which exists precisely so that `hx-sandbox` need not depend on
//! `hx-remote` (see that module's doc — adding that edge would be a layering inversion, and the
//! one place it is legal to depend on both crates is here, in `hx-server`). This module is that
//! legal seam: a [`HostCommandRunner`] that holds an `Arc<dyn Host>` and implements
//! [`RemoteCommandRunner`] by calling `Host::exec` and copying the output field for field.
//!
//! ## The timeout is this module's decision, and it is deliberate
//!
//! `Host::exec` demands a `Duration`, while the runner trait — and therefore the remote runtime's
//! Docker command builders — supply none. The runtime's operations (`docker create`, `start`, `stop`,
//! `rm`, `exec`) have no natural per-command deadline of their own on the daemon side: a `stop`
//! carries a grace but a wedged *transport* would not care. So this adapter fixes one timeout for
//! every command it forwards: **120 seconds**.
//!
//! Why 120s rather than longer or unbounded: the two long poles are `docker create` (a `pull` of
//! an image not yet on the far host can take a while) and `docker exec` (a build or test run
//! inside the box). Both are well under two minutes for a normal run, and a command that genuinely
//! needs more should be bounded by the *container's* own keep-alive and the caller's explicit outer
//! deadline (the chat path already wraps the whole sandbox `exec` in a `tokio::time::timeout`) —
//! never by letting a single far-host shell hang the daemon's connection indefinitely. A wedged SSH
//! channel that `Host::exec` would otherwise wait on forever must instead turn into a timeout error the
//! reaper and the caller can see, rather than a leak that looks like a running container. The
//! alternative — no timeout, trusting every transport to have its own — was rejected because the runner is
//! deliberately transport-agnostic and cannot rely on that.
//!
//! ## What is deliberately NOT done here
//!
//! - **No container pooling or lifetime policy.** `hx-sandbox`'s [`SandboxManager`] owns the
//!   concurrency cap and the TTL reaper; this adapter is only the transport seam and does not reinvent any
//!   of that. A `HostCommandRunner` is `Clone`-free and stateless besides its `Host`: one is built per
//!   host and shared by the [`SandboxManager`] that shares the host's containers.
//! - **No execution semantics on exit codes.** A non-zero (or `None`) [`ExecOutput`] exit is forwarded
//!   *unchanged* into a [`RemoteCommandOutput`]. Deciding whether a non-zero is a failure is the remote
//!   runtime's job (a `docker` command that exits non-zero *is* a failed remote operation there, while a
//!   command *inside* the container exits non-zero as a legitimate result). The adapter must not blur that:
//!   turning a non-zero transport result into an adapter error here would defeat the remote runtime's own
//!   failure reporting, which distinguishes the two. `duration_ms` is dropped because the runner's output
//!   shape has no field for it; it is the transport's measurement, not the sandbox's.

use async_trait::async_trait;
use hx_remote::Host;
use hx_sandbox::remote::RemoteCommandOutput;
use hx_sandbox::RemoteCommandRunner;
use std::sync::Arc;
use std::time::Duration;

/// How long a single Docker command may take on the far host before the adapter gives up.
///
/// See the module doc for the reasoning. Long enough for a `pull`-driven `create` and a build
/// inside the box, short enough that a wedged transport surfaces as a visible timeout rather than a
/// connection that hangs forever.
const REMOTE_COMMAND_TIMEOUT: Duration = Duration::from_secs(120);

/// A [`RemoteCommandRunner`] backed by an `Arc<dyn Host>`.
///
/// The field-for-field copy the `hx-sandbox` module doc promised: `Host::exec` returns
/// `{stdout, stderr, exit_code, duration_ms}` and the runner's output is
/// `{stdout, stderr, exit_code}`, so this type only drops the transport's own timing measurement.
pub struct HostCommandRunner {
    host: Arc<dyn Host>,
}

impl HostCommandRunner {
    /// Wrap a host so its `exec` can drive a [`RemoteSandboxRuntime`].
    pub fn new(host: Arc<dyn Host>) -> Self {
        Self { host }
    }
}

#[async_trait]
impl RemoteCommandRunner for HostCommandRunner {
    async fn run(&self, command: &str) -> hx_core::error::Result<RemoteCommandOutput> {
        let out = self
            .host
            .exec(command, REMOTE_COMMAND_TIMEOUT)
            .await
            .map_err(|err| {
                hx_core::error::HxError::Sandbox(format!(
                    "remote sandbox transport failed for host {}: {err}",
                    self.host.id()
                ))
            })?;
        Ok(RemoteCommandOutput {
            stdout: out.stdout,
            stderr: out.stderr,
            // Passed through unchanged: whether a non-zero is a *failure* is the remote runtime's
            // decision, not the transport's. See the module doc.
            exit_code: out.exit_code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_tools::testing::FakeHost;

    #[tokio::test]
    async fn the_adapter_copies_stdout_stderr_and_exit_code_across_the_seam() {
        // The whole point of this type: `RemoteSandboxRuntime`'s output shape is exactly what a
        // transport's exec returns, minus `duration_ms`. A field dropped or altered here would be a
        // transport that lies to the remote runtime about what the far host did.
        let host = Arc::new(FakeHost::unix().with_exec_output("built ok\n", "", Some(0)));
        let runner = HostCommandRunner::new(host);

        let out = runner.run("docker info").await.expect("transport succeeds");
        assert_eq!(out.stdout, "built ok\n");
        assert_eq!(out.stderr, "");
        assert_eq!(out.exit_code, Some(0));
    }

    #[tokio::test]
    async fn a_non_zero_exit_is_forwarded_unchanged_not_turned_into_an_adapter_error() {
        // A non-zero exit is a *successful transport* result. `docker` itself exits non-zero to mean
        // "a remote operation failed", and a command *inside* the container exits non-zero as a
        // legitimate result — deciding which is the remote runtime's job, not the transport's. If this
        // adapter returned an `Err` for any non-zero code, the remote runtime could never report a
        // command's real exit status, and every non-zero would read as a transport failure.
        let host = Arc::new(FakeHost::unix().with_exec_output("boom\n", "error line", Some(127)));
        let runner = HostCommandRunner::new(host);

        let out = runner.run("docker exec hx-x sh -c 'false'").await.unwrap();
        assert_eq!(out.stdout, "boom\n");
        assert_eq!(out.stderr, "error line");
        assert_eq!(
            out.exit_code,
            Some(127),
            "127 must pass through, not become an error"
        );
    }

    #[tokio::test]
    async fn an_unknown_exit_code_is_forwarded_as_unknown_not_as_success() {
        // `Host::exec` reports `None` when the transport could not see the exit status (some SSH
        // servers, killed processes). The runner's `None` means the same thing — unknown — and the
        // remote runtime treats it as a failure, not as a success. An adapter that translated `None`
        // to `Some(0)` would turn a machine we could not read into a command that "worked".
        let host = Arc::new(FakeHost::unix().with_exec_output("", "", None));
        let runner = HostCommandRunner::new(host);

        let out = runner.run("docker info").await.unwrap();
        assert_eq!(
            out.exit_code, None,
            "unknown must stay unknown across the seam"
        );
    }
}

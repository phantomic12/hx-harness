//! Sandbox lifecycle: creating, tracking, expiring and reaping.
//!
//! The runtime is abstracted so that the lifecycle logic — the concurrency cap, the TTL reaper,
//! and the guarantee that a half-created sandbox is not left behind — can be tested exhaustively
//! without a container engine. Those are the properties that decide whether a month of agent
//! work leaves forty orphaned containers eating 200 GB of disk.
//!
//! Two invariants this module exists to hold:
//!
//! 1. **No leaks.** If a sandbox fails at any point in its creation sequence, whatever was
//!    created is torn down before the error is returned.
//! 2. **No unbounded growth.** A concurrency cap and a TTL are enforced here, not left to the
//!    caller's discipline.

use crate::spec::SandboxSpec;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use hx_core::error::{HxError, Result};
use hx_core::ids::SandboxId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Where a sandbox is in its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxState {
    Creating,
    Running,
    Stopped,
    /// Reaped by the TTL sweeper.
    Expired,
    Failed,
}

impl SandboxState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            SandboxState::Stopped | SandboxState::Expired | SandboxState::Failed
        )
    }
}

/// A live sandbox.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxHandle {
    pub id: SandboxId,
    pub profile: String,
    /// The engine's own identifier (a container id or name).
    pub runtime_id: String,
    pub state: SandboxState,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub workspace_host_path: String,
    pub workspace_path: String,
    pub isolation: hx_core::config::IsolationLevel,
}

impl SandboxHandle {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    /// How long until the reaper takes it. Negative once past due.
    pub fn remaining(&self, now: DateTime<Utc>) -> Duration {
        self.expires_at - now
    }
}

/// Output of a command run inside a sandbox.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SandboxExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i64,
}

impl SandboxExecOutput {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// A container engine (or a test double).
#[async_trait]
pub trait SandboxRuntime: Send + Sync {
    /// Engine name, for status output.
    fn name(&self) -> &str;

    /// Whether the engine is reachable right now.
    async fn available(&self) -> bool;

    /// Create a container from the spec and return the engine's identifier.
    async fn create(
        &self,
        id: &SandboxId,
        spec: &SandboxSpec,
        settings: &crate::spec::HostSettings,
    ) -> Result<String>;

    async fn start(&self, runtime_id: &str) -> Result<()>;

    async fn stop(&self, runtime_id: &str, grace_secs: i64) -> Result<()>;

    async fn remove(&self, runtime_id: &str) -> Result<()>;

    async fn exec(
        &self,
        runtime_id: &str,
        command: &str,
        workdir: Option<&str>,
    ) -> Result<SandboxExecOutput>;

    /// Stage a tar archive's contents into the sandbox at `path`.
    ///
    /// The default reports unsupported, so backends without a transfer
    /// mechanism compile unchanged and fail honestly at the call site.
    async fn upload(&self, runtime_id: &str, path: &str, _tar: Vec<u8>) -> Result<()> {
        Err(HxError::Sandbox(format!(
            "{runtime_id}: {path}: this sandbox backend does not support upload"
        )))
    }

    /// Fetch `path` from the sandbox as a tar archive.
    ///
    /// The default reports unsupported, so backends without a transfer
    /// mechanism compile unchanged and fail honestly at the call site.
    async fn download(&self, runtime_id: &str, path: &str) -> Result<Vec<u8>> {
        Err(HxError::Sandbox(format!(
            "{runtime_id}: {path}: this sandbox backend does not support download"
        )))
    }
}

/// Owns the set of live sandboxes.
pub struct SandboxManager {
    runtime: Arc<dyn SandboxRuntime>,
    live: Mutex<HashMap<String, SandboxHandle>>,
    max_concurrent: usize,
}

impl SandboxManager {
    pub fn new(runtime: Arc<dyn SandboxRuntime>, max_concurrent: usize) -> Self {
        Self {
            runtime,
            live: Mutex::new(HashMap::new()),
            // A cap of zero would make the manager useless rather than "unlimited", which is
            // never what the operator meant.
            max_concurrent: max_concurrent.max(1),
        }
    }

    pub fn runtime_name(&self) -> &str {
        self.runtime.name()
    }

    pub async fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Create and start a sandbox.
    ///
    /// If any step fails, whatever was created is torn down before returning — a container that
    /// exists but is not tracked is invisible to the reaper and lives forever.
    pub async fn spawn(&self, spec: &SandboxSpec, now: DateTime<Utc>) -> Result<SandboxHandle> {
        spec.validate().map_err(|e| {
            HxError::Sandbox(format!(
                "sandbox profile '{}' is invalid: {e}",
                spec.profile
            ))
        })?;

        let id = SandboxId::new();
        let settings = spec.host_settings();

        let mut live = self.live.lock().await;
        if live.len() >= self.max_concurrent {
            return Err(HxError::Sandbox(format!(
                "refusing to start '{}': {} of {} sandbox slots are in use. Destroy one with \
                 `hx sandbox destroy <id>` or raise sandbox.max_concurrent.",
                spec.profile,
                live.len(),
                self.max_concurrent
            )));
        }

        let runtime_id = self.runtime.create(&id, spec, &settings).await?;

        if let Err(err) = self.runtime.start(&runtime_id).await {
            // Roll back rather than leaving an untracked container behind.
            if let Err(remove_err) = self.runtime.remove(&runtime_id).await {
                // WHY the half-created sandbox is *tracked* here instead of just reported:
                // the container exists on the engine but nothing points at it, which is
                // exactly the invisible leak the reaper exists to prevent. Marking it
                // `Failed` makes the next reap retry the removal (reap sweeps `Failed`
                // handles regardless of TTL), so a transient engine failure cleans up on
                // its own instead of holding disk until someone notices.
                let handle = SandboxHandle {
                    id: id.clone(),
                    profile: spec.profile.clone(),
                    runtime_id,
                    state: SandboxState::Failed,
                    created_at: now,
                    expires_at: now + Duration::seconds(spec.ttl_secs as i64),
                    workspace_host_path: spec.workspace_host_path.clone(),
                    workspace_path: spec.workspace_path.clone(),
                    isolation: spec.isolation,
                };
                live.insert(id.to_string(), handle);
                return Err(HxError::Sandbox(format!(
                    "sandbox failed to launch ({err}), and removing the half-created container \
                     failed as well ({remove_err}); it is still tracked and the reaper will retry \
                     the removal"
                )));
            }
            return Err(HxError::Sandbox(format!(
                "sandbox started but failed to launch ({err}); it has been removed"
            )));
        }

        let handle = SandboxHandle {
            id: id.clone(),
            profile: spec.profile.clone(),
            runtime_id,
            state: SandboxState::Running,
            created_at: now,
            expires_at: now + Duration::seconds(spec.ttl_secs as i64),
            workspace_host_path: spec.workspace_host_path.clone(),
            workspace_path: spec.workspace_path.clone(),
            isolation: spec.isolation,
        };

        live.insert(id.to_string(), handle.clone());
        tracing::info!(
            sandbox = %handle.id,
            profile = %handle.profile,
            runtime = %handle.runtime_id,
            "sandbox started"
        );

        Ok(handle)
    }

    pub async fn get(&self, id: &str) -> Option<SandboxHandle> {
        self.live.lock().await.get(id).cloned()
    }

    pub async fn list(&self) -> Vec<SandboxHandle> {
        let mut all: Vec<SandboxHandle> = self.live.lock().await.values().cloned().collect();
        all.sort_by_key(|a| a.created_at);
        all
    }

    pub async fn exec(
        &self,
        id: &str,
        command: &str,
        workdir: Option<&str>,
    ) -> Result<SandboxExecOutput> {
        let runtime_id = {
            let live = self.live.lock().await;
            let handle = live
                .get(id)
                .ok_or_else(|| HxError::Sandbox(format!("no sandbox with id {id}")))?;
            if handle.state != SandboxState::Running {
                return Err(HxError::Sandbox(format!(
                    "sandbox {id} is {:?}, not running",
                    handle.state
                )));
            }
            handle.runtime_id.clone()
        };

        self.runtime.exec(&runtime_id, command, workdir).await
    }

    /// Stage a tar archive's contents into a running sandbox at `dest_path`.
    pub async fn upload_dir(&self, sandbox_id: &str, dest_path: &str, tar: Vec<u8>) -> Result<()> {
        let runtime_id = {
            let live = self.live.lock().await;
            let handle = live
                .get(sandbox_id)
                .ok_or_else(|| HxError::Sandbox(format!("no sandbox with id {sandbox_id}")))?;
            if handle.state != SandboxState::Running {
                return Err(HxError::Sandbox(format!(
                    "sandbox {sandbox_id} is {:?}, not running",
                    handle.state
                )));
            }
            handle.runtime_id.clone()
        };

        self.runtime.upload(&runtime_id, dest_path, tar).await
    }

    /// Fetch `path` from a running sandbox as a tar archive.
    pub async fn download_file(&self, sandbox_id: &str, path: &str) -> Result<Vec<u8>> {
        let runtime_id = {
            let live = self.live.lock().await;
            let handle = live
                .get(sandbox_id)
                .ok_or_else(|| HxError::Sandbox(format!("no sandbox with id {sandbox_id}")))?;
            if handle.state != SandboxState::Running {
                return Err(HxError::Sandbox(format!(
                    "sandbox {sandbox_id} is {:?}, not running",
                    handle.state
                )));
            }
            handle.runtime_id.clone()
        };

        self.runtime.download(&runtime_id, path).await
    }

    /// Stop and remove a sandbox. Idempotent: destroying something already gone is not an error,
    /// because the caller almost always means "make sure this is not running".
    ///
    /// A sandbox whose engine removal fails stays tracked (marked `Failed`) instead of being
    /// deregistered: once deregistered, nothing points at the container and the reaper can never
    /// retry, so the old "deregister and report" behaviour was a slow leak dressed as cleanup.
    /// Only a successful `remove` deregisters; a `stop` failure with a successful `remove` still
    /// deregisters, because the container is gone and holding its slot would be the leak in the
    /// other direction.
    pub async fn destroy(&self, id: &str) -> Result<()> {
        let handle = self.live.lock().await.remove(id);

        let Some(handle) = handle else {
            return Ok(());
        };

        let mut errors = Vec::new();
        if let Err(err) = self.runtime.stop(&handle.runtime_id, 10).await {
            errors.push(format!("stop: {err}"));
        }
        if let Err(err) = self.runtime.remove(&handle.runtime_id).await {
            errors.push(format!("remove: {err}"));
            // WHY reinsert rather than return the error: the container still exists on the
            // engine, and this map is the only thing that can find it again. Marking it
            // `Failed` keeps `exec` away (it only runs `Running` sandboxes) while making
            // the next reap retry the removal — reap sweeps `Failed` handles regardless
            // of TTL, so a transient engine failure resolves itself within one interval
            // instead of holding a slot and disk until the TTL happens to expire.
            let mut handle = handle;
            handle.state = SandboxState::Failed;
            self.live.lock().await.insert(id.to_string(), handle);
            return Err(HxError::Sandbox(format!(
                "sandbox {id} could not be removed from the engine ({}); it is still tracked \
                 and the reaper will retry the removal",
                errors.join("; ")
            )));
        }

        if errors.is_empty() {
            tracing::info!(sandbox = %id, "sandbox destroyed");
            Ok(())
        } else {
            Err(HxError::Sandbox(format!(
                "sandbox {id} was deregistered but the engine reported: {}",
                errors.join("; ")
            )))
        }
    }

    /// Reap sandboxes past their TTL, returning the ids that were removed.
    ///
    /// `Failed` handles are swept regardless of TTL: they are sandboxes a previous
    /// `destroy` (or a failed `spawn` rollback) could not remove from the engine, and
    /// waiting for a TTL that may be hours away before retrying would leave the
    /// container — and its slot — held for no reason.
    pub async fn reap(&self, now: DateTime<Utc>) -> Result<Vec<SandboxId>> {
        let expired: Vec<(String, SandboxId)> = {
            let live = self.live.lock().await;
            live.values()
                .filter(|h| h.is_expired(now) || h.state == SandboxState::Failed)
                .map(|h| (h.id.to_string(), h.id.clone()))
                .collect()
        };

        let mut reaped = Vec::new();
        for (key, id) in expired {
            match self.destroy(&key).await {
                Ok(()) => {
                    tracing::info!(sandbox = %id, "reaped expired sandbox");
                    reaped.push(id);
                }
                Err(err) => {
                    tracing::warn!(sandbox = %id, error = %err, "could not reap sandbox");
                }
            }
        }

        Ok(reaped)
    }

    /// How many slots are free.
    pub async fn free_slots(&self) -> usize {
        self.max_concurrent
            .saturating_sub(self.live.lock().await.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{HostSettings, SandboxSpec};
    use hx_core::config::IsolationLevel;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Records everything it was asked to do, and can be told to fail at a chosen step.
    #[derive(Default)]
    struct FakeRuntime {
        created: Mutex<Vec<String>>,
        started: Mutex<Vec<String>>,
        stopped: Mutex<Vec<String>>,
        removed: Mutex<Vec<String>>,
        uploaded: Mutex<Vec<(String, String, Vec<u8>)>>,
        downloaded: Mutex<Vec<(String, String)>>,
        /// Bytes `download` hands back, so a round-trip test can assert them.
        download_bytes: Mutex<Vec<u8>>,
        fail_start: bool,
        fail_create: bool,
        fail_stop: bool,
        // WHY atomic rather than a plain bool: a retry test flips the engine from failing to
        // healthy *between* a failed destroy and the reaping retry, while the manager holds
        // only a shared reference. A `Mutex<bool>` would do, but the atomic never blocks.
        fail_remove: AtomicBool,
        counter: AtomicUsize,
    }

    impl FakeRuntime {
        fn new() -> Self {
            Self::default()
        }

        fn failing_at_start() -> Self {
            Self {
                fail_start: true,
                ..Default::default()
            }
        }

        fn failing_at_create() -> Self {
            Self {
                fail_create: true,
                ..Default::default()
            }
        }
    }

    #[async_trait]
    impl SandboxRuntime for FakeRuntime {
        fn name(&self) -> &str {
            "fake"
        }

        async fn available(&self) -> bool {
            true
        }

        async fn create(
            &self,
            _id: &SandboxId,
            _spec: &SandboxSpec,
            _settings: &HostSettings,
        ) -> Result<String> {
            if self.fail_create {
                return Err(HxError::Sandbox("engine refused".into()));
            }
            let n = self.counter.fetch_add(1, Ordering::SeqCst);
            let name = format!("hx-fake-{n}");
            self.created.lock().await.push(name.clone());
            Ok(name)
        }

        async fn start(&self, runtime_id: &str) -> Result<()> {
            if self.fail_start {
                return Err(HxError::Sandbox("image not found".into()));
            }
            self.started.lock().await.push(runtime_id.to_string());
            Ok(())
        }

        async fn stop(&self, runtime_id: &str, _grace_secs: i64) -> Result<()> {
            if self.fail_stop {
                return Err(HxError::Sandbox("stop failed".into()));
            }
            self.stopped.lock().await.push(runtime_id.to_string());
            Ok(())
        }

        async fn remove(&self, runtime_id: &str) -> Result<()> {
            if self.fail_remove.load(Ordering::SeqCst) {
                return Err(HxError::Sandbox("remove failed".into()));
            }
            self.removed.lock().await.push(runtime_id.to_string());
            Ok(())
        }

        async fn exec(
            &self,
            _runtime_id: &str,
            command: &str,
            _workdir: Option<&str>,
        ) -> Result<SandboxExecOutput> {
            Ok(SandboxExecOutput {
                stdout: format!("ran: {command}"),
                stderr: String::new(),
                exit_code: 0,
            })
        }

        async fn upload(&self, runtime_id: &str, path: &str, tar: Vec<u8>) -> Result<()> {
            self.uploaded.lock().await.push((
                runtime_id.to_string(),
                path.to_string(),
                tar.clone(),
            ));
            // What `download` hands back next: the fake stores rather than
            // synthesizing, so a round-trip test asserts the stored bytes.
            *self.download_bytes.lock().await = tar;
            Ok(())
        }

        async fn download(&self, runtime_id: &str, path: &str) -> Result<Vec<u8>> {
            self.downloaded
                .lock()
                .await
                .push((runtime_id.to_string(), path.to_string()));
            Ok(self.download_bytes.lock().await.clone())
        }
    }

    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn spec(ttl_secs: u64) -> SandboxSpec {
        SandboxSpec {
            profile: "dev".into(),
            image: "ubuntu:24.04".into(),
            isolation: IsolationLevel::L2,
            cpus: 2.0,
            memory_mb: 4096,
            pids_max: 1024,
            workspace_mb: 8192,
            ttl_secs,
            egress_allow: Vec::new(),
            network: false,
            readonly_rootfs: true,
            workspace_host_path: "/tmp/hx/ws".into(),
            workspace_path: "/workspace".into(),
            user: None,
            env: Vec::new(),
            runtime: None,
        }
    }

    fn manager_with(runtime: Arc<FakeRuntime>, cap: usize) -> SandboxManager {
        SandboxManager::new(runtime, cap)
    }

    #[tokio::test]
    async fn spawning_creates_starts_and_tracks_a_sandbox() {
        let runtime = Arc::new(FakeRuntime::new());
        let manager = manager_with(runtime.clone(), 4);

        let handle = manager.spawn(&spec(3600), t0()).await.unwrap();

        assert_eq!(handle.state, SandboxState::Running);
        assert_eq!(handle.profile, "dev");
        assert_eq!(runtime.created.lock().await.len(), 1);
        assert_eq!(runtime.started.lock().await.len(), 1);
        assert_eq!(manager.list().await.len(), 1);
        assert_eq!(manager.get(handle.id.as_str()).await.unwrap().id, handle.id);
    }

    #[tokio::test]
    async fn the_ttl_is_derived_from_the_spec() {
        let manager = manager_with(Arc::new(FakeRuntime::new()), 4);
        let handle = manager.spawn(&spec(600), t0()).await.unwrap();
        assert_eq!(handle.expires_at, t0() + Duration::seconds(600));
        assert!(!handle.is_expired(t0() + Duration::seconds(599)));
        assert!(handle.is_expired(t0() + Duration::seconds(600)));
    }

    #[tokio::test]
    async fn a_failed_start_removes_the_container_it_created() {
        // The leak-prevention invariant. A container that exists but is not tracked is
        // invisible to the reaper, so it would live until someone noticed the disk fill.
        let runtime = Arc::new(FakeRuntime::failing_at_start());
        let manager = manager_with(runtime.clone(), 4);

        let err = manager.spawn(&spec(3600), t0()).await.unwrap_err();
        assert!(err.to_string().contains("has been removed"), "{err}");

        assert_eq!(runtime.created.lock().await.len(), 1, "it did create one");
        assert_eq!(
            runtime.removed.lock().await.len(),
            1,
            "and it must have cleaned it up"
        );
        assert!(
            manager.list().await.is_empty(),
            "nothing should be tracked as live"
        );
    }

    #[tokio::test]
    async fn a_failed_create_rolls_back_nothing_and_tracks_nothing() {
        let runtime = Arc::new(FakeRuntime::failing_at_create());
        let manager = manager_with(runtime.clone(), 4);

        assert!(manager.spawn(&spec(3600), t0()).await.is_err());
        assert!(
            runtime.removed.lock().await.is_empty(),
            "there was nothing to remove"
        );
        assert!(manager.list().await.is_empty());
    }

    #[tokio::test]
    async fn an_invalid_spec_is_refused_before_the_engine_is_touched() {
        let runtime = Arc::new(FakeRuntime::new());
        let manager = manager_with(runtime.clone(), 4);

        let mut bad = spec(3600);
        bad.image = String::new();

        let err = manager.spawn(&bad, t0()).await.unwrap_err();
        assert!(err.to_string().contains("invalid"), "{err}");
        assert!(
            runtime.created.lock().await.is_empty(),
            "validation must happen before any engine call"
        );
    }

    #[tokio::test]
    async fn the_concurrency_cap_is_enforced_with_an_actionable_message() {
        let runtime = Arc::new(FakeRuntime::new());
        let manager = manager_with(runtime.clone(), 2);

        manager.spawn(&spec(3600), t0()).await.unwrap();
        manager.spawn(&spec(3600), t0()).await.unwrap();

        let err = manager.spawn(&spec(3600), t0()).await.unwrap_err();
        let message = err.to_string();
        assert!(message.contains("2 of 2"), "{message}");
        assert!(
            message.contains("sandbox destroy") || message.contains("max_concurrent"),
            "the error must say how to fix it: {message}"
        );
        assert_eq!(runtime.created.lock().await.len(), 2, "the third never ran");
    }

    #[tokio::test]
    async fn a_cap_of_zero_is_clamped_to_one_rather_than_being_unlimited() {
        let manager = manager_with(Arc::new(FakeRuntime::new()), 0);
        assert_eq!(manager.max_concurrent().await, 1);
        manager.spawn(&spec(3600), t0()).await.unwrap();
        assert!(manager.spawn(&spec(3600), t0()).await.is_err());
    }

    #[tokio::test]
    async fn freeing_a_slot_allows_another_sandbox() {
        let manager = manager_with(Arc::new(FakeRuntime::new()), 1);
        let first = manager.spawn(&spec(3600), t0()).await.unwrap();
        assert!(manager.spawn(&spec(3600), t0()).await.is_err());

        manager.destroy(first.id.as_str()).await.unwrap();
        assert_eq!(manager.free_slots().await, 1);
        assert!(manager.spawn(&spec(3600), t0()).await.is_ok());
    }

    #[tokio::test]
    async fn reaping_removes_only_expired_sandboxes() {
        let runtime = Arc::new(FakeRuntime::new());
        let manager = manager_with(runtime.clone(), 4);

        let short = manager.spawn(&spec(60), t0()).await.unwrap();
        let long = manager.spawn(&spec(86_400), t0()).await.unwrap();

        let reaped = manager.reap(t0() + Duration::seconds(120)).await.unwrap();

        assert_eq!(reaped, vec![short.id.clone()]);
        assert!(manager.get(short.id.as_str()).await.is_none());
        assert!(
            manager.get(long.id.as_str()).await.is_some(),
            "a live sandbox must survive the sweeper"
        );
        assert_eq!(runtime.stopped.lock().await.len(), 1);
        assert_eq!(runtime.removed.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn reaping_nothing_is_not_an_error() {
        let manager = manager_with(Arc::new(FakeRuntime::new()), 4);
        manager.spawn(&spec(86_400), t0()).await.unwrap();
        assert!(manager.reap(t0()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn destroying_an_unknown_sandbox_is_idempotent() {
        // Callers overwhelmingly mean "make sure this is gone", so a second destroy must not
        // fail a cleanup path.
        let manager = manager_with(Arc::new(FakeRuntime::new()), 4);
        manager.destroy("sbx_does_not_exist").await.unwrap();
    }

    #[tokio::test]
    async fn a_destroy_that_fails_at_the_engine_still_deregisters() {
        // Otherwise the slot is held forever by an entry the reaper will never expire early.
        let runtime = Arc::new(FakeRuntime {
            fail_stop: true,
            ..Default::default()
        });
        let manager = manager_with(runtime, 1);
        let handle = manager.spawn(&spec(3600), t0()).await.unwrap();

        let err = manager.destroy(handle.id.as_str()).await.unwrap_err();
        assert!(err.to_string().contains("deregistered"), "{err}");
        assert_eq!(manager.free_slots().await, 1, "the slot must be released");
    }

    #[tokio::test]
    async fn a_destroy_whose_removal_fails_stays_tracked_until_removal_succeeds() {
        // The leak-prevention invariant for teardown: a container the engine would not
        // remove still exists, so deregistering it would make it invisible to the reaper
        // forever. It must stay tracked (and hold its slot, which is honest — the
        // container is still there) until a retry removes it.
        let runtime = Arc::new(FakeRuntime::default());
        runtime.fail_remove.store(true, Ordering::SeqCst);
        let manager = manager_with(runtime.clone(), 1);
        let handle = manager.spawn(&spec(3600), t0()).await.unwrap();

        let err = manager.destroy(handle.id.as_str()).await.unwrap_err();
        assert!(err.to_string().contains("still tracked"), "{err}");
        assert!(
            manager.get(handle.id.as_str()).await.is_some(),
            "the sandbox must still be tracked so the reaper can retry"
        );
        assert_eq!(
            manager.free_slots().await,
            0,
            "the slot is still occupied by a container that still exists"
        );

        // The engine recovers; the next reap retries the removal and frees the slot,
        // without waiting for the TTL.
        runtime.fail_remove.store(false, Ordering::SeqCst);
        let reaped = manager.reap(t0()).await.unwrap();
        assert_eq!(reaped, vec![handle.id.clone()]);
        assert_eq!(manager.free_slots().await, 1);
    }

    #[tokio::test]
    async fn a_failed_start_whose_rollback_fails_stays_tracked_for_the_reaper() {
        // Same invariant on the creation path: `start` failed, and the rollback `remove`
        // failed too, so the container exists but was never tracked. Reporting "has been
        // removed" would be a lie; track it as `Failed` so the reaper retries.
        let runtime = Arc::new(FakeRuntime {
            fail_start: true,
            ..Default::default()
        });
        runtime.fail_remove.store(true, Ordering::SeqCst);
        let manager = manager_with(runtime.clone(), 4);

        let err = manager.spawn(&spec(3600), t0()).await.unwrap_err();
        assert!(err.to_string().contains("still tracked"), "{err}");
        assert_eq!(
            manager.list().await.len(),
            1,
            "the half-created sandbox must be tracked"
        );
        assert_eq!(
            manager.list().await[0].state,
            SandboxState::Failed,
            "marked Failed so exec refuses it while the reaper retries it"
        );

        runtime.fail_remove.store(false, Ordering::SeqCst);
        assert_eq!(manager.reap(t0()).await.unwrap().len(), 1);
        assert!(manager.list().await.is_empty());
    }

    #[tokio::test]
    async fn exec_passes_through_to_the_runtime() {
        let manager = manager_with(Arc::new(FakeRuntime::new()), 4);
        let handle = manager.spawn(&spec(3600), t0()).await.unwrap();

        let out = manager
            .exec(handle.id.as_str(), "cargo test", None)
            .await
            .unwrap();
        assert!(out.success());
        assert_eq!(out.stdout, "ran: cargo test");
    }

    #[tokio::test]
    async fn exec_on_an_unknown_sandbox_is_a_clear_error() {
        let manager = manager_with(Arc::new(FakeRuntime::new()), 4);
        let err = manager.exec("sbx_nope", "ls", None).await.unwrap_err();
        assert!(err.to_string().contains("no sandbox with id"), "{err}");
    }

    #[tokio::test]
    async fn upload_dir_on_an_unknown_sandbox_matches_the_exec_error() {
        let manager = manager_with(Arc::new(FakeRuntime::new()), 4);
        let exec_err = manager.exec("sbx_nope", "ls", None).await.unwrap_err();
        let upload_err = manager
            .upload_dir("sbx_nope", "/workspace", vec![1, 2, 3])
            .await
            .unwrap_err();
        assert!(
            upload_err.to_string().contains("no sandbox with id"),
            "{upload_err}"
        );
        // Same class of error: both resolve through the same live-handle lookup.
        assert_eq!(
            std::mem::discriminant(&exec_err),
            std::mem::discriminant(&upload_err)
        );
    }

    #[tokio::test]
    async fn download_file_on_an_unknown_sandbox_is_a_clear_error() {
        let manager = manager_with(Arc::new(FakeRuntime::new()), 4);
        let err = manager
            .download_file("sbx_nope", "/workspace/out")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no sandbox with id"), "{err}");
    }

    #[tokio::test]
    async fn upload_dir_reaches_the_runtime_with_the_runtime_id_and_bytes() {
        let runtime = Arc::new(FakeRuntime::new());
        let manager = manager_with(runtime.clone(), 4);
        let handle = manager.spawn(&spec(3600), t0()).await.unwrap();

        let tar = vec![7u8, 8, 9, 10];
        manager
            .upload_dir(handle.id.as_str(), "/workspace", tar.clone())
            .await
            .unwrap();

        let uploaded = runtime.uploaded.lock().await;
        assert_eq!(uploaded.len(), 1);
        assert_eq!(uploaded[0].0, handle.runtime_id);
        assert_eq!(uploaded[0].1, "/workspace");
        assert_eq!(uploaded[0].2, tar);
    }

    #[tokio::test]
    async fn download_file_round_trips_the_bytes_the_fake_recorded() {
        let runtime = Arc::new(FakeRuntime::new());
        let manager = manager_with(runtime.clone(), 4);
        let handle = manager.spawn(&spec(3600), t0()).await.unwrap();

        // The fake stores whatever `upload` received and hands it back from
        // `download`, so staging then pulling round-trips the exact bytes.
        let tar = vec![42u8, 1, 2, 3, 4];
        manager
            .upload_dir(handle.id.as_str(), "/workspace", tar.clone())
            .await
            .unwrap();

        let got = manager
            .download_file(handle.id.as_str(), "/workspace/out.tar")
            .await
            .unwrap();
        assert_eq!(got, tar);

        let downloaded = runtime.downloaded.lock().await;
        assert_eq!(downloaded.len(), 1);
        assert_eq!(downloaded[0].0, handle.runtime_id);
        assert_eq!(downloaded[0].1, "/workspace/out.tar");
    }

    #[tokio::test]
    async fn listing_is_ordered_by_creation() {
        let manager = manager_with(Arc::new(FakeRuntime::new()), 4);
        let a = manager.spawn(&spec(3600), t0()).await.unwrap();
        let b = manager
            .spawn(&spec(3600), t0() + Duration::seconds(10))
            .await
            .unwrap();

        let listed = manager.list().await;
        assert_eq!(listed[0].id, a.id);
        assert_eq!(listed[1].id, b.id);
    }
}

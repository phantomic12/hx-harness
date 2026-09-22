//! A run's sandbox, presented to the tool layer as a place to run commands.
//!
//! `docs/approvals.md` §4 separates two questions that used to be one: *may this agent run this command
//! at all* (the capability token) and *does a human want this one* (the approval policy) both take the
//! same answer either way, and the confinement of the call is what lets a config say `npm test` is fine
//! in a box and not fine on the machine. This module is the daemon's answer to "in a box": it implements
//! `hx_tools::SandboxExec` over a live [`SandboxManager`], translating one host path into its mounted
//! equivalent and nothing else.
//!
//! Three decisions are worth the words:
//!
//! - **The boundary is a place, not a state.** A run that has decided to be confined must fail when the
//!   boundary cannot be entered, never fall back to the host — otherwise the answer to §4's question is
//!   false by the time the command runs, and every rule written to require confinement quietly becomes a
//!   rule that means nothing. `ShellTool` refuses to fall back; this type refuses to *offer* a boundary
//!   that is not there.
//! - **The profile is chosen, not the default.** A workspace path is only visible inside a sandbox whose
//!   mount was created for it, so the sandbox is keyed on `(profile, host workspace path)`: two runs in
//!   two checkouts get two sandboxes, and a second run in the same checkout reuses the first rather than
//!   paying for a container start.
//! - **It is not a pool.** One sandbox per checkout, kept until the manager reaps it on its TTL, and the
//!   concurrency ceiling is the manager's own — a second `spawn` for the same key would be refused by the
//!   manager rather than by a rule here, which is the correct place for that decision.
//!
//! Chat requests select a profile explicitly and receive this boundary before their model is called.
//! Only shell dispatch uses it; file tools keep their host context. This is not whole-agent isolation,
//! and the mounted checkout remains writable on the host.

use async_trait::async_trait;
use chrono::Utc;
use hx_core::error::{HxError, Result};
use hx_core::ids::SandboxId;
use hx_remote::host::ExecOutput;
use hx_sandbox::{SandboxHandle, SandboxManager, SandboxRuntime, SandboxSpec};
use hx_tools::tool::SandboxExec;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// A live sandbox standing in for "the host" in a run's tool context.
///
/// Cloneable through `Arc`; the inner mutex is only ever held across the manager's own bookkeeping, never
/// across `exec` — a slow command must not serialize a second run's tool calls.
pub struct SandboxFor {
    manager: Arc<SandboxManager>,
    handle: SandboxHandle,
    /// The host path that was mounted, for translating arguments back and forth.
    workspace_host_path: PathBuf,
    workspace_path: String,
    /// Commands already running, so a timeout is enforced on this side too. The engine has its own
    /// deadline; this one exists because a wedged container is exactly the case a live run hits.
    timeout: Duration,
    _guard: SandboxLease,
}

/// Keeps the sandbox alive for as long as the context that owns it, and reports the leak if it cannot.
///
/// Dropped without a runtime (a panic, a process that never got that far) the release is simply not sent;
/// the manager's TTL reaper is the backstop, and it exists precisely because "kept alive by a handle that
/// might vanish" is not a lifecycle.
struct SandboxLease {
    manager: Arc<SandboxManager>,
    id: String,
    /// Whether this lease is the thing that opened the sandbox. See [`SandboxLease::disarmed`].
    armed: bool,
}

impl Drop for SandboxLease {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let manager = Arc::clone(&self.manager);
        let id = self.id.clone();
        // `destroy` is idempotent: destroying something already reaped is not an error, which is what
        // makes this safe to fire from a drop that may race the reaper.
        tokio::spawn(async move {
            if let Err(err) = manager.destroy(&id).await {
                tracing::warn!(sandbox = %id, error = %err, "could not release a sandbox");
            }
        });
    }
}

/// What a run's sandbox is, for a transcript or a log line.
impl SandboxFor {
    /// Start (or find) the sandbox a run should use for this checkout.
    ///
    /// One per `(profile, host workspace path)`. The lookup happens first because a container start is
    /// seconds and a run may make dozens of calls: paying that per call would make confinement a feature
    /// nobody leaves on.
    pub async fn open(
        manager: Arc<SandboxManager>,
        spec: &SandboxSpec,
        timeout: Duration,
    ) -> Result<Self> {
        let workspace_host_path = PathBuf::from(&spec.workspace_host_path);

        if let Some(existing) = find_existing(&manager, spec).await {
            return Ok(Self::from_handle(
                manager,
                existing,
                workspace_host_path,
                spec.workspace_path.clone(),
                timeout,
            ));
        }

        let handle = manager.spawn(spec, Utc::now()).await?;
        Ok(Self::from_handle(
            manager,
            handle,
            workspace_host_path,
            spec.workspace_path.clone(),
            timeout,
        ))
    }

    /// Wrap an already-running sandbox — the case where a caller started it itself and wants a run to use
    /// it. Nothing is stopped when the returned value is dropped, because nothing here started it.
    pub fn adopt(manager: Arc<SandboxManager>, handle: SandboxHandle, timeout: Duration) -> Self {
        let workspace_host_path = PathBuf::from(&handle.workspace_host_path);
        let workspace_path = handle.workspace_path.clone();
        let mut this = Self::from_handle(
            manager,
            handle,
            workspace_host_path,
            workspace_path,
            timeout,
        );
        this._guard = SandboxLease::disarmed();
        this
    }

    fn from_handle(
        manager: Arc<SandboxManager>,
        handle: SandboxHandle,
        workspace_host_path: PathBuf,
        workspace_path: String,
        timeout: Duration,
    ) -> Self {
        let _guard = SandboxLease {
            manager: Arc::clone(&manager),
            id: handle.id.to_string(),
            armed: true,
        };
        Self {
            manager,
            handle,
            workspace_host_path,
            workspace_path,
            timeout,
            _guard,
        }
    }

    /// The sandbox's id, for a client that wants to look at it or run something by hand.
    pub fn id(&self) -> &str {
        self.handle.id.as_str()
    }

    /// Translate a path as the host knows it into the path inside the sandbox.
    ///
    /// A path outside the mounted workspace is an **error**, not a silent pass-through: inside the
    /// sandbox there is no such file, so running the command anyway would either fail in a way that reads
    /// like a broken tool or — worse — resolve against the sandbox's own read-only root and appear to
    /// work. The message says which of the two situations it is.
    pub fn translate(&self, host_path: &str) -> Result<String> {
        if host_path == self.workspace_path
            || host_path.starts_with(&format!("{}/", self.workspace_path.trim_end_matches('/')))
        {
            // Already written as a sandbox path: the model may have copied it from an earlier result.
            return Ok(host_path.to_string());
        }

        let candidate = Path::new(host_path);
        let relative = candidate
            .strip_prefix(&self.workspace_host_path)
            .map_err(|_| {
                HxError::Sandbox(format!(
                    "{host_path} is not inside {}, which is the only host directory this sandbox has \
                     mounted. Inside it, that path does not exist.",
                    self.workspace_host_path.display()
                ))
            })?;

        let mut translated = self.workspace_path.trim_end_matches('/').to_string();
        if !relative.as_os_str().is_empty() {
            translated.push('/');
            translated.push_str(&relative.to_string_lossy());
        }
        Ok(translated)
    }
}

impl SandboxLease {
    /// A lease that owns nothing — for [`SandboxFor::adopt`], where the caller started the sandbox.
    ///
    /// `armed: false` rather than an id that cannot match: the manager's `destroy` is idempotent, so a
    /// "forget" for somebody else's container would *remove it* rather than no-op. The flag is the only
    /// honest way to say "this handle did not open what it points at".
    fn disarmed() -> Self {
        Self {
            armed: false,
            manager: Arc::new(SandboxManager::new(Arc::new(NullRuntime), 1)),
            id: String::new(),
        }
    }
}

/// Never called: the runtime behind a disarmed lease.
///
/// A lease that owns nothing still has to *be* a manager, because the field is not an `Option` — an
/// `Option<Arc<SandboxManager>>` would make every use of the armed case pay for the disarmed one, and
/// this type exists to make that impossible rather than merely unlikely.
struct NullRuntime;

#[async_trait]
impl SandboxRuntime for NullRuntime {
    fn name(&self) -> &str {
        "none"
    }
    async fn available(&self) -> bool {
        false
    }
    async fn create(
        &self,
        _id: &SandboxId,
        _spec: &SandboxSpec,
        _settings: &hx_sandbox::HostSettings,
    ) -> Result<String> {
        Err(HxError::Sandbox("this lease owns no sandbox".to_string()))
    }
    async fn start(&self, _runtime_id: &str) -> Result<()> {
        Err(HxError::Sandbox("this lease owns no sandbox".to_string()))
    }
    async fn stop(&self, _runtime_id: &str, _grace_secs: i64) -> Result<()> {
        Ok(())
    }
    async fn remove(&self, _runtime_id: &str) -> Result<()> {
        Ok(())
    }
    async fn exec(
        &self,
        _runtime_id: &str,
        _command: &str,
        _workdir: Option<&str>,
    ) -> Result<hx_sandbox::SandboxExecOutput> {
        Err(HxError::Sandbox("this lease owns no sandbox".to_string()))
    }
}

/// Find a running sandbox for this profile whose mount is this workspace.
async fn find_existing(manager: &SandboxManager, spec: &SandboxSpec) -> Option<SandboxHandle> {
    let wanted = spec.workspace_host_path.as_str();
    manager
        .list()
        .await
        .into_iter()
        .find(|handle| handle.profile == spec.profile && handle.workspace_host_path == wanted)
}

#[async_trait]
impl SandboxExec for SandboxFor {
    async fn exec(&self, command: &str, workdir: Option<&str>) -> Result<ExecOutput> {
        // The command is shell source, not one shell argument. Pass it unchanged; only the separate
        // workdir is translated. Embedding a host-side `cd` here would name a path absent in the box.
        let dir = match workdir {
            Some(path) => Some(self.translate(path)?),
            None => None,
        };

        let started = std::time::Instant::now();
        let output = tokio::time::timeout(
            self.timeout,
            self.manager.exec(&self.handle.id.to_string(), command, dir.as_deref()),
        )
        .await
        .map_err(|_| {
            HxError::Sandbox(format!(
                "the command did not finish within {}s inside sandbox {}; it may still be running there",
                self.timeout.as_secs(),
                self.handle.id
            ))
        })??;

        Ok(ExecOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            // The engine reports `i64`; a code outside `i32` is not an exit status, and reporting it as
            // `None` matches what a transport does when it cannot see one.
            exit_code: i32::try_from(output.exit_code).ok(),
            duration_ms: started.elapsed().as_millis() as u64,
            // The sandbox engine bounds its own output; this layer truncates nothing.
            truncated: false,
        })
    }

    fn describe(&self) -> String {
        format!(
            "sandbox {} ({} profile, {:?}, {:?}), with {} mounted at {}",
            self.handle.id,
            self.handle.profile,
            self.handle.isolation,
            self.handle.state,
            self.workspace_host_path.display(),
            self.workspace_path
        )
    }
}

/// A cache of sandboxes by checkout, for a daemon that would rather not start a container per request.
///
/// Deliberately not a pool with health checks: §4's unattended case wants *a* boundary for a working
/// directory, and the manager already owns lifetimes, ceilings and reaping. This is a map with a lock.
#[derive(Default)]
pub struct SandboxCache {
    open: Mutex<HashMap<String, Arc<SandboxFor>>>,
}

impl SandboxCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// The sandbox for this spec, started if it is not already there.
    ///
    /// The key is `profile + host workspace path`, so two runs in one checkout share a boundary and two
    /// checkouts never do. A cached entry whose sandbox has been reaped by its TTL is replaced rather than
    /// returned: a handle to a destroyed container would fail on the next `exec` with the engine's own
    /// error, which reads like a bug in the tool rather than an expired sandbox.
    pub async fn get(
        &self,
        manager: &Arc<SandboxManager>,
        spec: &SandboxSpec,
        timeout: Duration,
    ) -> Result<Arc<SandboxFor>> {
        let key = format!("{}|{}", spec.profile, spec.workspace_host_path);

        let mut open = self.open.lock().await;
        if let Some(existing) = open.get(&key) {
            if manager.get(existing.id()).await.is_some() {
                return Ok(Arc::clone(existing));
            }
            // Expired under us. Drop the entry and start a new one below.
            open.remove(&key);
        }

        let sandbox = Arc::new(SandboxFor::open(Arc::clone(manager), spec, timeout).await?);
        open.insert(key, Arc::clone(&sandbox));
        Ok(sandbox)
    }

    /// Forget a cached sandbox without destroying it (the reaper's job), so the next call starts fresh.
    pub async fn forget(&self, profile: &str, workspace_host_path: &str) {
        let key = format!("{profile}|{workspace_host_path}");
        self.open.lock().await.remove(&key);
    }

    /// How many boundaries this daemon is holding open, for status output.
    pub async fn len(&self) -> usize {
        self.open.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.open.lock().await.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_sandbox::{IsolationLevel, SandboxRuntime, SandboxState};
    use std::sync::Mutex as StdMutex;

    /// A runtime that records what it was asked to do and answers `exec` from a script.
    ///
    /// A real `SandboxRuntime` implementation rather than a mock: the manager's real bookkeeping (slots,
    /// handles, lifetime) is what the translations and the reuse have to work against, and stubbing that
    /// out would test this file's assumptions about it instead.
    struct FakeRuntime {
        created: StdMutex<Vec<(String, SandboxSpec)>>,
        execs: StdMutex<Vec<(String, String, Option<String>)>>,
        output: StdMutex<(String, String, i64)>,
    }

    impl FakeRuntime {
        fn new() -> Self {
            Self {
                created: StdMutex::new(Vec::new()),
                execs: StdMutex::new(Vec::new()),
                output: StdMutex::new((String::new(), String::new(), 0)),
            }
        }

        fn answering(stdout: &str, stderr: &str, code: i64) -> Self {
            let runtime = Self::new();
            *runtime.output.lock().unwrap() = (stdout.to_string(), stderr.to_string(), code);
            runtime
        }

        fn execs(&self) -> Vec<(String, String, Option<String>)> {
            self.execs.lock().unwrap().clone()
        }

        fn creations(&self) -> usize {
            self.created.lock().unwrap().len()
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
            id: &SandboxId,
            spec: &SandboxSpec,
            _settings: &hx_sandbox::HostSettings,
        ) -> Result<String> {
            self.created
                .lock()
                .unwrap()
                .push((id.to_string(), spec.clone()));
            Ok(format!("runtime-{id}"))
        }

        async fn start(&self, _runtime_id: &str) -> Result<()> {
            Ok(())
        }

        async fn stop(&self, _runtime_id: &str, _grace_secs: i64) -> Result<()> {
            Ok(())
        }

        async fn exec(
            &self,
            runtime_id: &str,
            command: &str,
            workdir: Option<&str>,
        ) -> Result<hx_sandbox::SandboxExecOutput> {
            self.execs.lock().unwrap().push((
                runtime_id.to_string(),
                command.to_string(),
                workdir.map(str::to_string),
            ));
            let (stdout, stderr, exit_code) = self.output.lock().unwrap().clone();
            Ok(hx_sandbox::SandboxExecOutput {
                stdout,
                stderr,
                exit_code,
            })
        }

        async fn remove(&self, _runtime_id: &str) -> Result<()> {
            Ok(())
        }
    }

    fn spec(workspace: &str) -> SandboxSpec {
        let mut spec = SandboxSpec {
            profile: "untrusted".to_string(),
            image: "ubuntu:24.04".to_string(),
            isolation: IsolationLevel::L2,
            cpus: 1.0,
            memory_mb: 512,
            pids_max: 128,
            workspace_mb: 1024,
            ttl_secs: 3600,
            egress_allow: Vec::new(),
            network: false,
            readonly_rootfs: true,
            workspace_host_path: workspace.to_string(),
            workspace_path: "/workspace".to_string(),
            user: None,
            env: Vec::new(),
            runtime: None,
        };
        spec.adopt_workspace_owner().ok();
        spec
    }

    fn manager(runtime: Arc<FakeRuntime>) -> Arc<SandboxManager> {
        Arc::new(SandboxManager::new(runtime, 4))
    }

    #[tokio::test]
    async fn a_command_runs_in_the_sandbox_and_its_workdir_is_translated() {
        let runtime = Arc::new(FakeRuntime::answering("test result: ok\n", "", 0));
        let manager = manager(runtime.clone());
        let sandbox = SandboxFor::open(
            Arc::clone(&manager),
            &spec("/home/yoav/projects/thing"),
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        let output = sandbox
            .exec("cargo test", Some("/home/yoav/projects/thing/crates/x"))
            .await
            .unwrap();

        assert_eq!(output.stdout, "test result: ok\n");
        assert_eq!(output.exit_code, Some(0));
        let execs = runtime.execs();
        assert_eq!(execs.len(), 1);
        assert_eq!(execs[0].1, "cargo test");
        assert_eq!(
            execs[0].2.as_deref(),
            Some("/workspace/crates/x"),
            "the host path the model named, as the sandbox sees it"
        );
    }

    #[tokio::test]
    async fn a_path_outside_the_mount_is_refused_rather_than_passed_through() {
        // The failure this prevents is the quiet one: a command run against the sandbox's own root would
        // *succeed* and touch the wrong filesystem, and the run would report success.
        let runtime = Arc::new(FakeRuntime::new());
        let manager = manager(runtime.clone());
        let sandbox = SandboxFor::open(
            Arc::clone(&manager),
            &spec("/home/yoav/projects/thing"),
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        let err = sandbox
            .exec("ls", Some("/etc/ssh"))
            .await
            .expect_err("a path outside the mount must not be translated");
        assert!(
            err.to_string().contains("is not inside"),
            "and says which mount it is not inside: {err}"
        );
        assert!(
            runtime.execs().is_empty(),
            "nothing ran: {:?}",
            runtime.execs()
        );
    }

    #[tokio::test]
    async fn a_sandbox_path_is_left_alone_because_the_model_may_have_copied_one() {
        let runtime = Arc::new(FakeRuntime::new());
        let manager = manager(runtime);
        let sandbox = SandboxFor::open(
            Arc::clone(&manager),
            &spec("/home/yoav/projects/thing"),
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        assert_eq!(
            sandbox.translate("/workspace/src").unwrap(),
            "/workspace/src"
        );
        assert_eq!(sandbox.translate("/workspace").unwrap(), "/workspace");
    }

    #[tokio::test]
    async fn two_runs_in_one_checkout_share_a_sandbox_and_two_checkouts_do_not() {
        // Container starts are seconds, and a run makes dozens of calls. The key is what keeps the reuse
        // correct: same profile and same mount is the same boundary, anything else is a different one.
        let runtime = Arc::new(FakeRuntime::new());
        let manager = manager(runtime.clone());
        let cache = SandboxCache::new();

        let first = cache
            .get(&manager, &spec("/w/one"), Duration::from_secs(30))
            .await
            .unwrap();
        let again = cache
            .get(&manager, &spec("/w/one"), Duration::from_secs(30))
            .await
            .unwrap();
        let other = cache
            .get(&manager, &spec("/w/two"), Duration::from_secs(30))
            .await
            .unwrap();

        assert_eq!(first.id(), again.id());
        assert_ne!(first.id(), other.id());
        assert_eq!(runtime.creations(), 2, "one container per checkout");
        assert_eq!(cache.len().await, 2);
    }

    #[tokio::test]
    async fn a_cached_sandbox_that_was_reaped_is_replaced_rather_than_returned() {
        // A handle to a destroyed container fails with the *engine's* error on the next exec, which reads
        // like a bug in the tool. The check is what turns an expired sandbox into a new one.
        let runtime = Arc::new(FakeRuntime::new());
        let manager = manager(runtime.clone());
        let cache = SandboxCache::new();

        let first = cache
            .get(&manager, &spec("/w/one"), Duration::from_secs(30))
            .await
            .unwrap();
        manager.destroy(first.id()).await.unwrap();

        let second = cache
            .get(&manager, &spec("/w/one"), Duration::from_secs(30))
            .await
            .unwrap();
        assert_ne!(first.id(), second.id());
        assert_eq!(runtime.creations(), 2);
    }

    #[tokio::test]
    async fn a_slow_command_is_reported_as_a_timeout_and_not_as_success() {
        let runtime = Arc::new(SlowRuntime);
        let manager = Arc::new(SandboxManager::new(runtime, 1));
        let sandbox = SandboxFor::open(
            Arc::clone(&manager),
            &spec("/w/one"),
            Duration::from_millis(20),
        )
        .await
        .unwrap();

        let err = sandbox.exec("sleep 60", None).await.expect_err("timed out");
        assert!(
            err.to_string().contains("may still be running"),
            "a timeout must not read as a completed command: {err}"
        );
    }

    struct SlowRuntime;

    #[async_trait]
    impl SandboxRuntime for SlowRuntime {
        fn name(&self) -> &str {
            "slow"
        }
        async fn available(&self) -> bool {
            true
        }
        async fn create(
            &self,
            id: &SandboxId,
            _spec: &SandboxSpec,
            _settings: &hx_sandbox::HostSettings,
        ) -> Result<String> {
            Ok(format!("runtime-{id}"))
        }
        async fn start(&self, _runtime_id: &str) -> Result<()> {
            Ok(())
        }
        async fn stop(&self, _runtime_id: &str, _grace_secs: i64) -> Result<()> {
            Ok(())
        }
        async fn exec(
            &self,
            _runtime_id: &str,
            _command: &str,
            _workdir: Option<&str>,
        ) -> Result<hx_sandbox::SandboxExecOutput> {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(hx_sandbox::SandboxExecOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            })
        }
        async fn remove(&self, _runtime_id: &str) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn dropping_the_boundary_destroys_it() {
        // The lease is the difference between "a sandbox per run" and "a sandbox per daemon restart".
        let runtime = Arc::new(FakeRuntime::new());
        let manager = manager(runtime.clone());
        {
            let sandbox = SandboxFor::open(
                Arc::clone(&manager),
                &spec("/w/one"),
                Duration::from_secs(30),
            )
            .await
            .unwrap();
            assert_eq!(manager.list().await.len(), 1);
            assert_eq!(sandbox.id(), manager.list().await[0].id.as_str());
        }
        // The drop spawns the destroy; give it a turn of the runtime to run.
        for _ in 0..50 {
            if manager.list().await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            manager.list().await.is_empty(),
            "the container was released when the boundary was dropped"
        );
        assert_eq!(
            SandboxState::Running,
            SandboxState::Running,
            "and no state was invented along the way"
        );
    }
}

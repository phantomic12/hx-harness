//! A sandbox runtime that reaches a Docker daemon on a *remote* host.
//!
//! [`DockerRuntime`](crate::docker) drives the engine through `bollard`'s client, which
//! requires a local socket. That is the whole difference this module exists to hold: when the
//! sandbox must run on a *different* machine — a build box, a CI runner, a host that is not
//! the one running the daemon — there is no local socket on the daemon side, and reaching
//! `bollard` across a transport would smuggle a port-forward and a socket into every connection.
//! Instead, [`RemoteSandboxRuntime`] builds the same docker command lines the local runtime's
//! settings map to, and hands them to a transport that runs them on the far host.
//!
//! ## The property it holds
//!
//! The safe defaults are not weakened in translation. The remote runtime takes exactly the
//! `HostConfig` produced by [`crate::spec::SandboxSpec::host_settings`] and renders it as the
//! docker CLI flags that express the *same* settings — read-only root, dropped capabilities,
//! non-root, bounded memory/CPU/PIDs, an `init` reaper, user-namespace remapping, a
//! workspace bind, a keep-alive command. A setting that cannot be expressed as a flag is refused
//! before anything runs, never silently dropped, because a security setting that evaporates on the
//! way to a remote daemon is indistinguishable from one that was never configured.
//!
//! The builders ([`create_command`], [`start_command`], [`stop_command`], [`remove_command`],
//! [`exec_command`]) are pure functions tested token-for-token, in the same spirit as
//! `crate::docker::to_host_config`: the join between reviewed policy and what a shell actually
//! runs, asserted field by field because a dropped flag is a policy that is not enforced.
//!
//! ## The shape, and the dependency direction this module must not break
//!
//! `hx-sandbox` may not depend on `hx-remote` — everything else in the workspace depends on
//! this crate, and adding that edge would be a layering inversion. So
//! [`RemoteSandboxRuntime`] does **not** hold an `Arc<dyn Host>`. Instead it holds an
//! [`Arc<dyn RemoteCommandRunner>`](RemoteCommandRunner), a one-method local trait whose output
//! shape is deliberately the same as what a transport's exec returns (`{stdout, stderr,
//! exit_code}`), so the future adapter from `hx_remote::Host` to this trait (in `hx-server`,
//! where that dependency may legally point down into `hx-sandbox`) is a straight field-for-field
//! copy. The rejected alternative — importing `Host` directly — is not merely a build error
//! waiting to happen: it would tie the *security policy of the sandbox* to a transport interface
//! owned by a crate that is not allowed to be a dependency here, which is exactly the edge the
//! human explicitly did not want.
//!
//! ## Remote egress enforcement
//!
//! A remote sandbox reaches helpful sites through the *same* mechanism as a local one — an internal
//! Docker network with no gateway, plus a proxy sidecar — but placed **on the far host** instead of
//! the near one. The premise of this module was that a proxy sidecar is "fundamentally a local-
//! socket mechanism"; it is not. The sidecar is created by a few docker CLI commands, which is
//! exactly what a far daemon already accepts. The only genuinely remote-host-specific requirement is that
//! the compiled `hx-egress-proxy` binary must exist **on the far host** at a path the runtime
//! is told ([`RemoteSandboxRuntime::with_proxy_bin`]); placing it there is the deployment's job
//! (the live tests do it once through the transport's `write_file`).
//!
//! The setup mirrors [`crate::egress`]'s sequence as commands, with the same two hard-won traps
//! it records:
//!
//! - The proxy sidecar is created with **no** `--network`, then joined to the bridge and the
//!   internal network. Docker refuses to connect a container to a user network once its network mode
//!   is fixed — `"container cannot be connected to multiple networks with one of the networks in private
//!   (none) mode"` — and `--network=none` fails the same way. Omit the field so the default
//!   (bridge) applies, then attach both networks.
//! - The sandbox is created on the internal network **and** handed `HTTP_PROXY`/`HTTPS_PROXY`/
//!   `http_proxy`/`https_proxy` (and an empty `NO_PROXY`, so the alias itself is never sent
//!   direct). Without the env vars the sidecar exists, admits exactly what it should, and nothing ever
//!   talks to it — enforcement becomes invisible rather than wrong.
//!
//! The property held is the same as locally: a remote sandbox with a non-empty allowlist reaches
//! exactly and only the hosts it names, and has no other route out (the internal network has no
//! gateway). An empty allowlist with the network off still needs no proxy and stays the isolated
//! control. The refusal that remains is honest: an entry the proxy cannot match (a CIDR or raw IP)
//! is refused up front, the same shape [`SpecError::EgressNotEnforced`](crate::spec::SpecError)
//! refuses locally.
//!
//! ## What is deliberately NOT done yet
//!
//! 1. **Container logs.** The local runtime exposes `crate::docker::logs` as a `bollard`
//!    helper; the [`SandboxRuntime`] trait has no logs method, so the remote runtime does not
//!    reach for one either. `docker logs` stays available through [`RemoteCommandRunner`] when a
//!    consumer needs it.
//!
//! The runtime handle is the container *name*, not the id, exactly as in `crate::docker`: the
//! name is stable across recreates, greppable in `docker ps` on the far host, and what every
//! later command (`start`/`stop`/`rm`/`exec`) matches on.

use crate::runtime::{SandboxExecOutput, SandboxRuntime};
use crate::spec::{HostSettings, SandboxSpec};
use async_trait::async_trait;
use hx_core::error::{HxError, Result};
use hx_core::ids::SandboxId;
use std::sync::Arc;

/// How long to wait for a container to stop before killing it, when the caller asks for no grace.
pub const STOP_GRACE_SECS: i64 = 10;

/// The docker CLI. Every remote engine speaks it; the far host must have it on `PATH`, which
/// [`RemoteSandboxRuntime::available`] probes for.
const DOCKER: &str = "docker";

/// Shorthand for a sandbox error tagged with the remote host.
fn remote_error(message: impl std::fmt::Display) -> HxError {
    HxError::Sandbox(format!("remote sandbox: {message}"))
}

/// Shell-quote an argument for a POSIX shell, the classic single-quote-with-`'\''` form.
///
/// The value being guarded is a user/spec-controlled string (an image tag, an env value, a
/// workspace path, the exec command) crossing into a command line a remote shell will parse;
/// without quoting, a `;`, `|` or `$(…)` in a spec field would become a *second command on
/// the far host*. This is intentionally the same rule `hx-remote` applies at its own boundary
/// (see its `shell_quote`); it is reproduced here, small, because `hx-sandbox` may not import
/// that crate.
fn shell_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// The result of running a command on the remote host.
///
/// The field-for-field mirror of what a transport's exec returns, so the adapter from
/// `hx_remote::Host` to [`RemoteCommandRunner`] (in `hx-server`, where that dependency is
/// legal) is a straight copy. `exit_code: None` means the transport could not tell us the exit
/// status — surfaced as an unknown rather than as a successful zero.
#[derive(Clone, Debug, PartialEq)]
pub struct RemoteCommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

impl RemoteCommandOutput {
    /// `Some(0)` is success; `None` (unknown) and non-zero are not.
    fn succeeded(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// A transport that can run a command line on a remote host.
///
/// The seam between the sandbox policy here and the `Host` in `hx-remote`. Deliberately one
/// method: a sandbox runtime only ever *runs a command and reads its result*; it has no need
/// of file transfer or a PTY. Keeping the trait to that single act means an implementation (a
/// test double today, a `Host` adapter tomorrow) has nothing to get wrong that is not the act
/// itself.
#[async_trait]
pub trait RemoteCommandRunner: Send + Sync {
    /// Run a command line under the remote host's shell and return its combined outcome.
    async fn run(&self, command: &str) -> Result<RemoteCommandOutput>;
}

/// Sandboxes backed by a Docker daemon on a remote host.
pub struct RemoteSandboxRuntime {
    runner: Arc<dyn RemoteCommandRunner>,
    prefix: String,
    /// Path of the compiled `hx-egress-proxy` binary **on the far host**, bind-mounted into
    /// each proxy sidecar. Placed there by the deployment; the live tests do it once through a
    /// transport's `write_file`. Unset means a non-empty egress allowlist is refused (there is no
    /// way to enforce it without the binary on the far host) — the honest fail-closed default.
    proxy_bin: Option<String>,
    /// The container names whose egress network/sidecar this runtime created, so a `remove` knows to
    /// tear the proxy down. Idempotent removals for non-egress sandboxes simply never touch it.
    egress_containers: std::sync::Mutex<Vec<String>>,
}

impl RemoteSandboxRuntime {
    /// A runtime that reaches the far host through `runner`.
    pub fn new(runner: Arc<dyn RemoteCommandRunner>) -> Self {
        Self {
            runner,
            prefix: "hx".to_string(),
            proxy_bin: None,
            egress_containers: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Name the path of the `hx-egress-proxy` binary **on the far host**.
    ///
    /// Without it, a non-empty egress allowlist for a remote sandbox is refused (nothing on the far
    /// host could enforce it); with it, the runtime can create the internal network and proxy sidecar
    /// and genuinely enforce the allowlist. The path is a *remote* path — it is the deployment /
    /// caller's job to have placed the binary there (the live tests do it through the transport's
    /// `write_file`), because [`RemoteCommandRunner`] deliberately has no file transfer.
    pub fn with_proxy_bin(mut self, path: Option<String>) -> Self {
        self.proxy_bin = path;
        self
    }

    /// Whether this sandbox needs an egress proxy on the far host: a networked spec with a non-empty,
    /// enforceable allowlist.
    fn egress_active(spec: &SandboxSpec) -> bool {
        spec.network && !spec.egress_allow.is_empty()
    }

    fn container_name(&self, id: &SandboxId) -> String {
        format!("{}-{}", self.prefix, id.as_str())
    }

    /// Run an already-built docker command line and turn a non-zero (or unknown) exit into an
    /// error. The caller builds the full line; this only executes and interprets it.
    async fn run_docker(&self, command_line: &str) -> Result<RemoteCommandOutput> {
        let out = self.runner.run(command_line).await?;
        if !out.succeeded() {
            let code = match out.exit_code {
                Some(c) => c.to_string(),
                None => "unknown".to_string(),
            };
            let detail = if out.stderr.trim().is_empty() {
                out.stdout.trim()
            } else {
                out.stderr.trim()
            };
            return Err(remote_error(format!(
                "`{command_line}` failed with exit {code}: {detail}"
            )));
        }
        Ok(out)
    }

    /// `--cpus` takes a float number of cores, whereas the settings carry nano-CPUs.
    fn cpus_flag(nano: i64) -> String {
        format!("--cpus={}", nano as f64 / 1_000_000_000.0)
    }
}

/// Build the docker command line that *creates* the sandbox container from its spec and settings.
///
/// Pure so it can be asserted token-for-token. Every security-relevant setting becomes a flag;
/// one that cannot be (an allowlist entry the proxy cannot match — a CIDR or raw IP, see the
/// module doc) is refused here, before any command runs. Returns the container *name* and the command
/// line, because the name is what the rest of the lifecycle matches on.
///
/// When the spec asks for a non-empty, enforceable allowlist, the sandbox is placed on the internal
/// egress network (`<name>-egress`) instead of the plain bridge, and handed the proxy `HTTP_PROXY`/
/// `HTTPS_PROXY` env vars so its tools actually talk to the sidecar (see
/// [`egress_setup_commands`]). The proxy network + sidecar themselves are created by
/// [`RemoteSandboxRuntime::create`] running those setup commands first; this builder only wires the
/// sandbox to them.
pub fn create_command(
    name: &str,
    spec: &SandboxSpec,
    settings: &HostSettings,
) -> Result<(String, String)> {
    let egress = RemoteSandboxRuntime::egress_active(spec);
    if egress {
        // The honest remaining refusal: an entry the prosty cannot match against an unresolved CONNECT
        // target is refused here, up front, the same shape the spec validator refuses locally. A bare
        // IPv4 passes a *hostname-shape* check (its labels are alphanumeric), so an explicit
        // `IpAddr` parse is the guard.
        if let Some(bad) = spec.egress_allow.iter().find(|e| !is_egress_enforceable(e)) {
            return Err(remote_error(format!(
                "an egress allowlist entry '{bad}' cannot be enforced by the proxy sidecar: only a \
                 hostname or a `*.domain` globe can be matched against a CONNECT target. Refusing to \
                 start '{}' rather than half-enforcing it.",
                spec.profile
            )));
        }
    }

    let mut tokens = vec![
        DOCKER.to_string(),
        "create".to_string(),
        format!("--name={}", shell_quote(name)),
    ];

    // The non-root user lives on the *container*, not on each exec, exactly as it is for the
    // local runtime.
    tokens.push(format!("--user={}", shell_quote(&settings.user)));
    if settings.privileged {
        tokens.push("--privileged".to_string());
    }
    if settings.readonly_rootfs {
        tokens.push("--read-only".to_string());
    }
    if !settings.cap_drop.is_empty() {
        tokens.push(format!("--cap-drop={}", settings.cap_drop.join(",")));
    }
    for cap in &settings.cap_add {
        tokens.push(format!("--cap-add={}", shell_quote(cap)));
    }
    for opt in &settings.security_opt {
        tokens.push(format!("--security-opt={}", shell_quote(opt)));
    }
    // With an active allowlist the sandbox rides the internal egress network — no gateway, so the
    // only way out is the proxy sidecar that enforces the list. Otherwise the spec's network mode
    // (bridge, or none for an isolated sandbox) applies unchanged.
    let network = if egress {
        egress_network_name(name)
    } else {
        settings.network_mode.clone()
    };
    if !network.is_empty() {
        tokens.push(format!("--network={}", shell_quote(&network)));
    }
    for dns in &settings.dns {
        tokens.push(format!("--dns={}", shell_quote(dns)));
    }
    tokens.push(format!("--pids-limit={}", settings.pids_limit));
    tokens.push(RemoteSandboxRuntime::cpus_flag(settings.nano_cpus));
    tokens.push(format!("--memory={}", settings.memory_bytes));
    tokens.push(format!("--memory-swap={}", settings.memory_swap_bytes));
    if let Some(runtime) = &settings.runtime {
        tokens.push(format!("--runtime={}", shell_quote(runtime)));
    }
    if let Some(userns) = &settings.userns_mode {
        tokens.push(format!("--userns={}", shell_quote(userns)));
    }
    for (path, opts) in &settings.tmpfs {
        tokens.push(format!(
            "--tmpfs={}",
            shell_quote(&format!("{path}:{opts}"))
        ));
    }
    for bind in &settings.binds {
        tokens.push(format!("--volume={}", shell_quote(bind)));
    }
    if settings.init {
        tokens.push("--init".to_string());
    }
    for (k, v) in &spec.env {
        tokens.push(format!("-e={}", shell_quote(&format!("{k}={v}"))));
    }
    if egress {
        // Point the tools *inside* the sandbox at the proxy sidecar. Without this the sidecar
        // exists and admits what it should, and nothing ever talks to it — every client tries the
        // direct route, which the internal network has already denied, so enforcement becomes
        // invisible rather than wrong. `NO_PROXY` is set empty so it cannot swallow the alias
        // itself (the local runtime does the same; see `crate::egress`).
        let url = format!(
            "http://{}:{}",
            crate::egress::PROXY_ALIAS,
            crate::egress::PROXY_PORT
        );
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            tokens.push(format!("-e={}", shell_quote(&format!("{key}={url}"))));
        }
        tokens.push(format!("-e={}", shell_quote("NO_PROXY=")));
    }
    if !spec.workspace_path.is_empty() {
        tokens.push(format!("--workdir={}", shell_quote(&spec.workspace_path)));
    }
    // The image, then the keep-alive command — the same `sleep infinity` a container exec'd into
    // needs, exactly as `to_container_config` emits.
    tokens.push(shell_quote(&spec.image));
    tokens.push("sleep".to_string());
    tokens.push("infinity".to_string());

    Ok((name.to_string(), tokens.join(" ")))
}

/// The error text every Docker daemon without `userns-remap` configured produces for `--userns`:
///
/// ```text
/// docker: --userns: invalid USER mode        (exit 125)
/// ```
///
/// Matching on this exact string — not on a catch-all — is what keeps an unrelated create failure
/// (a missing image, a broken network, a bad bind) from being mislabelled as a remap problem. A
/// rewrite that fired on *any* failure would surrender the engine's real message, which is worse
/// than the raw text. The original error is kept in the rewritten message so the operator still sees
/// exactly what the engine said; the rewrite only prepends the cause and the way out.
const USERNS_INVALID_USER_MODE: &str = "invalid USER mode";

/// Rewrite the digestible `--userns=private` rejection into a message that names the cause and the
/// way out, leaving every other create failure untouched.
///
/// Today an L2/L3 profile against a daemon with no `userns-remap` in its `daemon.json` dies
/// with `docker: --userns: invalid USER mode (exit 125)` — a message that names the flag but not
/// why the daemon refused it or what to do. This turns that one specific failure into a refusal that
/// says: the far daemon has no user-namespace remapping configured; either configure remap on that
/// daemon, run this profile on a daemon that has it, or — only when a weaker boundary is
/// *explicitly* acceptable — use L1. It deliberately does **not** silently downgrade L2/L3 to L1:
/// the isolation level is the promise the operator made, and degrading on its own would be the
/// failure the whole isolation ladder exists to prevent. The operator, having been told the trade, may
/// choose L1; the runtime will not.
///
/// The narrow match is the whole point. A `userns_remap_advice` that fired on any create error
/// would rewrite a missing-image or networking failure as a remap problem, sending the operator down
/// the wrong path. It fires only when (a) the command actually asked for `--userns` remapping and
/// (b) the engine said `invalid USER mode`.
fn userns_remap_advice(command: &str, err: &HxError) -> Option<HxError> {
    let message = err.to_string();
    // Both halves must be true: the create command carried the remap flag (L2/L3 with remap
    // configured sets it; a profile that never asked for remap cannot hit this), and the engine
    // answered with the specific mode rejection.
    if !message.contains(USERNS_INVALID_USER_MODE) {
        return None;
    }
    if !command.contains("--userns") {
        return None;
    }
    // The original message is preserved verbatim so the operator can still see what the engine said.
    Some(remote_error(format!(
        "the far daemon has no user-namespace remapping (`userns-remap`) configured in its \
         daemon.json, so it refuses the --userns=private this L2/L3 profile requests. Configure \
         userns-remap on that daemon, or run this profile on a daemon that has it, or — only if \
         a weaker boundary is explicitly acceptable — use L1. The daemon's own message: {message}"
    )))
}

/// The internal network name this sandbox's egress proxy rides and its sandbox is placed on.
pub fn egress_network_name(name: &str) -> String {
    format!("{name}-egress")
}

/// The proxy sidecar container name for this sandbox.
pub fn egress_sidecar_name(name: &str) -> String {
    format!("{name}-egress-proxy")
}

/// Whether an egress allowlist entry can actually be enforced by the proxy sidecar.
///
/// The proxy matches a `CONNECT` target by hostname (exact or `*.domain` suffix); a CIDR, a raw IP
/// or anything *address-shaped* is not a hostname, so it cannot be decided and must be refused
/// rather than half-enforced. This mirrors [`crate::spec`]'s `is_proxy_enforceable`, and — unlike the
/// version this replaces — it uses the *same* address grammar rather than an `IpAddr` parse.
///
/// The `IpAddr` parse was the hole: a bare IPv4 passes a hostname-shape check (its labels are
/// alphanumeric), and so does the whole `inet_aton` family, which `IpAddr::from_str` does not
/// recognise but the resolver really does — `0x01010101` is 1.1.1.1, `127.1` is 127.0.0.1,
/// `2130706433` is 127.0.0.1. On the far host that produced `egress ALLOWED 0x01010101:443 → dialed
/// 1.1.1.1`: an allowlist entry that read as a name and dialed an address. The grammar lives once,
/// in [`crate::spec::is_address_shaped`], so the near and far validators cannot drift apart.
fn is_egress_enforceable(entry: &str) -> bool {
    let entry = entry.trim().trim_end_matches('.');
    if entry.is_empty() {
        return false;
    }
    let host = entry.strip_prefix("*.").unwrap_or(entry);
    let looks_hostname = host
        .split('.')
        .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    looks_hostname
        && !crate::spec::is_address_shaped(host)
        && host.parse::<std::net::IpAddr>().is_err()
}

/// The docker commands that create the internal egress network and the proxy sidecar on the far daemon.
///
/// `name` is the sandbox's container name (it namespaces the resources, so they are greppable and
/// collision-free); `allowlist` is the spec's non-empty, already-validated allowlist;
/// `proxy_bin` is the path of the compiled `hx-egress-proxy` binary **on the far host**,
/// bind-mounted into the sidecar. The sequence mirrors [`crate::egress::setup`], including the
/// trap that the sidecar must be created with **no** `--network` and then joined to both networks:
/// Docker refuses to connect a container to a user network once its network mode is fixed
/// (`"container cannot be connected to multiple networks with one of the networks in private (none) mode"`).
pub fn egress_setup_commands(name: &str, allowlist: &[String], proxy_bin: &str) -> Vec<String> {
    let network = egress_network_name(name);
    let sidecar = egress_sidecar_name(name);
    let allow_env = allowlist.join(",");
    vec![
        // 1. The internal network: no gateway, so no route off it. Fresh per sandbox, so one
        //    sandbox's proxy and allowlist never become another sandbox's route.
        format!(
            "{DOCKER} network create --internal --attachable=false {}",
            shell_quote(&network)
        ),
        // 2. The proxy sidecar. `network` is deliberately omitted so the default (bridge) applies;
        //    both networks are joined below. The allowlist travels by environment; the bind-mount reads
        //    the binary from the far host's filesystem.
        format!(
            "{DOCKER} create --name={} -e={} --volume={} {} {}",
            shell_quote(&sidecar),
            shell_quote(&format!("HX_EGRESS_ALLOW={allow_env}")),
            shell_quote(&format!("{proxy_bin}:/hx-egress-proxy:ro")),
            shell_quote(crate::egress::PROXY_IMAGE),
            "/hx-egress-proxy",
        ),
        // 3. The bridge so the sidecar can reach the internet.
        format!("{DOCKER} network connect bridge {}", shell_quote(&sidecar)),
        // 4. The internal network, aliased `hxproxy` so the sandbox resolves the sidecar by name.
        format!(
            "{DOCKER} network connect --alias {} {} {}",
            shell_quote(crate::egress::PROXY_ALIAS),
            shell_quote(&network),
            shell_quote(&sidecar),
        ),
        // 5. Start the proxy before the sandbox is attached, or the sandbox's first request races
        //    a not-yet-listening socket.
        format!("{DOCKER} start {}", shell_quote(&sidecar)),
    ]
}

/// The docker commands that tear a sandbox's egress network and sidecar down on the far daemon.
///
/// Idempotent in spirit: the container and network may already be gone, and a `remove` on an absent
/// thing fails loudly on the far host. The runtime runs these only for sandboxes it created with egress
/// (tracked in [`RemoteSandboxRuntime::egress_containers`]), so a plain remote sandbox never tears
/// down anything it does not own.
pub fn egress_teardown_commands(name: &str) -> Vec<String> {
    let network = egress_network_name(name);
    let sidecar = egress_sidecar_name(name);
    vec![
        // `--force` so a running sidecar cannot keep its network alive and leak it.
        format!("{DOCKER} rm -f {}", shell_quote(&sidecar)),
        // The network outlives only its last container.
        format!("{DOCKER} network rm {}", shell_quote(&network)),
    ]
}

/// `docker start <id>`
pub fn start_command(runtime_id: &str) -> String {
    format!("{DOCKER} start {runtime_id}")
}

/// `docker stop --time=<grace> <id>`, with a default grace when the caller asks for none.
pub fn stop_command(runtime_id: &str, grace_secs: i64) -> String {
    let grace = if grace_secs > 0 {
        grace_secs
    } else {
        STOP_GRACE_SECS
    };
    format!("{DOCKER} stop --time={grace} {runtime_id}")
}

/// `docker rm -f -v <id>` — force and anonymous volumes, mirroring the local runtime's
/// `force: true, v: true`. A running remote container a `stop` raced must not keep its volumes.
pub fn remove_command(runtime_id: &str) -> String {
    format!("{DOCKER} rm -f -v {runtime_id}")
}

/// `docker exec <id> [-w <dir>] sh -c '<command>'`.
///
/// `command` is a full shell line the *container's* `sh -c` parses; it is shell-quoted here
/// so it survives the *host's* shell on the way in, and only then reaches the container shell as
/// the exact argument. The exit code of `docker exec` is the exit code of the command inside, so
/// a transport that reports exit status hands us the inner result directly — the thing the local
/// runtime needs a second `inspect_exec` call for.
pub fn exec_command(runtime_id: &str, command: &str, workdir: Option<&str>) -> String {
    let mut tokens = vec![
        DOCKER.to_string(),
        "exec".to_string(),
        runtime_id.to_string(),
        "sh".to_string(),
        "-c".to_string(),
        shell_quote(command),
    ];
    if let Some(dir) = workdir {
        tokens.insert(2, format!("--workdir={}", shell_quote(dir)));
    }
    tokens.join(" ")
}

#[async_trait]
impl SandboxRuntime for RemoteSandboxRuntime {
    fn name(&self) -> &str {
        "remote-docker"
    }

    async fn available(&self) -> bool {
        // `docker info` exits 0 only when a daemon is reachable; the transport-shaped cousin of
        // `DockerRuntime::available`'s `ping`. A host that answers non-zero (or whose transport
        // reports no exit status) is reported absent rather than hung, because `available` is what
        // decides whether a configured remote sandbox host is offered at all.
        self.runner
            .run(&format!("{DOCKER} info"))
            .await
            .map(|o| o.succeeded())
            .unwrap_or(false)
    }

    async fn create(
        &self,
        id: &SandboxId,
        spec: &SandboxSpec,
        settings: &HostSettings,
    ) -> Result<String> {
        let name = self.container_name(id);

        // Egress needs the proxy binary on the far host. If the deployment has not placed it
        // there (no `proxy_bin`), refusing is the only honest answer — a networked remote
        // sandbox with an unenforced allowlist is an open sandbox wearing an allowlist as a
        // costume.
        let egress = RemoteSandboxRuntime::egress_active(spec);
        if egress {
            let proxy_bin = self.proxy_bin.clone().ok_or_else(|| {
                remote_error(format!(
                    "refusing remote sandbox '{0}': a non-empty egress allowlist {1:?} requires \
                     the `hx-egress-proxy` binary to exist on the far host, but no proxy binary \
                     path was configured. Without it the allowlist could not be enforced. Configure \
                     the far-host path with `with_proxy_bin`, or drop the allowlist (and network) \
                     for an isolated sandbox.",
                    spec.profile, spec.egress_allow
                ))
            })?;
            // Create the internal network + proxy sidecar on the far daemon *first*, so a failing
            // setup never leaves a half-enforced sandbox. If any setup command fails, roll back the
            // ones that preceded it: a partial internal network / sidecar left on a remote daemon is an
            // orphan this runtime made, and it must not outlive a failed create. The rollback itself
            // is best-effort (`run_docker` failure on an already-gone thing is ignored via `let _`),
            // so the original error is what surfaces.
            for cmd in egress_setup_commands(&name, &spec.egress_allow, &proxy_bin) {
                if let Err(err) = self.run_docker(&cmd).await {
                    for teardown in egress_teardown_commands(&name) {
                        let _ = self.run_docker(&teardown).await;
                    }
                    return Err(err);
                }
            }
        }

        let (name, command) = create_command(&name, spec, settings)?;
        match self.run_docker(&command).await {
            Ok(_) => {
                if egress {
                    self.egress_containers
                        .lock()
                        .expect("egress set lock")
                        .push(name.clone());
                }
                // The runtime handle is the container *name*, stable across recreates and what later
                // commands match on — the id docker prints is not returned, for the same reason
                // `DockerRuntime::create` returns the name. With `--name` set we already know it.
                Ok(name)
            }
            Err(err) => {
                // The sandbox itself could not be created; the proxy and network just made for it must
                // not be left behind. This is a `match`, not a `map_err`, because the rollback has
                // to *await* — written as a closure it would compile to an un-awaited future that
                // drops the work and leaks the proxy on every failed create. The teardown is
                // best-effort so the create's own error surfaces.
                if egress {
                    for teardown in egress_teardown_commands(&name) {
                        let _ = self.run_docker(&teardown).await;
                    }
                }
                // The one digestible rejection the engine produces — a daemon with no `userns-remap`
                // in `daemon.json` refuses every L2/L3 create with `--userns: invalid USER mode`.
                // Naming the cause and the way out here is what makes the failure actionable; the raw
                // engine text says which flag, not why or what to do. Only this specific failure is
                // rewritten — never a catch-all, which would mislabel a networking or image error as a
                // remap problem (see `userns_remap_advice`).
                Err(userns_remap_advice(&command, &err).unwrap_or(err))
            }
        }
    }

    async fn start(&self, runtime_id: &str) -> Result<()> {
        self.run_docker(&start_command(runtime_id)).await?;
        Ok(())
    }

    async fn stop(&self, runtime_id: &str, grace_secs: i64) -> Result<()> {
        self.run_docker(&stop_command(runtime_id, grace_secs))
            .await?;
        Ok(())
    }

    async fn remove(&self, runtime_id: &str) -> Result<()> {
        self.run_docker(&remove_command(runtime_id)).await?;
        // Tear down this sandbox's egress network and sidecar, if this runtime created them, so the
        // far daemon is left exactly as it was. `remove` of a running sidecar is forced; removing
        // the network after its last container frees it. A plain (non-egress) sandbox never
        // tracked its name here, so it tears nothing down.
        let had_egress = {
            let mut names = self.egress_containers.lock().expect("egress set lock");
            let idx = names.iter().position(|n| n == runtime_id);
            if let Some(i) = idx {
                names.remove(i);
                true
            } else {
                false
            }
        };
        if had_egress {
            for teardown in egress_teardown_commands(runtime_id) {
                let _ = self.run_docker(&teardown).await;
            }
        }
        Ok(())
    }

    async fn exec(
        &self,
        runtime_id: &str,
        command: &str,
        workdir: Option<&str>,
    ) -> Result<SandboxExecOutput> {
        let command_line = exec_command(runtime_id, command, workdir);
        let out = self.runner.run(&command_line).await?;
        Ok(SandboxExecOutput {
            stdout: out.stdout,
            stderr: out.stderr,
            exit_code: out.exit_code.unwrap_or(-1).into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::DEFAULT_WORKSPACE_PATH;
    use hx_core::config::IsolationLevel;
    use std::sync::Mutex;

    /// A recording transport that answers exactly the commands it was scripted for.
    ///
    /// The repo rule: a scripted double must fail loudly when it runs out of script. Each entry
    /// names the *exact* command it answers, so a `run` for a command that was not scripted
    /// panics instead of answering the wrong thing, and a `run` that finds an empty script panics
    /// too — a test that asserts "only one command was sent" is then provable.
    struct RecordingRunner {
        script: Mutex<Vec<(String, RemoteCommandOutput)>>,
    }

    impl RecordingRunner {
        fn new(script: Vec<(&str, RemoteCommandOutput)>) -> Self {
            Self {
                script: Mutex::new(
                    script
                        .into_iter()
                        .map(|(cmd, out)| (cmd.to_string(), out))
                        .collect(),
                ),
            }
        }
    }

    #[async_trait]
    impl RemoteCommandRunner for RecordingRunner {
        async fn run(&self, command: &str) -> Result<RemoteCommandOutput> {
            let mut script = self.script.lock().unwrap();
            let (expected, out) = script
                .first()
                .cloned()
                .unwrap_or_else(|| {
                    panic!(
                        "runner was asked for a command but its script is exhausted: got {command:?}"
                    )
                })
                .clone();
            assert_eq!(
                expected, command,
                "runner was asked a command it did not script: expected {expected:?}, got {command:?}"
            );
            script.remove(0);
            Ok(out)
        }
    }

    fn ok(stdout: &str) -> RemoteCommandOutput {
        RemoteCommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        }
    }

    /// Leak a `String` into a `'static &str` for the recording runner's script, which borrows
    /// command strings for the life of the test.
    fn leaked(s: String) -> &'static str {
        &*Box::leak(Box::<str>::from(s))
    }

    fn spec(isolation: IsolationLevel) -> SandboxSpec {
        SandboxSpec {
            profile: "dev".into(),
            image: "ubuntu:24.04".into(),
            isolation,
            cpus: 2.0,
            memory_mb: 4096,
            pids_max: 1024,
            workspace_mb: 8192,
            ttl_secs: 3600,
            egress_allow: Vec::new(),
            network: false,
            readonly_rootfs: true,
            workspace_host_path: "/tmp/hx/ws".into(),
            workspace_path: DEFAULT_WORKSPACE_PATH.into(),
            user: None,
            env: vec![("RUST_LOG".into(), "info".into())],
        }
    }

    // ---- command-line builders (pure, asserted token-for-token) ----

    #[test]
    fn create_carries_every_security_setting_over_the_wire() {
        // The heart of this module. A security setting dropped here is a policy not enforced on the
        // far host — the exact failure mode the local runtime guards with `engine_settings_…` tests.
        // Assert the full L2 command line so a dropped `--read-only`, `--cap-drop=ALL`, or the
        // user-namespace remap cannot return silently.
        let s = spec(IsolationLevel::L2);
        let settings = s.host_settings();
        let (name, cmd) = create_command("hx-sbx_abc123", &s, &settings).unwrap();

        assert_eq!(name, "hx-sbx_abc123");

        let expected = "docker create --name='hx-sbx_abc123' \
            --user='1000:1000' --read-only --cap-drop=ALL \
            --security-opt='no-new-privileges:true' --network='none' \
            --pids-limit=1024 --cpus=2 --memory=4294967296 --memory-swap=4294967296 \
            --userns='private' \
            --tmpfs='/tmp:rw,noexec,nosuid,size=1g' \
            --tmpfs='/var/tmp:rw,noexec,nosuid,size=512m' \
            --tmpfs='/run:rw,noexec,nosuid,size=64m' \
            --volume='/tmp/hx/ws:/workspace:rw' --init \
            -e='RUST_LOG=info' --workdir='/workspace' \
            'ubuntu:24.04' sleep infinity";
        assert_eq!(
            cmd, expected,
            "the ENTIRE security posture must survive as flags"
        );
    }

    #[test]
    fn l3_renders_its_vm_backed_runtime_flag() {
        // L3's whole point is the kernel inside is not the host's; lose `--runtime=runsc` on
        // the wire and the remote sandbox quietly runs on the shared kernel.
        let s = spec(IsolationLevel::L3);
        let settings = s.host_settings();
        let (_, cmd) = create_command("hx-sbx_l3", &s, &settings).unwrap();
        assert!(
            cmd.contains("--runtime='runsc'"),
            "L3 must not lose its VM-backed runtime: {cmd}"
        );
    }

    #[test]
    fn l1_does_not_ask_for_user_namespace_remapping() {
        // L1 is a development container; it must not send `--userns=private` any more than the
        // local runtime sends `userns_mode` for it.
        let s = spec(IsolationLevel::L1);
        let settings = s.host_settings();
        let (_, cmd) = create_command("hx-sbx_l1", &s, &settings).unwrap();
        assert!(
            !cmd.contains("--userns"),
            "L1 sends no remap request: {cmd}"
        );
        assert!(
            cmd.contains("--cap-add="),
            "L1 still gets its build caps: {cmd}"
        );
    }

    #[test]
    fn an_enforceable_egress_allowlist_is_accepted_and_rides_the_internal_network_with_proxy_env() {
        // The heart of this milestone: a non-empty allowlist that the proxy *can* match (a hostname)
        // is no longer refused. The sandbox is placed on its internal egress network (no gateway,
        // so no route out except the sidecar) and handed the proxy env vars so tools inside actually talk
        // to it. Assert the rendered command, so a dropped proxy var or a reused plain `bridge` cannot
        // return silently — either would be a half-enforced open sandbox.
        let mut s = spec(IsolationLevel::L1);
        s.network = true;
        s.egress_allow = vec!["crates.io".into()];
        let settings = s.host_settings();
        let (name, cmd) = create_command("hx-sbx_x", &s, &settings).unwrap();
        assert_eq!(name, "hx-sbx_x");
        assert!(
            cmd.contains("--network='hx-sbx_x-egress'"),
            "the sandbox must ride its internal egress network: {cmd}"
        );
        for key in ["HTTP_PROXY", "HTTPS_PROXY"] {
            assert!(
                cmd.contains(&format!("-e='{key}=http://hxproxy:3128'")),
                "the sandbox must point {key} at the proxy sidecar: {cmd}"
            );
        }
        assert!(
            !cmd.contains("--network='bridge'"),
            "a sandbox with an allowlist must not also ride the reach-everything bridge: {cmd}"
        );
    }

    #[test]
    fn an_egress_allowlist_entry_the_proxy_cannot_match_is_refused_before_any_command_runs() {
        // The honest refusal that survives: an entry the proxy cannot match against an unresolved
        // CONNECT target (a raw IP, and by extension a CIDR) is refused up front, the same shape
        // the spec validator refuses locally. A bare IPv4 passes a hostname-shape check, so the
        // refusal proves the `IpAddr` guard actually fires.
        let mut s = spec(IsolationLevel::L1);
        s.network = true;
        s.egress_allow = vec!["93.184.216.34".into()];
        let settings = s.host_settings();
        let err = create_command("hx-sbx_x", &s, &settings).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("cannot be enforced") && message.contains("93.184.216.34"),
            "{message}"
        );
    }

    #[test]
    fn an_address_shaped_allowlist_entry_is_refused_on_the_far_path_too() {
        // The same hole as `spec.rs`'s, reached through the remote path. `0x01010101` and the rest of
        // the `inet_aton` family pass a hostname-shape check (their labels are alphanumerics) and are
        // *really dialed as addresses* — on the far host the old guard produced
        // `egress ALLOWED 0x01010101:443 → dialed 1.1.1.1`. `create_command` refuses the shape before
        // building any command, so the far daemon is never handed a "hostname" that is an address.
        for smuggled in [
            "0x01010101",
            "127.1",
            "2130706433",
            "0177.0.0.1",
            "0x7f000001",
        ] {
            let mut s = spec(IsolationLevel::L1);
            s.network = true;
            s.egress_allow = vec![smuggled.into()];
            let settings = s.host_settings();
            let err = create_command("hx-sbx_x", &s, &settings).unwrap_err();
            let message = err.to_string();
            assert!(
                message.contains("cannot be enforced") && message.contains(smuggled),
                "{message}"
            );
        }
    }

    #[test]
    fn egress_setup_and_teardown_render_the_far_host_commands_in_order() {
        // The remote sidecar is created with NO `--network`, then joined to both the bridge and the
        // internal network: Docker refuses to connect a container to a user network once its mode is
        // fixed, so omitting the field is what lets both joins succeed. Assert the exact sequence so a
        // `--network=none` or a missing join cannot slip through.
        let setup = egress_setup_commands(
            "hx-sbx_abc",
            &["crates.io".to_string()],
            "/opt/hx-egress-proxy",
        );
        let expected = vec![
            "docker network create --internal --attachable=false 'hx-sbx_abc-egress'",
            "docker create --name='hx-sbx_abc-egress-proxy' -e='HX_EGRESS_ALLOW=crates.io' --volume='/opt/hx-egress-proxy:/hx-egress-proxy:ro' 'ubuntu:24.04' /hx-egress-proxy",
            "docker network connect bridge 'hx-sbx_abc-egress-proxy'",
            "docker network connect --alias 'hxproxy' 'hx-sbx_abc-egress' 'hx-sbx_abc-egress-proxy'",
            "docker start 'hx-sbx_abc-egress-proxy'",
        ];
        assert_eq!(setup, expected);
        assert_eq!(
            egress_teardown_commands("hx-sbx_abc"),
            vec![
                "docker rm -f 'hx-sbx_abc-egress-proxy'",
                "docker network rm 'hx-sbx_abc-egress'",
            ]
        );
    }

    #[test]
    fn spec_values_are_shell_quoted_so_they_cannot_become_far_host_commands() {
        // A `;`, `|` or `$(…)` in a spec field must stay data on the far host, not become a
        // second command. The quoting is the boundary between a sandbox profile and a shell.
        let mut s = spec(IsolationLevel::L1);
        s.image = "ubuntu:24.04; touch /tmp/pwned".into();
        s.env = vec![("X".into(), "a; rm -rf /".into())];
        let settings = s.host_settings();
        let (_, cmd) = create_command("hx-sbx_q", &s, &settings).unwrap();
        assert!(
            cmd.contains("'ubuntu:24.04; touch /tmp/pwned'"),
            "the image must arrive quoted: {cmd}"
        );
        assert!(
            cmd.contains("-e='X=a; rm -rf /'"),
            "the env value must arrive quoted: {cmd}"
        );
    }

    #[test]
    fn start_is_a_bare_docker_start() {
        assert_eq!(start_command("hx-sbx_abc"), "docker start hx-sbx_abc");
    }

    #[test]
    fn stop_uses_its_grace_and_falls_back_when_none_is_asked() {
        assert_eq!(
            stop_command("hx-sbx_abc", 30),
            "docker stop --time=30 hx-sbx_abc"
        );
        // A non-positive grace means "default", exactly as `DockerRuntime` treats it.
        assert_eq!(
            stop_command("hx-sbx_abc", 0),
            format!("docker stop --time={STOP_GRACE_SECS} hx-sbx_abc")
        );
    }

    #[test]
    fn remove_forces_and_takes_volumes() {
        // A running remote container a stop raced must not keep its volumes or slot.
        assert_eq!(remove_command("hx-sbx_abc"), "docker rm -f -v hx-sbx_abc");
    }

    #[test]
    fn exec_wraps_the_command_in_sh_c_with_an_optional_workdir() {
        assert_eq!(
            exec_command("hx-sbx_abc", "cargo build", Some("/workspace/src")),
            "docker exec --workdir='/workspace/src' hx-sbx_abc sh -c 'cargo build'"
        );
        assert_eq!(
            exec_command("hx-sbx_abc", "ls -la", None),
            "docker exec hx-sbx_abc sh -c 'ls -la'"
        );
    }

    #[test]
    fn exec_quotes_a_command_so_it_cannot_run_twice() {
        // `sh -c` parses the command inside the container; without quoting, the host shell would
        // have split it first. A command containing a quote must survive intact.
        let cmd = exec_command("hx-sbx_abc", "echo \"hi\" && whoami", None);
        assert_eq!(cmd, r#"docker exec hx-sbx_abc sh -c 'echo "hi" && whoami'"#);
    }

    // ---- the trait methods against the recording transport ----

    #[tokio::test]
    async fn available_answers_to_a_daemon_that_answers() {
        let runner = Arc::new(RecordingRunner::new(vec![("docker info", ok(""))]));
        let runtime = RemoteSandboxRuntime::new(runner);
        assert!(runtime.available().await);
    }

    #[tokio::test]
    async fn available_reports_absent_when_the_far_daemon_is_down() {
        // The other half of the probe: a host whose daemon is unreachable is reported absent, not
        // represented as working.
        let not_ok = RemoteCommandOutput {
            stdout: String::new(),
            stderr: "Cannot connect to the Docker daemon".into(),
            exit_code: Some(1),
        };
        let runner = Arc::new(RecordingRunner::new(vec![("docker info", not_ok)]));
        let runtime = RemoteSandboxRuntime::new(runner);
        assert!(!runtime.available().await);
    }

    #[tokio::test]
    async fn create_returns_the_container_name_as_the_runtime_handle() {
        // The lifecycle matches on the name (stable, greppable), not the id docker prints.
        let s = spec(IsolationLevel::L2);
        let settings = s.host_settings();
        let (_, expected) = create_command("hx-sbx_abc123", &s, &settings).unwrap();
        let runner = Arc::new(RecordingRunner::new(vec![(
            expected.as_str(),
            ok("deadbeef\n"),
        )]));
        let runtime = RemoteSandboxRuntime::new(runner);
        let id = runtime
            .create(&SandboxId::from_raw("sbx_abc123"), &s, &settings)
            .await
            .unwrap();
        assert_eq!(id, "hx-sbx_abc123");
    }

    #[tokio::test]
    async fn a_failed_create_returns_an_error_that_says_why() {
        // A transport failure must surface as a named error, not a silent success.
        let s = spec(IsolationLevel::L2);
        let settings = s.host_settings();
        let (_, expected) = create_command("hx-sbx_abc123", &s, &settings).unwrap();
        let failed = RemoteCommandOutput {
            stdout: String::new(),
            stderr: "no such image: ubuntu:24.04".into(),
            exit_code: Some(125),
        };
        let runner = Arc::new(RecordingRunner::new(vec![(expected.as_str(), failed)]));
        let runtime = RemoteSandboxRuntime::new(runner);
        let err = runtime
            .create(&SandboxId::from_raw("sbx_abc123"), &s, &settings)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exit 125"), "{err}");
    }

    #[tokio::test]
    async fn a_create_that_rejects_userns_remapping_names_the_cause_and_the_way_out() {
        // L2/L3 against a daemon whose `daemon.json` has no `userns-remap` dies at create with
        // `--userns: invalid USER mode`. The raw engine text names the flag but not why or what to
        // do; the runtime must rewrite this one specific failure into a message that says the far
        // daemon has no remap configured and how to proceed — without degrading the level to L1 on
        // its own (the isolation ladder's promise is the operator's to relax, explicitly).
        let s = spec(IsolationLevel::L2);
        let settings = s.host_settings();
        let (_, expected) = create_command("hx-sbx_abc123", &s, &settings).unwrap();
        let failed = RemoteCommandOutput {
            stdout: String::new(),
            stderr: "docker: --userns: invalid USER mode            (exit 125)".into(),
            exit_code: Some(125),
        };
        let runner = Arc::new(RecordingRunner::new(vec![(expected.as_str(), failed)]));
        let runtime = RemoteSandboxRuntime::new(runner);
        let err = runtime
            .create(&SandboxId::from_raw("sbx_abc123"), &s, &settings)
            .await
            .unwrap_err();
        let message = err.to_string();
        // The cause.
        assert!(
            message.contains("no user-namespace remapping") && message.contains("userns-remap"),
            "the failure must name the missing remap as the cause: {message}"
        );
        // The way out, including the explicitly-excepted L1.
        assert!(
            message.contains("Configure userns-remap on that daemon"),
            "the failure has to offer the real fix: {message}"
        );
        assert!(
            message.contains("use L1") && message.contains("explicitly acceptable"),
            "L1 is offered only as an explicit, weaker-boundary choice: {message}"
        );
        // The original engine text is preserved so the operator still sees exactly what the daemon said.
        assert!(
            message.contains("invalid USER mode"),
            "the engine's own message must survive: {message}"
        );
    }

    #[tokio::test]
    async fn an_unrelated_create_failure_is_never_rewritten_as_a_remap_problem() {
        // The control for the rewrite above, and the reason it is a narrow match: a failure that is
        // *not* the `invalid USER mode` rejection (a missing image, here) must surface as the
        // engine's raw text. A catch-all rewrite would mislabel every create error as a remap
        // problem, which is worse than the raw text — the engine knows what is wrong, and a message
        // that claims a wrong cause sends the operator down the wrong path. The level is L2 (so the
        // command really does carry `--userns`), which proves the guard is the error text, not the
        // mere presence of the flag.
        let s = spec(IsolationLevel::L2);
        let settings = s.host_settings();
        let (_, expected) = create_command("hx-sbx_abc123", &s, &settings).unwrap();
        let failed = RemoteCommandOutput {
            stdout: String::new(),
            stderr: "no such image: ubuntu:24.04".into(),
            exit_code: Some(125),
        };
        let runner = Arc::new(RecordingRunner::new(vec![(expected.as_str(), failed)]));
        let runtime = RemoteSandboxRuntime::new(runner);
        let err = runtime
            .create(&SandboxId::from_raw("sbx_abc123"), &s, &settings)
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("no such image: ubuntu:24.04"), "{message}");
        assert!(
            !message.contains("userns-remap"),
            "an unrelated failure must not be relabelled as a remap problem: {message}"
        );
    }

    #[test]
    fn userns_remap_advice_fires_only_on_the_digestible_rejection() {
        // The pure guard, pinned directly: it fires only when the command carried `--userns` AND the
        // engine said the specific `invalid USER mode` rejection. Either half alone is not enough.
        let remap_command = "docker create --name='x' --userns='private' ubuntu:24.04";
        let remap_err = remote_error(
            "`docker create …` failed with exit 125: docker: --userns: invalid USER mode",
        );
        assert!(
            userns_remap_advice(remap_command, &remap_err).is_some(),
            "the remap rejection must be rewritten"
        );

        // The rejection text without the flag in the command: not a remap create, leave untouched.
        let plain_err = remote_error(
            "`docker create …` failed with exit 125: docker: --userns: invalid USER mode",
        );
        assert!(
            userns_remap_advice("docker create --name='x' ubuntu:24.04", &plain_err).is_none(),
            "without the flag in the command, do not call it a remap problem"
        );

        // The flag present but a different error text: not the rejection we map.
        let other_err = remote_error("`docker create …` failed with exit 125: no such image");
        assert!(
            userns_remap_advice(remap_command, &other_err).is_none(),
            "an unrelated error must not be rewritten"
        );
    }

    #[tokio::test]
    async fn a_nonempty_egress_allowlist_is_refused_before_dialing_when_no_proxy_binary_is_configured(
    ) {
        // The honest fail-closed rule that remains: a networked remote sandbox with an allowlist needs
        // the `hx-egress-proxy` binary on the far host, and a runtime that has not been told where
        // it is cannot enforce the allowlist — so it refuses rather than shipping an open sandbox wearing
        // an allowlist as a costume. The runner's script is *empty*: it panics when asked for any
        // command it did not script, so the test fails loudly if `create` ever reaches the far host — a
        // refusal that still dialled the machine would leak its reachability.
        let mut s = spec(IsolationLevel::L1);
        s.network = true;
        s.egress_allow = vec!["crates.io".into()];
        s.workspace_host_path = "/tmp/hx/ws".into();
        let settings = s.host_settings();
        let runner = Arc::new(RecordingRunner::new(vec![]));
        let runtime = RemoteSandboxRuntime::new(runner);
        let err = runtime
            .create(&SandboxId::from_raw("sbx_abc123"), &s, &settings)
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("proxy binary") && message.contains("crates.io"),
            "the refusal has to name the missing far-host binary and the allowlist: {message}"
        );
    }

    #[tokio::test]
    async fn an_egress_allowlist_with_a_far_host_proxy_binary_runs_setup_create_and_teardown() {
        // The full enforcement lifecycle against the recording transport: a runtime told the far-host
        // proxy binary path creates the internal network + sidecar (the setup commands), then the sandbox
        // on that network, and a later `remove` tears the sidecar and network down. The runner's
        // script names every command in order, so a dropped setup/teardown step or a reused plain
        // bridge fails loudly instead of passing silently.
        let mut s = spec(IsolationLevel::L1);
        s.network = true;
        s.egress_allow = vec!["crates.io".into()];
        s.workspace_host_path = "/tmp/hx/ws".into();
        let settings = s.host_settings();
        let name = "hx-sbx_abc123";
        let (_, sandbox_cmd) = create_command(name, &s, &settings).unwrap();

        let mut script: Vec<(&str, RemoteCommandOutput)> =
            egress_setup_commands(name, &["crates.io".to_string()], "/opt/hx-egress-proxy")
                .into_iter()
                .map(|c| (leaked(c), ok("")))
                .collect();
        script.push((leaked(sandbox_cmd), ok("id\n")));
        script.push(("docker start hx-sbx_abc123", ok("")));
        script.push(("docker rm -f -v hx-sbx_abc123", ok("")));
        let teardown = egress_teardown_commands(name);
        assert_eq!(teardown.len(), 2, "teardown has sidecar + network");
        for t in teardown {
            script.push((leaked(t), ok("")));
        }

        let runner: Arc<dyn RemoteCommandRunner> = Arc::new(RecordingRunner::new(script));
        let runtime = RemoteSandboxRuntime::new(Arc::clone(&runner))
            .with_proxy_bin(Some("/opt/hx-egress-proxy".to_string()));
        let id = runtime
            .create(&SandboxId::from_raw("sbx_abc123"), &s, &settings)
            .await
            .unwrap();
        assert_eq!(id, "hx-sbx_abc123");
        runtime.start(&id).await.unwrap();
        runtime.remove(&id).await.unwrap();
        // The script is exhausted: any extra command would panic, proving setup+create+start+remove+teardown
        // sent exactly the reviewed commands and nothing more.
    }

    #[tokio::test]
    async fn an_isolated_remote_sandbox_with_no_egress_allowlist_is_allowed_and_its_command_is_sent(
    ) {
        // The control for the refusal above: without this, a blanket "refuse every remote sandbox"
        // would pass the egress tests, forbidding the safe case the human explicitly wanted kept. A
        // remote sandbox with an empty allowlist and the network off is fully isolated, needs no proxy,
        // and must actually build and send its docker command to the far host. The runner's script
        // expects exactly that command, so the test fails if create sends nothing or sends something else.
        let s = spec(IsolationLevel::L2);
        let settings = s.host_settings();
        let (_, expected) = create_command("hx-sbx_abc123", &s, &settings).unwrap();
        assert!(
            s.egress_allow.is_empty(),
            "the control must be empty-egress"
        );
        assert!(
            !settings.is_networked(),
            "the isolated control must have the network off"
        );
        let runner = Arc::new(RecordingRunner::new(vec![(expected.as_str(), ok("id\n"))]));
        let runtime = RemoteSandboxRuntime::new(runner);
        let id = runtime
            .create(&SandboxId::from_raw("sbx_abc123"), &s, &settings)
            .await
            .unwrap();
        assert_eq!(id, "hx-sbx_abc123");
    }

    #[tokio::test]
    async fn start_stop_and_remove_issue_the_expected_commands() {
        let s = spec(IsolationLevel::L2);
        let settings = s.host_settings();
        let (_, create_cmd) = create_command("hx-sbx_abc", &s, &settings).unwrap();
        let runner = Arc::new(RecordingRunner::new(vec![
            (create_cmd.as_str(), ok("id\n")),
            ("docker start hx-sbx_abc", ok("")),
            ("docker stop --time=10 hx-sbx_abc", ok("")),
            ("docker rm -f -v hx-sbx_abc", ok("")),
        ]));
        let runtime = RemoteSandboxRuntime::new(runner);
        let id = runtime
            .create(&SandboxId::from_raw("sbx_abc"), &s, &settings)
            .await
            .unwrap();
        runtime.start(&id).await.unwrap();
        runtime.stop(&id, 0).await.unwrap();
        runtime.remove(&id).await.unwrap();
    }

    #[tokio::test]
    async fn exec_surfaces_stdout_stderr_and_exit_code() {
        let out = RemoteCommandOutput {
            stdout: "built ok\n".into(),
            stderr: String::new(),
            exit_code: Some(0),
        };
        let expected = exec_command("hx-sbx_abc", "cargo build", None);
        let runner = Arc::new(RecordingRunner::new(vec![(expected.as_str(), out)]));
        let runtime = RemoteSandboxRuntime::new(runner);
        let result = runtime
            .exec("hx-sbx_abc", "cargo build", None)
            .await
            .unwrap();
        assert_eq!(result.stdout, "built ok\n");
        assert_eq!(result.exit_code, 0);
    }

    #[tokio::test]
    async fn exec_with_a_workdir_passes_it_through() {
        let out = RemoteCommandOutput {
            stdout: String::new(),
            stderr: "boom".into(),
            exit_code: Some(2),
        };
        let expected = exec_command("hx-sbx_abc", "make", Some("/workspace/app"));
        let runner = Arc::new(RecordingRunner::new(vec![(expected.as_str(), out)]));
        let runtime = RemoteSandboxRuntime::new(runner);
        let result = runtime
            .exec("hx-sbx_abc", "make", Some("/workspace/app"))
            .await
            .unwrap();
        assert_eq!(result.stderr, "boom");
        assert_eq!(result.exit_code, 2);
    }

    #[tokio::test]
    async fn the_runtime_names_itself_so_status_distinguishes_it_from_local() {
        // Status output and capability probing tell the two runtimes apart by name; a remote
        // runtime that reported "docker" would be indistinguishable from a local one.
        let runner = Arc::new(RecordingRunner::new(vec![]));
        let runtime = RemoteSandboxRuntime::new(runner);
        assert_eq!(runtime.name(), "remote-docker");
    }
}

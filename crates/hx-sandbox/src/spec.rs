//! Sandbox specifications and the isolation ladder.
//!
//! ## The ladder
//!
//! "Isolated container" is not one thing. The distinction that matters for an agent harness is
//! **what happens when the code inside turns hostile**:
//!
//! | Level | Mechanism | Stops | Cost |
//! |---|---|---|---|
//! | [`IsolationLevel::L1`] | Shared kernel, dropped capabilities, no-new-privileges, read-only root | Misconfiguration, accidental damage, most supply-chain footguns | ~0 |
//! | [`IsolationLevel::L2`] | L1 + no capabilities at all, forced read-only root, non-root, user-namespace remapping | A process probing the kernel for a known CVE | Small |
//! | [`IsolationLevel::L3`] | L2 settings inside a VM-backed runtime (`runsc`, `kata`) | A kernel exploit, fully — it lands in the guest | Noticeable |
//!
//! The mapping from level to concrete container settings lives in [`SandboxSpec::host_settings`]
//! as a pure function, because this is the part that has to be *right* and the part that must be
//! reviewable. Reading a hundred-line `HostConfig` construction to work out whether `CAP_SYS_ADMIN`
//! survives is how privilege escalations get shipped.
//!
//! ## The default is the safe one
//!
//! Network off, capabilities dropped, non-root, bounded memory/CPU/PIDs, finite TTL. Every one of
//! those is a default an operator has to *explicitly* loosen. The failure mode of forgetting to
//! configure a sandbox should be a broken build, never a compromised host.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use hx_core::config::{IsolationLevel, SandboxProfile};

/// Whether an egress allowlist entry can actually be enforced by the proxy.
///
/// The proxy matches a `CONNECT` target by hostname (exact or `*.domain` suffix). A CIDR or a
/// raw IP is not a hostname, so the proxy cannot decide it — such an entry must be refused at
/// validation rather than quietly half-enforced. This is the one shape that genuinely remains
/// unenforceable by the current mechanism, and it is why [`SpecError::EgressNotEnforced`] still
/// exists.
fn is_proxy_enforceable(entry: &str) -> bool {
    let entry = entry.trim().trim_end_matches('.');
    if entry.is_empty() {
        return false;
    }
    let host = if let Some(domain) = entry.strip_prefix("*.") {
        domain
    } else {
        entry
    };
    // A hostname is letters/digits/hyphens separated by dots; anything else (a slash, a colon, a
    // space) is a CIDR or an address and cannot be matched by name.
    let looks_like_a_hostname = host.split('.').all(|label| {
        !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    });
    if !looks_like_a_hostname {
        return false;
    }
    // ...and the letter-shape test above is not sufficient on its own: a dotted IPv4 address is
    // entirely digits, dots and hyphens, so `10.0.0.1` passes it while being an address the proxy
    // cannot decide by name. Matching it as a "hostname" would produce an allowlist entry that is
    // silently never satisfied — a destination the operator believes they permitted and that no
    // connection ever reaches. `IpAddr::from_str` is the definitive test, so it is the one used.
    host.parse::<std::net::IpAddr>().is_err()
}

/// The user a sandbox runs as. Never root: a container escape from uid 0 is a much shorter path
/// to the host than one from an unprivileged user.
pub const SANDBOX_UID: &str = "1000:1000";

/// What to ask the engine for when a level wants user-namespace remapping.
///
/// `"private"` is the Docker API's spelling (`HostConfig.UsernsMode`). Podman's `keep-id` is a
/// *different mode* with different semantics, and it is not a valid `security_opt` for Docker —
/// see [`SandboxSpec::host_settings`].
pub const USERNS_REMAPPED: &str = "private";

/// Where the working tree is mounted inside the sandbox.
pub const DEFAULT_WORKSPACE_PATH: &str = "/workspace";

/// What to run, and under what constraints.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SandboxSpec {
    /// Name of the profile this came from, for logs and status output.
    pub profile: String,
    pub image: String,
    pub isolation: IsolationLevel,
    /// Fractional cores, e.g. `2.5`.
    pub cpus: f64,
    pub memory_mb: u64,
    /// Process ceiling. The fork-bomb guard.
    pub pids_max: i64,
    /// Workspace ceiling, enforced by the filesystem rather than by hope.
    pub workspace_mb: u64,
    /// Hard lifetime. A sandbox that nobody reaps is a resource leak with a nice name.
    pub ttl_secs: u64,
    /// Egress allowlist — hostnames or `*.domain` globs the sandbox may reach. Empty means no
    /// egress.
    ///
    /// Enforced by placing the sandbox on an internal Docker network (no gateway) and routing its
    /// outbound traffic through a proxy sidecar that admits only these destinations — see
    /// [`crate::egress`]. An entry that is not a hostname or a `*.domain` globe (a CIDR, an
    /// IP) cannot be enforced through that proxy, so such an allowlist is refused by
    /// [`SandboxSpec::validate`] rather than quietly accepted.
    pub egress_allow: Vec<String>,
    pub network: bool,
    pub readonly_rootfs: bool,
    /// Host path holding the working tree.
    pub workspace_host_path: String,
    /// Where it appears inside the sandbox.
    pub workspace_path: String,
    /// The user the sandbox runs as, as `uid:gid`.
    ///
    /// `None` means [`SANDBOX_UID`]. It is overridable because a hardcoded uid cannot write a
    /// bind-mounted workspace that belongs to somebody else: on a host whose user is not uid 1000
    /// — a CI runner, a Mac, most shared boxes — the sandbox runs, the mount works, and every write
    /// into it fails with `Permission denied`. [`SandboxSpec::adopt_workspace_owner`] is the
    /// supported way to set this; matching the workspace's owner is what keeps it writable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub env: Vec<(String, String)>,
}

impl SandboxSpec {
    /// Build a spec from a configured profile, filling in the defaults a profile did not state.
    pub fn from_profile(name: &str, profile: &SandboxProfile) -> Self {
        Self {
            profile: name.to_string(),
            image: profile.image.clone(),
            isolation: profile.isolation,
            cpus: if profile.cpus > 0.0 {
                profile.cpus
            } else {
                2.0
            },
            memory_mb: if profile.memory_mb > 0 {
                profile.memory_mb
            } else {
                4096
            },
            pids_max: if profile.pids_max > 0 {
                profile.pids_max as i64
            } else {
                2048
            },
            workspace_mb: if profile.workspace_mb > 0 {
                profile.workspace_mb
            } else {
                16_384
            },
            ttl_secs: if profile.ttl_secs > 0 {
                profile.ttl_secs
            } else {
                4 * 3600
            },
            egress_allow: profile.egress.clone(),
            network: profile.network,
            readonly_rootfs: profile.readonly_rootfs,
            workspace_host_path: String::new(),
            workspace_path: DEFAULT_WORKSPACE_PATH.to_string(),
            user: None,
            env: Vec::new(),
        }
    }

    /// Run the sandbox as whoever owns the workspace, so it can actually write there.
    ///
    /// A container whose uid does not match the bind-mounted directory's owner gets a read-only
    /// workspace in practice, whatever the mount options say. The workspace is also the only place
    /// the agent's work is expected to survive, so a mismatch breaks the sandbox's whole purpose
    /// with an error that looks like a filesystem problem.
    ///
    /// Callers that know the workspace owner should use this instead of setting [`SANDBOX_UID`]:
    /// it is I/O (a `stat`), which is why it is a builder step here and not a `host_settings`
    /// decision — that function stays pure and testable.
    ///
    /// Off Unix this is a no-op: there is no uid:gid to match, and Windows containers do not select
    /// their user that way, so `user` is left unset rather than filled with an invented id.
    pub fn adopt_workspace_owner(&mut self) -> Result<(), SpecError> {
        let path = self.workspace_host_path.clone();
        let metadata = std::fs::metadata(&path).map_err(|err| SpecError::WorkspaceOwner {
            path: path.clone(),
            reason: err.to_string(),
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // The numeric ids, not the names: the container's /etc/passwd has nothing to do with
            // the host's, and a name that means something on the host means nothing inside.
            self.user = Some(format!("{}:{}", metadata.uid(), metadata.gid()));
        }
        #[cfg(not(unix))]
        {
            // There is no uid:gid to adopt off Unix, and Windows containers do not select their
            // user this way. Leaving `user` unset is the honest outcome — inventing an id would be
            // worse than letting the engine use its default.
            let _ = metadata;
        }

        Ok(())
    }

    /// Reject specs that would produce an unsafe or unusable sandbox.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.image.trim().is_empty() {
            return Err(SpecError::NoImage);
        }
        if self.workspace_host_path.trim().is_empty() {
            return Err(SpecError::NoWorkspace);
        }
        if self.cpus <= 0.0 || !self.cpus.is_finite() {
            return Err(SpecError::BadCpus(self.cpus));
        }
        if self.memory_mb == 0 {
            return Err(SpecError::NoMemory);
        }
        if self.ttl_secs == 0 {
            return Err(SpecError::NoTtl);
        }
        // A sandbox with no process ceiling is a fork bomb waiting for a prompt injection.
        if self.pids_max <= 0 {
            return Err(SpecError::NoPidCeiling);
        }
        // An egress allowlist with networking off is almost always a mistake in the config —
        // the operator expects host A to be reachable and it silently is not.
        if !self.network && !self.egress_allow.is_empty() {
            return Err(SpecError::EgressWithoutNetwork(self.egress_allow.clone()));
        }
        // With networking *on*, a non-empty allowlist is enforced: the sandbox rides an internal
        // network whose only exit is a proxy that admits exactly these destinations (see `crate::egress`).
        // But only a hostname or a `*.domain` globe can be matched by that proxy; a CIDR or a raw IP
        // cannot be checked against an unresolved CONNECT target, so an allowlist that needs one is refused
        // rather than silently half-enforced.
        if self.network && !self.egress_allow.is_empty() {
            if let Some(unenforceable) = self.egress_allow.iter().find(|e| !is_proxy_enforceable(e))
            {
                return Err(SpecError::EgressNotEnforced(vec![unenforceable.clone()]));
            }
        }
        Ok(())
    }

    /// The concrete container settings this level implies.
    ///
    /// Pure on purpose: no Docker connection, no I/O, no defaults inherited from a daemon that
    /// might have been started with `--privileged`.
    pub fn host_settings(&self) -> HostSettings {
        let mut settings = HostSettings {
            privileged: false,
            // Non-root by default at every level, and overridable only by an explicit `user`:
            // whoever mounts a workspace for the agent has to be able to match its owner, or the
            // agent gets a read-only workspace and a permission error instead of a build.
            user: self.user.clone().unwrap_or_else(|| SANDBOX_UID.to_string()),
            cap_drop: vec!["ALL".to_string()],
            cap_add: Vec::new(),
            security_opt: vec!["no-new-privileges:true".to_string()],
            network_mode: if self.network { "bridge" } else { "none" }.to_string(),
            pids_limit: self.pids_max,
            nano_cpus: (self.cpus * 1_000_000_000.0) as i64,
            memory_bytes: (self.memory_mb * 1024 * 1024) as i64,
            // Equal to memory: a container that can swap around its limit is not limited.
            memory_swap_bytes: (self.memory_mb * 1024 * 1024) as i64,
            runtime: None,
            readonly_rootfs: self.readonly_rootfs,
            auto_remove: false,
            init: true,
            userns_mode: None,
            tmpfs: Vec::new(),
            binds: Vec::new(),
            dns: Vec::new(),
        };

        match self.isolation {
            IsolationLevel::L1 => {
                // L1 is a working development container: it needs to be able to install
                // packages into the root filesystem unless the profile says otherwise, so the
                // read-only root is honoured from the profile rather than forced.
                settings.cap_add = vec![
                    // Enough to build and install, and no more.
                    "CHOWN".to_string(),
                    "DAC_OVERRIDE".to_string(),
                    "FOWNER".to_string(),
                    "SETGID".to_string(),
                    "SETUID".to_string(),
                ];
            }
            IsolationLevel::L2 => {
                // No capabilities back at all: at this level the sandbox is expected to hold
                // code that is actively looking for a way out.
                settings.cap_add.clear();
                // A read-only root is non-negotiable here; a writable root is how you persist a
                // foothold across a reaped container.
                settings.readonly_rootfs = true;
                // No seccomp option is sent, and that is deliberate: an engine applies its default
                // seccomp profile to every container it starts. The option only exists to *change*
                // that — `seccomp=<path>`, or `seccomp=unconfined` — and `seccomp=default` is not
                // a value a Docker daemon accepts. It parses the value as a profile and fails:
                //   Decoding seccomp profile failed: invalid character 'd' looking for beginning
                // which made every L2 sandbox fail to start. The default filter is already applied;
                // a *stronger* one would have to be a shipped profile, not a keyword.
                //
                // User-namespace remapping, by contrast, does have a real field. Podman spells it
                // `--userns=keep-id` and putting that in `security_opt` is what a Docker daemon
                // rejects outright:
                //   invalid --security-opt 2: "userns=keep-id"
                // Docker's API takes the intent as `HostConfig.UsernsMode = "private"`: accepted on
                // a daemon with no remap configured (where it is a no-op), and honoured on one that
                // has it. So the request is always expressible and never fatal.
                settings.userns_mode = Some(USERNS_REMAPPED.to_string());
            }
            IsolationLevel::L3 => {
                settings.cap_add.clear();
                settings.readonly_rootfs = true;
                settings.userns_mode = Some(USERNS_REMAPPED.to_string());
                // The whole point of L3: the kernel inside is not the host's kernel. A container
                // escape is then a guest escape, which is a different and much harder problem.
                settings.runtime = Some("runsc".to_string());
            }
        }

        // Every level gets a writable scratch area, which is what makes a read-only root
        // usable rather than merely strict. `noexec` on /tmp because a dropped binary there is
        // the standard post-exploitation move.
        settings.tmpfs = vec![
            ("/tmp".to_string(), "rw,noexec,nosuid,size=1g".to_string()),
            (
                "/var/tmp".to_string(),
                "rw,noexec,nosuid,size=512m".to_string(),
            ),
            ("/run".to_string(), "rw,noexec,nosuid,size=64m".to_string()),
        ];

        if !self.workspace_host_path.is_empty() {
            settings.binds = vec![format!(
                "{}:{}:rw",
                self.workspace_host_path, self.workspace_path
            )];
        }

        settings
    }
}

/// Concrete container settings. A plain data structure so it can be asserted on in tests and
/// diffed in a review.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostSettings {
    pub privileged: bool,
    pub user: String,
    pub cap_drop: Vec<String>,
    pub cap_add: Vec<String>,
    pub security_opt: Vec<String>,
    pub network_mode: String,
    pub pids_limit: i64,
    pub nano_cpus: i64,
    pub memory_bytes: i64,
    pub memory_swap_bytes: i64,
    pub runtime: Option<String>,
    pub readonly_rootfs: bool,
    pub auto_remove: bool,
    pub init: bool,
    /// `HostConfig.UsernsMode`: `"private"` asks for remapping, `None` leaves the engine default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userns_mode: Option<String>,
    pub tmpfs: Vec<(String, String)>,
    pub binds: Vec<String>,
    /// `HostConfig.Dns`: name servers the container uses, by IP.
    ///
    /// Empty means the engine default, which is what every sandbox uses today: Docker's `Dns` field
    /// accepts addresses and not `host:port`, so a proxy sidecar cannot be named here. Kept as a
    /// field because an IP-address resolver is a legitimate future need, and an empty one is a
    /// no-op rather than a wrong answer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
}

impl HostSettings {
    pub fn has_cap(&self, capability: &str) -> bool {
        self.cap_add
            .iter()
            .any(|c| c.eq_ignore_ascii_case(capability))
    }

    pub fn drops_all_capabilities(&self) -> bool {
        self.cap_drop.iter().any(|c| c == "ALL")
    }

    pub fn has_no_new_privileges(&self) -> bool {
        self.security_opt
            .iter()
            .any(|o| o.starts_with("no-new-privileges"))
    }

    /// Whether user-namespace remapping was requested.
    ///
    /// A *request*, not a guarantee: the engine applies it only when its daemon is configured for
    /// remapping. Reading this as "uid 0 inside is definitely not uid 0 outside" would be reading
    /// more into the setting than it says, which is why the name does not claim enforcement.
    pub fn requests_userns_remapping(&self) -> bool {
        self.userns_mode.as_deref() == Some(USERNS_REMAPPED)
    }

    pub fn is_networked(&self) -> bool {
        self.network_mode != "none"
    }

    /// Whether the sandbox is denied access to the kernel by something stronger than namespaces.
    pub fn has_kernel_isolation(&self) -> bool {
        self.runtime.is_some()
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum SpecError {
    #[error("sandbox profile has no image; set `image:` to something that exists")]
    NoImage,

    #[error("sandbox has no workspace host path; nothing would be mounted")]
    NoWorkspace,

    #[error("cpu limit must be a positive finite number, got {0}")]
    BadCpus(f64),

    #[error("memory limit must be greater than zero")]
    NoMemory,

    #[error("ttl must be greater than zero; an unexpiring sandbox is a leak")]
    NoTtl,

    #[error("pids_max must be greater than zero; without a process ceiling a fork bomb wins")]
    NoPidCeiling,

    #[error(
        "egress allowlist {0:?} is set but networking is disabled — enable `network: true` or \
         drop the allowlist"
    )]
    EgressWithoutNetwork(Vec<String>),

    #[error(
        "egress allowlist entry {0:?} cannot be enforced: the egress proxy matches destinations \
         by hostname, and {0:?} is not a hostname or a `*.domain` globe. Write the destination \
         as a hostname, or as `*.domain` to allow every subdomain."
    )]
    EgressNotEnforced(Vec<String>),

    #[error("could not determine the owner of the workspace {path}: {reason}")]
    WorkspaceOwner { path: String, reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(isolation: IsolationLevel) -> SandboxSpec {
        SandboxSpec {
            profile: "test".into(),
            image: "ubuntu:24.04".into(),
            isolation,
            cpus: 2.0,
            memory_mb: 4096,
            pids_max: 2048,
            workspace_mb: 16_384,
            ttl_secs: 3600,
            egress_allow: Vec::new(),
            network: false,
            readonly_rootfs: false,
            workspace_host_path: "/tmp/hx/ws".into(),
            workspace_path: DEFAULT_WORKSPACE_PATH.into(),
            user: None,
            env: Vec::new(),
        }
    }

    // ---- shared guarantees across every level ----

    #[test]
    fn no_level_is_ever_privileged() {
        for level in [IsolationLevel::L1, IsolationLevel::L2, IsolationLevel::L3] {
            let settings = spec(level).host_settings();
            assert!(!settings.privileged, "{level:?} must not be privileged");
        }
    }

    #[test]
    fn every_level_drops_all_capabilities_and_sets_no_new_privileges() {
        for level in [IsolationLevel::L1, IsolationLevel::L2, IsolationLevel::L3] {
            let settings = spec(level).host_settings();
            assert!(settings.drops_all_capabilities(), "{level:?}");
            assert!(settings.has_no_new_privileges(), "{level:?}");
        }
    }

    #[test]
    fn no_level_hands_back_cap_sys_admin_or_ptrace() {
        // These two are the ones that turn a container into a host.
        for level in [IsolationLevel::L1, IsolationLevel::L2, IsolationLevel::L3] {
            let settings = spec(level).host_settings();
            assert!(
                !settings.has_cap("SYS_ADMIN"),
                "{level:?} granted SYS_ADMIN"
            );
            assert!(
                !settings.has_cap("SYS_PTRACE"),
                "{level:?} granted SYS_PTRACE"
            );
            assert!(
                !settings.has_cap("SYS_MODULE"),
                "{level:?} granted SYS_MODULE"
            );
            assert!(
                !settings.has_cap("NET_ADMIN"),
                "{level:?} granted NET_ADMIN"
            );
        }
    }

    #[test]
    fn networking_is_off_unless_explicitly_enabled() {
        assert_eq!(
            spec(IsolationLevel::L1).host_settings().network_mode,
            "none"
        );
        assert!(!spec(IsolationLevel::L1).host_settings().is_networked());
    }

    #[test]
    fn a_process_ceiling_is_always_applied() {
        // The fork-bomb guard must never be absent, at any level.
        for level in [IsolationLevel::L1, IsolationLevel::L2, IsolationLevel::L3] {
            assert!(spec(level).host_settings().pids_limit > 0, "{level:?}");
        }
    }

    #[test]
    fn init_is_enabled_so_zombies_are_reaped() {
        // Without this, a long-running sandbox accumulates zombies from every build it runs.
        assert!(spec(IsolationLevel::L1).host_settings().init);
    }

    #[test]
    fn scratch_space_is_writable_but_not_executable() {
        let settings = spec(IsolationLevel::L2).host_settings();
        let tmp = settings
            .tmpfs
            .iter()
            .find(|(path, _)| path == "/tmp")
            .expect("/tmp must be writable");
        assert!(tmp.1.contains("rw"), "{}", tmp.1);
        assert!(
            tmp.1.contains("noexec"),
            "a dropped binary in /tmp is the standard next step: {}",
            tmp.1
        );
    }

    #[test]
    fn the_workspace_is_mounted_read_write_at_the_expected_path() {
        let settings = spec(IsolationLevel::L1).host_settings();
        assert_eq!(settings.binds, vec!["/tmp/hx/ws:/workspace:rw"]);
    }

    #[test]
    fn resource_limits_convert_to_the_units_the_runtime_wants() {
        let mut s = spec(IsolationLevel::L1);
        s.cpus = 2.5;
        s.memory_mb = 1024;
        let settings = s.host_settings();

        // Docker wants nanocpus and bytes, not cores and mebibytes.
        assert_eq!(settings.nano_cpus, 2_500_000_000);
        assert_eq!(settings.memory_bytes, 1024 * 1024 * 1024);
    }

    #[test]
    fn swap_equals_memory_so_the_limit_cannot_be_evaded() {
        let settings = spec(IsolationLevel::L1).host_settings();
        assert_eq!(
            settings.memory_swap_bytes, settings.memory_bytes,
            "allowing swap above the memory limit makes the limit advisory"
        );
    }

    // ---- what distinguishes the levels ----

    #[test]
    fn l1_is_a_working_development_container() {
        let settings = spec(IsolationLevel::L1).host_settings();
        assert!(
            settings.has_cap("CHOWN") && settings.has_cap("SETUID"),
            "L1 must be able to install packages, or it is useless for development"
        );
        assert!(!settings.has_kernel_isolation());
        assert!(
            !settings.readonly_rootfs,
            "L1 honours the profile's choice of a writable root"
        );
    }

    #[test]
    fn l2_hands_back_no_capabilities_and_forces_a_read_only_root() {
        let mut s = spec(IsolationLevel::L2);
        s.readonly_rootfs = false; // even when the profile asks for a writable root
        let settings = s.host_settings();

        assert!(settings.cap_add.is_empty(), "L2 grants nothing back");
        assert!(
            settings.readonly_rootfs,
            "L2 must override a profile that asks for a writable root"
        );
    }

    #[test]
    fn l2_remaps_user_namespaces_and_does_not_run_as_root() {
        let settings = spec(IsolationLevel::L2).host_settings();
        assert!(
            settings.requests_userns_remapping(),
            "L2 asks for user-namespace remapping: {:?}",
            settings.userns_mode
        );
        assert_ne!(settings.user, "0:0");
        assert_ne!(settings.user, "root");
    }

    #[test]
    fn no_engine_rejected_security_option_is_ever_sent() {
        // Two regressions are guarded here, both of the same kind: a container-engine keyword that
        // is not a keyword. Both were sent as `security_opt`, both made the daemon refuse to run
        // the container, and neither was visible to a test that only asserted the struct:
        //
        //   userns=keep-id   invalid --security-opt 2: "userns=keep-id"     (podman spelling)
        //   seccomp=default  Decoding seccomp profile failed: invalid character 'd' …
        //
        // The second is the subtler one: an engine already applies its default seccomp profile to
        // every container, so the *option* only exists to change it, and "default" is not a value
        // it accepts.
        for level in [IsolationLevel::L1, IsolationLevel::L2, IsolationLevel::L3] {
            let settings = spec(level).host_settings();
            for option in &settings.security_opt {
                assert!(
                    !option.starts_with("userns="),
                    "{level:?} sends the security option {option:?}, which the engine rejects"
                );
                assert!(
                    !option.starts_with("seccomp=default"),
                    "{level:?} sends the security option {option:?}, which the engine rejects"
                );
            }
        }

        // The confinement those two options were standing in for still reaches the engine, through
        // the mechanisms that express it: a read-only root, no capabilities, non-root, and the
        // user-namespace field.
        let l2 = spec(IsolationLevel::L2).host_settings();
        assert!(l2.readonly_rootfs);
        assert!(l2.cap_add.is_empty());
        assert!(l2.drops_all_capabilities());
        assert_eq!(l2.userns_mode.as_deref(), Some(USERNS_REMAPPED));
        assert_ne!(l2.user, "0:0");
    }

    #[test]
    fn remapping_is_only_requested_by_the_levels_that_need_it() {
        assert!(!spec(IsolationLevel::L1)
            .host_settings()
            .requests_userns_remapping());
        assert!(spec(IsolationLevel::L2)
            .host_settings()
            .requests_userns_remapping());
        assert!(spec(IsolationLevel::L3)
            .host_settings()
            .requests_userns_remapping());
    }

    #[test]
    fn l3_runs_on_a_vm_backed_runtime() {
        let settings = spec(IsolationLevel::L3).host_settings();
        assert!(
            settings.has_kernel_isolation(),
            "L3 exists precisely to deny the sandbox the host kernel"
        );
        assert_eq!(settings.runtime.as_deref(), Some("runsc"));
    }

    #[test]
    fn the_ladder_is_monotonic_in_strength() {
        // Each level must be at least as strict as the one below it. A ladder that loosens
        // somewhere is a trap for whoever reads the table and trusts it.
        let l1 = spec(IsolationLevel::L1).host_settings();
        let l2 = spec(IsolationLevel::L2).host_settings();
        let l3 = spec(IsolationLevel::L3).host_settings();

        assert!(l2.cap_add.len() <= l1.cap_add.len(), "L2 must not add caps");
        assert!(l2.security_opt.len() >= l1.security_opt.len());
        assert!(l3.has_kernel_isolation() && !l1.has_kernel_isolation());
        assert!(l2.readonly_rootfs && l3.readonly_rootfs);
        assert!(
            l2.requests_userns_remapping() && l3.requests_userns_remapping(),
            "the levels that hold hostile code ask for remapping; L1 is a dev container and does not"
        );
    }

    #[test]
    fn all_levels_still_have_identical_resource_ceilings() {
        // Isolation level is about *containment*, not about how much CPU you get. Conflating
        // the two makes the level a performance setting, which is how it gets downgraded.
        let l1 = spec(IsolationLevel::L1).host_settings();
        let l3 = spec(IsolationLevel::L3).host_settings();
        assert_eq!(l1.nano_cpus, l3.nano_cpus);
        assert_eq!(l1.memory_bytes, l3.memory_bytes);
        assert_eq!(l1.pids_limit, l3.pids_limit);
    }

    // ---- defaults and profile conversion ----

    #[test]
    fn profile_defaults_are_bounded_not_unlimited() {
        let profile = SandboxProfile::default();
        let s = SandboxSpec::from_profile("default", &profile);

        // A profile that states nothing must still produce something bounded.
        assert!(s.cpus > 0.0);
        assert!(s.memory_mb > 0);
        assert!(
            s.pids_max > 0,
            "no process ceiling would be a fork-bomb invitation"
        );
        assert!(s.ttl_secs > 0, "an unexpiring sandbox is a resource leak");
    }

    #[test]
    fn an_explicit_profile_value_wins_over_the_default() {
        let profile = SandboxProfile {
            image: "node:22".into(),
            cpus: 8.0,
            memory_mb: 32_768,
            pids_max: 512,
            ttl_secs: 60,
            network: true,
            ..Default::default()
        };
        let s = SandboxSpec::from_profile("node", &profile);
        assert_eq!(s.image, "node:22");
        assert_eq!(s.cpus, 8.0);
        assert_eq!(s.memory_mb, 32_768);
        assert_eq!(s.ttl_secs, 60);
        assert!(s.host_settings().is_networked());
    }

    // ---- validation ----

    #[test]
    fn an_empty_image_is_rejected() {
        let mut s = spec(IsolationLevel::L1);
        s.image = "   ".into();
        assert_eq!(s.validate(), Err(SpecError::NoImage));
    }

    #[test]
    fn a_missing_workspace_path_is_rejected() {
        let mut s = spec(IsolationLevel::L1);
        s.workspace_host_path = String::new();
        assert_eq!(s.validate(), Err(SpecError::NoWorkspace));
    }

    #[test]
    fn zero_limits_are_rejected_rather_than_silently_meaning_unlimited() {
        let mut s = spec(IsolationLevel::L1);
        s.memory_mb = 0;
        assert_eq!(s.validate(), Err(SpecError::NoMemory));

        let mut s = spec(IsolationLevel::L1);
        s.pids_max = 0;
        assert_eq!(s.validate(), Err(SpecError::NoPidCeiling));

        let mut s = spec(IsolationLevel::L1);
        s.ttl_secs = 0;
        assert_eq!(s.validate(), Err(SpecError::NoTtl));
    }

    #[test]
    fn non_finite_cpu_counts_are_rejected() {
        let mut s = spec(IsolationLevel::L1);
        s.cpus = f64::NAN;
        assert!(matches!(s.validate(), Err(SpecError::BadCpus(_))));

        let mut s = spec(IsolationLevel::L1);
        s.cpus = -1.0;
        assert!(matches!(s.validate(), Err(SpecError::BadCpus(_))));
    }

    #[test]
    fn an_egress_allowlist_without_networking_is_a_configuration_error() {
        // This catches a real class of silent breakage: it would be tedious to diagnose.
        let mut s = spec(IsolationLevel::L2);
        s.network = false;
        s.egress_allow = vec!["crates.io".into()];
        assert_eq!(
            s.validate(),
            Err(SpecError::EgressWithoutNetwork(vec!["crates.io".into()]))
        );
    }

    #[test]
    fn a_hostname_or_domain_allowlist_is_now_accepted_and_enforced() {
        // The setting used to be refused wholesale because nothing enforced it; it is now enforced
        // by the internal-network + proxy mechanism. A plain hostname or `*.domain` allowlist must
        // therefore validate cleanly — refusing it now would be refusing the enforced middle ground the
        // operator asked for.
        let mut s = spec(IsolationLevel::L1);
        s.network = true;
        s.egress_allow = vec!["crates.io".into(), "*.crates.io".into()];
        assert_eq!(s.validate(), Ok(()));
    }

    #[test]
    fn an_allowlist_entry_the_proxy_cannot_match_is_refused() {
        // The proxy matches a CONNECT target by hostname. A CIDR or a raw IP cannot be decided
        // by name, so accepting it would be a half-enforced allowlist — the one shape that
        // genuinely remains unenforceable, and the reason `EgressNotEnforced` still exists.
        for bad in ["10.0.0.0/8", "10.0.0.1", "1.2.3.4:443"] {
            let mut s = spec(IsolationLevel::L1);
            s.network = true;
            s.egress_allow = vec![bad.into()];
            let err = s.validate().unwrap_err();
            assert_eq!(
                err,
                SpecError::EgressNotEnforced(vec![bad.to_string()]),
                "{bad}"
            );
            let message = err.to_string();
            assert!(message.contains("cannot be enforced"), "{message}");
            assert!(
                message.contains("hostname") && message.contains("*.domain"),
                "the error has to say what shape is allowed: {message}"
            );
        }
    }

    #[test]
    fn an_explicit_user_overrides_the_default_at_every_level() {
        // A hardcoded uid is why this exists: the workspace is bind-mounted from the host, and the
        // container has to run as someone who can write it.
        for level in [IsolationLevel::L1, IsolationLevel::L2, IsolationLevel::L3] {
            let mut s = spec(level);
            s.user = Some("4242:4242".to_string());
            assert_eq!(s.host_settings().user, "4242:4242", "{level:?}");
        }
    }

    #[test]
    fn the_default_user_is_not_root() {
        assert_eq!(spec(IsolationLevel::L2).host_settings().user, SANDBOX_UID);
        assert_ne!(SANDBOX_UID, "0:0");
    }

    #[test]
    fn the_sandbox_can_be_told_to_run_as_the_workspace_owner() {
        // The defect this closes: on a host whose user is not uid 1000 — a CI runner, a Mac, most
        // shared boxes — the sandbox started, the bind mount succeeded, and every write into the
        // workspace failed with `Permission denied`.
        let dir = tempfile::tempdir().unwrap();
        let mut s = spec(IsolationLevel::L2);
        s.workspace_host_path = dir.path().to_string_lossy().into_owned();

        s.adopt_workspace_owner().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let owner = std::fs::metadata(dir.path()).unwrap();
            assert_eq!(
                s.host_settings().user,
                format!("{}:{}", owner.uid(), owner.gid()),
                "the sandbox has to run as whoever owns the mount"
            );
        }
        #[cfg(not(unix))]
        {
            // Nothing to adopt off Unix: Windows containers do not pick their user as a uid:gid,
            // so the engine default is left alone rather than an invented id being sent.
            assert!(s.user.is_none());
            assert_eq!(s.host_settings().user, SANDBOX_UID);
        }
    }

    #[test]
    fn adopting_a_workspace_that_does_not_exist_says_so_and_changes_nothing() {
        let mut s = spec(IsolationLevel::L2);
        s.workspace_host_path = "/definitely/not/here".into();

        let err = s.adopt_workspace_owner().unwrap_err();
        assert!(
            err.to_string().contains("could not determine the owner"),
            "{err}"
        );
        assert!(
            s.user.is_none(),
            "a failed stat must not half-configure the sandbox"
        );
    }

    #[test]
    fn networking_without_an_allowlist_is_still_allowed() {
        // The other way to have a networked sandbox: say so, and mean it.
        let mut s = spec(IsolationLevel::L1);
        s.network = true;
        assert_eq!(s.validate(), Ok(()));
    }

    #[test]
    fn a_valid_sandbox_validates_and_a_default_profile_produces_one() {
        assert_eq!(spec(IsolationLevel::L1).validate(), Ok(()));

        let profile = SandboxProfile::default();
        let mut s = SandboxSpec::from_profile("default", &profile);
        s.workspace_host_path = "/tmp/hx/ws".into();
        assert_eq!(
            s.validate(),
            Ok(()),
            "the shipped default profile must be valid"
        );
    }

    #[test]
    fn settings_serialise_for_status_output() {
        let settings = spec(IsolationLevel::L2).host_settings();
        let json = serde_json::to_string(&settings).unwrap();
        assert!(json.contains("no-new-privileges"));
        assert!(json.contains("\"network_mode\":\"none\""));
    }
}

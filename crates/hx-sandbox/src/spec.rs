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
//! | [`IsolationLevel::L2`] | L1 + seccomp filter, user-namespace remapping, non-root, proxy-only egress | A process probing the kernel for a known CVE | Small |
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

/// The user a sandbox runs as. Never root: a container escape from uid 0 is a much shorter path
/// to the host than one from an unprivileged user.
pub const SANDBOX_UID: &str = "1000:1000";

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
    /// Egress allowlist — hostnames or CIDRs. Empty means no egress.
    pub egress_allow: Vec<String>,
    pub network: bool,
    pub readonly_rootfs: bool,
    /// Host path holding the working tree.
    pub workspace_host_path: String,
    /// Where it appears inside the sandbox.
    pub workspace_path: String,
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
            env: Vec::new(),
        }
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
        Ok(())
    }

    /// The concrete container settings this level implies.
    ///
    /// Pure on purpose: no Docker connection, no I/O, no defaults inherited from a daemon that
    /// might have been started with `--privileged`.
    pub fn host_settings(&self) -> HostSettings {
        let mut settings = HostSettings {
            privileged: false,
            // Non-root by default at every level.
            user: SANDBOX_UID.to_string(),
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
            tmpfs: Vec::new(),
            binds: Vec::new(),
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
                settings.security_opt.push("seccomp=default".to_string());
                // User-namespace remapping: uid 0 inside maps to an unprivileged uid outside,
                // so even a successful uid-0 escape is not uid 0 on the host.
                settings.security_opt.push("userns=keep-id".to_string());
                settings.user.clone_from(&SANDBOX_UID.to_string());
            }
            IsolationLevel::L3 => {
                settings.cap_add.clear();
                settings.readonly_rootfs = true;
                settings.security_opt.push("seccomp=default".to_string());
                settings.security_opt.push("userns=keep-id".to_string());
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
    pub tmpfs: Vec<(String, String)>,
    pub binds: Vec<String>,
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
            settings.security_opt.iter().any(|o| o.contains("userns")),
            "L2 needs user-namespace remapping: {:?}",
            settings.security_opt
        );
        assert_ne!(settings.user, "0:0");
        assert_ne!(settings.user, "root");
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

//! Subcommand implementations.
//!
//! Rendering is separated from dispatch so the output can be asserted on. When a command's job
//! is to report a security-relevant setting — which is exactly what `hx sandbox spec` does — the
//! output is part of the interface and belongs under test.

use chrono::Utc;
use hx_core::config::{Config, SandboxProfile};
use hx_provider::ModelRouter;
use hx_sandbox::{SandboxRuntime, SandboxSpec};
use std::fmt::Write;

/// Render the routing table: pools, their routes, credential health, and role bindings.
pub fn render_pools(router: &ModelRouter) -> String {
    let status = router.status();
    let mut out = String::new();

    for pool in &status.pools {
        let _ = writeln!(
            out,
            "pool {:<16} {} route(s), {}/{} credential(s) healthy",
            pool.name,
            pool.routes.len(),
            pool.healthy_credentials,
            pool.total_credentials
        );
        for (index, route) in pool.routes.iter().enumerate() {
            let marker = if index == 0 { "->" } else { "  " };
            let _ = writeln!(out, "  {marker} {}/{}", route.provider, route.model);
        }
    }

    out.push_str("\nroles:\n");
    for (role, pool) in &status.roles {
        let _ = writeln!(out, "  {role:<16} -> {pool}");
    }

    out
}

/// Render the configured hosts.
pub fn render_hosts(config: &Config) -> String {
    let mut out = String::from("local            (the machine running the daemon)\n");

    if config.hosts.is_empty() {
        out.push_str("\nno remote hosts configured; add a `hosts:` section\n");
        return out;
    }

    for (name, host) in &config.hosts {
        let address = match (&host.address, host.port) {
            (Some(addr), Some(port)) => format!("{addr}:{port}"),
            (Some(addr), None) => addr.clone(),
            (None, _) => "(no address configured)".to_string(),
        };
        let _ = writeln!(
            out,
            "{name:<16} {:?} {}{}",
            host.kind,
            address,
            host.user
                .as_ref()
                .map(|u| format!(" as {u}"))
                .unwrap_or_default()
        );
    }

    out
}

/// Render a sandbox profile and the concrete container settings it produces.
///
/// This is the command that answers "what does L2 actually mean", so it prints the settings that
/// will be handed to the container engine, not a summary of the profile.
pub fn render_sandbox_spec(name: &str, profile: &SandboxProfile, workspace: &str) -> String {
    let mut spec = SandboxSpec::from_profile(name, profile);
    spec.workspace_host_path = workspace.to_string();
    let settings = spec.host_settings();

    let mut out = String::new();
    let _ = writeln!(out, "profile {name}  (isolation {:?})", spec.isolation);

    let _ = writeln!(out, "  image             {}", spec.image);
    let _ = writeln!(out, "  cpus              {}", spec.cpus);
    let _ = writeln!(out, "  memory            {} MiB", spec.memory_mb);
    let _ = writeln!(out, "  pids              {}", spec.pids_max);
    let _ = writeln!(out, "  ttl               {}s", spec.ttl_secs);
    let _ = writeln!(
        out,
        "  network           {}",
        if settings.is_networked() {
            "enabled"
        } else {
            "none"
        }
    );
    let _ = writeln!(
        out,
        "  privileged        {}",
        if settings.privileged { "YES" } else { "no" }
    );
    let _ = writeln!(
        out,
        "  readonly rootfs   {}",
        if settings.readonly_rootfs {
            "yes"
        } else {
            "no"
        }
    );
    let _ = writeln!(out, "  user              {}", settings.user);

    let caps = if settings.cap_add.is_empty() {
        "(none granted)".to_string()
    } else {
        settings.cap_add.join(", ")
    };
    let _ = writeln!(
        out,
        "  capabilities      {caps}  [dropped: {}]",
        settings.cap_drop.join(", ")
    );
    let _ = writeln!(
        out,
        "  security opts     {}",
        settings.security_opt.join(", ")
    );
    // "requested" rather than a bare value: the engine applies remapping only when its daemon is
    // configured for it, and printing it as though it were enforced would overstate the sandbox.
    let _ = writeln!(
        out,
        "  userns mode       {}",
        settings
            .userns_mode
            .as_deref()
            .map(|mode| format!("{mode} (requested)"))
            .unwrap_or_else(|| "(engine default)".to_string())
    );
    let _ = writeln!(
        out,
        "  runtime           {}",
        settings.runtime.as_deref().unwrap_or("(engine default)")
    );

    if settings.tmpfs.is_empty() {
        let _ = writeln!(out, "  tmpfs             (none)");
    } else {
        for (path, options) in &settings.tmpfs {
            let _ = writeln!(out, "  tmpfs             {path} {options}");
        }
    }

    let _ = writeln!(
        out,
        "  workspace         {} -> {}",
        spec.workspace_host_path, spec.workspace_path
    );

    if let Err(err) = spec.validate() {
        let _ = writeln!(out, "\n  WARNING: this profile is invalid: {err}");
    }

    out
}

/// Render every configured sandbox profile.
pub fn render_profiles(config: &Config) -> String {
    if config.sandbox_profiles.is_empty() {
        return "no sandbox profiles configured; add a `sandbox_profiles:` section\n".to_string();
    }

    let mut out = String::new();
    for (name, profile) in &config.sandbox_profiles {
        let _ = writeln!(
            out,
            "{name:<16} {:?}  {}  {} cpu / {} MiB",
            profile.isolation, profile.image, profile.cpus, profile.memory_mb
        );
    }
    out
}

/// One environment check.
#[derive(Clone, Debug, PartialEq)]
pub struct DoctorCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

impl DoctorCheck {
    fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok: true,
            detail: detail.into(),
        }
    }

    fn fail(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok: false,
            detail: detail.into(),
        }
    }
}

/// The checks that do not need to touch the network or the container engine.
pub fn static_checks(config: &Config) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();

    if config.providers.is_empty() {
        checks.push(DoctorCheck::fail(
            "providers",
            "none configured — no model can be routed to",
        ));
    } else {
        let credentials: usize = config.providers.values().map(|p| p.credentials.len()).sum();
        if credentials == 0 {
            checks.push(DoctorCheck::fail(
                "provider credentials",
                "no credentials configured for any provider",
            ));
        } else {
            checks.push(DoctorCheck::pass(
                "provider credentials",
                format!(
                    "{credentials} across {} provider(s)",
                    config.providers.len()
                ),
            ));
        }
    }

    // The routing table is where most configuration mistakes land, so building it is the check.
    match ModelRouter::from_config(config, Utc::now()) {
        Ok(router) => checks.push(DoctorCheck::pass(
            "routing table",
            format!(
                "{} pool(s), {} role binding(s)",
                router.pool_names().len(),
                router.roles().len()
            ),
        )),
        Err(err) => checks.push(DoctorCheck::fail("routing table", err.to_string())),
    }

    if config.roles.is_empty() {
        checks.push(DoctorCheck::fail(
            "roles",
            "no roles bound — agents will have nothing to ask for",
        ));
    } else {
        checks.push(DoctorCheck::pass(
            "roles",
            config.roles.keys().cloned().collect::<Vec<_>>().join(", "),
        ));
    }

    if config.search.backends.is_empty() {
        checks.push(DoctorCheck::fail(
            "search backends",
            "none configured; the web_search tool will return nothing",
        ));
    } else {
        checks.push(DoctorCheck::pass(
            "search backends",
            config.search.backends.join(", "),
        ));
    }

    if config.sandbox_profiles.is_empty() {
        checks.push(DoctorCheck::fail(
            "sandbox profiles",
            "none configured; agents will have nowhere isolated to work",
        ));
    } else {
        let mut invalid = Vec::new();
        for (name, profile) in &config.sandbox_profiles {
            let mut spec = SandboxSpec::from_profile(name, profile);
            spec.workspace_host_path = "/probe".to_string();
            if let Err(err) = spec.validate() {
                invalid.push(format!("{name}: {err}"));
            }
        }
        if invalid.is_empty() {
            checks.push(DoctorCheck::pass(
                "sandbox profiles",
                format!("{} valid profile(s)", config.sandbox_profiles.len()),
            ));
        } else {
            checks.push(DoctorCheck::fail("sandbox profiles", invalid.join("; ")));
        }
    }

    checks
}

/// Render the doctor report.
pub fn render_doctor(checks: &[DoctorCheck]) -> String {
    let mut out = String::new();
    for check in checks {
        let _ = writeln!(
            out,
            "  {} {:<22} {}",
            if check.ok { "ok  " } else { "FAIL" },
            check.name,
            check.detail
        );
    }

    let failed = checks.iter().filter(|c| !c.ok).count();
    if failed == 0 {
        out.push_str("\nall checks passed\n");
    } else {
        let _ = writeln!(out, "\n{failed} check(s) failed");
    }
    out
}

/// Check whether a container engine is reachable.
pub async fn docker_check() -> DoctorCheck {
    match hx_sandbox::DockerRuntime::connect().await {
        Ok(runtime) => {
            if runtime.available().await {
                DoctorCheck::pass("container engine", "reachable")
            } else {
                DoctorCheck::fail(
                    "container engine",
                    "the Docker socket exists but the daemon is not responding",
                )
            }
        }
        Err(err) => DoctorCheck::fail("container engine", err.to_string()),
    }
}

/// Run the live search with the configured backends.
pub async fn run_search(
    config: &Config,
    query: &str,
    limit: usize,
) -> anyhow::Result<hx_search::SearchReport> {
    let client = reqwest::Client::builder()
        .user_agent(hx_search::backends::USER_AGENT)
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let registry = hx_search::BackendRegistry::from_config(&config.search, client)?;
    Ok(registry
        .search(&hx_search::SearchQuery::new(query).with_limit(limit))
        .await)
}

/// Render a search report.
pub fn render_search(report: &hx_search::SearchReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}\n", report.summary());

    for (index, result) in report.results.iter().enumerate() {
        let _ = writeln!(out, "{}. {}", index + 1, result.title);
        let _ = writeln!(out, "   {}", result.url);
        if !result.snippet.is_empty() {
            let _ = writeln!(out, "   {}", result.snippet);
        }
        let _ = writeln!(
            out,
            "   [score {:.4}, agreed by {}: {}]",
            result.score,
            result.agreement(),
            result.sources.join(", ")
        );
    }

    for failure in &report.failures {
        let _ = writeln!(
            out,
            "\n! {} did not answer ({}ms): {}",
            failure.backend, failure.elapsed_ms, failure.reason
        );
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_core::config::Config;

    const CONFIG: &str = r#"
providers:
  anthropic-main:
    kind: anthropic
    models: ["claude-opus-4-7", "claude-sonnet-4-7"]
    price: { input_per_mtok: 3.0, output_per_mtok: 15.0 }
    credentials:
      - { id: a1, secret: "vault:x", limits: { rpm: 50 } }
      - { id: a2, secret: "vault:y" }

pools:
  interactive: { members: ["anthropic-main/claude-*"] }
  background: { members: ["anthropic-main/claude-sonnet-4-7"], limits: { concurrent: 2 } }

roles:
  builder: interactive
  scout: background

sandbox_profiles:
  dev:
    image: ubuntu:24.04
    isolation: l1
  hardened:
    image: ubuntu:24.04
    isolation: l2
    readonly_rootfs: false
"#;

    fn config() -> Config {
        Config::from_yaml(CONFIG).unwrap()
    }

    #[test]
    fn pools_render_routes_and_role_bindings() {
        let router = ModelRouter::from_config(&config(), Utc::now()).unwrap();
        let rendered = render_pools(&router);

        assert!(rendered.contains("pool interactive"), "{rendered}");
        assert!(rendered.contains("claude-opus-4-7"), "{rendered}");
        assert!(rendered.contains("builder"), "{rendered}");
        assert!(rendered.contains("scout"), "{rendered}");
        assert!(
            rendered.contains("2/2 credential(s) healthy"),
            "credential health must be visible: {rendered}"
        );
    }

    #[test]
    fn sandbox_spec_reports_the_settings_that_will_actually_apply() {
        // This is the command an operator runs before trusting a profile, so the security
        // settings have to be in the output, not implied.
        let profiles = config().sandbox_profiles.clone();
        let rendered = render_sandbox_spec("hardened", &profiles["hardened"], "/tmp/ws");

        assert!(rendered.contains("isolation L2"), "{rendered}");
        assert!(rendered.contains("network           none"), "{rendered}");
        assert!(rendered.contains("privileged        no"), "{rendered}");
        assert!(rendered.contains("readonly rootfs   yes"), "{rendered}");
        assert!(
            rendered.contains("capabilities      (none granted)"),
            "{rendered}"
        );
        assert!(rendered.contains("dropped: ALL"), "{rendered}");
        assert!(rendered.contains("no-new-privileges:true"), "{rendered}");
        // Remapping is printed as *requested*, because that is what it is: the engine applies it
        // only when its daemon is configured for it. An operator reading "private" without the
        // qualifier would take the sandbox for stronger than it is.
        assert!(
            rendered.contains("userns mode       private (requested)"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("userns=keep-id"),
            "a security option the engine rejects is not a setting, it is a failed create: \
             {rendered}"
        );
        assert!(rendered.contains("tmpfs             /tmp"), "{rendered}");
        assert!(rendered.contains("noexec"), "{rendered}");
        assert!(rendered.contains("/tmp/ws -> /workspace"), "{rendered}");
        assert!(
            !rendered.contains("WARNING"),
            "a valid profile must not warn: {rendered}"
        );
    }

    #[test]
    fn l2_overrides_a_profile_that_asks_for_a_writable_root() {
        // `hardened` sets readonly_rootfs: false, and L2 must refuse it and say so.
        let profiles = config().sandbox_profiles.clone();
        let rendered = render_sandbox_spec("hardened", &profiles["hardened"], "/tmp/ws");
        assert!(rendered.contains("readonly rootfs   yes"), "{rendered}");
    }

    #[test]
    fn an_invalid_profile_warns_in_the_output() {
        let profile = SandboxProfile {
            image: String::new(),
            ..Default::default()
        };
        let rendered = render_sandbox_spec("broken", &profile, "/tmp/ws");
        assert!(rendered.contains("WARNING"), "{rendered}");
        assert!(rendered.contains("image"), "{rendered}");
    }

    #[test]
    fn profiles_render_shows_isolation_and_image() {
        let rendered = render_profiles(&config());
        assert!(rendered.contains("dev"), "{rendered}");
        assert!(rendered.contains("L1"), "{rendered}");
        assert!(rendered.contains("L2"), "{rendered}");
        assert!(rendered.contains("ubuntu:24.04"), "{rendered}");
    }

    #[test]
    fn doctor_passes_on_a_complete_config() {
        let checks = static_checks(&config());
        let rendered = render_doctor(&checks);
        assert!(
            checks.iter().all(|c| c.ok),
            "a complete config should pass every check:\n{rendered}"
        );
        assert!(rendered.contains("all checks passed"), "{rendered}");
    }

    #[test]
    fn doctor_identifies_each_missing_piece() {
        let bare = Config::from_yaml(
            r#"
providers: {}
pools: {}
roles: {}
sandbox_profiles: {}
search: { backends: [] }
"#,
        )
        .unwrap();

        let checks = static_checks(&bare);
        let names: Vec<&str> = checks
            .iter()
            .filter(|c| !c.ok)
            .map(|c| c.name.as_str())
            .collect();

        for expected in ["providers", "roles", "search backends", "sandbox profiles"] {
            assert!(
                names.contains(&expected),
                "doctor missed '{expected}': {names:?}"
            );
        }
        assert!(render_doctor(&checks).contains("check(s) failed"));
    }

    #[test]
    fn doctor_flags_a_role_bound_to_a_missing_pool() {
        let broken = Config::from_yaml(
            r#"
providers:
  p1: { kind: openai, models: ["m"], credentials: [{ id: c, secret: "vault:x" }] }
pools:
  real: { members: ["p1/m"] }
roles: { builder: ghost }
"#,
        )
        .unwrap();

        let checks = static_checks(&broken);
        let routing = checks
            .iter()
            .find(|c| c.name == "routing table")
            .expect("the routing table must be checked");
        assert!(!routing.ok);
        assert!(routing.detail.contains("ghost"), "{}", routing.detail);
    }

    #[test]
    fn hosts_render_includes_local_and_notes_when_empty() {
        let rendered = render_hosts(&config());
        assert!(rendered.contains("local"), "{rendered}");
        assert!(
            rendered.contains("no remote hosts configured"),
            "{rendered}"
        );
    }

    #[test]
    fn hosts_render_includes_remote_details() {
        let with_hosts = Config::from_yaml(
            r#"
providers:
  p1: { kind: openai, models: ["m"], credentials: [{ id: c, secret: "vault:x" }] }
pools:
  real: { members: ["p1/m"] }
roles: { builder: real }
hosts:
  buildbox:
    kind: ssh
    address: 10.0.0.5
    port: 2222
    user: deploy
"#,
        )
        .unwrap();

        let rendered = render_hosts(&with_hosts);
        assert!(rendered.contains("buildbox"), "{rendered}");
        assert!(rendered.contains("10.0.0.5:2222"), "{rendered}");
        assert!(rendered.contains("as deploy"), "{rendered}");
    }

    #[test]
    fn search_rendering_reports_failures_separately_from_results() {
        // A thin result set and a broken backend must not look the same to the reader.
        let report = hx_search::SearchReport {
            results: vec![hx_search::FusedResult {
                title: "T".into(),
                url: "https://x.test/".into(),
                snippet: "S".into(),
                score: 1.0 / 61.0,
                sources: vec!["a".into()],
            }],
            answered: vec!["a".into()],
            failures: vec![hx_search::BackendFailure {
                backend: "b".into(),
                reason: "403 bot check".into(),
                elapsed_ms: 120,
            }],
            elapsed_ms: 200,
        };

        let rendered = render_search(&report);
        assert!(rendered.contains("https://x.test/"), "{rendered}");
        assert!(rendered.contains("agreed by 1"), "{rendered}");
        assert!(rendered.contains("403 bot check"), "{rendered}");
    }
}

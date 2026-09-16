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

// ---------------------------------------------------------------------------------------------
// Runs and sessions: what the daemon reports back
// ---------------------------------------------------------------------------------------------

/// A run's report, written for a person unless `--json` was asked for.
///
/// The numbers come before the answer, because a run that stopped early explains itself that way:
/// `stop` is the first thing that says whether the text below is an answer or a fragment of one.
pub fn render_chat(reply: &serde_json::Value, json: bool) -> String {
    if json {
        return match serde_json::to_string_pretty(reply) {
            Ok(pretty) => format!("{pretty}\n"),
            Err(err) => format!("{{\"error\":\"could not serialise the reply: {err}\"}}\n"),
        };
    }

    let mut out = String::new();
    let _ = writeln!(
        out,
        "session {}  ({})",
        reply["session_id"].as_str().unwrap_or("?"),
        if reply["created"].as_bool().unwrap_or(false) {
            "new"
        } else {
            "resumed"
        }
    );

    let repaired = reply["repaired"].as_u64().unwrap_or(0);
    if repaired > 0 {
        let _ = writeln!(
            out,
            "repaired {repaired} call(s) a previous run left without a result"
        );
    }

    let _ = writeln!(
        out,
        "stop {} after {} turn(s): {} tool call(s), {} refusal(s)",
        reply["stop"].as_str().unwrap_or("?"),
        reply["turns"].as_u64().unwrap_or(0),
        reply["tool_calls"].as_u64().unwrap_or(0),
        reply["refusals"].as_u64().unwrap_or(0),
    );

    let cost = reply["cost_usd"].as_f64().unwrap_or(0.0);
    let _ = writeln!(
        out,
        "tokens {} in / {} out   cost {}",
        reply["input_tokens"].as_u64().unwrap_or(0),
        reply["output_tokens"].as_u64().unwrap_or(0),
        if cost > 0.0 {
            format!("${cost:.4}")
        } else {
            // The absence of a price table is reported as an absence, not as free.
            "no rate card configured".to_string()
        }
    );

    out.push('\n');
    out.push_str(reply["final_text"].as_str().unwrap_or("(no text)"));
    out.push('\n');
    out
}

/// The questions waiting for a human, rendered by the *daemon's* own renderer.
///
/// `ApprovalRequest::render` is used rather than a format invented here, and that is the point:
/// `docs/approvals.md` §3 makes the target list and the plain sentence part of the question, and a
/// terminal that showed less than a web page would be a second, weaker interface to the same
/// decision. Each question is followed by the command that answers it, so the id never has to be
/// copied out of a wall of text.
pub fn render_approvals(list: &serde_json::Value, json: bool) -> String {
    if json {
        return match serde_json::to_string_pretty(list) {
            Ok(pretty) => format!("{pretty}\n"),
            Err(err) => format!("{{\"error\":\"could not serialise the list: {err}\"}}\n"),
        };
    }

    let Some(questions) = list.as_array() else {
        return format!("the daemon sent something that is not a list of approvals: {list}\n");
    };
    if questions.is_empty() {
        return "no approvals are waiting.\n".to_string();
    }

    let mut out = String::new();
    for question in questions {
        match serde_json::from_value::<hx_core::approval::ApprovalRequest>(question.clone()) {
            Ok(request) => {
                out.push_str(&request.render());
                out.push('\n');
                let _ = writeln!(
                    out,
                    "id: {}   ->  hx approve {} --option once",
                    request.id.as_str(),
                    request.id.as_str()
                );
            }
            // A question this build cannot read is still a question, and hiding it would be the
            // worst possible failure mode: a run waiting on something nobody can see.
            Err(err) => {
                let _ = writeln!(out, "could not read an approval ({err}): {question}");
            }
        }
        out.push('\n');
    }
    out
}

/// The session list.
pub fn render_sessions(list: &serde_json::Value) -> String {
    let sessions = list.as_array().cloned().unwrap_or_default();
    if sessions.is_empty() {
        return "no sessions yet: `hx chat \"…\"` starts one.\n".to_string();
    }

    let mut out = String::new();
    let _ = writeln!(out, "{:<34} {:>4} {:>5}  TITLE", "ID", "MSGS", "TURNS");
    for session in sessions {
        let _ = writeln!(
            out,
            "{:<34} {:>4} {:>5}  {}",
            session["id"].as_str().unwrap_or("?"),
            session["messages"].as_u64().unwrap_or(0),
            session["turns"].as_u64().unwrap_or(0),
            session["title"].as_str().unwrap_or("(untitled)")
        );
    }
    out
}

/// One session's record and totals.
pub fn render_session(value: &serde_json::Value) -> String {
    let mut out = String::new();
    let record = &value["record"];

    let _ = writeln!(out, "session  {}", record["id"].as_str().unwrap_or("?"));
    let _ = writeln!(
        out,
        "title    {}",
        record["title"].as_str().unwrap_or("(untitled)")
    );
    if let Some(workspace) = record["workspace"].as_str() {
        let _ = writeln!(out, "workspace {workspace}");
    }
    if let Some(model) = record["model"].as_str() {
        let _ = writeln!(out, "model    {model}");
    }

    let totals = &value["totals"];
    let cost = totals["cost_usd"].as_f64().unwrap_or(0.0);
    let _ = writeln!(
        out,
        "spent    {} provider call(s), {} in / {} out tokens, {}",
        totals["provider_calls"].as_u64().unwrap_or(0),
        totals["input_tokens"].as_u64().unwrap_or(0),
        totals["output_tokens"].as_u64().unwrap_or(0),
        if cost > 0.0 {
            format!("${cost:.4}")
        } else {
            "no rate card configured".to_string()
        }
    );

    // A dangling call is the one thing about a session that changes what a caller should do next, so
    // it is stated rather than left to be inferred from the transcript.
    let interrupted = value["interrupted_calls"].as_u64().unwrap_or(0);
    if interrupted > 0 {
        let _ = writeln!(
            out,
            "note     {interrupted} call(s) have no result: a previous run ended inside them. The next\n         \
             `hx chat --session` on this session repairs them before the model sees it."
        );
    }
    out
}

#[cfg(test)]
mod run_tests {
    use super::*;
    use serde_json::json;

    fn reply() -> serde_json::Value {
        json!({
            "session_id": "ses_abc",
            "created": false,
            "repaired": 2,
            "stop": "maxturns",
            "turns": 12,
            "tool_calls": 7,
            "refusals": 1,
            "input_tokens": 1234,
            "output_tokens": 56,
            "cost_usd": 0.0,
            "final_text": "I ran out of turns.",
            "messages": 30,
        })
    }

    #[test]
    fn a_run_for_a_person_leads_with_what_stopped_it() {
        let rendered = render_chat(&reply(), false);

        assert!(rendered.contains("ses_abc"), "{rendered}");
        assert!(rendered.contains("resumed"), "{rendered}");
        assert!(rendered.contains("repaired 2 call(s)"), "{rendered}");
        assert!(rendered.contains("stop maxturns"), "{rendered}");
        assert!(rendered.contains("12 turn(s)"), "{rendered}");
        assert!(rendered.contains("7 tool call(s)"), "{rendered}");
        assert!(rendered.contains("1 refusal(s)"), "{rendered}");
        assert!(rendered.contains("1234 in / 56 out"), "{rendered}");
        // No price table means no price, which is not the same statement as "$0.0000".
        assert!(rendered.contains("no rate card configured"), "{rendered}");
        assert!(rendered.contains("I ran out of turns."), "{rendered}");
    }

    #[test]
    fn a_run_as_json_is_still_the_daemons_reply() {
        let rendered = render_chat(&reply(), true);
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("the JSON mode emits JSON");
        assert_eq!(parsed["session_id"], "ses_abc");
        assert_eq!(parsed["cost_usd"], 0.0);
    }

    #[test]
    fn a_priced_run_shows_the_price() {
        let mut priced = reply();
        priced["cost_usd"] = json!(0.0123);
        assert!(render_chat(&priced, false).contains("$0.0123"));
    }

    #[test]
    fn a_waiting_question_is_rendered_whole_with_the_command_that_answers_it() {
        // The terminal must not show less than the daemon asked. A client that dropped the target list
        // would be asking a person to approve something they were never told about, which is the
        // failure `docs/approvals.md` §3 exists to prevent.
        let list = json!([{
            "id": "apr_1",
            "tool": "delete",
            "summary": "delete /w/build",
            "risk": "destructive",
            "reason": "deletes /w/build",
            "key": "delete",
            "options": ["allow_once", "allow_for_chat", "deny"],
            "targets": [{
                "path": "/w/build",
                "kind": "directory",
                "entries": 1342,
                "bytes": 503316480,
                "partial": false
            }],
            "reversible": false,
            "undo": "moves to the trash at /home/agent/.local/share/Trash/files, where it can be moved back",
            "default_on_timeout": "deny",
            "timeout_secs": 60
        }]);

        let rendered = render_approvals(&list, false);
        assert!(
            rendered.contains("/w/build — directory, 1342 entries, 480.0 MB"),
            "{rendered}"
        );
        assert!(
            rendered.contains("moved back"),
            "the way back, in the tool's own words: {rendered}"
        );
        assert!(rendered.contains("risk: destructive"), "{rendered}");
        assert!(
            rendered.contains("hx approve apr_1 --option once"),
            "the answer is one copy-paste away: {rendered}"
        );
        assert!(
            rendered.contains("deny if nobody answers within 60s"),
            "and silence is spelled out: {rendered}"
        );
    }

    #[test]
    fn no_waiting_questions_says_so_rather_than_printing_nothing() {
        let rendered = render_approvals(&json!([]), false);
        assert!(rendered.contains("no approvals are waiting"), "{rendered}");
    }

    #[test]
    fn a_question_this_build_cannot_read_is_shown_rather_than_hidden() {
        // The worst failure mode available here: a run blocked on a question nobody can see.
        let rendered = render_approvals(&json!([{ "id": "apr_9", "tool": 42 }]), false);
        assert!(rendered.contains("apr_9"), "{rendered}");
        assert!(rendered.contains("could not read"), "{rendered}");
    }

    #[test]
    fn an_empty_session_list_says_how_to_start_one() {
        let rendered = render_sessions(&json!([]));
        assert!(rendered.contains("hx chat"), "{rendered}");
        assert!(
            !rendered.contains("ID"),
            "no header for no rows: {rendered}"
        );
    }

    #[test]
    fn the_session_list_is_a_table() {
        let list = json!([{
            "id": "ses_1",
            "messages": 20,
            "turns": 4,
            "title": "untitled",
        }]);
        let rendered = render_sessions(&list);
        assert!(rendered.contains("ses_1"), "{rendered}");
        assert!(rendered.contains("20"), "{rendered}");
        assert!(rendered.contains("untitled"), "{rendered}");
    }

    #[test]
    fn a_dangling_call_is_called_out_with_what_to_do_about_it() {
        let value = json!({
            "record": { "id": "ses_1", "title": "untitled", "workspace": "/w" },
            "totals": { "provider_calls": 3, "input_tokens": 10, "output_tokens": 2, "cost_usd": 0.0 },
            "interrupted_calls": 1,
        });
        let rendered = render_session(&value);
        assert!(rendered.contains("ses_1"), "{rendered}");
        assert!(rendered.contains("3 provider call(s)"), "{rendered}");
        assert!(rendered.contains("1 call(s) have no result"), "{rendered}");
        assert!(rendered.contains("repairs them"), "{rendered}");
    }

    #[test]
    fn a_healthy_session_says_nothing_about_repair() {
        let value = json!({
            "record": { "id": "ses_1", "title": "untitled" },
            "totals": { "provider_calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0 },
            "interrupted_calls": 0,
        });
        let rendered = render_session(&value);
        assert!(!rendered.contains("no result"), "{rendered}");
    }
}

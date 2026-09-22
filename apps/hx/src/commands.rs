//! Subcommand implementations.
//!
//! Rendering is separated from dispatch so the output can be asserted on. When a command's job
//! is to report a security-relevant setting — which is exactly what `hx sandbox spec` does — the
//! output is part of the interface and belongs under test.

use hx_core::approval::RiskClass;
use hx_core::config::{Config, SandboxProfile};
use hx_provider::ModelRouter;
use hx_sandbox::SandboxSpec;
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

/// The effective approval ladder for a configuration.
///
/// `docs/approvals.md` §6: a policy nobody can read is a policy nobody will check, and the first
/// question after "why did it do that?" is "what did I allow?". So this prints what *will happen*
/// rather than what the config file says — the level with its threshold spelled out per risk class,
/// the ceiling, the budget, the rules in the order they are checked, and which options a prompt may
/// offer at each tier — because "balanced" on its own tells nobody whether `git push` is prompted for.
///
/// Provenance is part of the report, not a footnote: a rule's origin (the shipped floor, the config,
/// or the project's `.hx/allow.toml`) is printed with it, because a reader cannot review a policy
/// they cannot tell apart from a policy nobody wrote. Project grants (`project_grants`, loaded from the
/// checkout's `.hx/allow.toml` by the caller) are folded into `allow` and marked `from .hx/allow.toml`,
/// so a reader can see which allows came with the software, which the operator wrote, and which a project
/// granted.
///
/// Two honest limits, both stated in the output rather than implied. It reads the *configuration*, so
/// it cannot see a session's live level (`--autonomy` on a chat, or an `allow for this chat` answer);
/// and it cannot know what the classifier will call a command, which is why the tiers are shown by
/// risk class and not by example.
pub fn render_policy(
    config: &Config,
    source: &str,
    project_grants: &[hx_core::approval::Rule],
    allow_path: Option<&str>,
) -> String {
    let policy = &config.agent.approval;
    let mut out = String::new();

    let _ = writeln!(out, "approval policy from {source}");
    let _ = writeln!(
        out,
        "  level    {} — {}",
        policy.level.label(),
        policy.level.describe()
    );

    // What the level does with each risk class, in the order the classifier escalates. The ceiling is
    // folded in here rather than listed separately, because what a person needs to know is not that a
    // ceiling exists but *which calls still get asked about* because of it.
    //
    // `third_party` is in the list because it is a class a call can be given — a stdio MCP server's
    // tools, most concretely — and a report that omitted it would be answering the question for five
    // of the six things that can happen to a call.
    let threshold = policy.level.threshold();
    for risk in [
        RiskClass::Read,
        RiskClass::Mutate,
        RiskClass::External,
        RiskClass::ThirdParty,
        RiskClass::Destructive,
        RiskClass::Privileged,
    ] {
        let above_threshold = threshold.is_some_and(|t| risk >= t);
        let capped = policy.ceiling.is_some_and(|c| risk > c);
        let (verdict, note) = if capped && !above_threshold {
            ("asks", "  <- capped by `ceiling`")
        } else if above_threshold {
            ("asks", "")
        } else {
            ("runs free", "")
        };
        let _ = writeln!(out, "  {:<12} {}{note}", risk.label(), verdict);
    }

    match policy.ceiling {
        Some(ceiling) => {
            let _ = writeln!(
                out,
                "  ceiling  {:?} — nothing above it is ever auto-approved, at any autonomy level",
                ceiling
            );
        }
        None => {
            let _ = writeln!(
                out,
                "  ceiling  none — a `yolo` chat can auto-approve anything, including a deleted database"
            );
        }
    }
    match policy.unattended_budget {
        Some(n) => {
            let _ = writeln!(
                out,
                "  budget   {n} — a check-in is forced after {n} consecutive actions nobody reviewed"
            );
        }
        None => {
            let _ = writeln!(
                out,
                "  budget   none — a run may keep going without a check-in"
            );
        }
    }
    match policy.expires_at {
        Some(when) => {
            let _ = writeln!(
                out,
                "  expires  {when} — the session tightens itself after that"
            );
        }
        None => {
            let _ = writeln!(out, "  expires  never");
        }
    }
    let _ = writeln!(
        out,
        "  deletes  {}",
        if policy.refuse_unenumerable_deletions {
            "a pattern or a variable in a delete is refused outright (`rm -rf build*`, `rm -rf $DIR`), \
             with the enumerable form offered"
        } else {
            "no refusal — a delete of a pattern or a variable is classified like any other destructive \
             call, and its targets stay unknown to whoever answers"
        }
    );

    // The project's own grants, from this checkout's `.hx/allow.toml` (`docs/approvals.md` §5).
    // Shown apart from the operator's config both because that is their provenance and because a grant from
    // the file is a reviewed, diffable change that deserves its own read.
    match allow_path {
        Some(path) => {
            let _ = writeln!(out, "  grants   {path}");
            if project_grants.is_empty() {
                let _ = writeln!(out, "             this checkout grants nothing");
            } else {
                for grant in project_grants {
                    let _ = writeln!(
                        out,
                        "             {}   # from .hx/allow.toml",
                        describe_rule(grant)
                    );
                }
            }
        }
        None => {
            let _ = writeln!(
                out,
                "  grants   none — this checkout has no `.hx/allow.toml`"
            );
        }
    }

    // The rule layer, in the order it fires. The order *is* the semantics (`deny → ask → allow`), so
    // printing the lists in the struct's order would be a different policy from the one in force.
    let shipped = hx_core::approval::default_denials();
    let shipped_in_deny = shipped.iter().filter(|r| policy.deny.contains(r)).count();
    let _ = writeln!(out, "\nrules, in the order they are checked:");

    let mut index = 0usize;
    let mut section =
        |out: &mut String, title: &str, why: &str, rules: &[hx_core::approval::Rule]| {
            let _ = writeln!(out, "  {title} — {why}");
            if rules.is_empty() {
                let _ = writeln!(out, "    (none)");
            }
            for rule in rules {
                index += 1;
                let _ = writeln!(out, "    {:>2}. {}", index, describe_rule(rule));
            }
        };

    section(
        &mut out,
        "deny",
        "refused before anything else is considered, and no approval can buy it back",
        &policy.deny,
    );
    if !shipped.is_empty() {
        // Three different truths, and the report has to say which one holds: a config that writes its
        // own `deny` list *replaces* the shipped floor (the trap `hx.example.yaml` warns about), and a
        // report that rendered "0 of these are shipped" as a footnote would hide exactly that.
        let _ = if shipped_in_deny == 0 {
            writeln!(
                out,
                "      (none of the shipped catastrophe set: this config's `deny` list replaced it)"
            )
        } else if shipped_in_deny < shipped.len() {
            writeln!(
                out,
                "      ({shipped_in_deny} of the {} shipped catastrophe rules; the rest were removed \
                 in this config — `inherit_denials: true` would put them back)",
                shipped.len()
            )
        } else {
            writeln!(
                out,
                "      (all {} shipped catastrophe rules, from `default_denials()`)",
                shipped.len()
            )
        };
    }
    section(
        &mut out,
        "ask",
        "a prompt, even where the level would have let it through",
        &policy.ask,
    );
    section(
        &mut out,
        "allow",
        "no prompt, even above the level's threshold",
        &policy.allow,
    );

    let _ = writeln!(out, "\nwhat a prompt may offer (§1's tiers):");
    let _ = writeln!(out, "  allow once, allow for this chat, deny   any call");
    let _ = writeln!(
        out,
        "  always allow this                       only a `reversible` call at `mutate` or below: a \
         local edit that can be taken back"
    );

    let _ = writeln!(out, "\nlive state this cannot see: a chat's `--autonomy` level, an `allow for this \
                            chat` answer, and the unattended counter (which restarts on every human \
                            answer). `hx approvals` shows what is waiting right now.");

    out
}

/// One rule, as the config wrote it.
fn describe_rule(rule: &hx_core::approval::Rule) -> String {
    let mut line = format!("tool {}", rule.tool);
    if let Some(command) = &rule.command {
        let _ = write!(line, ", matching {command}");
    }
    if let Some(risk) = rule.risk {
        let _ = write!(line, ", risk {}", risk.label());
    }
    if let Some(confined) = rule.confined {
        // §4's axis, spelled the way the config spells it. "either" is not shown, because a rule that does
        // not mention confinement matching both is the *absence* of a restriction rather than one.
        let _ = write!(
            line,
            ", {}",
            if confined {
                "confined: true (a sandbox only)"
            } else {
                "confined: false (the host only)"
            }
        );
    }
    if let Some(note) = &rule.note {
        let _ = write!(line, "  # {note}");
    }
    line
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
    // `hx search` resolves `env:` credential references only, the same as the daemon before its
    // vault is unlocked. A `vault:` reference therefore fails loudly with the reference named rather
    // than sending an unauthenticated request.
    let secrets = hx_secrets::SecretStores::new().with(std::sync::Arc::new(hx_secrets::EnvSecrets));
    let registry = hx_search::BackendRegistry::from_config(&config.search, client, &secrets)?;
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

pub async fn run_decision(
    base_url: &str,
    state: &str,
    questions_path: &str,
    threshold: f32,
) -> anyhow::Result<()> {
    use hx_decision::client::LayaClient;
    use hx_decision::{AnswerKind, Question, QuestionSet};

    // State: a bare string, or "@file" meaning read the file's contents.
    let state_text = if let Some(path) = state.strip_prefix('@') {
        std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading state file {}: {e}", path))?
    } else {
        state.to_string()
    };

    // Question set from a JSON document: an object mapping id -> question, or an array of
    // questions each carrying its own id.
    let raw = std::fs::read_to_string(questions_path)
        .map_err(|e| anyhow::anyhow!("reading questions file {}: {e}", questions_path))?;
    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("parsing questions file {}: {e}", questions_path))?;
    let mut questions: Vec<Question> = Vec::new();
    match parsed {
        serde_json::Value::Object(map) => {
            for (id, qv) in map {
                let q: Question = serde_json::from_value(qv)
                    .map_err(|e| anyhow::anyhow!("question '{id}' is not valid: {e}"))?;
                questions.push(q);
            }
        }
        serde_json::Value::Array(arr) => {
            for qv in arr {
                let q: Question = serde_json::from_value(qv)
                    .map_err(|e| anyhow::anyhow!("question is not valid: {e}"))?;
                questions.push(q);
            }
        }
        _ => anyhow::bail!("questions file must be a JSON object or array of questions"),
    }

    let qs = QuestionSet::new(state_text, questions);
    let client = LayaClient::new(base_url);
    let res = client
        .predict(&qs)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut out = String::new();
    use std::fmt::Write;
    for answer in &res.answers {
        let id = &answer.id;
        // The "top probability" is the decision's confidence on the winning pick.
        let top = match &answer.kind {
            AnswerKind::Choice { probabilities, .. } => {
                probabilities.values().copied().fold(0.0_f32, f32::max)
            }
            AnswerKind::Score { probabilities, .. } => {
                probabilities.iter().copied().fold(0.0_f32, f32::max)
            }
            AnswerKind::Noul { noul, .. } => (*noul).max(1.0 - *noul),
        };
        let verdict = if top >= threshold { "ACT" } else { "escalate" };
        let _ = writeln!(out, "{id}: top={top:.3} threshold={threshold} -> {verdict}");
        match &answer.kind {
            AnswerKind::Choice {
                choice,
                probabilities,
                ..
            } => {
                let _ = writeln!(out, "  choice: {choice}");
                for (k, v) in probabilities {
                    let _ = writeln!(out, "    {k}: {v:.3}");
                }
            }
            AnswerKind::Score {
                score,
                probabilities,
                legend,
                ..
            } => {
                let _ = writeln!(out, "  score: {score:.3}");
                for (i, v) in probabilities.iter().enumerate() {
                    let label = legend.get(i).map(|l| l.as_str()).unwrap_or("");
                    let _ = writeln!(out, "    [{i}] {label}: {v:.3}");
                }
            }
            AnswerKind::Noul { noul, .. } => {
                let _ = writeln!(out, "  noul: {noul:.3}");
            }
        }
        let _ = writeln!(out, "  confidence: {:.3}", answer.confidence());
        let _ = writeln!(out, "  act_probability: {:.3}", answer.act_probability);
    }
    let _ = writeln!(out, "input_tokens: {}", res.usage_input_tokens);
    print!("{out}");
    anyhow::Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
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
    // ---- the ladder ---------------------------------------------------------

    #[test]
    fn the_policy_report_says_what_this_level_does_with_each_risk_class() {
        // "balanced" is the config's word for it and tells nobody whether `git push` is prompted for.
        // The report has to answer that in the terms the classifier uses, or it is decoration.
        let rendered = render_policy(&config(), "hx.yaml", &[], None);

        assert!(
            rendered.contains("approval policy from hx.yaml"),
            "{rendered}"
        );
        assert!(
            rendered.contains("level    balanced — asks before anything leaving the machine"),
            "{rendered}"
        );
        // `Balanced`'s threshold is `external`: below it runs free, at it and above it asks.
        assert!(rendered.contains("read         runs free"), "{rendered}");
        assert!(rendered.contains("mutate       runs free"), "{rendered}");
        assert!(rendered.contains("external     asks"), "{rendered}");
        assert!(
            rendered.contains("third_party  asks"),
            "a stdio MCP call is `third_party`, and the report has to say `balanced` asks about it \
             — the gap this class was added to close: {rendered}"
        );
        assert!(rendered.contains("destructive  asks"), "{rendered}");
        assert!(rendered.contains("privileged   asks"), "{rendered}");
    }

    #[test]
    fn the_policy_report_shows_the_shipped_floor_and_where_it_came_from() {
        // The question this answers is "what did I allow?" — and `deny: 31 rules` is not an answer
        // unless a reader can tell which of them they wrote and which came with the software.
        let rendered = render_policy(&config(), "hx.yaml", &[], None);
        let shipped = hx_core::approval::default_denials().len();

        assert!(
            rendered.contains(&format!(
                "(all {shipped} shipped catastrophe rules, from `default_denials()`)"
            )),
            "{rendered}"
        );
        assert!(
            rendered.contains("recursive delete of the root directory"),
            "the rules themselves, not a count: {rendered}"
        );
        assert!(
            rendered.contains("a pattern or a variable in a delete is refused outright"),
            "{rendered}"
        );
        assert!(
            rendered.contains("ceiling  none"),
            "and where the ceiling is absent, say so: {rendered}"
        );
    }

    #[test]
    fn the_policy_report_shows_project_grants_and_their_source() {
        // Provenance is the point of the whole file (§5): a reader has to be able to tell a rule
        // that came with the software from a rule the operator wrote from a grant the *project* made.
        // The grants live in `.hx/allow.toml`, and a policy report that merged them into the allow
        // list without saying so would be asking a reader to review a policy they cannot attribute. A
        // real file on disk provides the grants, so the report is fed what a checkout would really carry.
        let dir = std::env::temp_dir().join(format!("hx-policy-grant-{}", std::process::id()));
        let path = dir.join(".hx").join("allow.toml");
        std::fs::create_dir_all(dir.join(".hx")).unwrap();
        std::fs::write(
            &path,
            "[[allow]]\ntool = \"shell\"\ncommand = \"cargo test*\"\nnote = \"the test loop\"\n",
        )
        .unwrap();
        let list = hx_core::allowlist::AllowFile::load(&path).unwrap();

        let rendered = render_policy(
            &config(),
            "hx.yaml",
            &list.into_rules(),
            Some(path.display().to_string().as_str()),
        );

        assert!(
            rendered.contains("grants"),
            "a project grants line exists: {rendered}"
        );
        assert!(
            rendered.contains("matching cargo test*") && rendered.contains("from .hx/allow.toml"),
            "the grant names what it covers and says where it came from: {rendered}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_policy_report_says_when_the_checkout_grants_nothing() {
        // An absent `.hx/allow.toml` is not an error, but a reader still needs to know there is no
        // project grant in force — "nothing granted" and "nothing shown" are different, and only the
        // former is safe to rely on.
        let rendered = render_policy(&config(), "hx.yaml", &[], None);
        assert!(
            rendered.contains("this checkout has no `.hx/allow.toml`"),
            "an absent file says so, naming the file a reader would create: {rendered}"
        );
    }

    #[test]
    fn the_rules_are_printed_in_the_order_they_are_checked() {
        // The order *is* the policy (`deny → ask → allow`). Printing them in the struct's order would
        // describe a policy this program does not have, which is the failure this command exists to
        // prevent — so the numbering is asserted, not just the presence of each rule.
        let yaml = format!(
            "{CONFIG}
agent:
  approval:
    level: trusting
    ceiling: mutate
    unattended_budget: 20
    refuse_unenumerable_deletions: true
    allow:
      - {{ tool: shell, command: \"cargo test*\" }}
      - {{ tool: shell, command: \"npm test*\", confined: true }}
    ask:
      - {{ tool: shell, command: \"git push*\", note: \"publishes to the world\" }}
    deny:
      - {{ tool: shell, command: \"*rm -rf /var*\", risk: destructive }}
"
        );
        let config = Config::from_yaml(&yaml).unwrap();
        let rendered = render_policy(&config, "hx.yaml", &[], None);

        let deny = rendered.find("  deny — ").unwrap();
        let ask = rendered.find("\n  ask — ").unwrap();
        let allow = rendered.find("\n  allow — ").unwrap();
        assert!(
            deny < ask && ask < allow,
            "deny first, allow last: {rendered}"
        );
        // The config's *own* deny rules come before the shipped floor (a file's words are the ones that
        // explain the refusal), and every rule is numbered in the order it is checked. The order is
        // asserted by locating lines rather than by hard-coded indices, because the floor's size is the
        // floor's business — hard-coded numbering is exactly what broke when it became additive.
        let line_of = |needle: &str| {
            rendered
                .lines()
                .find(|line| line.contains(needle))
                .unwrap_or_else(|| panic!("no line for {needle:?}: {rendered}"))
                .to_string()
        };
        let num = |line: &str| {
            line.trim_start()
                .split('.')
                .next()
                .unwrap()
                .parse::<usize>()
                .unwrap()
        };

        let own_deny = line_of("matching *rm -rf /var*, risk destructive");
        assert_eq!(
            num(&own_deny),
            1,
            "the config's own rule is checked first: {rendered}"
        );

        let floor_rule = line_of("recursive delete of the root directory");
        assert!(
            num(&floor_rule) > num(&own_deny),
            "and the shipped floor is behind it: {rendered}"
        );

        let ask_line = line_of("matching git push*  # publishes to the world");
        assert!(
            num(&ask_line) > num(&floor_rule),
            "`ask` is checked after the whole deny list: {rendered}"
        );

        let allow_line = line_of("matching cargo test*");
        let confined_line = line_of("matching npm test*, confined: true (a sandbox only)");
        assert!(
            num(&allow_line) > num(&ask_line) && num(&confined_line) == num(&allow_line) + 1,
            "§4's axis is part of the ladder, so a reader can see which rules need a boundary: {rendered}"
        );

        // A ceiling is shown where it bites, not as a footnote: `read` and `mutate` run free at
        // `trusting`, and the ceiling is what would stop anything above `mutate` from doing so.
        assert!(rendered.contains("capped by `ceiling`"), "{rendered}");
        assert!(rendered.contains("budget   20"), "{rendered}");
        assert!(
            rendered.contains(
                "(all 32 shipped catastrophe rules, from `default_denials()`)"
            ),
            "a config that writes its own deny list keeps the floor, and the report says so: {rendered}"
        );
    }

    #[test]
    fn a_policy_with_no_rules_says_it_has_no_rules_rather_than_printing_nothing() {
        // The blank policy is what a library caller gets, and it is the one shape where a prompt with a
        // pattern in it will be asked about instead of refused. A report that left the sections empty
        // would read as "nothing is allowed"; the truth is "nothing is decided here".
        // `inherit_denials: false` is the only way to get here now, and that is the point: a config has
        // to say the words to drop the catastrophe set, and the report can then be honest about it.
        let yaml = format!(
            "{CONFIG}
agent:
  approval:
    level: yolo
    inherit_denials: false
"
        );
        let config = Config::from_yaml(&yaml).unwrap();
        let rendered = render_policy(&config, "hx.yaml", &[], None);

        assert_eq!(rendered.matches("(none)").count(), 3, "{rendered}");
        assert!(
            rendered.contains("no refusal — a delete of a pattern or a variable"),
            "the absent floor is the important part: {rendered}"
        );
        for risk in [
            "read",
            "mutate",
            "external",
            "third_party",
            "destructive",
            "privileged",
        ] {
            assert!(
                rendered.contains(&format!("{risk:<12} runs free")),
                "`yolo` with no ceiling asks about nothing, and the report has to say so for every \
                 class rather than reassure the reader: {rendered}"
            );
        }
        assert!(
            rendered.contains("a `yolo` chat can auto-approve anything"),
            "{rendered}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Runs and sessions: what the daemon reports back
// ---------------------------------------------------------------------------------------------

/// A run's report, written for a person unless `--json` was asked for.
///
/// The numbers come before the answer, because a run that stopped early explains itself that way:
/// `stop` is the first thing that says whether the text below is an answer or a fragment of one.
/// Render the result of checking a session's trail.
///
/// The three outcomes are worded so they cannot be confused: `intact` is a claim that every event was
/// checked, and when some were not, the count says so rather than letting the word cover them.
pub fn render_audit(report: &serde_json::Value, json: bool) -> String {
    if json {
        return match serde_json::to_string_pretty(report) {
            Ok(pretty) => format!("{pretty}\n"),
            Err(err) => format!("{{\"error\":\"could not serialise the report: {err}\"}}\n"),
        };
    }

    let session = report["session_id"].as_str().unwrap_or("?");
    let verified = report["verified"].as_u64().unwrap_or(0);
    let unchained = report["unchained"].as_u64().unwrap_or(0);
    let mut out = String::new();

    match report["status"].as_str().unwrap_or("?") {
        "intact" => {
            let _ = writeln!(out, "session {session}: trail intact");
            let _ = writeln!(out, "  {verified} event(s) verified against their digests");
        }
        "broken" => {
            let _ = writeln!(out, "session {session}: TRAIL ALTERED");
            let _ = writeln!(
                out,
                "  event {} does not match the digest stored with it",
                report["seq"].as_i64().unwrap_or(-1)
            );
            let _ = writeln!(
                out,
                "  expected {}",
                &report["expected"].as_str().unwrap_or("?")
                    [..16.min(report["expected"].as_str().unwrap_or("?").len())]
            );
            let _ = writeln!(
                out,
                "  stored   {}",
                &report["stored"].as_str().unwrap_or("?")
                    [..16.min(report["stored"].as_str().unwrap_or("?").len())]
            );
            let _ = writeln!(out, "  {verified} event(s) checked before the break");
        }
        other => {
            let _ = writeln!(out, "session {session}: unexpected status {other}");
        }
    }

    // Said separately and unconditionally: an `intact` verdict covers only the events that carried a
    // digest, and a reader who is not told how many did not would over-trust it.
    if unchained > 0 {
        let _ = writeln!(
            out,
            "  {unchained} event(s) predate the chain and were NOT checked"
        );
    }

    // Which guarantee the verdict carries. Without this line `intact` reads as "nobody could have
    // rewritten this", which an unkeyed chain cannot support.
    match report["keyed"].as_bool() {
        Some(true) => {
            let _ = writeln!(out, "  keyed: a rewrite would need the chain key");
        }
        Some(false) => {
            let _ = writeln!(
                out,
                "  UNKEYED: this detects an inconsistent edit, not a rewrite by someone with the key"
            );
        }
        None => {}
    }
    out
}

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

/// The fan-out outcome, written for a person unless `--json` was asked for.
///
/// The route's [`FanOutOutcome`](hx_server::fanout::FanOutOutcome) returns, per child in
/// request order, either `Ran` (with the member it ran on) or `Errored` (with the member
/// and a redacted reason). The outcome carries no answer text — the fan-out is a spawn/cost
/// path, not a chat — so the honest render is one line per child naming its member, and the whole
/// block is bracketed so a reader can see at a glance whether every child ran.
pub fn render_fanout(outcome: &serde_json::Value, json: bool) -> String {
    if json {
        return match serde_json::to_string_pretty(outcome) {
            Ok(pretty) => format!("{pretty}\n"),
            Err(err) => format!("{{\"error\":\"could not serialise the fan-out: {err}\"}}\n"),
        };
    }

    let members = outcome["members"].as_array().cloned().unwrap_or_default();
    let children = outcome["children"].as_array().cloned().unwrap_or_default();
    // "child" is irregular, so the plural is decided by count rather than a bare "s".
    let plural = if members.len() == 1 {
        "child"
    } else {
        "children"
    };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} {}: {}",
        members.len(),
        plural,
        members
            .iter()
            .map(|m| m.as_str().unwrap_or("?").to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let mut errored = 0usize;
    for (index, child) in children.iter().enumerate() {
        let label = if let Some(rec) = child["Ran"].as_object() {
            format!("member {}", rec["model"].as_str().unwrap_or("?"))
        } else if let Some(e) = child["Errored"].as_object() {
            errored += 1;
            format!(
                "member {} — errored: {}",
                e["member"].as_str().unwrap_or("?"),
                e["error"].as_str().unwrap_or("?")
            )
        } else {
            format!("unrecognised outcome {child}")
        };
        let _ = writeln!(out, "  {}: {label}", index + 1);
    }

    let verdict = if errored == 0 {
        "all children ran".to_string()
    } else if errored == 1 {
        "1 child errored".to_string()
    } else {
        format!("{errored} children errored")
    };
    let _ = writeln!(out, "{verdict}");
    out
}

/// Parse `--fetch-mode` into the pipeline's own [`hx_search::FetchMode`].
///
/// Through `serde` rather than a second `match` on the strings, because `FetchMode`'s wire spelling
/// is what the route deserialises: a mode this accepts is a mode the route accepts, and adding a
/// mode to the enum cannot leave the CLI a step behind. The error lists the known modes, since a
/// typo in a flag is the caller's to fix and "unknown" alone does not say with what.
pub fn parse_fetch_mode(raw: &str) -> anyhow::Result<hx_search::FetchMode> {
    serde_json::from_value::<hx_search::FetchMode>(serde_json::Value::String(raw.to_string()))
        .map_err(|_| {
            anyhow::anyhow!(
                "unknown fetch mode '{raw}'; known modes: http (plain fetch only), \
                 auto (escalate to a browser for a page a plain fetch cannot read), \
                 browser (drive a browser even for a page a plain fetch could read)"
            )
        })
}

/// Turn `hx research`'s arguments into the route's request body.
///
/// Only the fields the caller actually set are sent, the same rule `hx chat` follows: the daemon's
/// defaults are the daemon's to decide, and serialising a CLI default of `auto` would make this
/// command's default look like the daemon's policy — two things that could then drift apart without
/// either saying so. A blank query is refused here rather than round-tripped, so the common mistake
/// costs no daemon call and reads the same either way.
pub fn research_body(
    query: &str,
    max_sources: Option<usize>,
    fetch_mode: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    if query.trim().is_empty() {
        anyhow::bail!("`hx research` needs a non-empty query");
    }
    let mut body = serde_json::json!({ "query": query });
    if let Some(max) = max_sources {
        body["max_sources"] = serde_json::json!(max);
    }
    if let Some(raw) = fetch_mode {
        // Validated before the round trip: a mode the daemon would reject should be an argument
        // error, not a request whose failure the caller has to read out of a response body.
        let mode = parse_fetch_mode(raw)?;
        body["fetch_mode"] = serde_json::to_value(mode)?;
    }
    Ok(body)
}

/// True when at least one backend answered.
///
/// What `hx research`'s exit status turns on: a report where every backend failed is not a success
/// a script should treat as one, even though the request itself was answered with a 200.
pub fn research_answered(outcome: &serde_json::Value) -> bool {
    outcome["backends"]
        .as_array()
        .is_some_and(|backends| backends.iter().any(|o| o["status"] == "answered"))
}

/// Render a research report: the query, which fetcher ran it, what each backend did, and the cited
/// sources in fused rank order.
pub fn render_research(outcome: &serde_json::Value, json: bool) -> String {
    if json {
        return match serde_json::to_string_pretty(outcome) {
            Ok(pretty) => format!("{pretty}\n"),
            Err(err) => format!("{{\"error\":\"could not serialise the report: {err}\"}}\n"),
        };
    }

    let mut out = String::new();
    let _ = writeln!(
        out,
        "query:   {}",
        outcome["query"].as_str().unwrap_or("(none)")
    );
    // The fetcher and its note are printed together because neither is honest alone: `http` on a
    // request that asked for a browser is exactly the degradation the note exists to record.
    let _ = writeln!(
        out,
        "fetcher: {} — {}",
        outcome["fetcher"].as_str().unwrap_or("(none)"),
        outcome["fetch_note"].as_str().unwrap_or("(no note)")
    );

    let backends = outcome["backends"].as_array().cloned().unwrap_or_default();
    let mut answered = 0usize;
    let mut failed = 0usize;
    let mut out_backends = String::new();
    for outcome in &backends {
        match outcome["status"].as_str() {
            Some("answered") => {
                answered += 1;
                let _ = writeln!(
                    out_backends,
                    "  {}: answered",
                    outcome["backend"].as_str().unwrap_or("?")
                );
            }
            Some("failed") => {
                failed += 1;
                let _ = writeln!(
                    out_backends,
                    "  {}: failed — {}",
                    outcome["backend"].as_str().unwrap_or("?"),
                    outcome["reason"].as_str().unwrap_or("no reason given")
                );
            }
            other => {
                let _ = writeln!(out_backends, "  unrecognised backend outcome {other:?}");
            }
        }
    }
    let _ = writeln!(out, "backends: {answered} answered, {failed} failed");
    out.push_str(&out_backends);

    let sources = outcome["sources"].as_array().cloned().unwrap_or_default();
    let _ = writeln!(out, "sources:  {} cited", sources.len());
    for source in &sources {
        let _ = writeln!(
            out,
            "  {}. {} [{}]",
            source["rank"].as_u64().unwrap_or(0),
            source["title"].as_str().unwrap_or("(untitled)"),
            source["rung"].as_str().unwrap_or("?")
        );
        let _ = writeln!(out, "     {}", source["url"].as_str().unwrap_or("?"));
        if let Some(snippet) = source["snippet"].as_str() {
            if !snippet.is_empty() {
                let _ = writeln!(out, "     {snippet}");
            }
        }
    }

    let _ = writeln!(
        out,
        "paid calls: {} (keyless research spends nothing)",
        outcome["paid_calls"].as_u64().unwrap_or(0)
    );
    if answered == 0 {
        // The line a script's non-zero exit corresponds to, said out loud rather than left to the
        // exit status alone.
        let _ = writeln!(
            out,
            "no backend answered: the report is empty because nothing was reachable, not because \
             the query matched nothing"
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

    #[test]
    fn a_fanout_for_a_person_lists_members_and_the_verdict() {
        let outcome = json!({
            "members": ["cheap", "strong"],
            "children": [
                { "Ran": { "model": "cheap" } },
                { "Ran": { "model": "strong" } },
            ],
        });
        let rendered = render_fanout(&outcome, false);
        assert!(rendered.contains("2 children: cheap, strong"), "{rendered}");
        assert!(rendered.contains("member cheap"), "{rendered}");
        assert!(rendered.contains("member strong"), "{rendered}");
        assert!(rendered.contains("all children ran"), "{rendered}");
        assert!(!rendered.contains("errored"), "{rendered}");
    }

    #[test]
    fn a_fanout_with_an_errored_child_names_it_and_says_so() {
        // The exit code 1 for an errored child is decided by the caller, but the *prose* must
        // make it impossible to read a partial fan-out as a success.
        let outcome = json!({
            "members": ["a", "b"],
            "children": [
                { "Ran": { "model": "b" } },
                { "Errored": { "member": "a", "error": "upstream 500" } },
            ],
        });
        let rendered = render_fanout(&outcome, false);
        assert!(rendered.contains("member b"), "{rendered}");
        assert!(
            rendered.contains("member a — errored: upstream 500"),
            "{rendered}"
        );
        assert!(rendered.contains("1 child errored"), "{rendered}");
    }

    #[test]
    fn a_fanout_as_json_is_still_the_daemons_outcome() {
        let outcome = json!({
            "members": ["cheap"],
            "children": [{ "Ran": { "model": "cheap" } }],
        });
        let rendered = render_fanout(&outcome, true);
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("the JSON mode emits JSON");
        assert_eq!(parsed["members"][0], "cheap");
    }

    #[test]
    fn an_unrecognized_child_outcome_is_shown_rather_than_dropped() {
        // A shape this build cannot read must not vanish: a re-route or a new outcome variant
        // that reaches the older CLI would otherwise read as "that child did nothing".
        let outcome = json!({
            "members": ["a"],
            "children": [{ "Pending": { "member": "a" } }],
        });
        let rendered = render_fanout(&outcome, false);
        assert!(rendered.contains("unrecognised outcome"), "{rendered}");
    }

    #[test]
    fn an_intact_trail_says_what_was_verified() {
        let rendered = render_audit(
            &serde_json::json!({
                "session_id": "ses_1",
                "status": "intact",
                "verified": 12,
                "unchained": 0
            }),
            false,
        );
        assert!(rendered.contains("intact"), "{rendered}");
        assert!(rendered.contains("12 event(s) verified"), "{rendered}");
        // Nothing about unchecked rows when there are none: a line saying "0 were not checked" is
        // noise that trains a reader to skip the line that matters.
        assert!(!rendered.contains("NOT checked"), "{rendered}");
    }

    #[test]
    fn a_broken_trail_is_impossible_to_read_as_fine() {
        let rendered = render_audit(
            &serde_json::json!({
                "session_id": "ses_1",
                "status": "broken",
                "verified": 3,
                "unchained": 0,
                "seq": 4,
                "expected": "aaaa1111bbbb2222cccc3333dddd4444",
                "stored": "99998888777766665555444433332222"
            }),
            false,
        );
        assert!(rendered.contains("ALTERED"), "{rendered}");
        assert!(rendered.contains("event 4"), "names the row: {rendered}");
        assert!(
            rendered.contains("aaaa1111"),
            "shows what it should be: {rendered}"
        );
        assert!(rendered.contains("99998888"), "and what it is: {rendered}");
        // The word `intact` must not appear anywhere in a tamper report.
        assert!(!rendered.contains("intact"), "{rendered}");
    }

    #[test]
    fn unchecked_rows_are_stated_even_when_the_rest_is_intact() {
        // The line that stops `intact` from being read as "everything was verified": over a database
        // upgraded from V1 the prefix has no digest, so the verdict covers only part of the log.
        let rendered = render_audit(
            &serde_json::json!({
                "session_id": "ses_1",
                "status": "intact",
                "verified": 5,
                "unchained": 40
            }),
            false,
        );
        assert!(rendered.contains("intact"), "{rendered}");
        assert!(
            rendered.contains("40 event(s) predate the chain"),
            "{rendered}"
        );
    }

    #[test]
    fn the_audit_report_can_be_asked_for_as_json() {
        let report = serde_json::json!({"session_id": "ses_1", "status": "intact", "verified": 2, "unchained": 0});
        let rendered = render_audit(&report, true);
        // Pretty-printed JSON, so a caller piping it to `jq` gets a document rather than prose.
        assert!(rendered.contains("\"session_id\": \"ses_1\""), "{rendered}");
    }

    // ---- research -----------------------------------------------------------

    #[test]
    fn a_research_body_sends_only_the_arguments_the_caller_actually_set() {
        // The daemon's defaults are the daemon's to decide. Serialising a CLI default here would
        // make this command's opinion look like the daemon's policy, and the two could then drift
        // apart with neither saying so — the same rule `hx chat` follows for its optional fields.
        let body = research_body("rust ownership", None, None).expect("a query alone is enough");
        assert_eq!(body["query"], "rust ownership");
        assert!(
            body.get("max_sources").is_none(),
            "an unset cap must not be sent: {body}"
        );
        assert!(
            body.get("fetch_mode").is_none(),
            "an unset mode must not be sent: {body}"
        );
    }

    #[test]
    fn a_research_body_carries_an_explicit_cap_and_mode() {
        let body =
            research_body("rust", Some(3), Some("browser")).expect("both arguments are valid");
        assert_eq!(body["query"], "rust");
        assert_eq!(body["max_sources"], 3);
        assert_eq!(body["fetch_mode"], "browser");
    }

    #[test]
    fn every_mode_the_pipeline_accepts_is_a_mode_the_cli_accepts() {
        // The CLI parses `--fetch-mode` through `FetchMode`'s own serde representation, which is
        // what the route deserialises. This is the assertion that the two cannot drift: a mode the
        // pipeline knows is a mode this command sends, spelled the way the route reads it.
        for (raw, expected) in [
            ("http", hx_search::FetchMode::Http),
            ("auto", hx_search::FetchMode::Auto),
            ("browser", hx_search::FetchMode::Browser),
        ] {
            let parsed = parse_fetch_mode(raw).unwrap_or_else(|err| panic!("{raw}: {err}"));
            assert_eq!(parsed, expected);
            let body = research_body("rust", None, Some(raw)).expect("a known mode is valid");
            assert_eq!(body["fetch_mode"], raw, "the wire spelling must round-trip");
        }
    }

    #[test]
    fn a_fetch_mode_outside_the_pipelines_vocabulary_is_an_argument_error_that_lists_the_real_ones()
    {
        // A typo in a flag is the caller's to fix, and it is fixed before the round trip: a mode
        // the daemon would reject as a 400 is an argument error here, not a request whose failure
        // the caller has to read out of a response body.
        let err = parse_fetch_mode("telepathy").expect_err("telepathy is not a fetch mode");
        let message = err.to_string();
        assert!(message.contains("telepathy"), "{message}");
        for mode in ["http", "auto", "browser"] {
            assert!(
                message.contains(mode),
                "the error must list the known modes so the typo is fixable, missing {mode}: {message}"
            );
        }
        assert!(
            research_body("rust", None, Some("telepathy")).is_err(),
            "an invalid mode must not reach a request body"
        );
    }

    #[test]
    fn a_blank_research_query_is_refused_before_any_daemon_call() {
        for blank in ["", "   ", "\t"] {
            assert!(
                research_body(blank, None, None).is_err(),
                "{blank:?} is not a query"
            );
        }
        // The daemon refuses the same request; refusing it here means the common mistake costs no
        // call and reads the same whether or not a daemon is running.
        assert!(research_body("  rust  ", None, None).is_ok());
    }

    #[test]
    fn research_answered_turns_on_any_backend_answering() {
        // What the command's exit status turns on: a report every backend failed is not a success.
        assert!(research_answered(&json!({
            "backends": [
                {"backend": "a", "status": "failed", "reason": "HTTP 503"},
                {"backend": "b", "status": "answered"},
            ]
        })));
        assert!(!research_answered(&json!({
            "backends": [{"backend": "a", "status": "failed", "reason": "HTTP 503"}]
        })));
        assert!(
            !research_answered(&json!({"backends": []})),
            "no backends is not an answered backend"
        );
    }

    #[test]
    fn a_research_report_names_the_fetcher_and_every_backend_outcome() {
        let report = json!({
            "query": "rust ownership",
            "fetcher": "http",
            "fetch_note": "http: plain fetch policy, no escalation",
            "backends": [
                {"backend": "duckduckgo", "status": "answered"},
                {"backend": "mojeek", "status": "failed", "reason": "backend returned HTTP 503"},
            ],
            "sources": [
                {"title": "Alpha", "url": "https://example.test/a", "snippet": "the text", "rank": 0, "rung": "readability"},
            ],
            "paid_calls": 0,
        });
        let rendered = render_research(&report, false);

        assert!(rendered.contains("rust ownership"), "{rendered}");
        // The fetcher and its note together: `http` alone on a request that asked for a browser is
        // exactly the degradation the note records.
        assert!(
            rendered.contains("http: plain fetch policy, no escalation"),
            "the note must be shown beside the fetcher: {rendered}"
        );
        assert!(rendered.contains("duckduckgo: answered"), "{rendered}");
        assert!(
            rendered.contains("backend returned HTTP 503"),
            "a backend's reason must be shown, not just its name: {rendered}"
        );
        assert!(rendered.contains("1 answered, 1 failed"), "{rendered}");
        assert!(rendered.contains("Alpha"), "{rendered}");
        assert!(rendered.contains("https://example.test/a"), "{rendered}");
        assert!(rendered.contains("readability"), "{rendered}");
        assert!(!rendered.contains("no backend answered"), "{rendered}");
    }

    #[test]
    fn a_research_report_no_backend_answered_says_so_and_still_renders_as_json() {
        let report = json!({
            "query": "rust",
            "fetcher": "http",
            "fetch_note": "http: plain fetch policy, no escalation",
            "backends": [{"backend": "mojeek", "status": "failed", "reason": "timed out"}],
            "sources": [],
            "paid_calls": 0,
        });
        // The line the non-zero exit corresponds to, said out loud rather than left to the status.
        let rendered = render_research(&report, false);
        assert!(rendered.contains("no backend answered"), "{rendered}");
        assert!(
            rendered.contains("not because the query matched nothing"),
            "an empty report from an unreachable backend must not read as an empty result set: {rendered}"
        );

        let as_json = render_research(&report, true);
        let parsed: serde_json::Value =
            serde_json::from_str(&as_json).expect("the JSON mode emits JSON");
        assert_eq!(parsed["query"], "rust");
    }
}

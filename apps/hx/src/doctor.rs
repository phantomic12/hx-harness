//! `hx doctor` — the health check, and the split that makes it worth trusting.
//!
//! When something is wrong the operator has to guess, and the expensive guesses are the wrong ones:
//! the config is fine and a pool member is down, or the pool is fine and there is no container
//! engine, or everything is fine and the API has no token because nobody thought about the bind
//! address. This command answers those questions in one place, one line per check, with the reason
//! in plain words rather than a code.
//!
//! ## The shape: decisions pure, evidence gathered
//!
//! [`diagnose`] is a function of *values* — the parsed [`Config`], the daemon's own `/v1/status`
//! document, and the results of the two probes that genuinely need the machine (a container engine
//! and the data directory). It performs no I/O, so every branch of every check is reachable from a
//! unit test by constructing the input, and each test asserts the sentence the operator would read.
//! [`gather`] is the shell: it reads the config, fetches `/v1/status` and runs the probes, then
//! hands the result over. Nothing here decides anything twice.
//!
//! ## A check that cannot run is a FAILURE, not a pass
//!
//! The daemon-dependent checks (pools, and the halves of the engine, search and secrets checks that
//! read what the daemon built) report [`Verdict::Fail`] with the reason the daemon could not be
//! read. A doctor that prints "all good" because it could not look is worse than no doctor at all —
//! and the operator reading it would conclude the opposite of the truth. [`hxd --check`] is the
//! config-only question; this command is the operational one, so it refuses to call a daemon it
//! never reached healthy.
//!
//! ## What each check is derived from, and what it cannot see
//!
//! Every check reads something the config or the daemon actually reports. Two limits are stated
//! here rather than left for the reader to discover:
//!
//! - **Credential health is reported per pool, not per member.** `PoolStatus` carries
//!   `healthy_credentials` / `total_credentials` for the distinct providers behind a pool's routes,
//!   so the pools check can answer exactly the question the contract asks — does this pool have a
//!   live member — and can name every member when the answer is no (they are all dead). A pool that
//!   lost one of three credentials is a warning with the counts, because which *member* is
//!   unservable is not in the report. Naming a member the report does not condemn would be worse
//!   than the count.
//! - **The bind address is the daemon's `--bind`** (or `HX_BIND`), falling back to
//!   `daemon.http_addr`. That last case is a fallback and not the daemon's own value: `hxd`'s
//!   default bind is `127.0.0.1:7717` while `daemon.http_addr` defaults to `127.0.0.1:8787`, so the
//!   `api token` line says which address it checked and where that address came from.

use chrono::{DateTime, Utc};
use hx_core::api_auth::{bind_is_loopback, require_token_for_bind, API_TOKEN_ENV};
use hx_core::config::{AuthMethod, Config, SandboxProfile, SecretRef};
use hx_provider::ModelRouter;
use hx_sandbox::{SandboxRuntime, SandboxSpec};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// ---------------------------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------------------------

/// What one check found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    /// The daemon runs, but something an operator should know about is degraded. A warning alone
    /// never changes the exit code: a degraded search backend is not a reason to fail a deploy.
    Warn,
    Fail,
}

impl Verdict {
    /// The word the report prints, and the only vocabulary for it: the human output and the JSON
    /// document carry the same three labels, so a script and a person cannot disagree about what
    /// a check said.
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Warn => "WARN",
            Verdict::Fail => "FAIL",
        }
    }
}

impl Serialize for Verdict {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

/// One check: what was asked, what was found, and why.
///
/// The reason is a sentence a person can act on, and it is part of the interface — the tests assert
/// it. `name` is `&'static str` because the set of checks is fixed: a check that existed only
/// sometimes would make two reports incomparable.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub verdict: Verdict,
    pub reason: String,
}

impl Check {
    pub fn pass(name: &'static str, reason: impl Into<String>) -> Self {
        Self::new(name, Verdict::Pass, reason)
    }

    pub fn warn(name: &'static str, reason: impl Into<String>) -> Self {
        Self::new(name, Verdict::Warn, reason)
    }

    pub fn fail(name: &'static str, reason: impl Into<String>) -> Self {
        Self::new(name, Verdict::Fail, reason)
    }

    /// Build a check, flattening its reason onto one line.
    ///
    /// A reason can come from a parser or an OS error, and both can carry newlines — a YAML parse
    /// error often does. The report is one line per check, so the flattening happens here, once,
    /// where both renderers get it: a reason that broke the table would be the kind of defect that
    /// makes a reader stop trusting the whole report.
    fn new(name: &'static str, verdict: Verdict, reason: impl Into<String>) -> Self {
        Self {
            name,
            verdict,
            reason: reason.into().replace('\n', " "),
        }
    }
}

/// The whole report.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    pub fn failed(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.verdict == Verdict::Fail)
            .count()
    }

    pub fn warned(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.verdict == Verdict::Warn)
            .count()
    }

    /// The process exit code: non-zero only when something failed.
    ///
    /// A warning does not fail the exit code, which is what lets `hx doctor` gate a deploy on the
    /// things that stop the harness working while still printing the things that merely make it
    /// worse.
    pub fn exit_code(&self) -> i32 {
        if self.failed() > 0 {
            1
        } else {
            0
        }
    }

    /// One line per check, then a verdict line. `json` prints the same checks as a document.
    pub fn render(&self, json: bool) -> String {
        if json {
            let document = serde_json::json!({
                "checks": self.checks,
                "checks_run": self.checks.len(),
                "failed": self.failed(),
                "warned": self.warned(),
                "exit_code": self.exit_code(),
            });
            return match serde_json::to_string_pretty(&document) {
                Ok(pretty) => format!("{pretty}\n"),
                Err(err) => format!("{{\"error\":\"could not serialise the report: {err}\"}}\n"),
            };
        }

        let mut out = String::new();
        for check in &self.checks {
            let _ = writeln!(
                out,
                "{} {:<18} {}",
                check.verdict.label(),
                check.name,
                check.reason
            );
        }

        let (failed, warned) = (self.failed(), self.warned());
        out.push('\n');
        if failed > 0 {
            let _ = write!(out, "{failed} of {} check(s) FAILED", self.checks.len());
            if warned > 0 {
                let _ = write!(out, ", {warned} warned");
            }
            out.push('\n');
        } else if warned > 0 {
            let _ = writeln!(out, "no check failed; {warned} warned");
        } else {
            let _ = writeln!(out, "all {} checks passed", self.checks.len());
        }
        out
    }
}

// ---------------------------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------------------------

/// The daemon's `/v1/status`, in the shape the checks read.
///
/// Deserialized from the document the route returns rather than reached for through the route's own
/// types, because the CLI has no dependency on `hx-server` and should not grow one to ask a
/// question over HTTP. Unknown fields are ignored on purpose: the daemon may report more than this
/// build reads, and a status document that gained a field must not become unreadable here. Missing
/// fields are *not* tolerated — a document that is not this shape is reported as unreadable, which
/// is the fail-closed direction for every check that depends on it.
#[derive(Clone, Debug, Deserialize)]
pub struct DaemonStatus {
    /// How many providers the *running* daemon was built with. Compared against the config's count,
    /// because "the daemon was started with a different file" is a real and confusing failure.
    pub providers_configured: usize,
    /// The secret stores a `store:name` reference can resolve through, by name.
    pub secret_stores: Vec<String>,
    /// Whether the vault was unlocked. Secrets are never loaded while it is locked.
    pub vault_unlocked: bool,
    pub pools: Vec<PoolStatus>,
    pub search_backends: Vec<String>,
    pub sandboxes: SandboxStatus,
}

/// One pool as the daemon reports it.
#[derive(Clone, Debug, Deserialize)]
pub struct PoolStatus {
    pub name: String,
    /// The pool's members, already expanded to concrete `provider/model` routes.
    pub routes: Vec<Route>,
    pub healthy_credentials: usize,
    pub total_credentials: usize,
}

/// One concrete destination.
#[derive(Clone, Debug, Deserialize)]
pub struct Route {
    pub provider: String,
    pub model: String,
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.provider, self.model)
    }
}

/// Whether the daemon has a container engine at all, and why not when it does not.
#[derive(Clone, Debug, Deserialize)]
pub struct SandboxStatus {
    pub available: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Where the daemon's bearer token comes from, as this process resolved it.
///
/// Three cases, because two would collapse the one that matters: "no token" is legal on a loopback
/// bind and a startup failure anywhere else, while a `api.token` reference that cannot be resolved
/// is a failure wherever it is bound. The carried `String` is a *setting's* name or an error
/// message, never a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenFact {
    /// A token resolved, from this setting.
    Set(String),
    /// Nothing configured anywhere.
    Absent,
    /// `api.token` names something this deployment cannot resolve.
    Unresolvable(String),
}

/// Everything the checks are decided from: the config, the daemon's report, and the two probes that
/// need the machine.
///
/// Plain data, deliberately. Each `Result` is either a value or the reason there is not one, which
/// is what lets a unit test hand [`diagnose`] a daemon that is down, an engine that never answered,
/// or a data directory that cannot be written — without any of those having to be simulated.
#[derive(Clone, Debug)]
pub struct Facts {
    /// The config file, as it was named on the command line — for the reason strings.
    pub config_path: String,
    /// The parsed config, or why it will not parse.
    pub config: Result<Config, String>,
    /// The daemon's status document, or why it could not be read.
    pub daemon: Result<DaemonStatus, String>,
    /// The address the `api token` check reasons about.
    pub bind: String,
    /// Where `bind` came from: `--bind`, `HX_BIND`, or `daemon.http_addr`. Printed, because an
    /// operator who set only one of the two settings needs to know which one was checked.
    pub bind_source: &'static str,
    pub token: TokenFact,
    /// A container engine reachable from *this* machine, or why not. The daemon's own answer is
    /// preferred when the daemon can be read; this is what makes the check answerable at all when
    /// the daemon cannot start.
    pub engine: Result<String, String>,
    /// Whether the configured data directory can be written, or why not.
    pub data_dir: Result<String, String>,
}

// ---------------------------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------------------------

const CONFIG: &str = "config";
const PROVIDERS: &str = "providers";
const ROLES: &str = "roles";
const POOLS: &str = "pools";
const PROFILES: &str = "sandbox profiles";
const ENGINE: &str = "container engine";
const SEARCH: &str = "search backends";
const SECRETS: &str = "secrets";
const API_TOKEN: &str = "api token";
const DATA_DIR: &str = "data dir";

/// The reason a check that needs the config carries when there is no config.
///
/// It points at the `config` line rather than repeating the parser's message ten times: the report
/// is read top to bottom, and a reason duplicated is a reason nobody finishes reading.
const NO_CONFIG: &str =
    "the config did not load, so this could not be checked — see the `config` line";

/// Decide every check from the evidence.
///
/// Pure: no I/O, no clock beyond the `now` it is given, no environment. That is what makes each
/// verdict below — including the ones that only happen on a machine with no Docker daemon — a
/// branch a test can reach by constructing its input.
pub fn diagnose(facts: &Facts, now: DateTime<Utc>) -> Report {
    let config = facts.config.as_ref().ok();
    Report {
        checks: vec![
            config_check(facts),
            providers_check(config, &facts.daemon),
            roles_check(config, now),
            pools_check(&facts.daemon),
            profiles_check(config),
            engine_check(config, &facts.daemon, &facts.engine),
            search_check(config, &facts.daemon),
            secrets_check(config, &facts.daemon),
            token_check(&facts.bind, facts.bind_source, &facts.token),
            data_dir_check(config, &facts.data_dir),
        ],
    }
}

/// Does the config file parse?
///
/// First, because ten of the checks below cannot run without it, and because it is the one failure
/// that stops the daemon from starting at all.
fn config_check(facts: &Facts) -> Check {
    match &facts.config {
        Ok(_) => Check::pass(
            CONFIG,
            format!(
                "{} parses, and every key in it is one this build knows",
                facts.config_path
            ),
        ),
        Err(err) => Check::fail(
            CONFIG,
            format!("{} does not parse: {err}", facts.config_path),
        ),
    }
}

/// Are there providers, and do they have credentials?
///
/// A provider with no credentials is not automatically broken — a local endpoint needs none — but
/// a config with *no* credential anywhere cannot make a single call, so it fails here.
fn providers_check(config: Option<&Config>, daemon: &Result<DaemonStatus, String>) -> Check {
    let Some(config) = config else {
        return Check::fail(PROVIDERS, NO_CONFIG);
    };

    if config.providers.is_empty() {
        return Check::fail(
            PROVIDERS,
            "no provider is configured, so there is nothing to route a model call to",
        );
    }

    let credentials: usize = config.providers.values().map(|p| p.credentials.len()).sum();
    if credentials == 0 {
        return Check::fail(
            PROVIDERS,
            format!(
                "{} provider(s) and not one credential between them ({}) — every model call fails \
                 on credential resolution",
                config.providers.len(),
                names(config.providers.keys().map(String::as_str)),
            ),
        );
    }

    match daemon {
        Ok(status) if status.providers_configured != config.providers.len() => Check::warn(
            PROVIDERS,
            format!(
                "this config names {} provider(s) and {credentials} credential(s), while the \
                 running daemon reports {} — it may have been started with a different config",
                config.providers.len(),
                status.providers_configured
            ),
        ),
        Ok(_) => Check::pass(
            PROVIDERS,
            format!(
                "{} provider(s), {credentials} credential(s), and the daemon was built from the \
                 same count",
                config.providers.len()
            ),
        ),
        Err(_) => Check::pass(
            PROVIDERS,
            format!(
                "{} provider(s), {credentials} credential(s), read from the config (the daemon \
                 could not be asked)",
                config.providers.len()
            ),
        ),
    }
}

/// Does the routing table build, and does at least one role resolve?
///
/// The table is the check: every configuration mistake that matters — a role pointing at a pool
/// that does not exist, a pool member naming an unknown provider, a pool with no members at all —
/// is an error out of `ModelRouter::from_config`, with its own message.
fn roles_check(config: Option<&Config>, now: DateTime<Utc>) -> Check {
    let Some(config) = config else {
        return Check::fail(ROLES, NO_CONFIG);
    };

    let router = match ModelRouter::from_config(config, now) {
        Ok(router) => router,
        Err(err) => {
            return Check::fail(ROLES, format!("the routing table does not build: {err}"));
        }
    };

    if router.roles().is_empty() {
        return Check::fail(
            ROLES,
            "no role is bound: `roles:` maps a role to a pool and a caller asks for a role, so \
             with none bound there is nothing to ask for",
        );
    }

    let bindings: Vec<String> = router
        .roles()
        .iter()
        .map(|(role, pool)| format!("{role}→{pool}"))
        .collect();
    Check::pass(
        ROLES,
        format!("{} role(s) resolve: {}", bindings.len(), names(&bindings)),
    )
}

/// Does every pool have at least one live member?
///
/// Read from the daemon, because this is the question only the daemon can answer: whether a
/// credential is still in rotation is runtime state, set when a provider refused it. When the
/// answer is no, every one of the pool's members is dead — so the message names them, which is the
/// most it can honestly say and more useful than the count.
fn pools_check(daemon: &Result<DaemonStatus, String>) -> Check {
    let status = match daemon {
        Ok(status) => status,
        Err(reason) => {
            return Check::fail(
                POOLS,
                format!(
                    "the daemon could not be read, so its pools could not be checked: {reason}"
                ),
            );
        }
    };

    if status.pools.is_empty() {
        return Check::fail(
            POOLS,
            "the daemon reports no pool at all, so no role can be routed",
        );
    }

    let mut dead: Vec<String> = Vec::new();
    let mut losing: Vec<String> = Vec::new();
    for pool in &status.pools {
        if pool.routes.is_empty() {
            dead.push(format!("{} (no member resolved)", pool.name));
        } else if pool.total_credentials == 0 {
            dead.push(format!(
                "{} (no credential is configured for any of the {} member(s): {})",
                pool.name,
                pool.routes.len(),
                names(pool.routes.iter().map(Route::to_string))
            ));
        } else if pool.healthy_credentials == 0 {
            dead.push(format!(
                "{} (all {} member(s) are out of rotation: {})",
                pool.name,
                pool.routes.len(),
                names(pool.routes.iter().map(Route::to_string))
            ));
        } else if pool.healthy_credentials < pool.total_credentials {
            losing.push(format!(
                "{} ({}/{} credential(s) healthy)",
                pool.name, pool.healthy_credentials, pool.total_credentials
            ));
        }
    }

    if !dead.is_empty() {
        return Check::fail(
            POOLS,
            format!(
                "{} of {} pool(s) have no live member: {}",
                dead.len(),
                status.pools.len(),
                dead.join("; ")
            ),
        );
    }
    if !losing.is_empty() {
        return Check::warn(
            POOLS,
            format!(
                "{} pool(s) can still be served but have lost a credential: {}",
                losing.len(),
                losing.join("; ")
            ),
        );
    }

    Check::pass(
        POOLS,
        format!(
            "all {} pool(s) have a live member: {}",
            status.pools.len(),
            names(status.pools.iter().map(|p| p.name.as_str()))
        ),
    )
}

/// Are the configured sandbox profiles usable, and do the hosts they name exist?
///
/// A profile that cannot be built is a boundary that fails at the moment a call needs it, which is
/// the worst possible time; and a profile naming a host that `hosts:` does not define would fail
/// there too. No profiles at all is a warning rather than a failure, and deliberately: a harness
/// with no profile is one whose shell calls run on the host, which an operator should see on the
/// report but which is not a broken daemon — it starts, and it works.
fn profiles_check(config: Option<&Config>) -> Check {
    let Some(config) = config else {
        return Check::fail(PROFILES, NO_CONFIG);
    };

    if config.sandbox_profiles.is_empty() {
        return Check::warn(
            PROFILES,
            "no sandbox profile is configured: `hx chat --sandbox-profile` has nothing to select \
             and every shell call runs on the host",
        );
    }

    let mut unusable: Vec<String> = Vec::new();
    let mut on_a_host = 0usize;
    for (name, profile) in &config.sandbox_profiles {
        // `validate` is what the sandbox actually applies, so it is what is asked here. The
        // workspace is supplied by the run rather than stated by the profile, so the probe value
        // only has to be non-empty for validation to reach the checks that are about the profile.
        let mut spec = SandboxSpec::from_profile(name, profile);
        spec.workspace_host_path = "/probe".to_string();
        if let Err(err) = spec.validate() {
            unusable.push(format!("{name}: {err}"));
            continue;
        }
        if let Some(host) = profile.host.as_deref().filter(|h| *h != "local") {
            if config.hosts.contains_key(host) {
                on_a_host += 1;
            } else {
                unusable.push(format!(
                    "{name}: runs on host '{host}', which `hosts:` does not define"
                ));
            }
        }
    }

    if !unusable.is_empty() {
        return Check::fail(
            PROFILES,
            format!(
                "{} of {} profile(s) are unusable: {}",
                unusable.len(),
                config.sandbox_profiles.len(),
                unusable.join("; ")
            ),
        );
    }

    Check::pass(
        PROFILES,
        format!(
            "{} profile(s) valid{}",
            config.sandbox_profiles.len(),
            if on_a_host > 0 {
                format!(", {on_a_host} of them on a named host")
            } else {
                String::new()
            }
        ),
    )
}

/// Is a container engine available, if a profile needs one?
///
/// The daemon's own answer first: it built (or failed to build) its sandbox manager at startup, and
/// its status carries that reason. When the daemon cannot be read the check falls back to probing
/// this machine, which is the case where an operator is diagnosing a daemon that will not start —
/// and the reason says which of the two answers it is reporting.
fn engine_check(
    config: Option<&Config>,
    daemon: &Result<DaemonStatus, String>,
    probe: &Result<String, String>,
) -> Check {
    let Some(config) = config else {
        return Check::fail(ENGINE, NO_CONFIG);
    };

    let needing: Vec<&str> = config
        .sandbox_profiles
        .iter()
        .filter(|(_, profile)| needs_local_engine(profile))
        .map(|(name, _)| name.as_str())
        .collect();

    if needing.is_empty() {
        return if config.sandbox_profiles.is_empty() {
            Check::pass(
                ENGINE,
                "no sandbox profile is configured, so no container engine is needed",
            )
        } else {
            Check::pass(
                ENGINE,
                format!(
                    "none of the {} profile(s) runs here — every one names a host — so no local \
                     container engine is needed",
                    config.sandbox_profiles.len()
                ),
            )
        };
    }

    match daemon {
        Ok(status) if status.sandboxes.available => Check::pass(
            ENGINE,
            format!(
                "the daemon's sandbox engine is up and {} profile(s) need it: {}",
                needing.len(),
                names(&needing)
            ),
        ),
        Ok(status) => Check::fail(
            ENGINE,
            format!(
                "{} profile(s) need a container engine ({}) and the daemon has none: {}",
                needing.len(),
                names(&needing),
                status
                    .sandboxes
                    .reason
                    .as_deref()
                    .unwrap_or("the daemon reported no reason")
            ),
        ),
        Err(reason) => match probe {
            Ok(found) => Check::pass(
                ENGINE,
                format!(
                    "{} profile(s) need a container engine ({}) and one answered on this machine: \
                     {found}. The daemon could not be asked: {reason}",
                    needing.len(),
                    names(&needing)
                ),
            ),
            Err(why) => Check::fail(
                ENGINE,
                format!(
                    "{} profile(s) need a container engine ({}) and none answered: {why}. The \
                     daemon could not be asked either: {reason}",
                    needing.len(),
                    names(&needing)
                ),
            ),
        },
    }
}

/// Whether a profile runs on this machine's container engine.
///
/// A profile with no `host` runs here, and `host: local` is the same thing spelled out —
/// `AppState::sandbox_manager_for` treats the two alike, so this does too rather than reporting a
/// local profile as remote.
fn needs_local_engine(profile: &SandboxProfile) -> bool {
    matches!(profile.host.as_deref(), None | Some("local"))
}

/// Are search backends configured, and did the daemon build them?
///
/// None configured warns rather than fails: `web_search` returns nothing, which degrades a run
/// instead of stopping the daemon. Backends this config names that the daemon did not build is a
/// warning too, and says why it can happen — the daemon is a separate process and may have been
/// started with a different file, which is the confusing case this line exists to end.
fn search_check(config: Option<&Config>, daemon: &Result<DaemonStatus, String>) -> Check {
    let Some(config) = config else {
        return Check::fail(SEARCH, NO_CONFIG);
    };

    let configured = &config.search.backends;
    if configured.is_empty() {
        return Check::warn(
            SEARCH,
            "no backend is configured: `web_search` returns nothing, which degrades search rather \
             than stopping the daemon",
        );
    }

    match daemon {
        Err(reason) => Check::fail(
            SEARCH,
            format!(
                "{} backend(s) are configured ({}) and the daemon could not be read, so whether \
                 it built them could not be checked: {reason}",
                configured.len(),
                names(configured)
            ),
        ),
        Ok(status) if status.search_backends.is_empty() => Check::fail(
            SEARCH,
            format!(
                "{} backend(s) are configured ({}) and the daemon built none, so search returns \
                 nothing — a backend it cannot build is an error at startup, so the daemon was \
                 most likely started with a different config",
                configured.len(),
                names(configured)
            ),
        ),
        Ok(status) => {
            let built = &status.search_backends;
            if built.len() != configured.len() || built.iter().any(|b| !configured.contains(b)) {
                return Check::warn(
                    SEARCH,
                    format!(
                        "this config names {} ({}) and the daemon reports {} ({}) — it may have \
                         been started with a different config",
                        configured.len(),
                        names(configured),
                        built.len(),
                        names(built)
                    ),
                );
            }
            Check::pass(
                SEARCH,
                format!(
                    "{} backend(s) configured and built: {}",
                    configured.len(),
                    names(built)
                ),
            )
        }
    }
}

/// Can every credential reference the config holds actually resolve?
///
/// A credential is written as a `store:name` reference, and the store decides where the value comes
/// from — `env`, or a vault. A reference to a store the daemon does not have cannot resolve, so
/// every call that uses it fails; that is the whole check. When a vault *is* a configured store but
/// the daemon reports it locked, the references are legal and merely not usable yet, which warns.
///
/// The daemon is not asked when the config references no store at all: there is nothing for its
/// answer to be about, and requiring a daemon for a check that cannot fail would be noise.
fn secrets_check(config: Option<&Config>, daemon: &Result<DaemonStatus, String>) -> Check {
    let Some(config) = config else {
        return Check::fail(SECRETS, NO_CONFIG);
    };

    let references = store_references(config);
    if references.is_empty() {
        return Check::pass(
            SECRETS,
            "no credential in this config is a `store:name` reference, so no store has to be \
             readable",
        );
    }

    let wanted: BTreeSet<&str> = references.iter().map(|r| r.store.as_str()).collect();

    let status = match daemon {
        Ok(status) => status,
        Err(reason) => {
            return Check::fail(
                SECRETS,
                format!(
                    "{} reference(s) resolve through {} and the daemon could not be read, so its \
                     stores could not be checked: {reason}",
                    references.len(),
                    names(&wanted)
                ),
            );
        }
    };

    let have: BTreeSet<&str> = status.secret_stores.iter().map(String::as_str).collect();
    let missing: Vec<String> = references
        .iter()
        .filter(|r| !have.contains(r.store.as_str()))
        .map(SecretRef::to_string)
        .collect();

    if !missing.is_empty() {
        return Check::fail(
            SECRETS,
            format!(
                "{} of {} reference(s) name a store the daemon does not have ({}); its stores are \
                 {} — a reference is resolved by the store it names, so every call that uses one \
                 fails. Put the value where the reference points, or point it at a store this \
                 deployment has",
                missing.len(),
                references.len(),
                names(&missing),
                names(&have)
            ),
        );
    }

    if wanted.contains("vault") && !status.vault_unlocked {
        return Check::warn(
            SECRETS,
            format!(
                "every referenced store is configured ({}), and the vault is locked — a `vault:` \
                 reference resolves once it is unlocked",
                names(&have)
            ),
        );
    }

    Check::pass(
        SECRETS,
        format!(
            "every store this config references is configured on the daemon: {}",
            names(&have)
        ),
    )
}

/// Is the API token set, for the address the daemon is bound to?
///
/// The rule is the daemon's own ([`require_token_for_bind`]), called here rather than restated, so
/// the doctor and `hxd` cannot disagree about when a token is required. A token is optional on a
/// loopback bind and a refusal to start anywhere else.
fn token_check(bind: &str, bind_source: &str, token: &TokenFact) -> Check {
    if let TokenFact::Unresolvable(reason) = token {
        return Check::fail(
            API_TOKEN,
            format!(
                "`api.token` names something this deployment cannot resolve: {reason}. The daemon \
                 refuses to start on this rather than serving an API whose token it cannot check"
            ),
        );
    }

    let configured = matches!(token, TokenFact::Set(_));
    let where_from = match token {
        TokenFact::Set(setting) => format!("set from `{setting}`"),
        _ => "none configured".to_string(),
    };

    if let Err(refusal) = require_token_for_bind(bind, configured) {
        return Check::fail(
            API_TOKEN,
            format!("{refusal} (checked against {bind}, from {bind_source})"),
        );
    }

    if bind_is_loopback(bind) {
        Check::pass(
            API_TOKEN,
            format!(
                "{where_from}, and {bind} (from {bind_source}) is a loopback address — the only \
                 bind where a token is optional, and one it is honoured on when set"
            ),
        )
    } else {
        Check::pass(
            API_TOKEN,
            format!(
                "{where_from}, and {bind} (from {bind_source}) is reachable from elsewhere, so \
                 `hxd` requires exactly this"
            ),
        )
    }
}

/// Can the data directory be written?
///
/// The session store lives there, so a directory the daemon cannot write is a daemon that cannot
/// record a run. The probe is the shell's job (it touches the filesystem) and its answer arrives
/// here as a value.
fn data_dir_check(config: Option<&Config>, probe: &Result<String, String>) -> Check {
    let Some(config) = config else {
        return Check::fail(DATA_DIR, NO_CONFIG);
    };

    let path = &config.daemon.data_dir;
    match probe {
        Ok(found) => Check::pass(DATA_DIR, format!("{path} is writable: {found}")),
        Err(why) => Check::fail(
            DATA_DIR,
            format!(
                "{path} is not writable: {why}. The session store (`hx.db`) lives there, so the \
                 daemon could not record a run"
            ),
        ),
    }
}

/// Every `store:name` reference this config holds, wherever it is written.
///
/// A value with no colon is a *literal* and not a store lookup, so it is skipped: it is the store
/// name that decides whether anything has to be readable. `api.token` is skipped for a different
/// reason — it is checked by the `api token` line, and a literal token that happens to contain a
/// colon would otherwise be reported as a reference to a store named after its own first word.
fn store_references(config: &Config) -> Vec<SecretRef> {
    let mut out: Vec<SecretRef> = Vec::new();
    let mut push = |value: &str| {
        if let Ok(reference) = SecretRef::parse(value) {
            out.push(reference);
        }
    };

    for provider in config.providers.values() {
        for credential in &provider.credentials {
            push(&credential.secret);
        }
    }
    for reference in config.search.credentials.values() {
        push(reference);
    }
    for host in config.hosts.values() {
        match &host.auth {
            AuthMethod::Key { secret_ref } | AuthMethod::Password { secret_ref } => {
                push(secret_ref)
            }
            AuthMethod::Agent | AuthMethod::Platform => {}
        }
    }
    for connector in config.connectors.values() {
        if let Some(token) = &connector.token {
            push(token);
        }
    }
    for server in config.mcp_servers.values() {
        if let Some(token) = &server.token {
            push(token);
        }
    }

    // De-duplicated so one credential shared by three providers is one entry in the reason: a line
    // an operator cannot finish reading is a line they will not act on.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    out.retain(|reference| seen.insert(reference.to_string()));
    out
}

/// Join names for a reason line, capped so that a pool with forty members does not produce a
/// paragraph. The cap says how many it left out rather than trailing off.
fn names(items: impl IntoIterator<Item = impl AsRef<str>>) -> String {
    const CAP: usize = 6;

    let collected: Vec<String> = items.into_iter().map(|i| i.as_ref().to_string()).collect();
    if collected.is_empty() {
        return "(none)".to_string();
    }
    if collected.len() <= CAP {
        return collected.join(", ");
    }
    format!(
        "{}, and {} more",
        collected[..CAP].join(", "),
        collected.len() - CAP
    )
}

// ---------------------------------------------------------------------------------------------
// The shell: reading the config, the daemon and the machine
// ---------------------------------------------------------------------------------------------

/// Gather the evidence: read the config, fetch the daemon's status, and probe what needs probing.
///
/// The only part of this module that touches the world. Everything it finds out is turned into a
/// [`Facts`] so that the decisions stay testable; nothing here interprets what it reads.
pub async fn gather(
    config_path: &Path,
    daemon_override: Option<&str>,
    bind: Option<&str>,
) -> Facts {
    let config = match std::fs::read_to_string(config_path) {
        Ok(raw) => Config::from_yaml(&raw).map_err(|err| err.to_string()),
        Err(err) => Err(format!("could not be read: {err}")),
    };

    // The daemon, over the same client — and the same token — every other command uses, so a
    // deployment cannot end up with `hx doctor` talking to one address and `hx chat` to another.
    let status = match &config {
        Ok(config) => match crate::daemon::connect(config, daemon_override) {
            Ok((client, base)) => match crate::daemon::status(&client, &base).await {
                Ok(document) => serde_json::from_value::<DaemonStatus>(document).map_err(|err| {
                    format!("the daemon's /v1/status is not a document this build can read: {err}")
                }),
                Err(err) => Err(format!("{err:#}")),
            },
            Err(err) => Err(format!("{err:#}")),
        },
        Err(reason) => Err(format!(
            "the config did not load ({reason}), so the daemon's address and token are unknown"
        )),
    };

    let (bind, bind_source) = match bind {
        Some(addr) => (addr.to_string(), "--bind"),
        None => match std::env::var("HX_BIND") {
            Ok(addr) if !addr.trim().is_empty() => (addr, "HX_BIND"),
            _ => match &config {
                Ok(config) => (config.daemon.http_addr.clone(), "daemon.http_addr"),
                Err(_) => ("127.0.0.1:7717".to_string(), "hxd's default"),
            },
        },
    };

    let token = match &config {
        Ok(config) => token_fact(config),
        Err(_) => TokenFact::Absent,
    };

    Facts {
        config_path: config_path.display().to_string(),
        data_dir: config
            .as_ref()
            .map(probe_data_dir)
            .unwrap_or_else(|reason| Err(format!("{reason}, so the data directory is unknown"))),
        config,
        daemon: status,
        bind,
        bind_source,
        token,
        engine: probe_engine().await,
    }
}

/// Resolve the API token the way the daemon does, from the stores a CLI process has.
///
/// The environment is the only store available here — a `vault:` reference cannot be opened by this
/// process — which is exactly the limit `daemon::connect` documents. It is reported as
/// [`TokenFact::Unresolvable`] rather than as "no token", because those two are different problems
/// with different fixes.
fn token_fact(config: &Config) -> TokenFact {
    let stores = hx_secrets::SecretStores::new().with(Arc::new(hx_secrets::EnvSecrets));
    let named_here = config
        .api
        .token
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());

    match hx_secrets::resolve_api_token(config, &stores) {
        Ok(Some(_)) if named_here => TokenFact::Set("api.token".to_string()),
        Ok(Some(_)) => TokenFact::Set(API_TOKEN_ENV.to_string()),
        Ok(None) => TokenFact::Absent,
        Err(err) => TokenFact::Unresolvable(err.to_string()),
    }
}

/// Whether a container engine answers on this machine.
///
/// The daemon prefers its own status; this is what the check falls back to when the daemon cannot
/// be read, which is the case where someone is working out why it will not start.
async fn probe_engine() -> Result<String, String> {
    match hx_sandbox::DockerRuntime::connect().await {
        Ok(runtime) if runtime.available().await => Ok("the Docker socket answered".to_string()),
        Ok(_) => Err("the Docker socket exists but no daemon answered on it".to_string()),
        Err(err) => Err(err.to_string()),
    }
}

/// Whether the configured data directory can be written.
///
/// The daemon creates the directory on its first run (`Store::open`), so this asks the same
/// question the daemon will: create it if it is missing, write a probe file, remove it again. That
/// probe file is the only thing `hx doctor` writes.
fn probe_data_dir(config: &Config) -> Result<String, String> {
    let dir = expand_home(&config.daemon.data_dir);
    // A `~` that could not be expanded is left as a literal by `expand_home`, and creating a
    // directory called `~` in the working directory would be a worse outcome than saying so.
    if dir.to_string_lossy().starts_with('~') {
        return Err(format!(
            "{} starts with `~` and HOME is not set, so it cannot be resolved",
            config.daemon.data_dir
        ));
    }

    std::fs::create_dir_all(&dir)
        .map_err(|err| format!("{} could not be created: {err}", dir.display()))?;

    let probe = dir.join(format!(".hx-doctor-probe-{}", std::process::id()));
    std::fs::write(&probe, b"").map_err(|err| format!("{err}"))?;
    std::fs::remove_file(&probe).map_err(|err| {
        format!(
            "a probe file at {} was written but could not be removed: {err}",
            probe.display()
        )
    })?;

    Ok(format!(
        "it exists and accepted a probe file ({})",
        dir.display()
    ))
}

/// Expand a leading `~/` in the configured data directory.
///
/// `hx-store` does the same thing privately when it opens the database, and this would rather call
/// it than restate it — but making it public would put SQLite in the CLI binary for one path rule.
/// The rule is two lines and is tested below, and it is the *daemon's* rule that matters: a path
/// this resolves differently from `Store::open` would make the check about a directory the daemon
/// never uses.
fn expand_home(path: &str) -> PathBuf {
    let home = {
        #[cfg(windows)]
        {
            std::env::var_os("USERPROFILE")
        }
        #[cfg(not(windows))]
        {
            std::env::var_os("HOME")
        }
    };

    match path.strip_prefix("~/") {
        Some(rest) => match home {
            Some(home) => PathBuf::from(home).join(rest),
            // Left alone rather than guessed at: the caller notices the literal `~` and says so.
            None => PathBuf::from(path),
        },
        None => PathBuf::from(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A complete, healthy config: one provider with two `env:` credentials, two pools, two roles,
    /// one local sandbox profile, and two search backends. Every check has something to say about
    /// this file, which is what makes it the base the failing cases are one edit away from.
    const HEALTHY: &str = r#"
providers:
  anthropic-main:
    kind: anthropic
    models: [claude-opus-4-7, claude-sonnet-4-7]
    credentials:
      - { id: a1, secret: "env:ANTHROPIC_KEY" }
      - { id: a2, secret: "env:ANTHROPIC_BACKUP" }
pools:
  interactive: { members: ["anthropic-main/claude-*"] }
  background: { members: ["anthropic-main/claude-sonnet-4-7"] }
roles:
  builder: interactive
  scout: background
sandbox_profiles:
  dev: { image: ubuntu:24.04, isolation: l1 }
search:
  backends: [duckduckgo, wikipedia]
"#;

    /// The daemon's status document, parsed the way the shell parses it.
    ///
    /// The fixture carries the keys the real route sends — including ones these checks do not read,
    /// like `sessions` and `hosts` — so that the deserialization under test is the shape a live
    /// daemon answers with rather than a shape invented to fit the struct.
    fn status(value: serde_json::Value) -> DaemonStatus {
        serde_json::from_value(value).expect("/v1/status as this build reads it")
    }

    /// A daemon built from [`HEALTHY`]: one provider, two built backends, two pools with every
    /// credential in rotation, and a sandbox engine.
    fn healthy_daemon() -> DaemonStatus {
        status(json!({
            "version": "0.0.1",
            "uptime_secs": 41,
            "vault_unlocked": false,
            "providers_configured": 1,
            "secret_stores": ["env"],
            "sessions": 3,
            "pools": [
                {
                    "name": "interactive",
                    "routes": [{ "provider": "anthropic-main", "model": "claude-opus-4-7" }],
                    "healthy_credentials": 2,
                    "total_credentials": 2
                },
                {
                    "name": "background",
                    "routes": [{ "provider": "anthropic-main", "model": "claude-sonnet-4-7" }],
                    "healthy_credentials": 2,
                    "total_credentials": 2
                }
            ],
            "roles": { "builder": "interactive", "scout": "background" },
            "search_backends": ["duckduckgo", "wikipedia"],
            "sandboxes": { "available": true, "reason": null, "live": 0 },
            "hosts": []
        }))
    }

    /// Everything the checks read, in the state a working deployment would be in.
    fn facts() -> Facts {
        Facts {
            config_path: "hx.yaml".to_string(),
            config: Config::from_yaml(HEALTHY).map_err(|err| err.to_string()),
            daemon: Ok(healthy_daemon()),
            bind: "127.0.0.1:8787".to_string(),
            bind_source: "daemon.http_addr",
            token: TokenFact::Absent,
            engine: Err("no Docker socket was found".to_string()),
            data_dir: Ok("it exists and accepted a probe file".to_string()),
        }
    }

    fn with_config(yaml: &str) -> Facts {
        Facts {
            config: Config::from_yaml(yaml).map_err(|err| err.to_string()),
            ..facts()
        }
    }

    /// Run the checks and hand back one of them.
    ///
    /// Named checks are looked up rather than indexed: a test that asserted `checks[3]` would pass
    /// on the wrong line the moment the report grew a check.
    fn check<'a>(report: &'a Report, name: &str) -> &'a Check {
        report
            .checks
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no check named {name:?} in {:?}", report.checks))
    }

    fn diagnose_ok(facts: &Facts, name: &str) -> (Verdict, String) {
        let report = diagnose(facts, Utc::now());
        let found = check(&report, name);
        (found.verdict, found.reason.clone())
    }

    fn assert_verdict(facts: &Facts, name: &str, verdict: Verdict, needle: &str) {
        let (found, reason) = diagnose_ok(facts, name);
        assert_eq!(
            found, verdict,
            "{name} should be {verdict:?}, and said {found:?}: {reason}"
        );
        assert!(
            reason.contains(needle),
            "{name} ({found:?}) must say {needle:?}: {reason}"
        );
    }

    // -- the config ----------------------------------------------------------

    #[test]
    fn a_complete_config_passes_every_check() {
        let report = diagnose(&facts(), Utc::now());
        assert_eq!(report.failed(), 0, "{}", report.render(false));
        assert_eq!(report.warned(), 0, "{}", report.render(false));
        assert_eq!(report.exit_code(), 0);
        assert!(
            report.render(false).contains("all 10 checks passed"),
            "{}",
            report.render(false)
        );
    }

    #[test]
    fn a_config_that_parses_is_reported_with_its_path() {
        assert_verdict(
            &facts(),
            "config",
            Verdict::Pass,
            "hx.yaml parses, and every key in it is one this build knows",
        );
    }

    #[test]
    fn a_config_that_does_not_parse_fails_with_the_parsers_own_message() {
        let broken = Facts {
            config: Config::from_yaml("providers:\n  p1: { kind: telepathy }\n")
                .map_err(|err| err.to_string()),
            ..facts()
        };
        let (verdict, reason) = diagnose_ok(&broken, "config");
        assert_eq!(verdict, Verdict::Fail);
        assert!(reason.contains("hx.yaml does not parse:"), "{reason}");
        assert!(
            reason.contains("telepathy"),
            "the parser's own message is the reason: {reason}"
        );
    }

    #[test]
    fn every_check_that_needs_the_config_says_so_when_it_did_not_load() {
        // The ten checks cannot all be run without a config, and a check that silently passed
        // because it had nothing to read would be exactly the failure this command exists to
        // prevent. Each names the `config` line rather than repeating the parser's message.
        let broken = Facts {
            config: Err("could not be read: no such file".to_string()),
            ..facts()
        };
        let report = diagnose(&broken, Utc::now());
        for name in [
            "providers",
            "roles",
            "sandbox profiles",
            "container engine",
            "search backends",
            "secrets",
            "data dir",
        ] {
            let found = check(&report, name);
            assert_eq!(found.verdict, Verdict::Fail, "{name}: {found:?}");
            assert!(
                found.reason.contains("see the `config` line"),
                "{name} must point at the config line: {}",
                found.reason
            );
        }
        // And the ones that need no config at all still run: the bind address and the engine probe
        // are facts about this machine, not about the file.
        assert_eq!(check(&report, "api token").verdict, Verdict::Pass);
    }

    // -- providers -----------------------------------------------------------

    #[test]
    fn a_config_with_no_provider_at_all_fails() {
        let facts = with_config("pools: {}\nroles: {}\n");
        assert_verdict(
            &facts,
            "providers",
            Verdict::Fail,
            "no provider is configured, so there is nothing to route a model call to",
        );
    }

    #[test]
    fn providers_without_a_single_credential_fail_and_are_named() {
        let facts = with_config(
            r#"
providers:
  anthropic-main: { kind: anthropic, models: ["claude-opus-4-7"] }
  local-llama: { kind: ollama }
"#,
        );
        let (verdict, reason) = diagnose_ok(&facts, "providers");
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            reason.contains("2 provider(s) and not one credential"),
            "{reason}"
        );
        assert!(
            reason.contains("anthropic-main, local-llama"),
            "the providers that cannot be called are named: {reason}"
        );
    }

    #[test]
    fn a_healthy_provider_set_passes_with_its_counts() {
        assert_verdict(
            &facts(),
            "providers",
            Verdict::Pass,
            "1 provider(s), 2 credential(s), and the daemon was built from the same count",
        );
    }

    #[test]
    fn a_provider_count_the_daemon_disagrees_with_warns() {
        // The daemon is a separate process and may have been started from a different file. That
        // is worth a line precisely because it explains every other check that disagrees with it.
        let facts = Facts {
            daemon: Ok(status(json!({
                "providers_configured": 4,
                "secret_stores": ["env"],
                "vault_unlocked": false,
                "pools": [],
                "search_backends": [],
                "sandboxes": { "available": false, "reason": "no engine" }
            }))),
            ..facts()
        };
        let (verdict, reason) = diagnose_ok(&facts, "providers");
        assert_eq!(verdict, Verdict::Warn);
        assert!(
            reason.contains("this config names 1 provider(s)"),
            "{reason}"
        );
        assert!(reason.contains("the running daemon reports 4"), "{reason}");
        assert!(
            reason.contains("started with a different config"),
            "the likely cause is named: {reason}"
        );
    }

    #[test]
    fn providers_are_reported_from_the_config_when_the_daemon_cannot_be_asked() {
        let facts = Facts {
            daemon: Err("could not reach the daemon".to_string()),
            ..facts()
        };
        assert_verdict(
            &facts,
            "providers",
            Verdict::Pass,
            "1 provider(s), 2 credential(s), read from the config (the daemon could not be asked)",
        );
    }

    // -- roles ---------------------------------------------------------------

    #[test]
    fn a_config_with_no_role_fails_because_nothing_can_be_asked_for() {
        let facts = with_config(
            r#"
providers:
  anthropic-main: { kind: anthropic, models: ["claude-opus-4-7"], credentials: [{ id: a1, secret: "env:A" }] }
pools:
  interactive: { members: ["anthropic-main/claude-opus-4-7"] }
"#,
        );
        assert_verdict(
            &facts,
            "roles",
            Verdict::Fail,
            "no role is bound: `roles:` maps a role to a pool and a caller asks for a role",
        );
    }

    #[test]
    fn a_role_pointing_at_a_missing_pool_is_a_failure_that_names_the_role() {
        // The most common config mistake there is, and the reason the routing table is built as
        // part of the check rather than read from the config's own keys.
        let facts = with_config(
            r#"
providers:
  anthropic-main: { kind: anthropic, models: ["claude-opus-4-7"], credentials: [{ id: a1, secret: "env:A" }] }
pools:
  interactive: { members: ["anthropic-main/claude-opus-4-7"] }
roles:
  builder: interactve
"#,
        );
        let (verdict, reason) = diagnose_ok(&facts, "roles");
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            reason.contains("the routing table does not build"),
            "{reason}"
        );
        assert!(reason.contains("builder"), "{reason}");
        assert!(reason.contains("interactve"), "{reason}");
    }

    #[test]
    fn every_role_resolving_passes_and_names_its_bindings() {
        assert_verdict(
            &facts(),
            "roles",
            Verdict::Pass,
            "2 role(s) resolve: builder→interactive, scout→background",
        );
    }

    // -- pools ---------------------------------------------------------------

    #[test]
    fn a_pool_with_no_live_member_fails_and_names_every_member() {
        // Zero healthy credentials with some configured means every credential was refused and
        // benched at runtime — so every member of the pool is dead, and naming them is the whole
        // value of the line.
        let facts = Facts {
            daemon: Ok(status(json!({
                "providers_configured": 1,
                "secret_stores": ["env"],
                "vault_unlocked": false,
                "pools": [{
                    "name": "interactive",
                    "routes": [
                        { "provider": "anthropic-main", "model": "claude-opus-4-7" },
                        { "provider": "anthropic-main", "model": "claude-sonnet-4-7" }
                    ],
                    "healthy_credentials": 0,
                    "total_credentials": 3
                }],
                "search_backends": [],
                "sandboxes": { "available": false, "reason": "no engine" }
            }))),
            ..facts()
        };
        let (verdict, reason) = diagnose_ok(&facts, "pools");
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            reason.contains("1 of 1 pool(s) have no live member"),
            "{reason}"
        );
        assert!(
            reason.contains("interactive (all 2 member(s) are out of rotation"),
            "{reason}"
        );
        assert!(
            reason.contains("anthropic-main/claude-opus-4-7, anthropic-main/claude-sonnet-4-7"),
            "the dead members are named, not counted: {reason}"
        );
    }

    #[test]
    fn a_pool_whose_providers_have_no_credentials_fails_naming_its_members() {
        let facts = Facts {
            daemon: Ok(status(json!({
                "providers_configured": 1,
                "secret_stores": ["env"],
                "vault_unlocked": false,
                "pools": [{
                    "name": "interactive",
                    "routes": [{ "provider": "anthropic-main", "model": "claude-opus-4-7" }],
                    "healthy_credentials": 0,
                    "total_credentials": 0
                }],
                "search_backends": [],
                "sandboxes": { "available": false, "reason": "no engine" }
            }))),
            ..facts()
        };
        let (verdict, reason) = diagnose_ok(&facts, "pools");
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            reason.contains("no credential is configured for any of the 1 member(s)"),
            "{reason}"
        );
        assert!(
            reason.contains("anthropic-main/claude-opus-4-7"),
            "{reason}"
        );
    }

    #[test]
    fn a_pool_with_no_member_resolved_fails() {
        let facts = Facts {
            daemon: Ok(status(json!({
                "providers_configured": 1,
                "secret_stores": ["env"],
                "vault_unlocked": false,
                "pools": [{
                    "name": "interactive",
                    "routes": [],
                    "healthy_credentials": 0,
                    "total_credentials": 0
                }],
                "search_backends": [],
                "sandboxes": { "available": false, "reason": "no engine" }
            }))),
            ..facts()
        };
        assert_verdict(
            &facts,
            "pools",
            Verdict::Fail,
            "interactive (no member resolved)",
        );
    }

    #[test]
    fn a_pool_that_lost_one_credential_warns_with_the_counts() {
        // The limit, asserted rather than described: the daemon reports credential health per
        // pool, not per member, so this is a count and not a named member. Naming one would be
        // naming a member nothing condemned.
        let facts = Facts {
            daemon: Ok(status(json!({
                "providers_configured": 1,
                "secret_stores": ["env"],
                "vault_unlocked": false,
                "pools": [{
                    "name": "interactive",
                    "routes": [{ "provider": "anthropic-main", "model": "claude-opus-4-7" }],
                    "healthy_credentials": 1,
                    "total_credentials": 3
                }],
                "search_backends": [],
                "sandboxes": { "available": false, "reason": "no engine" }
            }))),
            ..facts()
        };
        let (verdict, reason) = diagnose_ok(&facts, "pools");
        assert_eq!(verdict, Verdict::Warn);
        assert!(
            reason.contains("interactive (1/3 credential(s) healthy)"),
            "{reason}"
        );
        assert!(
            reason.contains("can still be served"),
            "a warning must not read like a failure: {reason}"
        );
    }

    #[test]
    fn a_daemon_with_no_pool_at_all_fails() {
        let facts = Facts {
            daemon: Ok(status(json!({
                "providers_configured": 1,
                "secret_stores": ["env"],
                "vault_unlocked": false,
                "pools": [],
                "search_backends": [],
                "sandboxes": { "available": false, "reason": "no engine" }
            }))),
            ..facts()
        };
        assert_verdict(
            &facts,
            "pools",
            Verdict::Fail,
            "the daemon reports no pool at all, so no role can be routed",
        );
    }

    #[test]
    fn a_daemon_that_cannot_be_read_fails_the_pool_check_with_the_reason() {
        let facts = Facts {
            daemon: Err("could not reach the daemon at http://127.0.0.1:8787".to_string()),
            ..facts()
        };
        let (verdict, reason) = diagnose_ok(&facts, "pools");
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            reason.contains("the daemon could not be read, so its pools could not be checked"),
            "{reason}"
        );
        assert!(
            reason.contains("could not reach the daemon at http://127.0.0.1:8787"),
            "the reason the daemon could not be read is carried, not swallowed: {reason}"
        );
    }

    #[test]
    fn every_pool_having_a_live_member_passes_and_names_them() {
        assert_verdict(
            &facts(),
            "pools",
            Verdict::Pass,
            "all 2 pool(s) have a live member: interactive, background",
        );
    }

    // -- sandbox profiles ----------------------------------------------------

    #[test]
    fn no_sandbox_profile_warns_rather_than_failing() {
        // A harness with no profile runs every shell call on the host. That is a degradation an
        // operator should see on the report; it is not a broken daemon, and calling it a failure
        // would make `hx doctor` red on a deployment that works.
        let facts = with_config(
            r#"
providers:
  anthropic-main: { kind: anthropic, models: ["m"], credentials: [{ id: a1, secret: "env:A" }] }
pools:
  interactive: { members: ["anthropic-main/m"] }
roles:
  builder: interactive
"#,
        );
        assert_verdict(
            &facts,
            "sandbox profiles",
            Verdict::Warn,
            "no sandbox profile is configured: `hx chat --sandbox-profile` has nothing to select",
        );
    }

    #[test]
    fn an_invalid_profile_fails_naming_the_profile_and_the_defect() {
        // The broken profile is declared alongside the valid one: appending an indented key to
        // HEALTHY would nest it under `search:` (the last mapping) and fail the config instead.
        let facts = with_config(
            r#"
providers:
  anthropic-main: { kind: anthropic, models: ["m"], credentials: [{ id: a1, secret: "env:A" }] }
pools:
  interactive: { members: ["anthropic-main/m"] }
roles:
  builder: interactive
sandbox_profiles:
  dev: { image: ubuntu:24.04 }
  broken: { image: "" }
"#,
        );
        let (verdict, reason) = diagnose_ok(&facts, "sandbox profiles");
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            reason.contains("1 of 2 profile(s) are unusable"),
            "{reason}"
        );
        assert!(reason.contains("broken:"), "{reason}");
        assert!(
            reason.contains("image"),
            "the defect is named, not just the profile: {reason}"
        );
    }

    #[test]
    fn a_profile_naming_a_host_that_is_not_defined_fails() {
        let facts = with_config(
            r#"
providers:
  anthropic-main: { kind: anthropic, models: ["m"], credentials: [{ id: a1, secret: "env:A" }] }
pools:
  interactive: { members: ["anthropic-main/m"] }
roles:
  builder: interactive
sandbox_profiles:
  far: { image: ubuntu:24.04, host: buildbox }
"#,
        );
        let (verdict, reason) = diagnose_ok(&facts, "sandbox profiles");
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            reason.contains("far: runs on host 'buildbox', which `hosts:` does not define"),
            "{reason}"
        );
    }

    #[test]
    fn profiles_that_are_all_valid_pass_and_count_the_ones_on_a_host() {
        let facts = with_config(
            r#"
providers:
  anthropic-main: { kind: anthropic, models: ["m"], credentials: [{ id: a1, secret: "env:A" }] }
pools:
  interactive: { members: ["anthropic-main/m"] }
roles:
  builder: interactive
hosts:
  buildbox: { kind: ssh, address: 10.0.0.5 }
sandbox_profiles:
  dev: { image: ubuntu:24.04 }
  far: { image: ubuntu:24.04, host: buildbox }
"#,
        );
        assert_verdict(
            &facts,
            "sandbox profiles",
            Verdict::Pass,
            "2 profile(s) valid, 1 of them on a named host",
        );
    }

    // -- container engine ----------------------------------------------------

    #[test]
    fn no_profile_needing_an_engine_passes_even_when_none_answered() {
        // The check is conditional on a profile needing one, and this is the branch that proves
        // it: a probe that failed must not fail the check when nothing needs the engine.
        let facts = with_config(
            r#"
providers:
  anthropic-main: { kind: anthropic, models: ["m"], credentials: [{ id: a1, secret: "env:A" }] }
pools:
  interactive: { members: ["anthropic-main/m"] }
roles:
  builder: interactive
"#,
        );
        assert_verdict(
            &facts,
            "container engine",
            Verdict::Pass,
            "no sandbox profile is configured, so no container engine is needed",
        );
    }

    #[test]
    fn profiles_that_all_run_on_a_named_host_need_no_local_engine() {
        let facts = with_config(
            r#"
providers:
  anthropic-main: { kind: anthropic, models: ["m"], credentials: [{ id: a1, secret: "env:A" }] }
pools:
  interactive: { members: ["anthropic-main/m"] }
roles:
  builder: interactive
hosts:
  buildbox: { kind: ssh, address: 10.0.0.5 }
sandbox_profiles:
  far: { image: ubuntu:24.04, host: buildbox }
"#,
        );
        assert_verdict(
            &facts,
            "container engine",
            Verdict::Pass,
            "none of the 1 profile(s) runs here — every one names a host",
        );
    }

    #[test]
    fn a_missing_engine_fails_when_a_profile_needs_one_and_names_it() {
        let facts = Facts {
            daemon: Err("could not reach the daemon".to_string()),
            engine: Err("the Docker socket exists but no daemon answered on it".to_string()),
            ..facts()
        };
        let (verdict, reason) = diagnose_ok(&facts, "container engine");
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            reason.contains("1 profile(s) need a container engine (dev)"),
            "{reason}"
        );
        assert!(
            reason.contains("the Docker socket exists but no daemon answered on it"),
            "{reason}"
        );
        assert!(
            reason.contains("The daemon could not be asked either"),
            "both sources are reported: {reason}"
        );
    }

    #[test]
    fn a_daemon_with_an_engine_passes_the_check_for_its_profiles() {
        assert_verdict(
            &facts(),
            "container engine",
            Verdict::Pass,
            "the daemon's sandbox engine is up and 1 profile(s) need it: dev",
        );
    }

    #[test]
    fn a_daemon_without_an_engine_fails_quoting_its_own_reason() {
        let facts = Facts {
            daemon: Ok(status(json!({
                "providers_configured": 1,
                "secret_stores": ["env"],
                "vault_unlocked": false,
                "pools": [],
                "search_backends": [],
                "sandboxes": { "available": false, "reason": "could not create a Docker client" }
            }))),
            ..facts()
        };
        let (verdict, reason) = diagnose_ok(&facts, "container engine");
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            reason.contains("and the daemon has none: could not create a Docker client"),
            "the daemon's own words, not a paraphrase: {reason}"
        );
    }

    #[test]
    fn an_unreachable_daemon_falls_back_to_probing_this_machine() {
        // The case the fallback exists for: someone working out why the daemon will not start.
        // The answer is qualified rather than presented as the daemon's.
        let facts = Facts {
            daemon: Err("could not reach the daemon".to_string()),
            engine: Ok("the Docker socket answered".to_string()),
            ..facts()
        };
        let (verdict, reason) = diagnose_ok(&facts, "container engine");
        assert_eq!(verdict, Verdict::Pass);
        assert!(reason.contains("one answered on this machine"), "{reason}");
        assert!(
            reason.contains("The daemon could not be asked"),
            "the qualification is part of the answer: {reason}"
        );
    }

    // -- search --------------------------------------------------------------

    #[test]
    fn no_search_backend_warns_because_search_degrades() {
        let facts = with_config(
            r#"
providers:
  anthropic-main: { kind: anthropic, models: ["m"], credentials: [{ id: a1, secret: "env:A" }] }
pools:
  interactive: { members: ["anthropic-main/m"] }
roles:
  builder: interactive
search:
  backends: []
"#,
        );
        assert_verdict(
            &facts,
            "search backends",
            Verdict::Warn,
            "no backend is configured: `web_search` returns nothing",
        );
    }

    #[test]
    fn configured_backends_that_the_daemon_built_pass_and_are_named() {
        assert_verdict(
            &facts(),
            "search backends",
            Verdict::Pass,
            "2 backend(s) configured and built: duckduckgo, wikipedia",
        );
    }

    #[test]
    fn configured_backends_the_daemon_did_not_build_warn() {
        let facts = Facts {
            daemon: Ok(status(json!({
                "providers_configured": 1,
                "secret_stores": ["env"],
                "vault_unlocked": false,
                "pools": [],
                "search_backends": ["duckduckgo"],
                "sandboxes": { "available": true, "reason": null }
            }))),
            ..facts()
        };
        let (verdict, reason) = diagnose_ok(&facts, "search backends");
        assert_eq!(verdict, Verdict::Warn);
        assert!(
            reason.contains("this config names 2 (duckduckgo, wikipedia)"),
            "{reason}"
        );
        assert!(
            reason.contains("the daemon reports 1 (duckduckgo)"),
            "{reason}"
        );
        assert!(
            reason.contains("started with a different config"),
            "{reason}"
        );
    }

    #[test]
    fn backends_are_a_failure_when_the_daemon_built_none_of_them() {
        let facts = Facts {
            daemon: Ok(status(json!({
                "providers_configured": 1,
                "secret_stores": ["env"],
                "vault_unlocked": false,
                "pools": [],
                "search_backends": [],
                "sandboxes": { "available": true, "reason": null }
            }))),
            ..facts()
        };
        assert_verdict(
            &facts,
            "search backends",
            Verdict::Fail,
            "2 backend(s) are configured (duckduckgo, wikipedia) and the daemon built none",
        );
    }

    #[test]
    fn the_search_check_fails_when_the_daemon_could_not_be_read() {
        let facts = Facts {
            daemon: Err("could not reach the daemon".to_string()),
            ..facts()
        };
        assert_verdict(
            &facts,
            "search backends",
            Verdict::Fail,
            "and the daemon could not be read, so whether it built them could not be checked",
        );
    }

    // -- secrets -------------------------------------------------------------

    #[test]
    fn a_literal_credential_is_not_a_store_lookup() {
        // A key written into the config has no store to be readable; treating `sk-…` as a
        // reference to a store named `sk-…` would invent a failure.
        let facts = Facts {
            config: Config::from_yaml(
                r#"
providers:
  anthropic-main: { kind: anthropic, models: ["m"], credentials: [{ id: a1, secret: "sk-literal-key" }] }
pools:
  interactive: { members: ["anthropic-main/m"] }
roles:
  builder: interactive
"#,
            )
            .map_err(|err| err.to_string()),
            daemon: Err("could not reach the daemon".to_string()),
            ..facts()
        };
        assert_verdict(
            &facts,
            "secrets",
            Verdict::Pass,
            "no credential in this config is a `store:name` reference, so no store has to be readable",
        );
    }

    #[test]
    fn a_reference_to_a_store_the_daemon_does_not_have_fails_and_names_the_reference() {
        let facts = with_config(
            r#"
providers:
  anthropic-main:
    kind: anthropic
    models: ["m"]
    credentials:
      - { id: a1, secret: "vault:anthropic/main" }
      - { id: a2, secret: "vault:anthropic/backup" }
pools:
  interactive: { members: ["anthropic-main/m"] }
roles:
  builder: interactive
"#,
        );
        let (verdict, reason) = diagnose_ok(&facts, "secrets");
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            reason.contains("2 of 2 reference(s) name a store the daemon does not have"),
            "{reason}"
        );
        assert!(
            reason.contains("vault:anthropic/main") && reason.contains("vault:anthropic/backup"),
            "the references are named: {reason}"
        );
        assert!(
            reason.contains("its stores are env"),
            "and so are the stores it does have: {reason}"
        );
    }

    #[test]
    fn a_duplicated_reference_is_reported_once() {
        let facts = with_config(
            r#"
providers:
  one: { kind: anthropic, models: ["m"], credentials: [{ id: a1, secret: "vault:shared" }] }
  two: { kind: openai, models: ["m"], credentials: [{ id: b1, secret: "vault:shared" }] }
pools:
  interactive: { members: ["one/m", "two/m"] }
roles:
  builder: interactive
"#,
        );
        let (verdict, reason) = diagnose_ok(&facts, "secrets");
        assert_eq!(verdict, Verdict::Fail);
        assert!(reason.contains("1 of 1 reference(s)"), "{reason}");
    }

    #[test]
    fn a_vault_reference_against_a_locked_vault_warns() {
        let facts = Facts {
            config: Config::from_yaml(
                r#"
providers:
  anthropic-main: { kind: anthropic, models: ["m"], credentials: [{ id: a1, secret: "vault:anthropic/main" }] }
pools:
  interactive: { members: ["anthropic-main/m"] }
roles:
  builder: interactive
"#,
            )
            .map_err(|err| err.to_string()),
            daemon: Ok(status(json!({
                "providers_configured": 1,
                "secret_stores": ["env", "vault"],
                "vault_unlocked": false,
                "pools": [],
                "search_backends": [],
                "sandboxes": { "available": false, "reason": "no engine" }
            }))),
            ..facts()
        };
        let (verdict, reason) = diagnose_ok(&facts, "secrets");
        assert_eq!(verdict, Verdict::Warn);
        assert!(
            reason.contains("every referenced store is configured (env, vault)"),
            "{reason}"
        );
        assert!(
            reason.contains("the vault is locked"),
            "a reference that cannot be used yet is not a reference that is wrong: {reason}"
        );
    }

    #[test]
    fn references_that_all_resolve_pass() {
        assert_verdict(
            &facts(),
            "secrets",
            Verdict::Pass,
            "every store this config references is configured on the daemon: env",
        );
    }

    #[test]
    fn a_host_key_reference_is_a_store_lookup_too() {
        // The reference can be written in five places; the credentials are the obvious one, and
        // this is the one a reader would not expect to be checked.
        let facts = with_config(
            r#"
providers:
  anthropic-main: { kind: anthropic, models: ["m"], credentials: [{ id: a1, secret: "env:A" }] }
pools:
  interactive: { members: ["anthropic-main/m"] }
roles:
  builder: interactive
hosts:
  buildbox:
    kind: ssh
    address: 10.0.0.5
    auth: { kind: key, secret_ref: "vault:ssh/buildbox" }
"#,
        );
        let (verdict, reason) = diagnose_ok(&facts, "secrets");
        assert_eq!(verdict, Verdict::Fail);
        assert!(reason.contains("vault:ssh/buildbox"), "{reason}");
    }

    #[test]
    fn the_secrets_check_fails_when_the_daemon_could_not_be_read() {
        let facts = Facts {
            daemon: Err("could not reach the daemon".to_string()),
            ..facts()
        };
        assert_verdict(
            &facts,
            "secrets",
            Verdict::Fail,
            "2 reference(s) resolve through env and the daemon could not be read",
        );
    }

    // -- the API token -------------------------------------------------------

    #[test]
    fn a_loopback_bind_with_no_token_passes_because_that_is_the_only_bind_it_is_legal_on() {
        assert_verdict(
            &facts(),
            "api token",
            Verdict::Pass,
            "none configured, and 127.0.0.1:8787 (from daemon.http_addr) is a loopback address",
        );
    }

    #[test]
    fn a_non_loopback_bind_with_no_token_fails_in_the_daemons_own_words() {
        // The refusal text is the daemon's own function, called rather than restated, so the
        // doctor cannot drift from the rule `hxd` applies before it binds.
        let facts = Facts {
            bind: "0.0.0.0:8787".to_string(),
            bind_source: "HX_BIND",
            ..facts()
        };
        let (verdict, reason) = diagnose_ok(&facts, "api token");
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            reason.contains("refusing to start: the HTTP API is bound to \"0.0.0.0:8787\""),
            "{reason}"
        );
        assert!(reason.contains("api.token"), "{reason}");
        assert!(reason.contains(API_TOKEN_ENV), "{reason}");
        assert!(
            reason.contains("(checked against 0.0.0.0:8787, from HX_BIND)"),
            "which address was checked, and where it came from: {reason}"
        );
    }

    #[test]
    fn a_non_loopback_bind_with_a_token_passes_and_names_the_setting() {
        let facts = Facts {
            bind: "192.168.1.5:8787".to_string(),
            token: TokenFact::Set("HX_API_TOKEN".to_string()),
            ..facts()
        };
        assert_verdict(
            &facts,
            "api token",
            Verdict::Pass,
            "set from `HX_API_TOKEN`, and 192.168.1.5:8787 (from daemon.http_addr) is reachable from elsewhere",
        );
    }

    #[test]
    fn a_loopback_bind_with_a_token_passes_and_says_the_token_is_honoured() {
        let facts = Facts {
            token: TokenFact::Set("api.token".to_string()),
            ..facts()
        };
        let (verdict, reason) = diagnose_ok(&facts, "api token");
        assert_eq!(verdict, Verdict::Pass);
        assert!(reason.contains("set from `api.token`"), "{reason}");
        assert!(reason.contains("honoured on when set"), "{reason}");
    }

    #[test]
    fn a_token_that_cannot_be_resolved_fails_wherever_the_daemon_is_bound() {
        // Not "no token": a reference the deployment cannot resolve is a daemon that refuses to
        // start at all, which is what `require_token_for_bind`'s sibling in `AppState::build` does.
        let facts = Facts {
            token: TokenFact::Unresolvable(
                "no source for secret store 'vault' (configured stores: env)".to_string(),
            ),
            ..facts()
        };
        let (verdict, reason) = diagnose_ok(&facts, "api token");
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            reason.contains("`api.token` names something this deployment cannot resolve"),
            "{reason}"
        );
        assert!(
            reason.contains(
                "refuses to start on this rather than serving an API whose token it cannot check"
            ),
            "{reason}"
        );
    }

    // -- the data directory --------------------------------------------------

    #[test]
    fn a_writable_data_directory_passes_and_names_the_path() {
        assert_verdict(
            &facts(),
            "data dir",
            Verdict::Pass,
            "~/.hx is writable: it exists and accepted a probe file",
        );
    }

    #[test]
    fn an_unwritable_data_directory_fails_with_the_io_reason() {
        let facts = Facts {
            data_dir: Err("Permission denied (os error 13)".to_string()),
            ..facts()
        };
        let (verdict, reason) = diagnose_ok(&facts, "data dir");
        assert_eq!(verdict, Verdict::Fail);
        assert!(
            reason.contains("~/.hx is not writable: Permission denied (os error 13)"),
            "{reason}"
        );
        assert!(reason.contains("(`hx.db`) lives there"), "{reason}");
    }

    #[test]
    fn a_data_directory_that_cannot_be_resolved_says_so_rather_than_creating_a_literal_tilde() {
        // The probe is what keeps `hx doctor` from creating a directory called `~` in the working
        // directory on a machine with no HOME, which is the failure mode of a shell-less probe.
        let dir = std::env::temp_dir().join(format!("hx-doctor-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::write(&dir, b"a file, not a directory").expect("the fixture is writable");
        let config = Config::from_yaml(&format!(
            "daemon:\n  data_dir: \"{}/data\"\n",
            dir.display()
        ))
        .expect("config parses");

        let verdict = probe_data_dir(&config).expect_err("a directory below a file cannot be made");
        assert!(
            verdict.contains("could not be created"),
            "the OS's own reason is carried: {verdict}"
        );

        let _ = std::fs::remove_file(&dir);
    }

    // -- the renderer and the exit code --------------------------------------

    #[test]
    fn warnings_alone_do_not_change_the_exit_code() {
        // The contract: a deploy gates on failures, and a degraded search backend is not a reason
        // to fail a deploy.
        let facts = with_config(
            r#"
providers:
  anthropic-main: { kind: anthropic, models: ["m"], credentials: [{ id: a1, secret: "env:A" }] }
pools:
  interactive: { members: ["anthropic-main/m"] }
roles:
  builder: interactive
search:
  backends: []
"#,
        );
        let report = diagnose(&facts, Utc::now());
        assert!(
            report.warned() > 0,
            "the fixture warns: {}",
            report.render(false)
        );
        assert_eq!(report.failed(), 0);
        assert_eq!(report.exit_code(), 0);
        assert!(
            report.render(false).contains("no check failed; 2 warned"),
            "{}",
            report.render(false)
        );
    }

    #[test]
    fn one_failure_changes_the_exit_code_and_is_below_every_other_line() {
        let facts = Facts {
            data_dir: Err("read-only file system".to_string()),
            ..facts()
        };
        let report = diagnose(&facts, Utc::now());
        assert_eq!(report.failed(), 1);
        assert_eq!(report.exit_code(), 1);
        let rendered = report.render(false);
        assert!(rendered.contains("1 of 10 check(s) FAILED"), "{rendered}");
        assert!(
            rendered.contains("FAIL data dir"),
            "the failing line is one of the ten, labelled: {rendered}"
        );
    }

    #[test]
    fn every_check_prints_on_one_line_even_when_its_reason_does_not() {
        // A YAML parser's message can carry newlines, and a reason that broke the table would be
        // the kind of defect that makes a reader stop trusting the whole report.
        let facts = Facts {
            config: Err("providers: invalid type\n  at line 3 column 5".to_string()),
            ..facts()
        };
        let audit = check(&diagnose(&facts, Utc::now()), "config")
            .reason
            .clone();
        assert!(!audit.contains('\n'), "{audit:?}");
        assert!(
            audit.contains("at line 3 column 5"),
            "flattened, not truncated: {audit}"
        );
    }

    #[test]
    fn the_json_report_is_a_document_with_the_same_verdicts() {
        let facts = Facts {
            bind: "0.0.0.0:8787".to_string(),
            ..facts()
        };
        let rendered = diagnose(&facts, Utc::now()).render(true);
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("the JSON mode emits a document");

        assert_eq!(parsed["checks_run"], 10);
        assert_eq!(parsed["failed"], 1);
        assert_eq!(parsed["exit_code"], 1);
        let checks = parsed["checks"].as_array().expect("a list of checks");
        assert_eq!(checks.len(), 10);
        let token = checks
            .iter()
            .find(|c| c["name"] == "api token")
            .expect("the api token check is in the document");
        assert_eq!(token["verdict"], "FAIL");
        assert!(
            token["reason"]
                .as_str()
                .is_some_and(|r| r.contains("not a loopback address")),
            "{token}"
        );
        // The label vocabulary is the same one the human output uses, so a script and a person
        // cannot read the same run differently.
        assert_eq!(checks[0]["verdict"], "PASS");
    }

    #[test]
    fn the_daemon_dependent_checks_all_fail_together_when_it_cannot_be_reached() {
        // One test for the property the whole command rests on: a doctor that could not look must
        // not report health. Every check that reads the daemon says so in its own line.
        let facts = Facts {
            daemon: Err("connection refused".to_string()),
            ..facts()
        };
        let report = diagnose(&facts, Utc::now());
        for name in ["pools", "search backends", "secrets"] {
            let found = check(&report, name);
            assert_eq!(found.verdict, Verdict::Fail, "{name}: {found:?}");
            assert!(
                found.reason.contains("connection refused"),
                "{name} must carry the reason: {}",
                found.reason
            );
        }
        assert_eq!(report.exit_code(), 1);
    }

    // -- the shell's probes --------------------------------------------------

    #[test]
    fn the_data_directory_probe_writes_and_removes_its_file() {
        let dir = std::env::temp_dir().join(format!("hx-doctor-probe-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = Config::from_yaml(&format!("daemon:\n  data_dir: \"{}\"\n", dir.display()))
            .expect("config parses");

        let found = probe_data_dir(&config).expect("a fresh directory is writable");
        assert!(
            found.contains("accepted a probe file"),
            "the answer says what was done: {found}"
        );
        assert!(dir.is_dir(), "the directory the daemon needs was made");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("the directory is readable")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            leftovers.is_empty(),
            "the probe leaves nothing behind, got {leftovers:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_leading_tilde_is_expanded_the_way_the_store_expands_it() {
        // `expand_home` is a copy of `hx-store`'s private rule (the CLI does not link SQLite for
        // one path). A difference between the two would make this check about a directory the
        // daemon never uses, so the expansion itself is pinned.
        let home = std::env::var_os("HOME").expect("these tests run with HOME set");
        assert_eq!(
            expand_home("~/.hx"),
            PathBuf::from(home).join(".hx"),
            "the default data directory is under the home directory"
        );
        assert_eq!(expand_home("/var/lib/hx"), PathBuf::from("/var/lib/hx"));
        assert_eq!(
            expand_home("~not-a-tilde/.hx"),
            PathBuf::from("~not-a-tilde/.hx"),
            "only a leading `~/` is a home reference"
        );
    }

    #[test]
    fn the_doctor_command_takes_json_and_a_bind_address() {
        use clap::Parser;

        let cli = crate::Cli::try_parse_from(["hx", "doctor", "--json", "--bind", "0.0.0.0:8787"])
            .expect("doctor takes --json and --bind");

        match cli.command {
            crate::Command::Doctor { json, bind } => {
                assert!(json);
                assert_eq!(bind.as_deref(), Some("0.0.0.0:8787"));
            }
            other => panic!("expected the doctor command, got {other:?}"),
        }
    }
}

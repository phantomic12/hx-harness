//! Capability tokens — the authority model.
//!
//! The design premise (see `ARCHITECTURE.md` §4) is **no ambient authority**: an agent is not
//! trusted because it is "our agent". It holds a token listing exactly what it may do, and the
//! policy engine answers `allow`/`deny` for every action. A denial is a normal, auditable
//! outcome — never a hang, and never a prompt the agent can argue its way past.
//!
//! Everything in this module is pure: no clocks are read, `now` is always passed in. That
//! makes expiry logic deterministic under test instead of flaky.

use crate::ids::{AgentId, CapabilityId, HostId, ProviderId, SandboxId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// What a capability applies to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Resource {
    /// A filesystem path. Grants cover the subtree (see [`path_grant_covers`]).
    FsPath { path: String },
    /// A registered machine — local, SSH, or WinRM.
    Host { id: HostId },
    /// A specific sandbox.
    Sandbox { id: SandboxId },
    /// A network destination. Supports a leading `*.` wildcard for subdomains.
    NetworkHost { host: String },
    /// A model provider (so a cheap subagent cannot silently burn the expensive pool).
    Provider { id: ProviderId },
    /// A named secret. `*` grants every secret — rarely what you want.
    Secret { name: String },
    /// Spawning processes at all. The bluntest capability.
    Process,
}

/// What may be done to a [`Resource`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Read,
    Write,
    Execute,
    Connect,
    Spawn,
    Delete,
    Admin,
}

impl Action {
    /// Actions that a read-only grant must refuse.
    pub fn is_mutating(self) -> bool {
        matches!(
            self,
            Action::Write | Action::Delete | Action::Execute | Action::Spawn | Action::Admin
        )
    }
}

/// Numeric and temporal bounds attached to a grant.
///
/// A bound here is a *promise the enforcement points keep*, not a hint:
/// - `max_bytes` is checked by [`CapabilityToken::check_with_usage`] whenever the caller states
///   how many bytes the call would move (fs writes do, via the tool requirement), and by the
///   agent loop against the bytes a call actually moved (fs reads report them on the outcome,
///   so an oversized read is refused before the model sees it).
/// - `budget_usd` is checked by the agent loop against the model spend accumulated so far
///   (see [`CapabilityToken::provider_budget_usd`]); the router's own credential ceilings are a
///   separate, additional limiter, not this bound.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constraints {
    /// Refuse operations that would move more than this many bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    /// Spend ceiling in USD on model calls for the run holding this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_usd: Option<f64>,
    /// Refuse every [`Action::is_mutating`] action.
    #[serde(default)]
    pub read_only: bool,
    /// When this individual grant lapses, independent of the token's own expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// One grant: a resource, the actions allowed on it, and their bounds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    #[serde(default)]
    pub id: CapabilityId,
    pub resource: Resource,
    pub actions: Vec<Action>,
    #[serde(default)]
    pub constraints: Constraints,
}

impl Capability {
    pub fn new(resource: Resource, actions: impl IntoIterator<Item = Action>) -> Self {
        Self {
            id: CapabilityId::new(),
            resource,
            actions: actions.into_iter().collect(),
            constraints: Constraints::default(),
        }
    }

    pub fn read_only(mut self) -> Self {
        self.constraints.read_only = true;
        self
    }

    pub fn with_budget(mut self, usd: f64) -> Self {
        self.constraints.budget_usd = Some(usd);
        self
    }

    /// Cap the bytes a single call under this grant may move. Reads over the cap are refused
    /// before the model sees them; writes over the cap are refused before they run.
    pub fn with_max_bytes(mut self, bytes: u64) -> Self {
        self.constraints.max_bytes = Some(bytes);
        self
    }

    /// Convenience: a grant of all actions on a workspace path.
    pub fn workspace(path: impl Into<String>) -> Self {
        Self::new(
            Resource::FsPath { path: path.into() },
            [Action::Read, Action::Write, Action::Execute, Action::Delete],
        )
    }
}

/// What a single call would cost, as far as the capability bounds are concerned.
///
/// Both fields are `Option` because neither is always knowable *before* the call: a write states
/// its byte count up front (the tool requirement carries it), a read cannot (the size is what the
/// read discovers). `None` means "not stated", and the check treats it as *not exceeding* —
///
/// WHY not fail closed here: this check runs before the call, and a read's size is unknowable
/// before the call, so denying unstated sizes would deny every read under a bounded grant and make
/// `max_bytes` unusable. Soundness is recovered downstream instead: tools report the bytes they
/// actually moved on the outcome, and the loop re-checks them against the granting bound before
/// the model sees anything. A bound that is never stated anywhere is not enforced — which is why
/// the fs tools always state or report theirs, and why a new tool that moves bytes must do the same.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct RequestUsage {
    /// Bytes this call would move (file size on read, content length on write).
    pub bytes: Option<u64>,
    /// Model spend accumulated by the run so far, in USD.
    pub spend_usd: Option<f64>,
}

impl RequestUsage {
    /// Nothing stated: the shape every pre-existing caller already has.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn bytes(bytes: u64) -> Self {
        Self {
            bytes: Some(bytes),
            spend_usd: None,
        }
    }

    pub fn spend(spend_usd: f64) -> Self {
        Self {
            bytes: None,
            spend_usd: Some(spend_usd),
        }
    }
}

/// The set of grants an agent runs under.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityToken {
    pub subject: AgentId,
    pub grants: Vec<Capability>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl CapabilityToken {
    /// A token for `subject` valid for `ttl_secs` from `now`.
    pub fn issue(
        subject: AgentId,
        grants: Vec<Capability>,
        now: DateTime<Utc>,
        ttl_secs: i64,
    ) -> Self {
        Self {
            subject,
            grants,
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_secs),
        }
    }

    /// The central question: may `subject` perform `action` on `resource` right now?
    ///
    /// Fail-closed: anything unrecognised, expired, malformed, or ambiguous denies.
    ///
    /// This is the unstated-usage form: numeric bounds apply only to what the caller states (see
    /// [`Self::check_with_usage`]). A bounded grant therefore allows a call that states nothing —
    /// the loop enforces the bound where the size becomes known instead.
    pub fn check(&self, resource: &Resource, action: Action, now: DateTime<Utc>) -> Decision {
        self.check_with_usage(resource, action, now, RequestUsage::none())
    }

    /// The central question, with the call's [`RequestUsage`] stated.
    ///
    /// A grant whose `max_bytes` is exceeded by `usage.bytes`, or whose `budget_usd` is exceeded
    /// by `usage.spend_usd`, does not allow the call — but the search continues past it, because
    /// authority is the *union* of the grants: a tighter grant never narrows a wider one, so a
    /// second grant without (or with a roomier) bound still allows. The denial reported is the
    /// most informative refusal seen, as with every other bound.
    pub fn check_with_usage(
        &self,
        resource: &Resource,
        action: Action,
        now: DateTime<Utc>,
        usage: RequestUsage,
    ) -> Decision {
        if now >= self.expires_at {
            return Decision::Deny(DenyReason::TokenExpired);
        }

        // Path traversal is rejected before any grant is consulted: a path containing `..`
        // cannot be safely evaluated for containment, so it is never allowed through.
        if let Resource::FsPath { path } = resource {
            if has_parent_component(path) {
                return Decision::Deny(DenyReason::UnsafePath { path: path.clone() });
            }
        }

        let matching: Vec<&Capability> = self
            .grants
            .iter()
            .filter(|g| resource_matches(&g.resource, resource))
            .collect();

        if matching.is_empty() {
            return Decision::Deny(DenyReason::NoMatchingGrant);
        }

        // Remember the most informative refusal so the audit log says something useful.
        let mut best: Option<DenyReason> = None;

        for grant in &matching {
            if let Some(exp) = grant.constraints.expires_at {
                if now >= exp {
                    best = Some(DenyReason::GrantExpired);
                    continue;
                }
            }
            if !grant.actions.contains(&action) {
                best = Some(DenyReason::ActionNotGranted {
                    granted: grant.actions.clone(),
                });
                continue;
            }
            if grant.constraints.read_only && action.is_mutating() {
                best = Some(DenyReason::ReadOnly);
                continue;
            }
            if let (Some(limit), Some(actual)) = (grant.constraints.max_bytes, usage.bytes) {
                if actual > limit {
                    best = Some(DenyReason::TooLarge {
                        limit_bytes: limit,
                        actual_bytes: actual,
                    });
                    continue;
                }
            }
            if let (Some(limit), Some(spent)) = (grant.constraints.budget_usd, usage.spend_usd) {
                if spent > limit {
                    best = Some(DenyReason::BudgetExceeded {
                        limit_usd: limit,
                        spent_usd: spent,
                    });
                    continue;
                }
            }
            return Decision::Allow;
        }

        Decision::Deny(best.unwrap_or(DenyReason::NoMatchingGrant))
    }

    /// The byte cap the loop enforces on a call *after* it runs, when the size was unknowable
    /// beforehand (reads).
    ///
    /// The most permissive bound among the grants that would otherwise allow this call — because
    /// the call is allowed when *any* grant allows it, and the bound that governs it is that
    /// grant's. `None` means no allowing grant caps bytes: unbounded, or no allowing grant at all
    /// (in which case the call is denied anyway and the cap is moot).
    pub fn max_bytes_for(
        &self,
        resource: &Resource,
        action: Action,
        now: DateTime<Utc>,
    ) -> Option<u64> {
        if now >= self.expires_at {
            return None;
        }
        if let Resource::FsPath { path } = resource {
            if has_parent_component(path) {
                return None;
            }
        }
        // The rule mirrors `check_with_usage`: the call is allowed when *any* grant allows it, so
        // an uncapped allowing grant means the call as such is uncapped — the tightest grant does
        // not get a veto over a wider one. Otherwise the cap is the largest of the allowing caps.
        let mut seen_allow = false;
        let mut best_cap: Option<u64> = None;
        let mut unbounded = false;
        for grant in self
            .grants
            .iter()
            .filter(|g| resource_matches(&g.resource, resource))
        {
            if let Some(exp) = grant.constraints.expires_at {
                if now >= exp {
                    continue;
                }
            }
            if !grant.actions.contains(&action) {
                continue;
            }
            if grant.constraints.read_only && action.is_mutating() {
                continue;
            }
            seen_allow = true;
            match grant.constraints.max_bytes {
                None => unbounded = true,
                Some(l) => best_cap = Some(best_cap.map_or(l, |c: u64| c.max(l))),
            }
        }
        if !seen_allow || unbounded {
            return None;
        }
        best_cap
    }

    /// The run's model-spend ceiling in USD, from its [`Resource::Provider`] grants.
    ///
    /// - No provider grant at all: `None` — and deliberately *not* a denial. Provider grants have
    ///   never gated model calls in this loop, and turning their absence into a refusal here would
    ///   break every run whose token scopes files but not models. The budget binds only where it
    ///   is expressed.
    /// - Any provider grant without a `budget_usd`: `None`. An uncapped grant is permission to
    ///   spend without this ceiling, and a capped grant beside it does not take that away.
    /// - Otherwise the largest cap: the run may spend up to the most generous bound it holds.
    pub fn provider_budget_usd(&self) -> Option<f64> {
        let mut any = false;
        let mut best: Option<f64> = None;
        for grant in &self.grants {
            if !matches!(grant.resource, Resource::Provider { .. }) {
                continue;
            }
            any = true;
            // An uncapped provider grant is permission to spend without this ceiling: fail the
            // whole computation back to `None` rather than letting a capped grant beside it bind.
            let limit = grant.constraints.budget_usd?;
            best = Some(best.map_or(limit, |b: f64| b.max(limit)));
        }
        if any {
            best
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny(DenyReason),
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    NoMatchingGrant,
    ActionNotGranted {
        granted: Vec<Action>,
    },
    ReadOnly,
    TokenExpired,
    GrantExpired,
    UnsafePath {
        path: String,
    },
    /// The call would move more bytes than the granting bound allows.
    TooLarge {
        limit_bytes: u64,
        actual_bytes: u64,
    },
    /// The run has already spent past the granting budget.
    BudgetExceeded {
        limit_usd: f64,
        spent_usd: f64,
    },
    /// The canonical path — symlinks resolved — leaves every granting subtree. This is the
    /// symlink-escape refusal: lexically the path was covered, physically it is not.
    SymlinkEscape {
        canonical: String,
    },
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DenyReason::NoMatchingGrant => write!(f, "no grant covers this resource"),
            DenyReason::ActionNotGranted { granted } => {
                write!(f, "action not granted (granted: {granted:?})")
            }
            DenyReason::ReadOnly => write!(f, "grant is read-only"),
            DenyReason::TokenExpired => write!(f, "token expired"),
            DenyReason::GrantExpired => write!(f, "grant expired"),
            DenyReason::UnsafePath { path } => {
                write!(
                    f,
                    "path {path:?} contains a parent component and cannot be evaluated"
                )
            }
            DenyReason::TooLarge {
                limit_bytes,
                actual_bytes,
            } => {
                write!(
                    f,
                    "call would move {actual_bytes} bytes, over the {limit_bytes}-byte grant bound"
                )
            }
            DenyReason::BudgetExceeded {
                limit_usd,
                spent_usd,
            } => {
                write!(
                    f,
                    "run has spent ${spent_usd:.2}, over the ${limit_usd:.2} grant budget"
                )
            }
            DenyReason::SymlinkEscape { canonical } => {
                write!(
                    f,
                    "path resolves to {canonical:?}, outside every granting subtree (symlink escape)"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

fn resource_matches(granted: &Resource, requested: &Resource) -> bool {
    match (granted, requested) {
        (Resource::FsPath { path: g }, Resource::FsPath { path: r }) => path_grant_covers(g, r),
        (Resource::Host { id: g }, Resource::Host { id: r }) => g == r,
        (Resource::Sandbox { id: g }, Resource::Sandbox { id: r }) => g == r,
        (Resource::Provider { id: g }, Resource::Provider { id: r }) => g == r,
        (Resource::NetworkHost { host: g }, Resource::NetworkHost { host: r }) => {
            host_grant_covers(g, r)
        }
        (Resource::Secret { name: g }, Resource::Secret { name: r }) => g == "*" || g == r,
        (Resource::Process, Resource::Process) => true,
        _ => false,
    }
}

/// Does a grant on `granted` cover the path `requested`?
///
/// Subtree semantics, evaluated component-wise so that a grant on `/workspace/a` does **not**
/// leak into `/workspace/ab` — the classic prefix-comparison bug.
///
/// ## Lexical only — and why that is not enough
///
/// This compares *strings*. It knows nothing about symlinks: if `/workspace/link` is a link to
/// `/etc`, then `/workspace/link/secret` passes this check while naming a file outside the grant.
/// That is not a bug in this function — it is the reason enforcement points must never stop here.
/// The safe sequence is: [`canonicalize_for_check`] the requested path (resolving symlinks
/// through the real filesystem, including the parent-walk for not-yet-existing write targets),
/// then [`path_grant_covers_canonical`] the result against the grant. A `check` that skips the
/// canonicalization step is a symlink-escape vulnerability, full stop.
///
/// Fail-closed rules, each of which is a privilege-escalation bug if relaxed:
/// - an empty or whitespace grant never means root (it means "no grant");
/// - both paths must be absolute, on either platform. A relative path is ambiguous, and resolving
///   it here would make the decision depend on a working directory the policy engine cannot see.
///   Callers must resolve to absolute *before* asking;
/// - only an explicit `"/"` grant covers everything.
///
/// "Absolute" includes Windows drive-letter (`C:\work`) and UNC (`\\server\share`) paths, which
/// this used to reject for want of a leading `/`. That made every grant deny on Windows — the
/// capability token could not name any file on the machine — so a test that reads a file inside its
/// own workspace was refused with `refusals: 1`. Accepting those forms does not widen what a grant
/// covers: the comparison stays component-wise on the normalized path, so the subtree rules below
/// are unchanged, and a relative path is still refused.
pub fn path_grant_covers(granted: &str, requested: &str) -> bool {
    let g_raw = granted.trim();
    let r_raw = requested.trim();

    if g_raw.is_empty() || r_raw.is_empty() {
        return false;
    }
    if !is_absolute_path(g_raw) || !is_absolute_path(r_raw) {
        return false;
    }

    let g = normalize_path(g_raw);
    let r = normalize_path(r_raw);

    if g == "/" {
        return true;
    }
    // A drive root (`C:/`, normalized from `C:\`) covers that drive: the subtree test below would
    // otherwise compare `C:/secret` against the prefix `C://`, which never matches.
    if g.len() == 3 && g.ends_with(":/") {
        return r.len() >= 3 && r[..2].eq_ignore_ascii_case(&g[..2]);
    }
    r == g || r.starts_with(&format!("{g}/"))
}

/// Is this path absolute in a form the policy engine can compare?
///
/// Unix: a leading `/`. Windows: a drive-letter path (`C:\work`, `C:/work`) or a UNC path
/// (`\\server\share`). A relative path is not absolute, and that is the point of asking — the engine
/// compares *text*, and resolving a relative path would need a working directory it cannot see.
fn is_absolute_path(p: &str) -> bool {
    if p.starts_with('/') {
        return true;
    }
    let bytes = p.as_bytes();
    // `C:\` or `C:/` — a drive letter, a colon, then a separator. `C:` alone is drive-relative.
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        return true;
    }
    // A UNC path: two leading separators, then a host.
    p.starts_with("\\\\") || p.starts_with("//")
}

fn normalize_path(p: &str) -> String {
    let trimmed = p.trim();
    if trimmed.is_empty() {
        return "/".to_string();
    }
    // Separators are unified, but a drive-letter path keeps its shape: turning `C:\work` into
    // `/C:/work` would stop it matching the equally-normalized requested path only by luck, and
    // would misrepresent it as living under a Unix root.
    let mut s = trimmed.replace('\\', "/");
    if is_windows_drive_path(&s) {
        // Uppercase the drive so `c:\work` and `C:\work` are one path, as Windows treats them.
        let mut chars = s.chars();
        let drive = chars.next().unwrap_or_default().to_ascii_uppercase();
        s = format!("{drive}{}", chars.as_str());
        while s.len() > 3 && s.ends_with('/') {
            s.pop();
        }
        return s;
    }
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    if !s.starts_with('/') {
        s.insert(0, '/');
    }
    s
}

/// Is this already-separator-unified path a Windows drive path (`C:/work`)?
fn is_windows_drive_path(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'/'
}

fn has_parent_component(p: &str) -> bool {
    p.replace('\\', "/").split('/').any(|c| c == "..")
}

/// Resolve symlinks in `requested` for a containment check, fail-closed.
///
/// - When the path exists, this is [`std::fs::canonicalize`]: symlinks resolved, `.`/`..`
///   collapsed, absolute result.
/// - When it does not exist yet (a write or create target), the nearest existing ancestor is
///   canonicalized and the remainder joined back on — so `/workspace/new/file.txt` checks as
///   `/workspace/new/file.txt` with every link above it resolved, instead of failing the check
///   outright and making bounded grants unusable for creates.
/// - `None` when nothing canonicalizes (no existing ancestor at all): the caller must deny.
///   There is no safe default here — guessing a location for an unresolvable path is exactly the
///   vulnerability this exists to close.
///
/// WHY in `hx-core` rather than next to the tools: every enforcement point (local host, agent
/// loop, tests) must resolve the *same* way, and two copies of an ancestor-walk will drift. Hosts
/// that cannot see this filesystem (SSH, WinRM) do not use this — they resolve on their side and
/// re-check the string they get back.
pub fn canonicalize_for_check(requested: &str) -> Option<std::path::PathBuf> {
    use std::path::Path;

    let path = Path::new(requested);
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return Some(canonical);
    }
    // Not canonicalizable as-is: missing, dangling, or a missing tail. Walk up to the nearest
    // existing ancestor, resolve *that* (which settles every symlink above the target), and join
    // the unresolvable remainder back on. The walk starts with the path's own final component
    // already on the tail — it is the first thing that failed to resolve. No final component
    // (`/`, `..`, the empty string) means nothing to rejoin, and the direct canonicalization
    // above already failed, so there is no safe answer.
    let name = path.file_name()?;
    let mut tail = vec![name.to_os_string()];
    let mut ancestor = path.parent();
    loop {
        match ancestor {
            None => return None,
            Some(dir) if dir.as_os_str().is_empty() => return None,
            Some(dir) => match std::fs::canonicalize(dir) {
                Ok(resolved) => {
                    let mut out = resolved;
                    for component in tail.iter().rev() {
                        out.push(component);
                    }
                    return Some(out);
                }
                Err(_) => {
                    // Push this level's final component and keep climbing.
                    if let Some(name) = dir.file_name() {
                        tail.push(name.to_os_string());
                    }
                    ancestor = dir.parent();
                }
            },
        }
    }
}

/// Re-check containment after canonicalization: does `granted` cover `requested_canonical`?
///
/// `requested_canonical` must come from [`canonicalize_for_check`] (or the equivalent resolution
/// on a remote host) — this function trusts that its input names the physical location, and only
/// answers the subtree question. The grant itself is canonicalized best-effort (grant roots
/// normally exist); when it cannot be, the grant's normalized spelling is used, because the grant
/// is operator configuration rather than attacker input — the escape this closes is always in the
/// *requested* path.
pub fn path_grant_covers_canonical(granted: &str, requested_canonical: &std::path::Path) -> bool {
    let requested = requested_canonical.to_string_lossy();
    if let Some(canonical_grant) = canonicalize_for_check(granted) {
        return path_grant_covers(&canonical_grant.to_string_lossy(), requested.as_ref());
    }
    path_grant_covers(granted, requested.as_ref())
}

/// Does a grant on `granted` cover host `requested`?
///
/// `"*.example.com"` covers `api.example.com` but *not* `example.com` itself — an explicit
/// choice, because the apex is usually a different machine with different trust.
pub fn host_grant_covers(granted: &str, requested: &str) -> bool {
    let g = granted.trim().to_ascii_lowercase();
    let r = requested.trim().to_ascii_lowercase();

    if g == "*" {
        return true;
    }
    if let Some(suffix) = g.strip_prefix('*') {
        // "*" already handled, so `suffix` starts with '.'
        return r.ends_with(suffix) && r.len() > suffix.len();
    }
    g == r
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 15, 12, 0, 0).unwrap()
    }

    fn token(grants: Vec<Capability>) -> CapabilityToken {
        CapabilityToken::issue(AgentId::from_raw("agt_test"), grants, t0(), 3600)
    }

    #[test]
    fn path_grant_covers_subtree() {
        assert!(path_grant_covers("/workspace", "/workspace/src/main.rs"));
        assert!(path_grant_covers("/workspace", "/workspace"));
        assert!(path_grant_covers("/workspace/", "/workspace/src"));
    }

    #[test]
    fn path_grant_does_not_leak_into_sibling_with_shared_prefix() {
        // The bug this test exists to prevent: naive `starts_with` would allow this.
        assert!(!path_grant_covers("/workspace/a", "/workspace/ab"));
        assert!(!path_grant_covers("/workspace/a", "/workspace/abc/secret"));
    }

    #[test]
    fn path_grant_does_not_escape_upward() {
        assert!(!path_grant_covers("/workspace", "/etc/passwd"));
        assert!(!path_grant_covers("/workspace", "/"));
    }

    #[test]
    fn empty_grant_never_means_root() {
        // Regression test. `normalize_path("")` yields "/", so a naive implementation would
        // grant root on a config typo. An empty grant must grant nothing.
        assert!(!path_grant_covers("", "/etc"));
        assert!(!path_grant_covers("", "/"));
        assert!(!path_grant_covers("   ", "/etc"));
        assert!(!path_grant_covers("", ""));
    }

    #[test]
    fn relative_paths_are_rejected_rather_than_guessed() {
        // Contained decisions must not depend on an unseen working directory.
        assert!(!path_grant_covers("workspace", "/workspace/x"));
        assert!(!path_grant_covers("/workspace", "workspace/x"));
        // The Windows equivalents, which the absolute-path check must also refuse.
        assert!(!path_grant_covers("work", r"C:\work\x"));
        assert!(!path_grant_covers(r"C:\work", r"work\x"));
        // `C:` alone is drive-*relative* in Windows, so it is not absolute.
        assert!(!path_grant_covers(r"C:", r"C:\work\x"));
    }

    #[test]
    fn windows_absolute_paths_are_covered_inside_their_subtree() {
        // Regression test. This used to require a leading `/`, so on Windows *every* grant was
        // denied — the token could not name any file on the machine, and a test reading a file in
        // its own workspace came back with `refusals: 1`.
        assert!(path_grant_covers(r"C:\work", r"C:\work\src\main.rs"));
        assert!(path_grant_covers(r"C:\work", r"C:\work"));
        // Separators and drive case are the same path to Windows, so they must compare equal.
        assert!(path_grant_covers(r"C:\work", "C:/work/src/main.rs"));
        assert!(path_grant_covers("c:/work", r"C:\work\src"));
        assert!(path_grant_covers(r"C:\work\", r"C:\work\src"));
        // A UNC path is absolute too.
        assert!(path_grant_covers(
            r"\\server\share",
            r"\\server\share\dir\file.txt"
        ));
    }

    #[test]
    fn windows_paths_keep_the_same_subtree_containment_rules() {
        // Accepting a drive-letter path must not widen what a grant covers. These are the same
        // leaks the Unix cases above guard, in Windows spelling.
        assert!(!path_grant_covers(r"C:\work\a", r"C:\work\ab"));
        assert!(!path_grant_covers(r"C:\work\a", r"C:\work\abc\secret"));
        assert!(!path_grant_covers(r"C:\work", r"D:\work\x"));
        assert!(!path_grant_covers(r"C:\work", r"C:\work2\x"));
        // A grant does not reach above itself.
        assert!(!path_grant_covers(r"C:\work\sub", r"C:\work"));
        // And a drive root is not a universal grant, unlike `/` on Unix.
        assert!(!path_grant_covers(r"C:\", r"D:\secret"));
        assert!(path_grant_covers(r"C:\", r"C:\secret"));
    }

    #[test]
    fn explicit_root_grant_covers_everything() {
        assert!(path_grant_covers("/", "/etc/passwd"));
        assert!(path_grant_covers("/", "/"));
    }

    #[test]
    fn write_grant_allows_write_inside_workspace() {
        let tk = token(vec![Capability::workspace("/workspace")]);
        let r = Resource::FsPath {
            path: "/workspace/src/lib.rs".into(),
        };
        assert!(tk.check(&r, Action::Write, t0()).is_allowed());
    }

    #[test]
    fn write_outside_workspace_is_denied() {
        let tk = token(vec![Capability::workspace("/workspace")]);
        let r = Resource::FsPath {
            path: "/etc/hosts".into(),
        };
        let d = tk.check(&r, Action::Write, t0());
        assert_eq!(d, Decision::Deny(DenyReason::NoMatchingGrant));
    }

    #[test]
    fn parent_component_is_denied_even_when_it_would_stay_inside() {
        let tk = token(vec![Capability::workspace("/workspace")]);
        // "/workspace/a/../b" resolves inside the grant, but we refuse to evaluate it at all.
        let r = Resource::FsPath {
            path: "/workspace/a/../b".into(),
        };
        assert!(matches!(
            tk.check(&r, Action::Read, t0()),
            Decision::Deny(DenyReason::UnsafePath { .. })
        ));
    }

    #[test]
    fn read_only_grant_refuses_write_but_allows_read() {
        let tk = token(vec![Capability::workspace("/workspace").read_only()]);
        let r = Resource::FsPath {
            path: "/workspace/x".into(),
        };
        assert!(tk.check(&r, Action::Read, t0()).is_allowed());
        assert_eq!(
            tk.check(&r, Action::Write, t0()),
            Decision::Deny(DenyReason::ReadOnly)
        );
    }

    #[test]
    fn expired_token_denies_everything() {
        let tk = token(vec![Capability::workspace("/workspace")]);
        let later = t0() + chrono::Duration::seconds(3601);
        let r = Resource::FsPath {
            path: "/workspace/x".into(),
        };
        assert_eq!(
            tk.check(&r, Action::Read, later),
            Decision::Deny(DenyReason::TokenExpired)
        );
    }

    #[test]
    fn token_is_valid_right_up_to_but_not_at_expiry() {
        let tk = token(vec![Capability::workspace("/workspace")]);
        let r = Resource::FsPath {
            path: "/workspace/x".into(),
        };
        let just_before = t0() + chrono::Duration::seconds(3599);
        let exactly = t0() + chrono::Duration::seconds(3600);
        assert!(tk.check(&r, Action::Read, just_before).is_allowed());
        assert!(!tk.check(&r, Action::Read, exactly).is_allowed());
    }

    #[test]
    fn wildcard_host_covers_subdomain_but_not_apex() {
        assert!(host_grant_covers("*.example.com", "api.example.com"));
        assert!(host_grant_covers("*.example.com", "a.b.example.com"));
        assert!(!host_grant_covers("*.example.com", "example.com"));
        assert!(!host_grant_covers("*.example.com", "example.com.evil.net"));
    }

    #[test]
    fn exact_host_grant_is_case_insensitive() {
        assert!(host_grant_covers("API.Example.com", "api.example.com"));
        assert!(!host_grant_covers("api.example.com", "other.example.com"));
    }

    #[test]
    fn wildcard_secret_grant_covers_named_secret() {
        let tk = token(vec![Capability::new(
            Resource::Secret { name: "*".into() },
            [Action::Read],
        )]);
        let r = Resource::Secret {
            name: "github/pat".into(),
        };
        assert!(tk.check(&r, Action::Read, t0()).is_allowed());
    }

    #[test]
    fn named_secret_grant_does_not_cover_a_different_secret() {
        let tk = token(vec![Capability::new(
            Resource::Secret {
                name: "github/pat".into(),
            },
            [Action::Read],
        )]);
        let r = Resource::Secret {
            name: "anthropic/key1".into(),
        };
        assert!(!tk.check(&r, Action::Read, t0()).is_allowed());
    }

    #[test]
    fn provider_scoping_keeps_a_scout_off_the_expensive_pool() {
        let tk = token(vec![Capability::new(
            Resource::Provider {
                id: ProviderId::from_raw("prv_local"),
            },
            [Action::Connect],
        )]);
        let expensive = Resource::Provider {
            id: ProviderId::from_raw("prv_anthropic"),
        };
        assert!(!tk.check(&expensive, Action::Connect, t0()).is_allowed());
    }

    #[test]
    fn reason_for_denial_names_the_granted_actions() {
        let tk = token(vec![Capability::new(
            Resource::FsPath { path: "/w".into() },
            [Action::Read],
        )]);
        let d = tk.check(
            &Resource::FsPath {
                path: "/w/x".into(),
            },
            Action::Write,
            t0(),
        );
        match d {
            Decision::Deny(DenyReason::ActionNotGranted { granted }) => {
                assert_eq!(granted, vec![Action::Read]);
            }
            other => panic!("expected ActionNotGranted, got {other:?}"),
        }
    }

    #[test]
    fn mismatched_resource_kinds_never_match() {
        let tk = token(vec![Capability::new(Resource::Process, [Action::Spawn])]);
        let host = Resource::Host {
            id: HostId::from_raw("hst_1"),
        };
        assert!(!tk.check(&host, Action::Spawn, t0()).is_allowed());
    }

    // ---- max_bytes ---------------------------------------------------------------------

    fn byte_token(grants: Vec<Capability>) -> CapabilityToken {
        token(grants)
    }

    #[test]
    fn a_write_stating_more_bytes_than_the_grant_is_refused_before_it_runs() {
        let tk = byte_token(vec![Capability::workspace("/workspace").with_max_bytes(10)]);
        let r = Resource::FsPath {
            path: "/workspace/x".into(),
        };
        let d = tk.check_with_usage(&r, Action::Write, t0(), RequestUsage::bytes(11));
        assert_eq!(
            d,
            Decision::Deny(DenyReason::TooLarge {
                limit_bytes: 10,
                actual_bytes: 11
            })
        );
    }

    #[test]
    fn a_write_within_the_grants_byte_bound_is_allowed() {
        let tk = byte_token(vec![Capability::workspace("/workspace").with_max_bytes(10)]);
        let r = Resource::FsPath {
            path: "/workspace/x".into(),
        };
        assert!(tk
            .check_with_usage(&r, Action::Write, t0(), RequestUsage::bytes(10))
            .is_allowed());
    }

    #[test]
    fn a_tighter_grant_does_not_veto_a_wider_grant_on_bytes() {
        // Authority is the union of the grants: the bounded grant refuses, the unbounded one
        // allows, and the call is allowed.
        let tk = byte_token(vec![
            Capability::workspace("/workspace").with_max_bytes(10),
            Capability::workspace("/workspace"),
        ]);
        let r = Resource::FsPath {
            path: "/workspace/x".into(),
        };
        assert!(tk
            .check_with_usage(&r, Action::Write, t0(), RequestUsage::bytes(10_000))
            .is_allowed());
    }

    #[test]
    fn an_unstated_byte_count_is_allowed_so_reads_stay_possible() {
        // A read cannot state its size before running; denying unstated sizes here would deny every
        // read under a bounded grant. The loop enforces the bound where the size is known instead.
        let tk = byte_token(vec![Capability::workspace("/workspace").with_max_bytes(10)]);
        let r = Resource::FsPath {
            path: "/workspace/x".into(),
        };
        assert!(tk.check(&r, Action::Read, t0()).is_allowed());
    }

    #[test]
    fn the_post_run_cap_is_the_most_permissive_allowing_bound() {
        let tk = byte_token(vec![
            Capability::workspace("/workspace").with_max_bytes(10),
            Capability::workspace("/workspace").with_max_bytes(100),
        ]);
        let r = Resource::FsPath {
            path: "/workspace/x".into(),
        };
        assert_eq!(tk.max_bytes_for(&r, Action::Read, t0()), Some(100));
    }

    #[test]
    fn an_uncapped_allowing_grant_removes_the_post_run_cap() {
        let tk = byte_token(vec![
            Capability::workspace("/workspace").with_max_bytes(10),
            Capability::workspace("/workspace"),
        ]);
        let r = Resource::FsPath {
            path: "/workspace/x".into(),
        };
        assert_eq!(tk.max_bytes_for(&r, Action::Read, t0()), None);
    }

    #[test]
    fn no_allowing_grant_means_no_cap_and_no_access() {
        let tk = byte_token(vec![Capability::workspace("/workspace").with_max_bytes(10)]);
        let r = Resource::FsPath {
            path: "/elsewhere/x".into(),
        };
        assert!(!tk.check(&r, Action::Read, t0()).is_allowed());
        assert_eq!(tk.max_bytes_for(&r, Action::Read, t0()), None);
    }

    // ---- budget_usd --------------------------------------------------------------------

    fn provider_grant(id: &str) -> Capability {
        Capability::new(
            Resource::Provider {
                id: ProviderId::from_raw(id),
            },
            [Action::Connect],
        )
    }

    #[test]
    fn spend_past_the_grant_budget_is_refused() {
        let tk = byte_token(vec![provider_grant("prv_a").with_budget(5.0)]);
        let r = Resource::Provider {
            id: ProviderId::from_raw("prv_a"),
        };
        let d = tk.check_with_usage(&r, Action::Connect, t0(), RequestUsage::spend(5.01));
        assert_eq!(
            d,
            Decision::Deny(DenyReason::BudgetExceeded {
                limit_usd: 5.0,
                spent_usd: 5.01
            })
        );
        assert!(tk
            .check_with_usage(&r, Action::Connect, t0(), RequestUsage::spend(5.0))
            .is_allowed());
    }

    #[test]
    fn the_run_budget_is_the_most_generous_provider_cap() {
        let tk = byte_token(vec![
            provider_grant("prv_a").with_budget(5.0),
            provider_grant("prv_b").with_budget(20.0),
        ]);
        assert_eq!(tk.provider_budget_usd(), Some(20.0));
    }

    #[test]
    fn an_uncapped_provider_grant_means_no_run_budget() {
        let tk = byte_token(vec![
            provider_grant("prv_a").with_budget(5.0),
            provider_grant("prv_b"),
        ]);
        assert_eq!(tk.provider_budget_usd(), None);
    }

    #[test]
    fn no_provider_grant_means_no_run_budget_and_no_new_denial() {
        // Provider grants never gated model calls; their absence must not start now. The budget
        // binds only where it is expressed.
        let tk = byte_token(vec![Capability::workspace("/workspace")]);
        assert_eq!(tk.provider_budget_usd(), None);
    }

    // ---- symlink containment -----------------------------------------------------------

    /// A scratch dir unique to this test: pid plus name, because tests in one binary share a
    /// temp dir and may run in parallel.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hx-capability-test-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn a_lexically_covered_symlink_escape_fails_the_canonical_recheck() {
        // The exact shape of #32: `/workspace/link/secret` passes the lexical check while the
        // link points at a directory outside the grant.
        let root = scratch("escape");
        let workspace = root.join("workspace");
        let outside = root.join("outside");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, workspace.join("link")).unwrap();

        let grant = workspace.to_string_lossy().into_owned();
        let requested = workspace.join("link").join("secret");
        let requested_str = requested.to_string_lossy().into_owned();

        // Lexically covered — this is the check that used to be the only check.
        assert!(path_grant_covers(&grant, &requested_str));

        // Canonically outside — this is the re-check that closes the escape.
        let canonical = canonicalize_for_check(&requested_str).expect("parent exists");
        assert_eq!(canonical, outside.join("secret"));
        assert!(!path_grant_covers_canonical(&grant, &canonical));

        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_inside_the_grant_survives_the_canonical_recheck() {
        // The re-check must not break legitimate links: a link whose target stays inside the
        // subtree is still covered after resolution.
        let root = scratch("inner");
        let workspace = root.join("workspace");
        std::fs::create_dir_all(workspace.join("data")).unwrap();
        std::os::unix::fs::symlink(workspace.join("data"), workspace.join("alias")).unwrap();

        let grant = workspace.to_string_lossy().into_owned();
        let requested = workspace.join("alias").join("file.txt");
        let requested_str = requested.to_string_lossy().into_owned();
        let canonical = canonicalize_for_check(&requested_str).expect("parent exists");
        assert_eq!(canonical, workspace.join("data").join("file.txt"));
        assert!(path_grant_covers_canonical(&grant, &canonical));

        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_not_yet_existing_write_target_resolves_through_its_parent() {
        // Creates must stay checkable: the missing tail is joined back onto the resolved parent
        // instead of failing the check outright.
        let root = scratch("create");
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();

        let grant = workspace.to_string_lossy().into_owned();
        let requested = workspace.join("new").join("file.txt");
        let canonical =
            canonicalize_for_check(&requested.to_string_lossy()).expect("parent exists");
        assert_eq!(canonical, requested);
        assert!(path_grant_covers_canonical(&grant, &canonical));

        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn an_unresolvable_path_resolves_to_nothing_and_must_deny() {
        // A relative path has no existing ancestor to walk to: `None`, and the caller denies.
        // (Any absolute path resolves at least through `/`, so absolute-but-missing targets take
        // the parent-walk above instead.) There is no safe guess here.
        assert!(canonicalize_for_check("no-such-dir/a/b").is_none());
        assert!(canonicalize_for_check("").is_none());
    }
}

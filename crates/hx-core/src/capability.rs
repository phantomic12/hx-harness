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
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constraints {
    /// Refuse operations that would move more than this many bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    /// Spend ceiling in USD. Enforced by `hx-provider`, not here — this just carries the bound.
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

    /// Convenience: a grant of all actions on a workspace path.
    pub fn workspace(path: impl Into<String>) -> Self {
        Self::new(
            Resource::FsPath { path: path.into() },
            [Action::Read, Action::Write, Action::Execute, Action::Delete],
        )
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
    pub fn check(&self, resource: &Resource, action: Action, now: DateTime<Utc>) -> Decision {
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
            return Decision::Allow;
        }

        Decision::Deny(best.unwrap_or(DenyReason::NoMatchingGrant))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    NoMatchingGrant,
    ActionNotGranted { granted: Vec<Action> },
    ReadOnly,
    TokenExpired,
    GrantExpired,
    UnsafePath { path: String },
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
}

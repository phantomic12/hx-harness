//! Project-scoped allowlists — the `.hx/allow.toml` file (`docs/approvals.md` §5).
//!
//! # What this module exists to hold
//!
//! A remembered approval today lives only in memory for the duration of one run, so an "always allow"
//! answer outlives *nothing*. Project-scoped grants are the tier that survives: a file in the
//! repository — reviewable, diffable, and shareable — that says what a checkout will let an agent do
//! without asking. The design intent, from §5, is that these are files rather than rows in a
//! database, and that they apply to **one repository**: an approval granted in one worktree must not
//! become an approval everywhere.
//!
//! Two properties are the whole point of the file, and both are load-bearing:
//!
//! - **A grant names what it covers.** A `command` glob is required on every grant. There is no way to
//!   spell `allow everything this tool does` in the file, because that is not a grant, it is the
//!   absence of a policy. `Docs` §5's table only offers `for this project` to Local-and-reversible
//!   actions, and a grant that cannot name its own signature is not one a reviewer can price.
//! - **It is scoped to one checkout.** The file lives in a repository's `.hx/` directory. A grant
//!   written in one worktree is not read from another, because the whole point of a *project* grant is
//!   that an approval in one checkout must not become an approval everywhere (`docs/approvals.md` §5 says
//!   this explicitly, as the lesson Claude Code learned the hard way).
//!
//! # What it deliberately does NOT do yet
//!
//! - It does not let the file *deny* anything, only allow. A capability denial cannot be approved away,
//!   and an attacker-controlled file must not become a way around that — denying from a file an attacker can
//!   edit would be trusting the attacker to set the lock. (It also does not *add* deny rules here for a
//!   subtler reason: deny rules can be the only thing standing between the agent and the floor, and a file
//!   that could weaken them would be a file that weakens safety, which is the opposite of this file's job.)
//! - It does not validate a grant's risk class on the way in. The scribed invariant is enforced on the way
//!   out — the harness writes `for this project` only for a Local-and-reversible action (§5's table), so a
//!   grant that reaches the file from a prompt is already bounded. A hand-written or edited file is a
//!   reviewed, diffable change, and the shipped floor (`deny`) and the ceiling still sit above any grant.
//! - It does not re-implement TOML. The `toml` crate owns parsing; this module owns the shape, the
//!   path, and the closed-on-error behavior.

use crate::approval::{ApprovalRequest, RiskClass, Rule};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

/// The file a project's grants live in, relative to the checkout root.
pub const ALLOW_FILE: &str = ".hx/allow.toml";

/// One grant in `.hx/allow.toml`.
///
/// The `command` field is **required**, by construction: `tool` alone would be "allow everything this
/// tool does", which is the one thing a project grant must never mean. The glob is matched the same way a
/// `Rule` matches — against the command line for a shell-like tool, against the resolved absolute path for a
/// file tool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectGrant {
    /// Tool name glob, as in a `Rule` (`shell`, `write_file`, `read_file`).
    pub tool: String,
    /// The command signature or resolved path this grant covers. Required — the grant names its target.
    pub command: String,
    /// Why the grant exists. Shown by `hx policy` and when the rule fires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl ProjectGrant {
    /// Turn this grant into a rule the approval ladder can match.
    ///
    /// The grant's `command` becomes the rule's command glob and `tool` its tool glob, so the shipped
    /// floor and every `deny` rule sit above it unchanged. The rule matches either confinement, as every
    /// rule written before the confinement axis existed does.
    pub fn to_rule(&self) -> Rule {
        let mut rule = Rule::tool(self.tool.clone()).command(self.command.clone());
        if let Some(note) = &self.note {
            rule = rule.note(note.clone());
        }
        rule
    }
}

impl fmt::Display for ProjectGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tool {}, matching {}", self.tool, self.command)?;
        if let Some(note) = &self.note {
            write!(f, "  # {note}")?;
        }
        Ok(())
    }
}

/// The on-disk shape of `.hx/allow.toml`: a list of grants.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowFile {
    #[serde(default)]
    pub allow: Vec<ProjectGrant>,
}

impl AllowFile {
    /// Read and validate a project allowlist from `path`.
    ///
    /// **Fails closed.** A file that cannot be read for a reason other than absence, is malformed TOML,
    /// or carries a shape this build does not understand is an *error*, and no grants from it are applied.
    /// An absent file is the empty list — there is nothing to be closed about. A present-but-broken file
    /// is a policy someone was relying on, and the failure names it rather than silently running without it.
    pub fn load(path: &Path) -> Result<Self, AllowlistError> {
        let bytes = std::fs::read(path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                AllowlistError::NotFound(path.to_path_buf())
            } else {
                AllowlistError::Unreadable(path.to_path_buf(), err.to_string())
            }
        })?;
        let text = String::from_utf8(bytes)
            .map_err(|err| AllowlistError::Malformed(path.to_path_buf(), err.to_string()))?;
        let parsed: AllowFile = toml::from_str(&text)
            .map_err(|err| AllowlistError::Malformed(path.to_path_buf(), err.to_string()))?;
        Ok(parsed)
    }

    /// Whether the file has any grants.
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty()
    }

    /// The rules the ladder should carry for these grants.
    ///
    /// Each grant becomes one `allow` rule, so the shipped floor (`deny`, checked first) and every
    /// `ask` rule (checked second) sit above it unchanged: a grant can never override a denial or turn an
    /// `ask me` into decoration. The order within the file is preserved.
    pub fn into_rules(self) -> Vec<Rule> {
        self.allow.into_iter().map(|g| g.to_rule()).collect()
    }

    /// Add a grant for an approved request, and write the file back.
    ///
    /// This is the write side of §5's table: `for this project` is offered **only** for a
    /// Local-and-reversible action. So if the request is not reversible, or is classified `External` or
    /// worse, this refuses to write it — a persistent grant for a push, a delete, or a privilege
    /// escalation is the defect the doc names, not a feature. The check uses the request's *own*
    /// classification (the same one that decided whether the prompt offered the button), so the file and the
    /// prompt can never disagree about whether a grant was allowed.
    ///
    /// The file is created if the checkout has none, and an existing file's other grants are preserved: a
    /// grant being added is not a reason to discard the ones already reviewed.
    pub fn add_for_request(
        &mut self,
        path: &Path,
        req: &ApprovalRequest,
    ) -> Result<(), AllowlistError> {
        if !req.reversible || req.risk >= RiskClass::External {
            return Err(AllowlistError::NotGrantable(
                path.to_path_buf(),
                format!(
                    "a `{}` ({}) action is not Local-and-reversible, so it cannot be granted for \
                     this project (docs/approvals.md §5)",
                    req.risk.label(),
                    req.summary
                ),
            ));
        }
        let command = req.key.clone();
        self.add(
            path,
            ProjectGrant {
                tool: req.tool.clone(),
                command,
                note: None,
            },
        )
    }

    /// Append a grant and write the file, preserving any existing grants.
    ///
    /// The caller (typically [`AllowFile::add_for_request`]) is responsible for the safety check; this is
    /// the mechanical "put it in the file" half.
    fn add(&mut self, path: &Path, grant: ProjectGrant) -> Result<(), AllowlistError> {
        if !self.allow.contains(&grant) {
            self.allow.push(grant);
        }
        self.write(path)
    }

    /// Somewhere the edited file can be staged before landing, e.g. a temp path.
    fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "# Project-scoped grants (docs/approvals.md §5): what this checkout will allow without asking.\n",
        );
        out.push_str(
            "# Each grant names what it covers. Only Local-and-reversible actions belong here.\n",
        );
        for grant in &self.allow {
            out.push_str("\n[[allow]]\n");
            out.push_str(&format!("tool = {:?}\n", grant.tool));
            out.push_str(&format!("command = {:?}\n", grant.command));
            if let Some(note) = &grant.note {
                out.push_str(&format!("note = {:?}\n", note));
            }
        }
        out
    }

    /// Write this allowlist to `path`, creating the parent `.hx/` directory.
    fn write(&self, path: &Path) -> Result<(), AllowlistError> {
        let parent = path.parent().ok_or_else(|| {
            AllowlistError::Unreadable(
                path.to_path_buf(),
                "the allowlist path has no parent directory".to_string(),
            )
        })?;
        std::fs::create_dir_all(parent)
            .map_err(|err| AllowlistError::Unreadable(parent.to_path_buf(), err.to_string()))?;
        // Atomic enough: write to a temp sibling, then rename over the real file, so a crash mid-write
        // cannot leave a half-written allowlist that reads as empty.
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, self.render())
            .map_err(|err| AllowlistError::Unreadable(tmp.clone(), err.to_string()))?;
        std::fs::rename(&tmp, path)
            .map_err(|err| AllowlistError::Unreadable(path.to_path_buf(), err.to_string()))?;
        Ok(())
    }
}

/// Why a project allowlist could not be used.
///
/// Each variant carries the path and a reason, because a fail-closed policy that does not say *why* is
/// a policy nobody can fix.
#[derive(Debug, thiserror::Error)]
pub enum AllowlistError {
    #[error("no project allowlist at {0}")]
    NotFound(PathBuf),
    #[error("could not read the project allowlist at {0}: {1}")]
    Unreadable(PathBuf, String),
    #[error("the project allowlist at {0} is malformed: {1}")]
    Malformed(PathBuf, String),
    #[error("cannot write a project grant to {0}: {1}")]
    NotGrantable(PathBuf, String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmpdir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("hx-allowlist-test-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_real_file_on_disk_parses_into_grants() {
        // Fixtures are real artefacts: a `.hx/allow.toml` written to disk, not a string handed
        // straight to the parser — because the contract this test pins is "the file the reviewer will
        // read", not "a struct that happens to serialize".
        let dir = tmpdir("parse");
        let hx = dir.join(".hx");
        fs::create_dir_all(&hx).unwrap();
        fs::write(
            hx.join("allow.toml"),
            r#"
# An allowlist that names what it covers.
[[allow]]
tool = "shell"
command = "cargo test*"
note = "the test loop is run often"

[[allow]]
tool = "write_file"
command = "/home/yoav/projects/x/src/*"
"#,
        )
        .unwrap();

        let list = AllowFile::load(&hx.join("allow.toml")).unwrap();
        assert_eq!(list.allow.len(), 2, "both grants parse");
        assert_eq!(list.allow[0].tool, "shell");
        assert_eq!(list.allow[0].command, "cargo test*");
        assert_eq!(
            list.allow[0].note.as_deref(),
            Some("the test loop is run often")
        );
        // And each becomes a rule the ladder can match, carrying the note forward.
        assert_eq!(list.allow[1].to_rule().tool, "write_file");
    }

    #[test]
    fn an_absent_file_is_the_empty_list_and_a_broken_one_fails_closed() {
        // An absent file is "nothing granted" — not an error. A present one that does not parse is an
        // error, and no grants from it may apply: a policy somebody was relying on being silently dropped
        // is how a harness quietly stops being safe.
        let dir = tmpdir("absent");
        assert!(
            matches!(
                AllowFile::load(&dir.join(".hx/allow.toml")),
                Err(AllowlistError::NotFound(_))
            ),
            "there is no file, so there is nothing to load"
        );

        let hx = dir.join(".hx");
        fs::create_dir_all(&hx).unwrap();
        fs::write(hx.join("allow.toml"), "allow: [ { tool: \"shell\", }").unwrap();
        let err = AllowFile::load(&hx.join("allow.toml")).unwrap_err();
        assert!(
            matches!(err, AllowlistError::Malformed(..)),
            "a malformed file is an error, not an empty list: {err}"
        );
    }

    #[test]
    fn a_grant_must_name_what_it_covers_or_the_file_is_refused() {
        // The invariant the format exists for: `tool = "shell"` with no command is "allow everything
        // this tool does", which is not a grant. The schema makes `command` mandatory, so a file that
        // tries it fails to parse and the whole file is refused rather than a rule being invented.
        let dir = tmpdir("blank");
        let hx = dir.join(".hx");
        fs::create_dir_all(&hx).unwrap();
        fs::write(
            hx.join("allow.toml"),
            r#"
[[allow]]
tool = "shell"
"#,
        )
        .unwrap();
        let err = AllowFile::load(&hx.join("allow.toml")).unwrap_err();
        assert!(
            matches!(err, AllowlistError::Malformed(..)),
            "a grant without a command fails closed: {err}"
        );
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        // `deny_unknown_fields` means a typo cannot silently drop a differently-spelled restriction later.
        let dir = tmpdir("unknown");
        let hx = dir.join(".hx");
        fs::create_dir_all(&hx).unwrap();
        fs::write(
            hx.join("allow.toml"),
            r#"
[[allow]]
tool = "shell"
command = "cargo test*"
risk = "destructive"
"#,
        )
        .unwrap();
        let err = AllowFile::load(&hx.join("allow.toml")).unwrap_err();
        assert!(
            matches!(err, AllowlistError::Malformed(..)),
            "a field this build does not understand is refused, not dropped: {err}"
        );
    }

    #[test]
    fn a_written_grant_round_trips_through_a_real_file() {
        // The writer is not a different format from the reader: what a grant is written as is exactly
        // what a later run reads back, and the existing grant survives the addition of a new one.
        let dir = tmpdir("roundtrip");
        let path = dir.join(".hx").join("allow.toml");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "[[allow]]\ntool = \"shell\"\ncommand = \"cargo test*\"\n",
        )
        .unwrap();

        let mut list = AllowFile::load(&path).unwrap();
        let granted = ApprovalRequest {
            tool: "write_file".to_string(),
            summary: "write /w/notes.txt".to_string(),
            risk: RiskClass::Mutate,
            reason: "a local edit".to_string(),
            key: "write_file|/w/notes.txt".to_string(),
            reversible: true,
            targets: vec![],
            undo: None,
            confined: crate::approval::Confinement::Host,
            default_on_timeout: crate::approval::ApprovalOption::Deny,
            timeout_secs: None,
            options: vec![], // not part of the grant
            id: crate::ids::ApprovalId::new(),
        };
        list.add_for_request(&path, &granted).unwrap();

        let reloaded = AllowFile::load(&path).unwrap();
        assert_eq!(reloaded.allow.len(), 2, "the old grant is preserved");
        assert!(
            reloaded.allow.iter().any(|g| g.tool == "write_file"),
            "the new grant is present"
        );
    }

    #[test]
    fn a_persistent_grant_is_never_written_for_an_irreversible_or_external_action() {
        // §5's table, as a test: `for this project` exists only for Local-and-reversible. A grant the
        // code would happily write for a push or a delete is the security defect the doc calls out, so the
        // writer refuses and the file stays untouched.
        let dir = tmpdir("refuse");
        let path = dir.join(".hx").join("allow.toml");
        let mut list = AllowFile::default();

        let destructive = ApprovalRequest {
            tool: "shell".to_string(),
            summary: "rm -rf /srv/data".to_string(),
            risk: RiskClass::Destructive,
            reason: "irreversible".to_string(),
            key: "shell|rm -rf /srv/data".to_string(),
            reversible: false,
            targets: vec![],
            undo: None,
            confined: crate::approval::Confinement::Host,
            default_on_timeout: crate::approval::ApprovalOption::Deny,
            timeout_secs: None,
            options: vec![],
            id: crate::ids::ApprovalId::new(),
        };
        assert!(
            matches!(
                list.add_for_request(&path, &destructive),
                Err(AllowlistError::NotGrantable(..))
            ),
            "a destructive action must never become a project grant"
        );

        let external = ApprovalRequest {
            tool: "shell".to_string(),
            summary: "git push origin main".to_string(),
            risk: RiskClass::External,
            reason: "leaves the machine".to_string(),
            key: "shell|git push origin main".to_string(),
            reversible: false,
            targets: vec![],
            undo: None,
            confined: crate::approval::Confinement::Host,
            default_on_timeout: crate::approval::ApprovalOption::Deny,
            timeout_secs: None,
            options: vec![],
            id: crate::ids::ApprovalId::new(),
        };
        assert!(
            matches!(
                list.add_for_request(&path, &external),
                Err(AllowlistError::NotGrantable(..))
            ),
            "an external action is chat-scoped at most, never a project grant"
        );
    }

    #[test]
    fn a_project_grant_does_not_apply_in_a_different_checkout() {
        // The whole point of a *project* grant (§5): it lives in one checkout and is read from that
        // checkout. A grant written in worktree A is not read from worktree B, because an approval in
        // one worktree must not become an approval everywhere. Two real directories, each with its own file.
        let a = tmpdir("checkout-a");
        let b = tmpdir("checkout-b");
        let path_a = a.join(".hx").join("allow.toml");
        let path_b = b.join(".hx").join("allow.toml");
        fs::create_dir_all(path_a.parent().unwrap()).unwrap();
        fs::write(
            &path_a,
            "[[allow]]\ntool = \"shell\"\ncommand = \"cargo test*\"\n",
        )
        .unwrap();

        // Checkout A has the grant...
        assert_eq!(AllowFile::load(&path_a).unwrap().allow.len(), 1);
        // ...checkout B has no file, and therefore no grants.
        assert!(AllowFile::load(&path_b).is_err_and(|e| matches!(e, AllowlistError::NotFound(_))));
    }

    #[test]
    fn a_folded_project_grant_sits_below_ask_in_the_ladder() {
        // The position is the security property, not a detail: `deny → ask → allow`. A grant folded
        // into `allow` lets the named command run free even at a paranoid level, but an `ask` rule for the
        // same command still prompts — otherwise "show me this" would be decoration and a project file could not
        // be told apart from a policy that is not looking. Uses a real parsed file's rules, so the ladder
        // is fed exactly what the on-disk format produces.
        let dir = tmpdir("ladder");
        let path = dir.join(".hx").join("allow.toml");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "[[allow]]\ntool = \"shell\"\ncommand = \"cargo test*\"\n",
        )
        .unwrap();
        let mut policy = crate::approval::ApprovalPolicy::paranoid();
        policy
            .allow
            .append(&mut AllowFile::load(&path).unwrap().into_rules());

        let mut session = crate::approval::ApprovalSession::new(policy);
        let granted = crate::approval::ActionRequest::shell("cargo test -- --run");
        assert!(
            session.decide(&granted, chrono::Utc::now()).is_allowed(),
            "the granted command runs free even at paranoid"
        );
        // A different command the grant does not name still asks at paranoid.
        assert!(
            session
                .decide(
                    &crate::approval::ActionRequest::shell("cargo publish"),
                    chrono::Utc::now()
                )
                .is_asking(),
            "a grant names what it covers: a different command is still a question"
        );
    }
}

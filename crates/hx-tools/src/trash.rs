//! `delete` — removal that can be taken back.
//!
//! `docs/approvals.md` §3 is the whole reason this tool exists: *"prefer reversible. Ship a `delete`
//! tool that moves to the XDG trash instead of a shell `rm`."* Three properties follow from it, and
//! each one is a thing a model writing `rm -rf` cannot do for itself.
//!
//! **1. One name, read literally.** There is no shell between the model and the filesystem here, so
//! `build*` is a filename that happens to contain an asterisk rather than a glob: the tool removes
//! exactly what it names, and both the prompt and the result name it. The case that *cannot* be
//! answered honestly is the one where a shell does the expanding — `rm -rf build*` — and that is
//! refused by the shipped policy (`ApprovalPolicy::refuse_unenumerable_deletions`), which offers the
//! enumerable form instead of guessing.
//!
//! **2. The prompt can say what will be gone.** [`DeleteTool::targets`] measures the target — how
//! many entries, how many bytes — *before* anyone is asked, so the question reads
//! `directory, 1 342 entries, 480 MB` rather than `build`. The measurement is bounded and reports
//! itself as a floor (`at least …`) when it hits the bound: understating a blast radius is the one
//! direction that must never happen.
//!
//! **3. The file is moved, not unlinked.** The destination is the freedesktop trash
//! (`~/.local/share/Trash`), the move is recorded in `info/<name>.trashinfo` with the path it came
//! from, and a name already in the trash is never replaced — the tool picks the next free numbered
//! name instead. `shell` keeps `rm` for everything this cannot express, and that path is classified
//! `Destructive` and asks about it.
//!
//! What this deliberately does not do: empty the trash, or restore from it. Both are a human's
//! business, and a tool that could empty the trash would be a `rm` with extra steps.

use crate::tool::{parse_args, Requirement, Tool, ToolContext, ToolError, ToolOutcome};
use async_trait::async_trait;
use hx_core::approval::{pattern_metachar, Target};
use hx_core::capability::{Action, Resource};
use hx_remote::host::RemoteEntry;
use hx_remote::Host;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeSet, VecDeque};

/// A timestamp for the trash record. `chrono` is here rather than re-exported through `hx-core`
/// because "when did this happen" is a fact about *this* call, not about the policy.
use chrono::Utc;

/// How much of a tree a measurement will walk before it stops and says "at least".
///
/// A prompt has to be produced in the time a person will wait for one, and the difference between
/// 10 000 entries and 900 000 entries is not a decision anyone makes differently — but it has to be
/// *said* as a lower bound rather than shown as a total.
const MEASURE_MAX_ENTRIES: u64 = 10_000;

/// How deep a measurement goes. Deeper than this and it reports a floor instead of a number.
const MEASURE_MAX_DEPTH: usize = 8;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteArgs {
    path: String,
    /// Required to remove a directory: a tree is not something to find out about afterwards.
    #[serde(default)]
    recursive: bool,
}

/// Move a file or directory to the trash.
pub struct DeleteTool;

impl DeleteTool {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DeleteTool {
    fn default() -> Self {
        Self::new()
    }
}

/// Where this host keeps its trash, when it has a home directory to put one under.
///
/// The freedesktop spec also honours `$XDG_DATA_HOME`, which would mean asking the host for its
/// environment — a round trip on every prompt to move a directory a few characters. The home
/// directory is the case that matches what `trash-cli`, Nautilus and the file managers on either
/// desktop actually use, so that is what the tool promises.
fn trash_root(host: &dyn Host) -> Option<String> {
    if !host.caps().is_unix() {
        // Windows has a recycle bin, and it is not this: pretending to trash into a POSIX path would
        // be a `mv` to nowhere. Better to refuse than to guess.
        return None;
    }
    host.caps()
        .home_dir
        .as_deref()
        .map(str::trim)
        .filter(|home| !home.is_empty())
        .map(|home| format!("{}/.local/share/Trash", home.trim_end_matches('/')))
}

/// A path that cannot be trashed, because there is nothing to move it *into*.
///
/// The root of a filesystem has no parent, so "move it aside" has no meaning for it, and a delete of
/// it is never a question worth putting to anyone.
fn is_filesystem_root(path: &str) -> bool {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return true;
    }
    let bytes = trimmed.as_bytes();
    // A Windows drive root: `C:`, `d:`.
    bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// The entry for a path, learned from its parent's listing — a `Host` has no `stat`, and a listing
/// is the thing every transport can do.
async fn entry_of(host: &dyn Host, path: &str) -> Result<Option<RemoteEntry>, String> {
    let (parent, name) = split_parent(path)?;
    let entries = host
        .list_dir(parent)
        .await
        .map_err(|err| format!("{err}"))?;
    Ok(entries.into_iter().find(|entry| entry.name == name))
}

/// Split an absolute path into its parent and its last component.
///
/// The root has no last component, which is the same statement as [`is_filesystem_root`].
fn split_parent(path: &str) -> Result<(&str, &str), String> {
    match path.rsplit_once('/') {
        Some((dir, name)) if !name.is_empty() => Ok((if dir.is_empty() { "/" } else { dir }, name)),
        _ => Err(format!(
            "{path} is the root of a filesystem: there is no name to move and no trash that could \
             hold it"
        )),
    }
}

/// How much there is, bounded.
struct Measurement {
    entries: u64,
    bytes: u64,
    partial: bool,
}

/// Count entries and add up sizes under `path`.
///
/// `recursive` is the model's own answer: measuring one level of a directory the tool is going to
/// refuse to delete anyway would be work for a number nobody acts on.
async fn walk(host: &dyn Host, path: &str, recursive: bool) -> Result<Measurement, String> {
    let mut entries = 0u64;
    let mut bytes = 0u64;
    let mut partial = false;
    let mut queue: VecDeque<(String, usize)> = VecDeque::from([(path.to_string(), 0)]);

    while let Some((dir, depth)) = queue.pop_front() {
        let listing = host.list_dir(&dir).await.map_err(|err| format!("{err}"))?;

        for entry in listing {
            entries += 1;
            if entry.is_dir {
                if recursive && depth < MEASURE_MAX_DEPTH {
                    queue.push_back((entry.path.clone(), depth + 1));
                } else if recursive {
                    // Deeper than the bound: the count continues, the size stops being a total.
                    partial = true;
                }
            } else {
                bytes += entry.size;
            }

            if entries >= MEASURE_MAX_ENTRIES {
                return Ok(Measurement {
                    entries,
                    bytes,
                    partial: true,
                });
            }
        }
    }

    Ok(Measurement {
        entries,
        bytes,
        partial,
    })
}

/// Measure a path into a [`Target`], turning every failure into a note rather than an error.
///
/// A prompt is built from this. A host that cannot be listed is a reason to say so in the prompt, not
/// a reason to refuse a call that was classified on other grounds.
async fn measure(host: &dyn Host, path: &str, recursive: bool) -> Target {
    match entry_of(host, path).await {
        Err(why) => Target::unmeasured(path, why),
        Ok(None) => Target::missing(path),
        Ok(Some(entry)) if !entry.is_dir => Target::file(path, entry.size),
        Ok(Some(_)) => match walk(host, path, recursive).await {
            Ok(measured) => {
                Target::directory(path, measured.entries, measured.bytes, measured.partial)
            }
            Err(why) => Target::unmeasured(path, why),
        },
    }
}

/// A name in the trash that nothing is using.
///
/// The freedesktop convention is `<name>`, then `<name>.2`, `<name>.3`, … and it is not a detail: the
/// one thing a trash must never do is destroy the file already in it, so a taken name is a reason to
/// pick another rather than to overwrite.
async fn free_name(
    host: &dyn Host,
    files_dir: &str,
    info_dir: &str,
    name: &str,
) -> Result<String, String> {
    let mut taken: BTreeSet<String> = BTreeSet::new();
    // No trash yet is not a failure: nothing is taken, and the move creates the directory.
    if let Ok(entries) = host.list_dir(files_dir).await {
        taken.extend(entries.into_iter().map(|entry| entry.name));
    }
    if let Ok(entries) = host.list_dir(info_dir).await {
        taken.extend(
            entries
                .into_iter()
                .filter_map(|entry| entry.name.strip_suffix(".trashinfo").map(str::to_string)),
        );
    }

    if !taken.contains(name) {
        return Ok(name.to_string());
    }
    for n in 2..=9999 {
        let candidate = format!("{name}.{n}");
        if !taken.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(format!(
        "the trash already holds 9999 entries called {name}; empty it before deleting more of them"
    ))
}

#[async_trait]
impl Tool for DeleteTool {
    fn name(&self) -> &str {
        "delete"
    }

    fn description(&self) -> &str {
        "Remove a file, or a directory with `recursive: true`, by moving it to the trash instead of \
         deleting it, so it can be put back. `path` must be one path: a glob or a variable is refused, \
         because a deletion has to name what it deletes. Use `shell` with `rm` only when a pattern is \
         genuinely what you mean — that path cannot be undone and will be asked about."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "the one file or directory to remove" },
                "recursive": {
                    "type": "boolean",
                    "description": "required to remove a directory: moves the whole tree to the trash"
                }
            },
            "required": ["path"]
        })
    }

    fn requirement(
        &self,
        args: &Value,
        ctx: &ToolContext,
    ) -> Result<Option<Requirement>, ToolError> {
        let parsed: DeleteArgs = parse_args(args)?;
        let path = ctx.resolve(&parsed.path);

        if is_filesystem_root(&path) {
            return Err(ToolError::Arguments(format!(
                "{path} is the root of a filesystem. Nothing can be moved out of it, and a delete of \
                 it is not a question anyone can answer usefully."
            )));
        }

        Ok(Some(Requirement::new(
            Resource::FsPath { path: path.clone() },
            Action::Delete,
            format!("delete {path}"),
        )))
    }

    /// What the prompt says will be gone. See the module docs.
    async fn targets(&self, args: &Value, ctx: &ToolContext) -> Result<Vec<Target>, ToolError> {
        let parsed: DeleteArgs = parse_args(args)?;
        let path = ctx.resolve(&parsed.path);
        // Never an error: a target that could not be measured is a target that is *reported* as
        // unmeasured, and failing here would turn a listing problem into a refusal of the call.
        Ok(vec![measure(&*ctx.host, &path, parsed.recursive).await])
    }

    fn undo(&self, args: &Value, ctx: &ToolContext) -> Option<String> {
        let _parsed: DeleteArgs = parse_args(args).ok()?;
        let trash = trash_root(&*ctx.host)?;
        Some(format!(
            "moves to the trash at {trash}/files, where it can be moved back — nothing is destroyed \
             until the trash is emptied"
        ))
    }

    async fn call(&self, args: Value, ctx: &ToolContext) -> Result<ToolOutcome, ToolError> {
        let parsed: DeleteArgs = parse_args(&args)?;
        let path = ctx.resolve(&parsed.path);
        let host: &dyn Host = &*ctx.host;

        let Some(trash) = trash_root(host) else {
            return Ok(ToolOutcome::failed(format!(
                "this host is not one this tool can trash on (it reported no POSIX home directory), so \
                 {path} would have to be removed some other way. Refusing rather than deleting: \
                 without a trash, `delete` is `rm` with a friendlier name."
            )));
        };

        match entry_of(host, &path).await {
            Err(why) => {
                return Ok(ToolOutcome::failed(format!(
                    "could not look at {path}: {why}. Nothing was deleted — this is a transport or \
                     permission problem rather than a missing file, so retrying the same call may work."
                )))
            }
            Ok(None) => {
                // No shell is involved, so a `*` in the path was read as one literal name and found
                // nothing. Say that plainly: a model that meant a pattern has to be told that this
                // tool will not expand it, or it will try the same call again.
                let hint = match pattern_metachar(&path) {
                    Some(metachar) => format!(
                        "\nThis tool does not expand `{metachar}` — it reads the path as one name. List \
                         the directory and delete the entries you mean, one path at a time."
                    ),
                    None => String::new(),
                };
                return Ok(ToolOutcome::failed(format!(
                    "nothing to delete: {path} does not exist{}. You may be working from a listing that \
                     is out of date — list the directory again.{hint}",
                    if pattern_metachar(&path).is_some() {
                        " (as that exact name)"
                    } else {
                        ""
                    }
                )));
            }
            Ok(Some(entry)) if entry.is_dir && !parsed.recursive => {
                return Ok(ToolOutcome::failed(format!(
                    "{path} is a directory. Pass `recursive: true` to move the whole tree to the trash, \
                     or list it and delete the entries you mean one at a time."
                )))
            }
            Ok(Some(_)) => {}
        }

        let name = match split_parent(&path) {
            Ok((_, name)) => name.to_string(),
            Err(why) => return Ok(ToolOutcome::failed(why)),
        };

        let files_dir = format!("{trash}/files");
        let info_dir = format!("{trash}/info");
        let destination_name = match free_name(host, &files_dir, &info_dir, &name).await {
            Ok(name) => name,
            Err(why) => return Ok(ToolOutcome::failed(why)),
        };
        let destination = format!("{files_dir}/{destination_name}");
        let record = format!("{info_dir}/{destination_name}.trashinfo");

        // The record first. It is the thing that makes the move reversible — a file in the trash whose
        // original path was never written down is a file nobody can put back — so it exists before
        // the file leaves its name.
        let contents = format!(
            "[Trash Info]\nPath={path}\nDeletionDate={}\n",
            Utc::now().to_rfc3339()
        );
        if let Err(err) = host.write_file(&record, contents.as_bytes()).await {
            return Ok(ToolOutcome::failed(format!(
                "could not write the trash record {record}: {err}. Nothing was deleted."
            )));
        }

        match host.rename(&path, &destination).await {
            Ok(()) => Ok(ToolOutcome::ok(format!(
                "moved {path} to {destination}\n\
                 undo: mv {destination} {path}\n\
                 recorded in {record}; nothing was destroyed"
            ))),
            Err(err) => Ok(ToolOutcome::failed(format!(
                "could not move {path} to {destination}: {err}. Nothing was deleted; the record \
                 {record} was written and can be removed by hand."
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{BrokenHost, FakeHost};
    use std::sync::Arc;

    fn ctx(host: Arc<dyn Host>) -> ToolContext {
        ToolContext::new(host)
    }

    /// A host with a workspace, a directory to delete, and a home directory for the trash.
    fn host_with_tree() -> Arc<FakeHost> {
        Arc::new(
            FakeHost::unix()
                .with_file("/ws/build/a.o", "aaaa")
                .with_file("/ws/build/sub/b.o", "bb")
                .with_file("/ws/keep.txt", "keep me"),
        )
    }

    // ---- the requirement: one path, named -----------------------------------

    #[test]
    fn a_delete_requires_a_delete_grant_on_the_resolved_path() {
        // The capability answer, not the prompt's: this agent must have been granted deletion here.
        let ctx = ctx(host_with_tree()).in_workspace("/ws");
        let requirement = DeleteTool
            .requirement(&json!({ "path": "build" }), &ctx)
            .unwrap()
            .expect("a delete touches the filesystem");

        assert_eq!(requirement.action, Action::Delete);
        assert!(
            requirement.command().is_none(),
            "a filesystem delete has no command line for the classifier"
        );
        match requirement.resource {
            Resource::FsPath { path } => assert_eq!(path, "/ws/build"),
            other => panic!("expected a path resource, got {other:?}"),
        }
    }

    #[test]
    fn a_pattern_shaped_path_is_checked_as_the_one_name_it_is() {
        // Nothing here expands anything: the resource the token is asked about is the literal string
        // the model wrote, joined onto the workspace. A `*` is a character in a filename, and a tool
        // that quietly expanded it would be a tool whose check and effect disagree.
        let ctx = ctx(host_with_tree()).in_workspace("/ws");
        let requirement = DeleteTool
            .requirement(&json!({ "path": "build*" }), &ctx)
            .unwrap()
            .expect("a delete touches the filesystem");
        match requirement.resource {
            Resource::FsPath { path } => assert_eq!(path, "/ws/build*"),
            other => panic!("expected a path resource, got {other:?}"),
        }
    }

    #[test]
    fn the_filesystem_root_is_refused() {
        for path in ["/", "//", "C:", "C:/"] {
            let ctx = ctx(host_with_tree());
            let err = DeleteTool
                .requirement(&json!({ "path": path }), &ctx)
                .unwrap_err()
                .to_string();
            assert!(err.contains("root"), "{path}: {err}");
        }
    }

    #[test]
    fn a_misnamed_argument_is_an_error_rather_than_a_default() {
        // `deny_unknown_fields`: a typo must not become "deleted something else".
        let ctx = ctx(host_with_tree()).in_workspace("/ws");
        let err = DeleteTool
            .requirement(&json!({ "path": "build", "recurse": true }), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("recurse"), "{err}");
    }

    // ---- the measurement the prompt shows -----------------------------------

    #[tokio::test]
    async fn a_directory_target_says_how_many_and_how_much() {
        let ctx = ctx(host_with_tree()).in_workspace("/ws");
        let targets = DeleteTool
            .targets(&json!({ "path": "build", "recursive": true }), &ctx)
            .await
            .unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].path, "/ws/build");
        assert_eq!(targets[0].kind, hx_core::approval::TargetKind::Directory);
        assert_eq!(
            targets[0].entries,
            Some(3),
            "the whole tree is counted: a.o, sub, and sub/b.o"
        );
        assert_eq!(
            targets[0].bytes,
            Some(6),
            "4 bytes + 2 bytes; a directory adds none"
        );
        assert!(!targets[0].partial);
        assert!(
            targets[0].describe().contains("3 entries"),
            "{}",
            targets[0].describe()
        );
    }

    #[tokio::test]
    async fn a_file_target_carries_its_size() {
        let ctx = ctx(host_with_tree()).in_workspace("/ws");
        let targets = DeleteTool
            .targets(&json!({ "path": "keep.txt" }), &ctx)
            .await
            .unwrap();
        assert_eq!(targets[0].kind, hx_core::approval::TargetKind::File);
        assert_eq!(targets[0].bytes, Some(7));
    }

    #[tokio::test]
    async fn a_path_that_is_not_there_is_reported_rather_than_counted_as_nothing() {
        let ctx = ctx(host_with_tree()).in_workspace("/ws");
        let targets = DeleteTool
            .targets(&json!({ "path": "gone" }), &ctx)
            .await
            .unwrap();
        assert_eq!(targets[0].kind, hx_core::approval::TargetKind::Missing);
        assert!(
            targets[0].describe().contains("missing"),
            "{}",
            targets[0].describe()
        );
    }

    #[tokio::test]
    async fn a_host_that_cannot_be_read_is_a_note_not_an_error() {
        // The prompt must still be built: the call was classified on other grounds, and "we could not
        // look" is not a reason to let it through silently.
        let ctx = ctx(Arc::new(BrokenHost::new())).in_workspace("/ws");
        let targets = DeleteTool
            .targets(&json!({ "path": "build" }), &ctx)
            .await
            .expect("a measurement never fails the call");
        assert_eq!(targets[0].kind, hx_core::approval::TargetKind::Unknown);
        assert!(
            targets[0].describe().contains("connection reset"),
            "{}",
            targets[0].describe()
        );
    }

    #[tokio::test]
    async fn a_measurement_that_hits_its_bound_says_at_least() {
        let mut host = FakeHost::unix();
        for n in 0..(MEASURE_MAX_ENTRIES + 5) {
            host = host.with_file(&format!("/ws/big/f{n}.o"), "x");
        }
        let ctx = ctx(Arc::new(host)).in_workspace("/ws");

        let targets = DeleteTool
            .targets(&json!({ "path": "big", "recursive": true }), &ctx)
            .await
            .unwrap();
        let described = targets[0].describe();
        assert!(targets[0].partial, "{described}");
        assert!(described.contains("at least"), "{described}");
    }

    // ---- the move ----------------------------------------------------------

    #[tokio::test]
    async fn deleting_moves_the_file_into_the_trash_and_records_where_it_came_from() {
        let host = host_with_tree();
        let ctx = ctx(host.clone()).in_workspace("/ws");

        let outcome = DeleteTool
            .call(json!({ "path": "keep.txt" }), &ctx)
            .await
            .unwrap();
        assert!(outcome.ok, "{}", outcome.content);

        // Moved, not copied and not deleted: the file is in the trash and no longer where it was.
        assert!(outcome
            .content
            .contains("/home/agent/.local/share/Trash/files/keep.txt"));
        assert_eq!(
            host.file("/home/agent/.local/share/Trash/files/keep.txt")
                .as_deref(),
            Some("keep me")
        );
        assert!(
            host.file("/ws/keep.txt").is_none(),
            "a copy is not a delete"
        );

        // And the record names the original path, which is what makes it reversible.
        let record = host
            .file("/home/agent/.local/share/Trash/info/keep.txt.trashinfo")
            .expect("the trash record exists");
        assert!(record.contains("[Trash Info]"), "{record}");
        assert!(record.contains("Path=/ws/keep.txt"), "{record}");
        assert!(record.contains("DeletionDate="), "{record}");
    }

    #[tokio::test]
    async fn deleting_a_directory_requires_saying_so() {
        let host = host_with_tree();
        let ctx = ctx(host.clone()).in_workspace("/ws");

        let outcome = DeleteTool
            .call(json!({ "path": "build" }), &ctx)
            .await
            .unwrap();

        assert!(!outcome.ok);
        assert!(
            outcome.content.contains("is a directory"),
            "{}",
            outcome.content
        );
        assert!(
            outcome.content.contains("recursive: true"),
            "the model is told what to do instead: {}",
            outcome.content
        );
        assert_eq!(
            host.file("/ws/build/a.o").as_deref(),
            Some("aaaa"),
            "nothing moves when the call is refused"
        );
    }

    #[tokio::test]
    async fn a_whole_tree_moves_to_the_trash_in_one_piece() {
        let host = host_with_tree();
        let ctx = ctx(host.clone()).in_workspace("/ws");

        let outcome = DeleteTool
            .call(json!({ "path": "build", "recursive": true }), &ctx)
            .await
            .unwrap();
        assert!(outcome.ok, "{}", outcome.content);

        assert_eq!(
            host.file("/home/agent/.local/share/Trash/files/build/sub/b.o")
                .as_deref(),
            Some("bb"),
            "the tree goes with it, subdirectories included"
        );
        assert!(host.file("/ws/build/sub/b.o").is_none());
    }

    #[tokio::test]
    async fn a_name_already_in_the_trash_is_never_replaced() {
        // The one thing a trash must not do. The freedesktop answer is the next numbered name.
        let host = host_with_tree();
        host.files.lock().unwrap().insert(
            "/home/agent/.local/share/Trash/files/keep.txt".to_string(),
            b"an older file with the same name".to_vec(),
        );
        let ctx = ctx(host.clone()).in_workspace("/ws");

        let outcome = DeleteTool
            .call(json!({ "path": "keep.txt" }), &ctx)
            .await
            .unwrap();
        assert!(outcome.ok, "{}", outcome.content);
        assert!(
            outcome
                .content
                .contains("/home/agent/.local/share/Trash/files/keep.txt.2"),
            "{}",
            outcome.content
        );
        assert_eq!(
            host.file("/home/agent/.local/share/Trash/files/keep.txt")
                .as_deref(),
            Some("an older file with the same name"),
            "the file already in the trash is untouched"
        );
    }

    #[tokio::test]
    async fn a_missing_file_is_reported_rather_than_invented() {
        let ctx = ctx(host_with_tree()).in_workspace("/ws");
        let outcome = DeleteTool
            .call(json!({ "path": "nope" }), &ctx)
            .await
            .unwrap();
        assert!(!outcome.ok);
        assert!(
            outcome.content.contains("does not exist"),
            "{}",
            outcome.content
        );
    }

    #[tokio::test]
    async fn a_pattern_shaped_path_is_not_expanded_and_says_so() {
        // No shell, so no glob: the honest answer to `delete build*` is "no file is called that",
        // plus a sentence telling the model this tool will not expand it. Refusing outright would
        // dead-end a model whose files really are named that way.
        let host = host_with_tree();
        let ctx = ctx(host.clone()).in_workspace("/ws");
        let outcome = DeleteTool
            .call(json!({ "path": "build*" }), &ctx)
            .await
            .unwrap();

        assert!(!outcome.ok);
        assert!(
            outcome.content.contains("does not exist"),
            "{}",
            outcome.content
        );
        assert!(
            outcome.content.contains("does not expand"),
            "the model is told why: {}",
            outcome.content
        );
        assert_eq!(
            host.file("/ws/build/a.o").as_deref(),
            Some("aaaa"),
            "nothing in the real tree is touched"
        );
    }

    #[tokio::test]
    async fn a_file_whose_name_really_contains_a_star_can_still_be_deleted() {
        // The case reading the path literally exists for: the file is *called* `build*` and the model
        // means exactly that one. It is enumerable — it is listed, named in the prompt, and moved.
        let host = Arc::new(FakeHost::unix().with_file("/ws/build*", "an awkward name"));
        let ctx = ctx(host.clone()).in_workspace("/ws");

        let outcome = DeleteTool
            .call(json!({ "path": "build*" }), &ctx)
            .await
            .unwrap();
        assert!(outcome.ok, "{}", outcome.content);
        assert!(host.file("/ws/build*").is_none());
    }

    #[tokio::test]
    async fn a_host_with_no_home_directory_is_refused_rather_than_deleted_from() {
        // Without a trash, this tool is `rm` with a friendlier name — so it refuses.
        let mut host = FakeHost::unix();
        host.caps.home_dir = None;
        let ctx = ctx(Arc::new(host)).in_workspace("/ws");

        let outcome = DeleteTool
            .call(json!({ "path": "keep.txt" }), &ctx)
            .await
            .unwrap();
        assert!(!outcome.ok);
        assert!(outcome.content.contains("Refusing"), "{}", outcome.content);
    }

    #[tokio::test]
    async fn a_windows_host_is_refused_rather_than_moved_into_a_posix_path() {
        let ctx = ctx(Arc::new(FakeHost::windows())).in_workspace("C:/ws");
        let outcome = DeleteTool
            .call(json!({ "path": "keep.txt" }), &ctx)
            .await
            .unwrap();
        assert!(!outcome.ok);
        assert!(outcome.content.contains("POSIX"), "{}", outcome.content);
    }

    #[tokio::test]
    async fn a_transport_failure_does_not_claim_the_file_was_moved() {
        let ctx = ctx(Arc::new(BrokenHost::new())).in_workspace("/ws");
        let outcome = DeleteTool
            .call(json!({ "path": "keep.txt" }), &ctx)
            .await
            .unwrap();
        assert!(!outcome.ok);
        assert!(
            outcome.content.contains("connection reset"),
            "{}",
            outcome.content
        );
        assert!(
            outcome.content.contains("Nothing was deleted"),
            "{}",
            outcome.content
        );
    }

    // ---- what the prompt gets ----------------------------------------------

    #[tokio::test]
    async fn the_prompt_can_say_the_delete_comes_back() {
        // §3 asks for a plain sentence about whether it returns. For this tool the answer is yes, and
        // the sentence has to name where the file goes — otherwise "reversible" is a claim, not a fact.
        let ctx = ctx(host_with_tree()).in_workspace("/ws");
        let undo = DeleteTool
            .undo(&json!({ "path": "build", "recursive": true }), &ctx)
            .expect("a trash delete is reversible");
        assert!(undo.contains("trash"), "{undo}");
        assert!(undo.contains("moved back"), "{undo}");
    }

    #[tokio::test]
    async fn a_host_with_no_trash_offers_no_undo_sentence() {
        let mut host = FakeHost::unix();
        host.caps.home_dir = None;
        let ctx = ctx(Arc::new(host)).in_workspace("/ws");
        assert!(DeleteTool.undo(&json!({ "path": "x" }), &ctx).is_none());
    }
}

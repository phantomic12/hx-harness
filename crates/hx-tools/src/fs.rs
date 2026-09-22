//! Filesystem tools: read, write, and a patch that refuses to guess.

use crate::tool::{bound, parse_args, Requirement, Tool, ToolContext, ToolError, ToolOutcome};
use async_trait::async_trait;
use hx_core::capability::{Action, Resource};
use hx_core::error::HxError;
use serde::Deserialize;
use serde_json::{json, Value};

/// Refuse to read more than this in one go. A model that asks for a 50 MB file does not want the
/// file; it wants the part that matters, and a bounded answer tells it to be specific.
pub const MAX_READ_BYTES: usize = 512 * 1024;

#[derive(Debug, Deserialize)]
struct ReadArgs {
    path: String,
}

#[derive(Debug, Deserialize)]
struct WriteArgs {
    path: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct PatchArgs {
    path: String,
    /// The text to find. Must be unique unless `replace_all`.
    old: String,
    new: String,
    #[serde(default)]
    replace_all: bool,
}

fn fs_requirement(path: &str, action: Action, verb: &str) -> Requirement {
    Requirement::new(
        Resource::FsPath {
            path: path.to_string(),
        },
        action,
        format!("{verb} {path}"),
    )
}

/// Resolve `path` to what the host will actually open, before touching it.
///
/// WHY: the capability token is checked against the resolved string, but a symlink between the
/// check and the open would redirect the effect elsewhere. Canonicalizing here — and opening the
/// answer — makes the effect match the re-checked path even for callers that bypass the agent
/// loop (`registry.dispatch`, `hx tool`). When the host cannot resolve (a transport without
/// symlink support), the lexical path is opened unchanged: a documented residual risk, and the
/// loop's own canonical re-check already refused whatever it could see.
async fn effective_path(ctx: &ToolContext, path: &str) -> String {
    ctx.host
        .canonicalize(path)
        .await
        .unwrap_or_else(|_| path.to_string())
}

// ---------------------------------------------------------------------------------------------
// read_file
// ---------------------------------------------------------------------------------------------

/// Read a file as text.
pub struct ReadFileTool;

impl ReadFileTool {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ReadFileTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for ReadFileTool {
    fn name(&self) -> &str {
        "read_file"
    }

    fn description(&self) -> &str {
        "Read a text file from the host. Returns the file's contents; very large files are \
         truncated in the middle with a note. Binary files are refused rather than mangled."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": { "path": { "type": "string", "description": "file to read" } },
            "required": ["path"]
        })
    }

    fn requirement(
        &self,
        args: &Value,
        ctx: &ToolContext,
    ) -> Result<Option<Requirement>, ToolError> {
        let parsed: ReadArgs = parse_args(args)?;
        // Resolved before it is named, so the resource the token is asked about is the path that will
        // be opened — not the relative string the model happened to write.
        Ok(Some(fs_requirement(
            &ctx.resolve(&parsed.path),
            Action::Read,
            "read",
        )))
    }

    async fn call(&self, args: Value, ctx: &ToolContext) -> Result<ToolOutcome, ToolError> {
        let mut parsed: ReadArgs = parse_args(&args)?;
        parsed.path = effective_path(ctx, &ctx.resolve(&parsed.path)).await;

        let bytes = match ctx
            .host
            .read_file_capped(&parsed.path, MAX_READ_BYTES as u64)
            .await
        {
            Ok(bytes) => bytes,
            // A read that would exceed the bound is refused at the source (a stale default that
            // materialised first is the same refusal), rather than pulled into memory and then rejected.
            Err(HxError::TooLarge { .. }) => {
                return Ok(ToolOutcome::failed(format!(
                    "{} is over the {MAX_READ_BYTES}-byte read limit. Read the part you need \
                     with `shell` (for example `sed -n '1,200p' {}`).",
                    parsed.path, parsed.path
                )));
            }
            Err(err) => return Ok(ToolOutcome::failed(format!("{err}"))),
        };
        let byte_len = bytes.len() as u64;

        if bytes.len() > MAX_READ_BYTES {
            return Ok(ToolOutcome::failed(format!(
                "{} is {} bytes, over the {MAX_READ_BYTES}-byte read limit. Read the part you need \
                 with `shell` (for example `sed -n '1,200p' {}`).",
                parsed.path,
                bytes.len(),
                parsed.path
            )));
        }

        // Refused, not replaced: a model that receives U+FFFD where the bytes were will reason
        // about a file that does not exist.
        let Ok(text) = String::from_utf8(bytes.clone()) else {
            return Ok(ToolOutcome::failed(format!(
                "{} is not UTF-8 text ({} bytes); it looks binary. Use `shell` for it.",
                parsed.path,
                bytes.len()
            )));
        };

        let empty = text.is_empty();
        let (content, truncated) = bound(text);
        // Measured, not guessed: the loop enforces the granting byte bound on this before the
        // model sees it, which is what makes bounded reads real.
        Ok(ToolOutcome {
            content: if empty {
                format!("({} is empty)", parsed.path)
            } else {
                content
            },
            ok: true,
            truncated,
            bytes_moved: Some(byte_len),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// write_file
// ---------------------------------------------------------------------------------------------

/// Write a file, creating it if needed.
pub struct WriteFileTool;

impl WriteFileTool {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WriteFileTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for WriteFileTool {
    fn name(&self) -> &str {
        "write_file"
    }

    fn description(&self) -> &str {
        "Write a text file on the host, replacing it if it exists. Prefer `patch` for small edits \
         to an existing file: a whole-file write cannot show a reviewer what changed."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "file to write" },
                "content": { "type": "string", "description": "the file's new contents" }
            },
            "required": ["path", "content"]
        })
    }

    fn requirement(
        &self,
        args: &Value,
        ctx: &ToolContext,
    ) -> Result<Option<Requirement>, ToolError> {
        let parsed: WriteArgs = parse_args(args)?;
        // The content length is known before anything runs, so the loop can refuse an over-bound
        // write without touching the disk.
        Ok(Some(
            fs_requirement(&ctx.resolve(&parsed.path), Action::Write, "write")
                .bytes(parsed.content.len() as u64),
        ))
    }

    async fn call(&self, args: Value, ctx: &ToolContext) -> Result<ToolOutcome, ToolError> {
        let mut parsed: WriteArgs = parse_args(&args)?;
        parsed.path = effective_path(ctx, &ctx.resolve(&parsed.path)).await;
        let byte_len = parsed.content.len() as u64;

        match ctx
            .host
            .write_file(&parsed.path, parsed.content.as_bytes())
            .await
        {
            Ok(()) => Ok(ToolOutcome::ok(format!(
                "wrote {} bytes to {}",
                parsed.content.len(),
                parsed.path
            ))
            .bytes_moved(byte_len)),
            Err(err) => Ok(ToolOutcome::failed(format!("could not write: {err}"))),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// patch
// ---------------------------------------------------------------------------------------------

/// Replace an exact snippet in a file.
pub struct PatchTool;

impl PatchTool {
    pub fn new() -> Self {
        Self
    }
}

/// What a patch would do to a file, decided without touching the filesystem.
#[derive(Debug, PartialEq, Eq)]
pub enum PatchPlan {
    /// One occurrence: unambiguous, go ahead.
    Apply { replaced: usize },
    /// The anchor is not in the file. Usually the model is working from a stale read.
    NotFound,
    /// More than one occurrence. Replacing either one is a coin flip, so neither is replaced.
    Ambiguous { occurrences: usize },
}

/// Decide what a patch means before applying it.
///
/// Pure, and the reason `patch` is safe to give an agent: a snippet that appears twice is a guess,
/// and a guess written to a file is a bug that looks like a model error.
pub fn plan_patch(contents: &str, old: &str, replace_all: bool) -> PatchPlan {
    if old.is_empty() {
        return PatchPlan::NotFound;
    }
    let occurrences = contents.matches(old).count();
    match (occurrences, replace_all) {
        (0, _) => PatchPlan::NotFound,
        (1, _) => PatchPlan::Apply { replaced: 1 },
        (n, true) => PatchPlan::Apply { replaced: n },
        (n, false) => PatchPlan::Ambiguous { occurrences: n },
    }
}

impl Default for PatchTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for PatchTool {
    fn name(&self) -> &str {
        "patch"
    }

    fn description(&self) -> &str {
        "Replace an exact snippet in a file with another. `old` must appear exactly once unless \
         `replace_all` is set — if it is ambiguous nothing is written and you are told how many \
         matches there are, so add surrounding context and retry."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string" },
                "old": { "type": "string", "description": "the exact text to replace" },
                "new": { "type": "string", "description": "what to replace it with" },
                "replace_all": { "type": "boolean", "description": "replace every occurrence" }
            },
            "required": ["path", "old", "new"]
        })
    }

    fn requirement(
        &self,
        args: &Value,
        ctx: &ToolContext,
    ) -> Result<Option<Requirement>, ToolError> {
        let parsed: PatchArgs = parse_args(args)?;
        // No byte count here on purpose: the patched size depends on the file's current contents,
        // which the requirement cannot see. The outcome reports the written size instead, and the
        // loop enforces the bound on that.
        Ok(Some(fs_requirement(
            &ctx.resolve(&parsed.path),
            Action::Write,
            "patch",
        )))
    }

    async fn call(&self, args: Value, ctx: &ToolContext) -> Result<ToolOutcome, ToolError> {
        let mut parsed: PatchArgs = parse_args(&args)?;
        parsed.path = effective_path(ctx, &ctx.resolve(&parsed.path)).await;
        if parsed.old.is_empty() {
            return Ok(ToolOutcome::failed(
                "`old` is empty: a patch with nothing to find would either do nothing or match \
                 everywhere",
            ));
        }

        let bytes = match ctx.host.read_file(&parsed.path).await {
            Ok(bytes) => bytes,
            Err(err) => return Ok(ToolOutcome::failed(format!("{err}"))),
        };
        let Ok(contents) = String::from_utf8(bytes) else {
            return Ok(ToolOutcome::failed(format!(
                "{} is not UTF-8 text; patch works on text files",
                parsed.path
            )));
        };

        match plan_patch(&contents, &parsed.old, parsed.replace_all) {
            PatchPlan::NotFound => Ok(ToolOutcome::failed(format!(
                "`old` was not found in {}. The file may have changed since you read it — read it \
                 again and copy the snippet exactly.",
                parsed.path
            ))),
            PatchPlan::Ambiguous { occurrences } => Ok(ToolOutcome::failed(format!(
                "`old` appears {occurrences} times in {}. Nothing was written: include more \
                 surrounding context to identify one of them, or set `replace_all` if you really \
                 mean all {occurrences}.",
                parsed.path
            ))),
            PatchPlan::Apply { replaced } => {
                let updated = if parsed.replace_all {
                    contents.replace(&parsed.old, &parsed.new)
                } else {
                    contents.replacen(&parsed.old, &parsed.new, 1)
                };
                let byte_len = updated.len() as u64;
                match ctx.host.write_file(&parsed.path, updated.as_bytes()).await {
                    Ok(()) => Ok(ToolOutcome::ok(format!(
                        "patched {replaced} occurrence(s) in {}",
                        parsed.path
                    ))
                    .bytes_moved(byte_len)),
                    Err(err) => Ok(ToolOutcome::failed(format!("could not write: {err}"))),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{BrokenHost, FakeHost};
    use crate::tool::resolve_path;
    use std::sync::Arc;

    fn ctx(host: Arc<dyn hx_remote::Host>) -> ToolContext {
        ToolContext::new(host)
    }

    // ---- read_file ---------------------------------------------------------------------------

    #[tokio::test]
    async fn reading_a_file_returns_its_text() {
        let host = Arc::new(FakeHost::unix().with_file("/tmp/a.txt", "hello\nworld\n"));
        let outcome = ReadFileTool
            .call(json!({"path": "/tmp/a.txt"}), &ctx(host))
            .await
            .unwrap();
        assert!(outcome.ok);
        assert_eq!(outcome.content, "hello\nworld\n");
    }

    #[test]
    fn resolve_path_leaves_absolute_paths_alone() {
        assert_eq!(resolve_path("/etc/hosts", Some("/ws")), "/etc/hosts");
        // Windows, because this daemon drives Windows hosts too: `Path::is_absolute` on Linux says a
        // drive letter is relative, and joining it onto a Linux workspace produces nonsense.
        assert_eq!(
            resolve_path("C:\\Users\\yoav\\a.txt", Some("/ws")),
            "C:\\Users\\yoav\\a.txt"
        );
        assert_eq!(resolve_path("d:/x", Some("/ws")), "d:/x");
    }

    #[test]
    fn resolve_path_joins_relative_paths_onto_the_workspace() {
        assert_eq!(resolve_path("Cargo.toml", Some("/ws")), "/ws/Cargo.toml");
        assert_eq!(resolve_path("crates/x.rs", Some("/ws/")), "/ws/crates/x.rs");
        // A parent component survives on purpose: the capability token refuses any path containing
        // `..` before it looks at a grant, and collapsing it here would hide exactly the shape of
        // path that cannot be safely evaluated for containment.
        assert_eq!(
            resolve_path("../../etc/shadow", Some("/ws")),
            "/ws/../../etc/shadow"
        );
    }

    #[test]
    fn resolve_path_without_a_workspace_changes_nothing() {
        // The host resolves it against its own directory and the token refuses it for not being
        // absolute. Failing closed beats guessing at a directory the run never named.
        assert_eq!(resolve_path("Cargo.toml", None), "Cargo.toml");
        assert_eq!(resolve_path("Cargo.toml", Some("   ")), "Cargo.toml");
    }

    #[tokio::test]
    async fn a_relative_path_is_read_against_the_workspace_and_checked_as_the_absolute_one() {
        // The bug this pins, found by pointing a real model at the harness: a model asked to read
        // "Cargo.toml in this workspace" writes `Cargo.toml`, the token holds an absolute workspace
        // path, and every call was denied. The requirement and the read must agree on one path.
        let host = Arc::new(FakeHost::unix().with_file("/ws/Cargo.toml", "[package]\n"));
        let ctx = ctx(host).in_workspace("/ws");

        let requirement = ReadFileTool
            .requirement(&json!({"path": "Cargo.toml"}), &ctx)
            .unwrap()
            .expect("reading a file has an external effect");

        match requirement.resource {
            hx_core::capability::Resource::FsPath { path } => assert_eq!(path, "/ws/Cargo.toml"),
            other => panic!("expected a path resource, got {other:?}"),
        }

        let outcome = ReadFileTool
            .call(json!({"path": "Cargo.toml"}), &ctx)
            .await
            .unwrap();
        assert!(outcome.ok, "{outcome:?}");
        assert!(outcome.content.contains("[package]"), "{outcome:?}");
    }

    #[tokio::test]
    async fn the_workspace_is_the_requirement_even_when_the_path_climbs_out() {
        // `..` is not collapsed, so the token's traversal rule still sees it and denies.
        let ctx = ctx(Arc::new(FakeHost::unix())).in_workspace("/ws");
        let requirement = ReadFileTool
            .requirement(&json!({"path": "../../etc/shadow"}), &ctx)
            .unwrap()
            .expect("reading a file has an external effect");

        match requirement.resource {
            hx_core::capability::Resource::FsPath { path } => {
                assert_eq!(path, "/ws/../../etc/shadow");
                assert!(!path_contains_escape_was_collapsed(&path));
            }
            other => panic!("expected a path resource, got {other:?}"),
        }
    }

    /// The traversal rule is in `hx-core`; this test only asserts the path still *contains* what the
    /// rule looks for, so the join cannot quietly launder an escape.
    fn path_contains_escape_was_collapsed(path: &str) -> bool {
        !path.split('/').any(|segment| segment == "..")
    }

    #[tokio::test]
    async fn reading_requires_a_read_grant_on_that_path() {
        let requirement = ReadFileTool
            .requirement(
                &json!({"path": "/etc/shadow"}),
                &ctx(Arc::new(FakeHost::unix())),
            )
            .unwrap()
            .expect("reading a file has an external effect");
        assert_eq!(requirement.action, Action::Read);
        match requirement.resource {
            Resource::FsPath { path } => assert_eq!(path, "/etc/shadow"),
            other => panic!("expected a path grant, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_binary_file_is_refused_rather_than_mangled() {
        // U+FFFD in place of the real bytes would have the model reason about a file that is not
        // there.
        let host = Arc::new(FakeHost::unix());
        host.files
            .lock()
            .unwrap()
            .insert("/tmp/bin".to_string(), vec![0xff, 0xfe, 0x00, 0x01]);

        let outcome = ReadFileTool
            .call(json!({"path": "/tmp/bin"}), &ctx(host))
            .await
            .unwrap();
        assert!(!outcome.ok);
        assert!(outcome.content.contains("not UTF-8"), "{}", outcome.content);
        assert!(outcome.content.contains("binary"));
    }

    #[tokio::test]
    async fn a_file_over_the_read_limit_is_refused_with_a_better_instruction() {
        let host = Arc::new(FakeHost::unix());
        host.files
            .lock()
            .unwrap()
            .insert("/tmp/big".to_string(), vec![b'x'; MAX_READ_BYTES + 1]);

        let outcome = ReadFileTool
            .call(json!({"path": "/tmp/big"}), &ctx(host))
            .await
            .unwrap();
        assert!(!outcome.ok);
        assert!(outcome.content.contains("over the"), "{}", outcome.content);
        assert!(
            outcome.content.contains("sed -n"),
            "the model should be told what to do instead: {}",
            outcome.content
        );
    }

    #[tokio::test]
    async fn an_empty_file_says_it_is_empty() {
        let host = Arc::new(FakeHost::unix().with_file("/tmp/empty", ""));
        let outcome = ReadFileTool
            .call(json!({"path": "/tmp/empty"}), &ctx(host))
            .await
            .unwrap();
        assert_eq!(outcome.content, "(/tmp/empty is empty)");
    }

    #[tokio::test]
    async fn a_missing_file_is_reported_not_invented() {
        let outcome = ReadFileTool
            .call(
                json!({"path": "/tmp/nope"}),
                &ctx(Arc::new(FakeHost::unix())),
            )
            .await
            .unwrap();
        assert!(!outcome.ok);
        assert!(outcome.content.contains("no such file"));
    }

    // ---- write_file --------------------------------------------------------------------------

    #[tokio::test]
    async fn writing_reports_how_much_landed() {
        let host = Arc::new(FakeHost::unix());
        let outcome = WriteFileTool
            .call(
                json!({"path": "/tmp/new.txt", "content": "abc"}),
                &ctx(host.clone()),
            )
            .await
            .unwrap();

        assert!(outcome.ok);
        assert!(outcome.content.contains("3 bytes"));
        assert_eq!(host.file("/tmp/new.txt").as_deref(), Some("abc"));
    }

    #[tokio::test]
    async fn writing_requires_a_write_grant() {
        let requirement = WriteFileTool
            .requirement(
                &json!({"path": "/etc/hosts", "content": "x"}),
                &ctx(Arc::new(FakeHost::unix())),
            )
            .unwrap()
            .expect("writing a file has an external effect");
        assert_eq!(requirement.action, Action::Write);
    }

    #[test]
    fn a_write_requirement_states_its_byte_count_up_front() {
        // The loop refuses an over-bound write before it runs; the count has to be here, not
        // discovered after the bytes landed.
        let requirement = WriteFileTool
            .requirement(
                &json!({"path": "/ws/x.txt", "content": "abc"}),
                &ctx(Arc::new(FakeHost::unix())),
            )
            .unwrap()
            .expect("writing a file has an external effect");
        assert_eq!(requirement.bytes, Some(3));
    }

    #[test]
    fn a_read_requirement_states_no_byte_count_it_cannot_know() {
        // The size is what the read discovers. Stating a guess would be worse than stating
        // nothing: the loop enforces the bound on the outcome's measured bytes instead.
        let requirement = ReadFileTool
            .requirement(
                &json!({"path": "/ws/x.txt"}),
                &ctx(Arc::new(FakeHost::unix())),
            )
            .unwrap()
            .expect("reading a file has an external effect");
        assert_eq!(requirement.bytes, None);
    }

    #[tokio::test]
    async fn a_read_reports_its_measured_bytes_for_the_post_run_check() {
        let host = Arc::new(FakeHost::unix().with_file("/ws/x.txt", "hello"));
        let outcome = ReadFileTool
            .call(json!({"path": "/ws/x.txt"}), &ctx(host))
            .await
            .unwrap();
        assert!(outcome.ok);
        assert_eq!(outcome.bytes_moved, Some(5));
    }

    #[tokio::test]
    async fn a_read_through_a_symlink_opens_the_target_not_the_name() {
        // The tool opens what the host resolves — the agent's canonical re-check (which refuses
        // this path under a `/ws` grant) is then deciding about the file actually read.
        let host = Arc::new(
            FakeHost::unix()
                .with_file("/etc/secret", "classified")
                .with_symlink("/ws/link", "/etc"),
        );
        let outcome = ReadFileTool
            .call(json!({"path": "/ws/link/secret"}), &ctx(host))
            .await
            .unwrap();
        assert!(outcome.ok, "{outcome:?}");
        assert_eq!(outcome.content, "classified");

        // And the re-check the loop runs on the resolved path refuses it under a `/ws` grant:
        // lexically covered, physically outside.
        assert!(hx_core::capability::path_grant_covers(
            "/ws",
            "/ws/link/secret"
        ));
        let canonical = "/etc/secret";
        assert!(!hx_core::capability::path_grant_covers_canonical(
            "/ws",
            std::path::Path::new(canonical)
        ));
    }

    #[tokio::test]
    async fn a_write_through_a_symlink_lands_at_the_target() {
        let host = Arc::new(FakeHost::unix().with_symlink("/ws/link", "/etc"));
        let outcome = WriteFileTool
            .call(
                json!({"path": "/ws/link/marker", "content": "x"}),
                &ctx(host.clone()),
            )
            .await
            .unwrap();
        assert!(outcome.ok, "{outcome:?}");
        assert_eq!(host.file("/etc/marker").as_deref(), Some("x"));
        assert_eq!(outcome.bytes_moved, Some(1));
    }

    // ---- patch -------------------------------------------------------------------------------

    #[test]
    fn a_unique_snippet_is_applied() {
        assert_eq!(
            plan_patch("one two three", "two", false),
            PatchPlan::Apply { replaced: 1 }
        );
    }

    #[test]
    fn a_missing_snippet_is_not_found() {
        assert_eq!(plan_patch("one two", "four", false), PatchPlan::NotFound);
    }

    #[test]
    fn an_ambiguous_snippet_is_refused_rather_than_guessed() {
        // The property that makes this safe for an agent to hold: no coin flips.
        assert_eq!(
            plan_patch("x x x", "x", false),
            PatchPlan::Ambiguous { occurrences: 3 }
        );
    }

    #[test]
    fn replace_all_is_opt_in() {
        assert_eq!(
            plan_patch("x x x", "x", true),
            PatchPlan::Apply { replaced: 3 }
        );
    }

    #[test]
    fn an_empty_anchor_matches_nothing() {
        assert_eq!(plan_patch("anything", "", false), PatchPlan::NotFound);
    }

    #[tokio::test]
    async fn patching_writes_the_change_and_counts_it() {
        let host = Arc::new(FakeHost::unix().with_file("/tmp/code.rs", "fn a() {}\nfn b() {}\n"));
        let outcome = PatchTool
            .call(
                json!({"path": "/tmp/code.rs", "old": "fn a() {}", "new": "fn a() { todo!() }"}),
                &ctx(host.clone()),
            )
            .await
            .unwrap();

        assert!(outcome.ok, "{}", outcome.content);
        assert!(outcome.content.contains("1 occurrence"));
        assert_eq!(
            host.file("/tmp/code.rs").as_deref(),
            Some("fn a() { todo!() }\nfn b() {}\n")
        );
    }

    #[tokio::test]
    async fn an_ambiguous_patch_changes_nothing_and_says_how_to_fix_it() {
        let original = "let x = 1;\nlet x = 2;\n";
        let host = Arc::new(FakeHost::unix().with_file("/tmp/code.rs", original));

        let outcome = PatchTool
            .call(
                json!({"path": "/tmp/code.rs", "old": "let x =", "new": "let y ="}),
                &ctx(host.clone()),
            )
            .await
            .unwrap();

        assert!(!outcome.ok);
        assert!(
            outcome.content.contains("appears 2 times"),
            "{}",
            outcome.content
        );
        assert!(
            host.file("/tmp/code.rs").as_deref() == Some(original),
            "nothing may be written when the anchor is ambiguous"
        );
    }

    #[tokio::test]
    async fn a_stale_anchor_tells_the_model_to_read_again() {
        let host = Arc::new(FakeHost::unix().with_file("/tmp/code.rs", "fn a() {}\n"));
        let outcome = PatchTool
            .call(
                json!({"path": "/tmp/code.rs", "old": "fn gone() {}", "new": "x"}),
                &ctx(host),
            )
            .await
            .unwrap();
        assert!(!outcome.ok);
        assert!(
            outcome.content.contains("read it again"),
            "{}",
            outcome.content
        );
    }

    #[tokio::test]
    async fn a_transport_failure_does_not_pretend_to_have_patched() {
        let outcome = PatchTool
            .call(
                json!({"path": "/tmp/x", "old": "a", "new": "b"}),
                &ctx(Arc::new(BrokenHost::new())),
            )
            .await
            .unwrap();
        assert!(!outcome.ok);
        assert!(
            outcome.content.contains("connection reset"),
            "{}",
            outcome.content
        );
    }
}

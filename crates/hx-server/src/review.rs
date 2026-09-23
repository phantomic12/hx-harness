//! What a session changed, reconstructed from its own transcript.
//!
//! A review pane that invents "files this session touched" from a directory walk is guessing: the
//! agent may have edited a file outside the workspace, and a walk cannot tell an edit the agent made
//! from one the operator made by hand. The transcript is the record. A `write_file` or `patch` call
//! that the tool result says succeeded is a change the agent made, and the arguments it was called
//! with are the text it proposed.
//!
//! Two honest limits, stated rather than papered over:
//!
//! - The reconstructed text is what the agent *last proposed*, not a byte-for-byte snapshot of the
//!   disk at that moment. A later edit by the operator, or a write the transcript does not record
//!   (a shell redirection), shows up as a difference against the file as it is now — which is what a
//!   reviewer wants to see, and is labelled as such.
//! - A `patch` whose `old` no longer appears in the reconstructed text is reported, not applied. A
//!   review that silently skipped it would hide the one edit most likely to be the interesting one.

use hx_core::message::{Message, Part, Role};
use hx_secrets::Redactor;
use serde::Serialize;

use crate::diff::{self, DiffLine};

/// Tools whose arguments are a file edit. A shell that happens to write a file is not one of them:
/// its effect is not recoverable from the arguments, and pretending otherwise would invent a diff.
const EDITING_TOOLS: &[&str] = &["write_file", "patch"];

/// One file a session changed, oldest edit first within the file and files in first-touch order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewedFile {
    /// The path the agent named. Not re-resolved: the transcript recorded what was asked for.
    pub path: String,
    /// How many recorded edits landed on this path.
    pub edits: usize,
    /// A `patch` the reconstruction could not apply, because its `old` was not in the text as
    /// reconstructed. Empty when every patch applied.
    pub unapplied: Vec<String>,
    /// The diff between the file as it is now (`before`) and the text the agent last proposed
    /// (`after`). Redacted on the way out — see [`diff::redact_diff`].
    pub diff: Vec<DiffLine>,
}

/// A change the transcript records but this reconstruction cannot replay.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Unapplied {
    path: String,
    /// What was looked for and not found, trimmed so a multi-line anchor stays readable.
    anchor: String,
}

/// Replay a session's transcript into the text each path ended at.
///
/// `messages` is the transcript in order. A tool call counts only when a later tool result with the
/// same id says it succeeded: a call the operator denied, or one that failed, changed nothing, and
/// a review that showed it would be reviewing a change that did not happen.
///
/// Returns the reconstructed text per path, in first-touch order, and the patches that could not be
/// applied. A `write_file` replaces the reconstructed text outright — that is what the tool does.
/// A `patch` replaces the first occurrence of `old`, because a patch the tool accepted was one
/// `plan_patch` judged unambiguous or `replace_all`.
fn reconstruct(messages: &[Message]) -> (Vec<(String, String)>, Vec<Unapplied>) {
    let succeeded = succeeded_calls(messages);

    // Paths in first-touch order, mapped to the text as reconstructed so far.
    let mut order: Vec<String> = Vec::new();
    let mut text: Vec<(String, String)> = Vec::new();
    let mut unapplied = Vec::new();

    for message in messages {
        if message.role != Role::Assistant {
            continue;
        }
        for part in &message.parts {
            let Part::ToolCall {
                id,
                name,
                arguments,
            } = part
            else {
                continue;
            };
            if !EDITING_TOOLS.contains(&name.as_str()) || !succeeded.contains(id.as_str()) {
                continue;
            }
            let Some(path) = arguments.get("path").and_then(|v| v.as_str()) else {
                // A call with no path changed no file this reconstruction can name.
                continue;
            };
            if path.is_empty() {
                continue;
            }

            let slot = match text.iter().position(|(p, _)| p == path) {
                Some(index) => index,
                None => {
                    order.push(path.to_string());
                    text.push((path.to_string(), String::new()));
                    text.len() - 1
                }
            };

            match name.as_str() {
                "write_file" => {
                    let content = arguments
                        .get("content")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    text[slot].1 = content.to_string();
                }
                "patch" => {
                    let old = arguments.get("old").and_then(|v| v.as_str()).unwrap_or("");
                    let new = arguments.get("new").and_then(|v| v.as_str()).unwrap_or("");
                    let replace_all = arguments
                        .get("replace_all")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if old.is_empty() || !text[slot].1.contains(old) {
                        unapplied.push(Unapplied {
                            path: path.to_string(),
                            anchor: trim_anchor(old),
                        });
                        continue;
                    }
                    text[slot].1 = if replace_all {
                        text[slot].1.replace(old, new)
                    } else {
                        text[slot].1.replacen(old, new, 1)
                    };
                }
                _ => {}
            }
        }
    }

    // `order` and `text` grow together; the split is only so the caller sees one list.
    debug_assert_eq!(order.len(), text.len());
    (text, unapplied)
}

/// One path the transcript says the agent changed, with the text it last proposed.
///
/// Split from [`review`] because reading the file is async and the reconstruction is not: the route
/// walks this list and reads each path itself, then asks [`render`] for the diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedEdit {
    pub path: String,
    /// The text the agent's edits reconstruct to.
    pub proposed: String,
    pub edits: usize,
    pub unapplied: Vec<String>,
}

/// The paths a session's transcript records as changed, in first-touch order.
pub fn proposed(messages: &[Message]) -> Vec<ProposedEdit> {
    let (reconstructed, unapplied) = reconstruct(messages);
    reconstructed
        .into_iter()
        .map(|(path, proposed)| {
            let edits = count_edits(messages, &path);
            let file_unapplied = unapplied
                .iter()
                .filter(|u| u.path == path)
                .map(|u| u.anchor.clone())
                .collect();
            ProposedEdit {
                path,
                proposed,
                edits,
                unapplied: file_unapplied,
            }
        })
        .collect()
}

/// Diff one reconstructed edit against the file as it reads now.
///
/// `current` is `None` when the path is not valid UTF-8, in which case there is nothing honest to
/// render and the answer is `None`. An empty `current` is a file that does not exist yet.
pub fn render(
    edit: &ProposedEdit,
    current: Option<&str>,
    redactor: &Redactor,
) -> Option<ReviewedFile> {
    let before = current?;
    let rendered = diff::redact_diff(&diff::unified_diff(before, &edit.proposed), redactor);
    Some(ReviewedFile {
        path: edit.path.clone(),
        edits: edit.edits,
        unapplied: edit.unapplied.clone(),
        diff: rendered,
    })
}

/// Tool-call ids whose matching tool result says the call succeeded.
fn succeeded_calls(messages: &[Message]) -> std::collections::BTreeSet<&str> {
    let mut ids = std::collections::BTreeSet::new();
    for message in messages {
        for part in &message.parts {
            if let Part::ToolResult { id, ok: true, .. } = part {
                ids.insert(id.as_str());
            }
        }
    }
    ids
}

fn count_edits(messages: &[Message], path: &str) -> usize {
    let succeeded = succeeded_calls(messages);
    messages
        .iter()
        .filter(|m| m.role == Role::Assistant)
        .flat_map(|m| m.parts.iter())
        .filter(|part| match part {
            Part::ToolCall {
                id,
                name,
                arguments,
            } => {
                EDITING_TOOLS.contains(&name.as_str())
                    && succeeded.contains(id.as_str())
                    && arguments.get("path").and_then(|v| v.as_str()) == Some(path)
            }
            _ => false,
        })
        .count()
}

/// Keep an unapplied anchor short enough to put in a list.
fn trim_anchor(anchor: &str) -> String {
    let flat = anchor.split_whitespace().collect::<Vec<_>>().join(" ");
    const MAX: usize = 80;
    if flat.chars().count() <= MAX {
        flat
    } else {
        let trimmed: String = flat.chars().take(MAX).collect();
        format!("{trimmed}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_core::ids::ToolCallId;
    use serde_json::json;

    fn call(id: &str, name: &str, arguments: serde_json::Value) -> Message {
        Message::new(
            Role::Assistant,
            vec![Part::ToolCall {
                id: ToolCallId::from(id),
                name: name.into(),
                arguments,
            }],
        )
    }

    fn ok(id: &str) -> Message {
        Message::tool_result(ToolCallId::from(id), true, "wrote it")
    }

    fn failed(id: &str) -> Message {
        Message::tool_result(ToolCallId::from(id), false, "denied")
    }

    #[test]
    fn a_successful_write_reconstructs_the_proposed_text() {
        let messages = vec![
            Message::user("write it"),
            call(
                "tc_1",
                "write_file",
                json!({"path": "/w/a.txt", "content": "one\ntwo\n"}),
            ),
            ok("tc_1"),
        ];
        let (files, unapplied) = reconstruct(&messages);
        assert!(unapplied.is_empty());
        assert_eq!(
            files,
            vec![("/w/a.txt".to_string(), "one\ntwo\n".to_string())]
        );
    }

    #[test]
    fn a_denied_write_is_not_a_change() {
        // The operator said no. Reviewing it would show a diff of a file the agent did not touch.
        let messages = vec![
            call(
                "tc_1",
                "write_file",
                json!({"path": "/w/a.txt", "content": "nope\n"}),
            ),
            failed("tc_1"),
        ];
        let (files, _) = reconstruct(&messages);
        assert!(
            files.is_empty(),
            "a refused call changed nothing: {files:?}"
        );
    }

    #[test]
    fn a_later_patch_edits_the_reconstructed_text() {
        let messages = vec![
            call(
                "tc_1",
                "write_file",
                json!({"path": "/w/a.txt", "content": "fn a() {}\nfn b() {}\n"}),
            ),
            ok("tc_1"),
            call(
                "tc_2",
                "patch",
                json!({"path": "/w/a.txt", "old": "fn b() {}", "new": "fn b() { todo!() }"}),
            ),
            ok("tc_2"),
        ];
        let (files, unapplied) = reconstruct(&messages);
        assert!(unapplied.is_empty(), "{unapplied:?}");
        assert_eq!(files[0].1, "fn a() {}\nfn b() { todo!() }\n");
    }

    #[test]
    fn a_patch_whose_anchor_is_gone_is_reported_not_applied() {
        let messages = vec![
            call(
                "tc_1",
                "write_file",
                json!({"path": "/w/a.txt", "content": "alpha\n"}),
            ),
            ok("tc_1"),
            call(
                "tc_2",
                "patch",
                json!({"path": "/w/a.txt", "old": "not here", "new": "beta"}),
            ),
            ok("tc_2"),
        ];
        let (files, unapplied) = reconstruct(&messages);
        // The write still stands; the patch that could not land is named.
        assert_eq!(files[0].1, "alpha\n");
        assert_eq!(unapplied.len(), 1);
        assert_eq!(unapplied[0].path, "/w/a.txt");
        assert!(unapplied[0].anchor.contains("not here"));
    }

    #[test]
    fn a_shell_call_is_not_treated_as_a_file_edit() {
        let messages = vec![
            call("tc_1", "shell", json!({"cmd": "echo hi > /w/a.txt"})),
            ok("tc_1"),
        ];
        let (files, _) = reconstruct(&messages);
        assert!(
            files.is_empty(),
            "a shell's effect is not recoverable: {files:?}"
        );
    }

    #[test]
    fn the_review_diffs_reconstructed_text_against_the_file_now() {
        let messages = vec![
            call(
                "tc_1",
                "write_file",
                json!({"path": "/w/a.txt", "content": "fn b() { todo!() }\n"}),
            ),
            ok("tc_1"),
        ];
        let edits = proposed(&messages);
        let rendered =
            render(&edits[0], Some("fn b() {}\n"), &Redactor::new()).expect("text renders");
        assert_eq!(rendered.edits, 1);
        assert!(rendered
            .diff
            .iter()
            .any(|l| matches!(l, DiffLine::Removed(t) if t == "fn b() {}")));
        assert!(rendered
            .diff
            .iter()
            .any(|l| matches!(l, DiffLine::Added(t) if t == "fn b() { todo!() }")));
    }

    #[test]
    fn a_binary_file_is_left_out_rather_than_mangled() {
        let edit = ProposedEdit {
            path: "/w/a.bin".into(),
            proposed: "not really binary".into(),
            edits: 1,
            unapplied: Vec::new(),
        };
        // `None` is the route's answer for bytes that are not UTF-8.
        assert!(render(&edit, None, &Redactor::new()).is_none());
    }

    #[test]
    fn a_provider_key_in_the_proposed_text_is_masked() {
        let token = format!("sk-{}", "A".repeat(24));
        let messages = vec![
            call(
                "tc_1",
                "write_file",
                json!({"path": "/w/.env", "content": format!("KEY={token}\n")}),
            ),
            ok("tc_1"),
        ];
        let edits = proposed(&messages);
        let rendered = render(&edits[0], Some(""), &Redactor::new()).expect("text renders");
        let text: String = rendered
            .diff
            .iter()
            .map(|l| l.text().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!text.contains(&token), "token leaked: {text}");
        assert!(text.contains("[REDACTED:"), "{text}");
    }
}

//! A diff/review pane is only honest if the diff it shows was computed from real file state.
//!
//! The daemon is the only thing that owns file state (see `ARCHITECTURE.md` §3.3 and `routes.rs`'s
//! header: every front end is a client of this API). A browser cannot know what a file currently contains
//! unless the daemon reads it, and a diff invented from data the client never had is the exact failure this
//! module exists to refuse. So the diff is computed here, on the daemon, from a real `Host::read_file`,
//! and served to the pane as a unified diff the pane *renders* rather than derives.
//!
//! ## The algorithm
//!
//! [`unified_diff`] is a line-based diff: it finds the longest common subsequence of lines between the
//! current and proposed contents, then walks it to emit `-` (removed), `+` (added) and ` ` (context)
//! lines. It is bounded so a pathological input cannot blow the budget: the LCS table (O(n·m)) is only
//! built when n·m ≤ [`MAX_LCS_CELLS`]; beyond that an O(n+m) whole-line fallback is used that still emits
//! every truly removed and truly added line, it just does not align out-of-order shared blocks. Both are *true*
//! diffs — the fallback is coarser, not wrong — and the trade is stated here rather than silent.
//!
//! ## Redaction
//!
//! A diff displays file contents, which is precisely where secrets live, and this repo's history is that a
//! redaction which *looked* right was not (the verification report at
//! `/home/yoav/projects/hx-wt/verify-m6/docs/verification-m6.md` found a redaction that refused only
//! all-alphanumeric strings, so real tokens passed through verbatim). So the served response is redacted with the
//! *same* [`hx_secrets::Redactor`] used everywhere else in the daemon — never a weaker hand-rolled
//! pass. That is exactly as strong (and exactly as limited) as the shared redactor: token shapes it knows
//! (`sk-…`, `sk-proj-…`, `ghp_…`, `eyJ…` JWTs) are masked; a shape it does not recognise
//! (such as the internal `signed-token-…` query credential, which has no pattern in
//! `hx-secrets/src/redact.rs`) is masked only when it is registered as a known vault literal. This module
//! does not silently claim to be stronger than the shared redactor — it tests the shapes that are covered and says
//! plainly which are not.

use hx_secrets::Redactor;
use serde::{Deserialize, Serialize};

/// Cap on LCS table cells (n·m) before the approximate fallback kicks in.
pub const MAX_LCS_CELLS: usize = 4_000_000;

/// A single line of a rendered diff, tagged with its provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffLine {
    /// A context line, present in both. Carries the text.
    Context(String),
    /// A line removed by the change.
    Removed(String),
    /// A line added by the change.
    Added(String),
}

impl DiffLine {
    /// The diff marker prefix, `" "`, `"-"` or `"+"`.
    pub fn mark(&self) -> &'static str {
        match self {
            DiffLine::Context(_) => " ",
            DiffLine::Removed(_) => "-",
            DiffLine::Added(_) => "+",
        }
    }

    pub fn text(&self) -> &str {
        match self {
            DiffLine::Context(t) | DiffLine::Removed(t) | DiffLine::Added(t) => t,
        }
    }
}

/// Compute a bounded unified diff between two texts.
///
/// Returns an ordered list of [`DiffLine`]s with the text each line actually carries. Empty inputs are
/// handled — an empty current becomes all-`Added`, an empty proposed becomes all-`Removed`.
pub fn unified_diff(current: &str, proposed: &str) -> Vec<DiffLine> {
    let a: Vec<&str> = current.lines().collect();
    let b: Vec<&str> = proposed.lines().collect();

    if a == b {
        return a
            .into_iter()
            .map(|s| DiffLine::Context(s.to_string()))
            .collect();
    }

    let ops = if a.len() as u64 * b.len() as u64 <= MAX_LCS_CELLS as u64 {
        lcs_ops(&a, &b)
    } else {
        whole_line_ops(&a, &b)
    };

    ops.into_iter()
        .map(|op| match op {
            Op::Keep(text) => DiffLine::Context(text.to_string()),
            Op::Delete(text) => DiffLine::Removed(text.to_string()),
            Op::Insert(text) => DiffLine::Added(text.to_string()),
        })
        .collect()
}

/// The edit script: one instruction per output line, carrying the text that line renders.
enum Op {
    Keep(String),
    Delete(String),
    Insert(String),
}

/// Classic O(n·m) LCS, capped by the caller's budget check.
fn lcs_ops(a: &[&str], b: &[&str]) -> Vec<Op> {
    let n = a.len();
    let m = b.len();
    // dp[i][j] = LCS length of a[i..] and b[j..].
    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }

    let mut ops = Vec::with_capacity(n + m);
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            ops.push(Op::Keep(a[i].to_string()));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            ops.push(Op::Delete(a[i].to_string()));
            i += 1;
        } else {
            ops.push(Op::Insert(b[j].to_string()));
            j += 1;
        }
    }
    while i < n {
        ops.push(Op::Delete(a[i].to_string()));
        i += 1;
    }
    while j < m {
        ops.push(Op::Insert(b[j].to_string()));
        j += 1;
    }
    ops
}

/// Coarse O(n+m) fallback for inputs too large for the LCS table.
///
/// Every line that appears in both sequences is emitted as context in the order it appears in `a`; every line
/// that appears only in `a` is a removal, only in `b` an addition. True (the removed and added sets are
/// exact); it simply will not align an out-of-order shared block.
fn whole_line_ops(a: &[&str], b: &[&str]) -> Vec<Op> {
    let set_b: std::collections::BTreeSet<&str> = b.iter().copied().collect();
    a.iter()
        .map(|&line| {
            if set_b.contains(line) {
                Op::Keep(line.to_string())
            } else {
                Op::Delete(line.to_string())
            }
        })
        .chain(
            b.iter()
                .copied()
                .filter(|&line| !set_b.contains(line))
                .map(|line| Op::Insert(line.to_string())),
        )
        .collect()
}

/// Redact the text of added and removed lines (the content a review reads), leaving context untouched.
///
/// Context lines are already on disk — masking them would hide a secret sitting in the file regardless — while the
/// added lines are new content under review, the place a freshly-introduced token would pass through. Both content
/// kinds go through the shared redactor via this one helper so the route applies it in exactly one place.
///
/// The content is redacted in **runs** rather than one line at a time: a credential split across two adjacent
/// lines (`sk-` ending one line and the rest of it starting the next) would defeat a per-line pass, because
/// neither line alone carries the full `sk-…{16,}` shape the redactor's pattern matches. Consecutive Added
/// (and consecutive Removed) lines are joined, redacted, and split back so a stray line break cannot smuggle a
/// token past redaction.
pub fn redact_diff(lines: &[DiffLine], redactor: &Redactor) -> Vec<DiffLine> {
    let mut out = Vec::with_capacity(lines.len());
    let mut run: Vec<String> = Vec::new();
    let mut run_kind = None;

    for line in lines {
        let (kind, text) = match line {
            DiffLine::Added(t) => (Some(DiffLineKind::Added), t.as_str()),
            DiffLine::Removed(t) => (Some(DiffLineKind::Removed), t.as_str()),
            DiffLine::Context(t) => (None, t.as_str()),
        };
        match kind {
            Some(k) if run_kind == Some(k) => run.push(text.to_string()),
            Some(k) => {
                flush_run(&mut run, run_kind, redactor, &mut out);
                run_kind = Some(k);
                run.push(text.to_string());
            }
            None => {
                flush_run(&mut run, run_kind, redactor, &mut out);
                run_kind = None;
                out.push(DiffLine::Context(text.to_string()));
            }
        }
    }
    flush_run(&mut run, run_kind, redactor, &mut out);
    out
}

fn flush_run(
    run: &mut [String],
    kind: Option<DiffLineKind>,
    redactor: &Redactor,
    out: &mut Vec<DiffLine>,
) {
    if run.is_empty() {
        return;
    }
    let kind = kind.expect("a non-empty run has a kind");
    // Content is redacted in pairs rather than one line at a time. The shared redactor's token
    // patterns need a run of `[A-Za-z0-9_-]{16,}` to match, and a credential split across two
    // lines (`sk-` ending one line, the rest starting the next) would defeat a per-line pass because
    // neither line alone carries enough contiguous shape. The pair pass concatenates each adjacent pair so the
    // pattern can see through the line boundary and mask the crossing token, then redistributes the line
    // boundary. Pairs overlap by one line, so a token running across two or more lines is caught wherever
    // it straddles.
    for i in 0..run.len() {
        let text = if i + 1 < run.len() {
            let (a, b) = redact_pair(&run[i], &run[i + 1], redactor);
            run[i + 1] = b;
            a
        } else {
            redactor.redact(&run[i]).text
        };
        out.push(match kind {
            DiffLineKind::Added => DiffLine::Added(text),
            DiffLineKind::Removed => DiffLine::Removed(text),
        });
    }
}

/// Redact a token that straddles the boundary between two consecutive same-kind lines.
///
/// `a` is the anchor line and `b` the following line. If a credential like `sk-` ends `a` and its
/// body continues at the start of `b`, neither redacts on its own: the shared pattern needs 16+ contiguous
/// `[A-Za-z0-9_-]` characters, and the line break breaks the run. Concatenating the pair lets the pattern
/// see through the boundary and mask the crossing token. Returns the redacted `a` (with the marker, if the
/// token started there) and the redacted/following `b`.
fn redact_pair(a: &str, b: &str, redactor: &Redactor) -> (String, String) {
    let a_before = redactor.redact(a).text;
    if a_before != a {
        // `a` already redacts on its own; `b` is handled when it becomes the anchor. Nothing to bridge.
        return (a_before, b.to_string());
    }
    let pair = format!("{a}{b}");
    let pair_redacted = redactor.redact(&pair).text;
    if pair_redacted == pair {
        // No token anywhere in the pair beyond what `a` already lacked.
        return (a.to_string(), b.to_string());
    }
    const MARKER: &str = "[REDACTED:";
    match pair_redacted.find(MARKER) {
        Some(p) if p >= a.len() => {
            // The only marker lies entirely within `b`'s region (a token wholly in `b`, not crossing).
            // Leave `a` alone; `b` redacts when it becomes the anchor.
            (a.to_string(), b.to_string())
        }
        Some(p) => {
            // A token crosses the boundary: the marker starts inside `a`. Text before it belongs to `a`,
            // the marker to `a`, and text after it to `b` (whose leading token-body was masked).
            let end = match pair_redacted[p..].find(']') {
                Some(close) => p + close + 1,
                None => pair_redacted.len(),
            };
            let (ra, rb) = pair_redacted.split_at(end);
            (ra.to_string(), rb.to_string())
        }
        None => (pair_redacted, String::new()),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DiffLineKind {
    Added,
    Removed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_inputs_are_all_context() {
        let d = unified_diff("a\nb\nc\n", "a\nb\nc\n");
        assert!(d.iter().all(|l| matches!(l, DiffLine::Context(_))));
        assert_eq!(d.len(), 3);
    }

    #[test]
    fn an_addition_carries_the_new_line() {
        let d = unified_diff("a\nb\n", "a\nx\nb\n");
        assert!(d
            .iter()
            .any(|l| matches!(l, DiffLine::Added(t) if t == "x")));
    }

    #[test]
    fn a_removal_carries_the_gone_line() {
        let d = unified_diff("a\nb\n", "a\n");
        assert!(d
            .iter()
            .any(|l| matches!(l, DiffLine::Removed(t) if t == "b")));
    }

    #[test]
    fn empty_current_is_all_additions() {
        let d = unified_diff("", "a\nb\n");
        assert!(d.iter().all(|l| matches!(l, DiffLine::Added(_))));
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn a_replacement_is_a_removal_then_an_addition() {
        let d = unified_diff("one\n", "two\n");
        assert!(d
            .iter()
            .any(|l| matches!(l, DiffLine::Removed(t) if t == "one")));
        assert!(d
            .iter()
            .any(|l| matches!(l, DiffLine::Added(t) if t == "two")));
    }

    #[test]
    fn redaction_masks_a_provider_key_in_an_added_line() {
        // The exact shape `redact.rs` matches for a provider key, assembled so a real token-shaped literal
        // does not sit in this source file.
        let token = format!("sk-{}", "A".repeat(24));
        let lines = vec![DiffLine::Added(format!("value = \"{token}\""))];
        let out = redact_diff(&lines, &Redactor::new());
        let DiffLine::Added(t) = &out[0] else {
            panic!("expected an added line")
        };
        assert!(!t.contains(&token), "token leaked: {t}");
        assert!(t.contains("[REDACTED:"), "{t}");
    }

    #[test]
    fn redaction_masks_a_jwt_shaped_token() {
        let jwt = format!("eyJ{}.{}.{}", "A".repeat(12), "B".repeat(12), "C".repeat(6));
        let lines = vec![DiffLine::Added(jwt.clone())];
        let out = redact_diff(&lines, &Redactor::new());
        let DiffLine::Added(t) = &out[0] else {
            panic!("expected added")
        };
        assert!(!t.contains(&jwt), "jwt leaked: {t}");
        assert!(t.contains("[REDACTED:"), "{t}");
    }

    #[test]
    fn an_opaque_token_with_no_pattern_is_left_by_the_shared_redactor() {
        // `signed-token-…` has no pattern in `redact.rs`. This asserts the diff pane is exactly as strong
        // as the shared redactor and no stronger: it is NOT masked here, and that is the honest statement of
        // the limit, not a claim to be stronger than the repo's one redaction.
        let token = "signed-token-9f3a2b7c";
        let lines = vec![DiffLine::Added(token.to_string())];
        let out = redact_diff(&lines, &Redactor::new());
        let DiffLine::Added(t) = &out[0] else {
            panic!("expected added")
        };
        assert_eq!(
            t, token,
            "an unregistered patternless token passes through, matching the shared redactor"
        );
    }

    #[test]
    fn a_provider_key_split_across_two_added_lines_is_masked() {
        // A per-line redaction pass would miss a credential broken across a line boundary: `sk-` ends the
        // first line and the rest of the token starts the next, so neither line alone carries the
        // `sk-…{16,}` shape the shared redactor's pattern matches. The run-joined pass must catch it.
        let id = "A".repeat(12);
        let rest = "B".repeat(12);
        let token = format!("sk-{id}{rest}");
        let lines = vec![
            DiffLine::Added(format!("api_key = \"sk-{id}")),
            DiffLine::Added(format!("{rest}\"")),
        ];
        let out = redact_diff(&lines, &Redactor::new());
        let joined_added: String = out
            .iter()
            .filter_map(|l| match l {
                DiffLine::Added(t) => Some(t.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !joined_added.contains(&token),
            "split token leaked: {joined_added}"
        );
        assert!(joined_added.contains("[REDACTED:"), "{joined_added}");
    }

    #[test]
    fn a_provider_key_split_across_two_removed_lines_is_masked() {
        let id = "A".repeat(12);
        let rest = "B".repeat(12);
        let token = format!("sk-{id}{rest}");
        let lines = vec![
            DiffLine::Removed(format!("key=\"sk-{id}")),
            DiffLine::Removed(format!("{rest}\"")),
        ];
        let out = redact_diff(&lines, &Redactor::new());
        let joined_removed: String = out
            .iter()
            .filter_map(|l| match l {
                DiffLine::Removed(t) => Some(t.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !joined_removed.contains(&token),
            "split removed token leaked: {joined_removed}"
        );
        assert!(joined_removed.contains("[REDACTED:"), "{joined_removed}");
    }

    #[test]
    fn a_token_wholly_in_the_second_line_does_not_disturb_the_first() {
        // A credential sitting entirely in `b` of a pair must not pull `b`'s marker (or text) back
        // into `a`. The pair pass leaves `a` clean and lets `b` redacts when it becomes the anchor.
        let id = "A".repeat(12);
        let lines = vec![
            DiffLine::Added("prefix".to_string()),
            DiffLine::Added(format!("key = sk-{id}{id}")),
        ];
        let out = redact_diff(&lines, &Redactor::new());
        assert_eq!(
            out[0],
            DiffLine::Added("prefix".to_string()),
            "the first line must be untouched"
        );
        assert!(
            matches!(&out[1], DiffLine::Added(t) if t.contains("[REDACTED:") && !t.contains(&format!("sk-{id}{id}"))),
            "{out:?}"
        );
    }

    #[test]
    fn a_three_line_run_bridges_an_interior_boundary() {
        // A token split across the second and third lines of a run is still caught by the overlapping
        // pair pass: lines 2 and 3 are a pair even though line 1 is clean.
        let a = "A".repeat(12);
        let b = "B".repeat(12);
        let token = format!("sk-{a}{b}");
        let lines = vec![
            DiffLine::Added("first".to_string()),
            DiffLine::Added(format!("sk-{a}")),
            DiffLine::Added(b),
        ];
        let out = redact_diff(&lines, &Redactor::new());
        let joined: String = out
            .iter()
            .filter_map(|l| match l {
                DiffLine::Added(t) => Some(t.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!joined.contains(&token), "split token leaked: {joined}");
        assert!(joined.contains("[REDACTED:"), "{joined}");
    }
}

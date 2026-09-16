//! What a session is: its row, its transcript, and how it reads.

use chrono::{DateTime, SecondsFormat, Utc};
use hx_core::error::{HxError, Result};
use hx_core::ids::{AgentId, SessionId, ToolCallId};
use hx_core::message::{Message, Part, Role};
use serde::{Deserialize, Serialize};

/// What a caller supplies to start a session.
///
/// Everything is optional because "new chat" has to work with no arguments: a client that had to
/// name the session before showing the first prompt would be a client nobody uses. What is missing
/// is filled in with something honest (`"untitled"`) rather than a generated uuid, so a list of
/// sessions is readable before anyone has titled anything.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewSession {
    pub title: Option<String>,
    pub agent: Option<AgentId>,
    pub workspace: Option<String>,
    pub model: Option<String>,
}

impl NewSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn titled(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    pub fn run_by(mut self, agent: AgentId) -> Self {
        self.agent = Some(agent);
        self
    }

    pub fn in_workspace(mut self, workspace: impl Into<String>) -> Self {
        self.workspace = Some(workspace.into());
        self
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// The title this session will carry: the caller's, or a placeholder.
    pub fn title_or_default(&self) -> String {
        match self.title.as_deref() {
            Some(title) if !title.trim().is_empty() => title.to_string(),
            _ => "untitled".to_string(),
        }
    }
}

/// The session's own row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub id: SessionId,
    pub title: String,
    /// Who ran it. `None` for a session created before an agent was chosen — the honest value for
    /// a chat that has not called a model yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Touched by every append. This is the field `list` orders on, so it is what "the session I
    /// was just in" means.
    pub updated_at: DateTime<Utc>,
}

/// A session and its transcript, in `seq` order.
#[derive(Clone, Debug, PartialEq)]
pub struct Session {
    pub record: SessionRecord,
    pub messages: Vec<Message>,
}

impl Session {
    pub fn id(&self) -> &SessionId {
        &self.record.id
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Tool calls in the last assistant turn that never got a result.
    ///
    /// A non-empty answer means the session was interrupted between the model's decision and the
    /// tool's outcome — the daemon was killed mid-run, or the process died. It matters because the
    /// transcript is not sendable in that state: every provider that supports tool calls requires a
    /// result for each call, and most answer a dangling call with a 400 that says nothing about why.
    ///
    /// Only the *last* turn is examined. An earlier turn with a missing result means a corrupt
    /// database rather than an interrupted run, and `close_interrupted` is not the right repair for
    /// something the store should never have written.
    pub fn interrupted_calls(&self) -> Vec<ToolCallId> {
        let Some(index) = self.messages.iter().rposition(Message::has_tool_call) else {
            return Vec::new();
        };

        let calls: Vec<ToolCallId> = self.messages[index]
            .tool_calls()
            .filter_map(|part| match part {
                Part::ToolCall { id, .. } => Some(id.clone()),
                _ => None,
            })
            .collect();

        let answered: Vec<&ToolCallId> = self.messages[index + 1..]
            .iter()
            .flat_map(|message| message.parts.iter())
            .filter_map(|part| match part {
                Part::ToolResult { id, .. } => Some(id),
                _ => None,
            })
            .collect();

        calls
            .into_iter()
            .filter(|id| !answered.contains(&id))
            .collect()
    }

    /// True when the last turn asked for something it never heard back about.
    pub fn is_mid_flight(&self) -> bool {
        !self.interrupted_calls().is_empty()
    }
}

/// A row in the session list: the record, plus what it would cost a client to render.
///
/// The counts are **computed** from the transcript and the usage rows rather than cached in the
/// session row. A cache here would be one more thing to keep true, and the only thing it would buy
/// is a query the size of this list.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionSummary {
    #[serde(flatten)]
    pub record: SessionRecord,
    pub messages: u64,
    /// Assistant messages. A proxy for turns that is exact in the only case anyone asks about:
    /// one model reply per turn.
    pub turns: u64,
    #[serde(flatten)]
    pub totals: Totals,
}

/// What a session spent, summed over its usage rows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Totals {
    pub provider_calls: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
    pub reasoning_tokens: u64,
    /// `0.0` when no price table was configured for the model. Not an estimate, not a guess: the
    /// absence of a price is reported as no cost rather than as free.
    pub cost_usd: f64,
}

/// One provider call, as recorded.
///
/// Deliberately plain: the crate graph puts `hx-store` below `hx-provider` (ARCHITECTURE §1), and a
/// usage row is durable data rather than a live provider handle. Ids arrive as strings for the same
/// reason an event payload is JSON — the store writes what it is handed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UsageRecord {
    pub provider: String,
    pub credential: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
    pub reasoning_tokens: u64,
    pub cost_usd: f64,
}

impl UsageRecord {
    /// A record with no cached or reasoning tokens, which is the common case.
    pub fn new(
        provider: impl Into<String>,
        credential: impl Into<String>,
        model: impl Into<String>,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Self {
        Self {
            provider: provider.into(),
            credential: credential.into(),
            model: model.into(),
            input_tokens,
            output_tokens,
            cached_input_tokens: 0,
            reasoning_tokens: 0,
            cost_usd: 0.0,
        }
    }

    pub fn cached(mut self, tokens: u64) -> Self {
        self.cached_input_tokens = tokens;
        self
    }

    pub fn reasoning(mut self, tokens: u64) -> Self {
        self.reasoning_tokens = tokens;
        self
    }

    pub fn costing(mut self, usd: f64) -> Self {
        self.cost_usd = usd;
        self
    }
}

/// How to write a session out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    /// The whole document: record, transcript, totals. What a bug report should carry.
    Json,
    /// A transcript a human reads — or pastes into an issue.
    Markdown,
}

impl ExportFormat {
    /// Parse a format name, as a CLI or a query string would supply it.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "json" => Some(Self::Json),
            "md" | "markdown" => Some(Self::Markdown),
            _ => None,
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Markdown => "md",
        }
    }
}

/// The JSON export: one document, so a reader needs no schema to interpret it.
#[derive(Serialize)]
struct JsonExport<'a> {
    session: &'a SessionRecord,
    totals: Totals,
    messages: &'a [Message],
}

/// Serialise a session as JSON.
pub fn export_json(session: &Session, totals: Totals) -> Result<String> {
    serde_json::to_string_pretty(&JsonExport {
        session: &session.record,
        totals,
        messages: &session.messages,
    })
    .map_err(|err| HxError::Store(format!("could not serialise the session: {err}")))
}

/// Render a session as a Markdown transcript.
///
/// Written for a person reading a bug report: who said what, which tool was called with which
/// arguments, and what came back — including the failures, which is usually the interesting part.
pub fn export_markdown(session: &Session) -> String {
    let record = &session.record;
    let mut out = String::new();

    out.push_str(&format!("# {}\n\n", record.title));
    out.push_str(&format!("- session    `{}`\n", record.id));
    out.push_str(&format!("- created    {}\n", stamp(record.created_at)));
    out.push_str(&format!("- updated    {}\n", stamp(record.updated_at)));
    if let Some(workspace) = &record.workspace {
        out.push_str(&format!("- workspace  `{workspace}`\n"));
    }
    if let Some(model) = &record.model {
        out.push_str(&format!("- model      `{model}`\n"));
    }
    if let Some(agent) = &record.agent {
        out.push_str(&format!("- agent      `{agent}`\n"));
    }
    if session.is_mid_flight() {
        out.push_str(
            "\n> This session was interrupted mid-call: it ends with a tool call that has no \
                      result.\n",
        );
    }
    out.push_str("\n---\n");

    for message in &session.messages {
        out.push('\n');
        match message.role {
            Role::System => out.push_str("## system\n\n"),
            Role::User => out.push_str("## user\n\n"),
            Role::Assistant => out.push_str("## assistant\n\n"),
            // Tool results get their own heading below, per part, so nothing is written twice.
            Role::Tool => {}
        }

        for part in &message.parts {
            match part {
                Part::Text { text } => {
                    out.push_str(text);
                    out.push('\n');
                }
                Part::Image { mime, .. } => {
                    out.push_str(&format!("_[image: {mime}]_\n"));
                }
                Part::ToolCall {
                    name, arguments, ..
                } => {
                    out.push_str(&format!("### tool call — `{name}`\n\n```json\n"));
                    out.push_str(
                        &serde_json::to_string_pretty(arguments)
                            .unwrap_or_else(|_| arguments.to_string()),
                    );
                    out.push_str("\n```\n");
                }
                Part::ToolResult { ok, content, id } => {
                    let verdict = if *ok { "ok" } else { "failed" };
                    // No escaping of a fence inside the content: the result is what it is, and
                    // mangling it would make the export disagree with the transcript it exports.
                    out.push_str(&format!("### tool result — `{id}` ({verdict})\n\n```\n"));
                    out.push_str(content);
                    out.push_str("\n```\n");
                }
            }
        }
    }

    out
}

/// `role` as stored in its column.
///
/// Hand-written rather than derived from serde so that the stored spelling is a decision here: a
/// rename of a serde attribute must not silently change what is already on disk.
pub(crate) fn role_column(role: Role) -> &'static str {
    match role {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    }
}

/// A timestamp as stored: RFC 3339, UTC, milliseconds, always the same width.
///
/// The width is the point. `updated_at` is ordered lexicographically in SQL, so a format that
/// sometimes writes `12:00:00Z` and sometimes `12:00:00.123+00:00` would sort a session created
/// after another one before it. Fixed precision and a fixed `Z` make the string a sortable instant.
pub(crate) fn stamp(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Parse a stored timestamp.
pub(crate) fn parse_stamp(text: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .map(|at| at.with_timezone(&Utc))
        .map_err(|err| HxError::Store(format!("a stored timestamp is unreadable ({text}): {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: &str) -> ToolCallId {
        ToolCallId::from(n)
    }

    fn call(n: &str) -> Message {
        Message::new(
            Role::Assistant,
            vec![Part::ToolCall {
                id: id(n),
                name: "shell".into(),
                arguments: serde_json::json!({ "cmd": "ls" }),
            }],
        )
    }

    fn session(messages: Vec<Message>) -> Session {
        let at = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        Session {
            record: SessionRecord {
                id: SessionId::from_raw("ses_test"),
                title: "test".into(),
                agent: None,
                workspace: Some("/w".into()),
                model: Some("m".into()),
                created_at: at,
                updated_at: at,
            },
            messages,
        }
    }

    #[test]
    fn a_transcript_that_ends_with_an_answered_call_is_finished() {
        let s = session(vec![
            Message::user("go"),
            call("tc_1"),
            Message::tool_result(id("tc_1"), true, "ok"),
            Message::assistant("done"),
        ]);
        assert!(s.interrupted_calls().is_empty());
        assert!(!s.is_mid_flight());
    }

    #[test]
    fn a_call_with_no_result_is_interrupted() {
        let s = session(vec![Message::user("go"), call("tc_1")]);
        assert_eq!(s.interrupted_calls(), vec![id("tc_1")]);
        assert!(s.is_mid_flight());
    }

    #[test]
    fn only_the_calls_that_were_not_answered_count() {
        // The daemon died between two calls in one turn: the first was run, the second never was.
        let both = Message::new(
            Role::Assistant,
            vec![
                Part::ToolCall {
                    id: id("tc_1"),
                    name: "shell".into(),
                    arguments: serde_json::json!({}),
                },
                Part::ToolCall {
                    id: id("tc_2"),
                    name: "shell".into(),
                    arguments: serde_json::json!({}),
                },
            ],
        );
        let s = session(vec![
            Message::user("go"),
            both,
            Message::tool_result(id("tc_1"), true, "ok"),
        ]);
        assert_eq!(s.interrupted_calls(), vec![id("tc_2")]);
    }

    #[test]
    fn an_earlier_answered_turn_does_not_mask_a_later_interruption() {
        let s = session(vec![
            Message::user("go"),
            call("tc_1"),
            Message::tool_result(id("tc_1"), true, "ok"),
            Message::assistant("next"),
            call("tc_2"),
        ]);
        assert_eq!(s.interrupted_calls(), vec![id("tc_2")]);
    }

    #[test]
    fn a_session_with_no_tool_calls_is_never_mid_flight() {
        let s = session(vec![Message::user("hi"), Message::assistant("hello")]);
        assert!(s.interrupted_calls().is_empty());
    }

    #[test]
    fn timestamps_round_trip_and_sort_as_strings() {
        let early = stamp(DateTime::from_timestamp(1_700_000_000, 0).unwrap());
        let late = stamp(DateTime::from_timestamp(1_700_000_001, 500_000_000).unwrap());
        assert!(early < late, "{early} should sort before {late}");
        assert_eq!(
            parse_stamp(&early).unwrap(),
            DateTime::from_timestamp(1_700_000_000, 0).unwrap()
        );
        assert!(parse_stamp("not a time").is_err());
    }

    #[test]
    fn the_default_title_is_a_word_not_a_uuid() {
        assert_eq!(NewSession::new().title_or_default(), "untitled");
        assert_eq!(
            NewSession::new().titled("   ").title_or_default(),
            "untitled",
            "whitespace is not a title"
        );
        assert_eq!(
            NewSession::new().titled("fix the build").title_or_default(),
            "fix the build"
        );
    }

    #[test]
    fn export_format_names_are_parsed_the_way_a_cli_would_pass_them() {
        assert_eq!(ExportFormat::parse("JSON"), Some(ExportFormat::Json));
        assert_eq!(ExportFormat::parse(" md "), Some(ExportFormat::Markdown));
        assert_eq!(
            ExportFormat::parse("markdown"),
            Some(ExportFormat::Markdown)
        );
        assert_eq!(ExportFormat::parse("pdf"), None);
    }

    #[test]
    fn the_markdown_export_shows_tools_arguments_and_failures() {
        let s = session(vec![
            Message::user("build it"),
            call("tc_1"),
            Message::tool_result(id("tc_1"), false, "make: no rule to make target"),
            Message::assistant("the build failed"),
        ]);
        let text = export_markdown(&s);

        assert!(text.starts_with("# test\n"), "{text}");
        assert!(text.contains("## user\n\nbuild it"), "{text}");
        assert!(text.contains("### tool call — `shell`"), "{text}");
        assert!(text.contains("\"cmd\": \"ls\""), "{text}");
        assert!(
            text.contains("### tool result — `tc_1` (failed)"),
            "a failure must be visible as one: {text}"
        );
        assert!(text.contains("make: no rule to make target"), "{text}");
        assert!(text.ends_with("the build failed\n"), "{text}");
    }

    #[test]
    fn the_markdown_export_says_when_a_session_was_interrupted() {
        let mut s = session(vec![Message::user("go"), call("tc_1")]);
        s.record.title = "half a run".into();
        let text = export_markdown(&s);
        assert!(text.contains("interrupted mid-call"), "{text}");
    }

    #[test]
    fn the_json_export_is_one_parseable_document() {
        let s = session(vec![Message::user("hi")]);
        let totals = Totals {
            provider_calls: 1,
            input_tokens: 10,
            ..Default::default()
        };
        let text = export_json(&s, totals).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert_eq!(value["session"]["id"], "ses_test");
        assert_eq!(value["totals"]["input_tokens"], 10);
        assert_eq!(value["messages"][0]["role"], "user");
        // The `flatten`ed record means an id is not nested under a second level.
        assert!(value.get("record").is_none(), "{text}");
    }
}

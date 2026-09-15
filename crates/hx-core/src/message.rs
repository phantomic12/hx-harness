//! Conversation message model.
//!
//! Deliberately provider-neutral: adapters convert to and from Anthropic/OpenAI/Google wire
//! formats. Keeping one internal shape is what stops provider quirks from leaking into the
//! agent loop (and into every tool).

use crate::ids::ToolCallId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Part {
    Text {
        text: String,
    },
    Image {
        mime: String,
        data_b64: String,
    },
    ToolCall {
        id: ToolCallId,
        name: String,
        arguments: serde_json::Value,
    },
    ToolResult {
        id: ToolCallId,
        ok: bool,
        content: String,
    },
}

impl Part {
    pub fn text(s: impl Into<String>) -> Self {
        Part::Text { text: s.into() }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Part::Text { text } => Some(text),
            _ => None,
        }
    }

    pub fn is_tool_call(&self) -> bool {
        matches!(self, Part::ToolCall { .. })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    #[serde(default)]
    pub parts: Vec<Part>,
}

impl Message {
    pub fn new(role: Role, parts: Vec<Part>) -> Self {
        Self { role, parts }
    }

    pub fn system(text: impl Into<String>) -> Self {
        Self::new(Role::System, vec![Part::text(text)])
    }

    pub fn user(text: impl Into<String>) -> Self {
        Self::new(Role::User, vec![Part::text(text)])
    }

    pub fn assistant(text: impl Into<String>) -> Self {
        Self::new(Role::Assistant, vec![Part::text(text)])
    }

    pub fn tool_result(id: ToolCallId, ok: bool, content: impl Into<String>) -> Self {
        Self::new(
            Role::Tool,
            vec![Part::ToolResult {
                id,
                ok,
                content: content.into(),
            }],
        )
    }

    /// All text in this message, concatenated.
    pub fn text(&self) -> String {
        let mut out = String::new();
        for p in &self.parts {
            match p {
                Part::Text { text } => out.push_str(text),
                Part::ToolResult { content, .. } => out.push_str(content),
                _ => {}
            }
        }
        out
    }

    pub fn tool_calls(&self) -> impl Iterator<Item = &Part> {
        self.parts.iter().filter(|p| p.is_tool_call())
    }

    pub fn has_tool_call(&self) -> bool {
        self.parts.iter().any(|p| p.is_tool_call())
    }

    /// Rough token estimate used to *reserve* capacity before a call is sent.
    ///
    /// Deliberately a cheap heuristic (~4 chars/token) rather than a real tokenizer: the
    /// reservation is reconciled against actual usage after the response, so the estimate only
    /// needs to be in the right ballpark to prevent over-admission. A per-model tokenizer is a
    /// later refinement, not a correctness requirement.
    pub fn approximate_tokens(&self) -> usize {
        let chars: usize = self
            .parts
            .iter()
            .map(|p| match p {
                Part::Text { text } => text.chars().count(),
                Part::Image { data_b64, .. } => data_b64.len() / 4,
                Part::ToolCall {
                    name, arguments, ..
                } => name.chars().count() + arguments.to_string().chars().count(),
                Part::ToolResult { content, .. } => content.chars().count(),
            })
            .sum();
        // 4 chars/token, rounded up, plus a small per-message overhead.
        chars.div_ceil(4) + 4
    }
}

/// Total estimated tokens across a transcript.
pub fn approximate_tokens(messages: &[Message]) -> usize {
    messages.iter().map(|m| m.approximate_tokens()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_constructor_and_accessor() {
        let m = Message::user("hello");
        assert_eq!(m.role, Role::User);
        assert_eq!(m.text(), "hello");
    }

    #[test]
    fn tool_call_is_detected() {
        let m = Message::new(
            Role::Assistant,
            vec![Part::ToolCall {
                id: ToolCallId::from_raw("tc_1"),
                name: "shell".into(),
                arguments: serde_json::json!({"cmd": "ls"}),
            }],
        );
        assert!(m.has_tool_call());
        assert_eq!(m.tool_calls().count(), 1);
    }

    #[test]
    fn token_estimate_scales_with_content() {
        let small = Message::user("hi").approximate_tokens();
        let large = Message::user("x".repeat(4000)).approximate_tokens();
        assert!(
            large > small * 100,
            "expected large to dominate: {large} vs {small}"
        );
        // ~4000 chars / 4 = 1000 tokens, plus overhead.
        assert!((1000..1010).contains(&large), "got {large}");
    }

    #[test]
    fn transcript_estimate_sums_messages() {
        let msgs = vec![
            Message::user("a".repeat(400)),
            Message::user("b".repeat(400)),
        ];
        let total = approximate_tokens(&msgs);
        assert!((200..220).contains(&total), "got {total}");
    }

    #[test]
    fn messages_round_trip_through_json() {
        let m = Message::tool_result(ToolCallId::from_raw("tc_9"), false, "boom");
        let json = serde_json::to_string(&m).unwrap();
        let back: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.text(), "boom");
    }
}

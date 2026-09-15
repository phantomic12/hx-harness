//! Events emitted by a running agent.
//!
//! Every surface — TUI, web UI, Tauri desktop/mobile, Discord, Telegram — renders *these*.
//! That is how feature parity stays structural rather than aspirational: a new event is
//! automatically visible everywhere, because no client owns its own copy of the logic.

use crate::ids::{AgentId, ApprovalId, CredentialId, ProviderId, SessionId, ToolCallId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AgentEvent {
    SessionStarted {
        session: SessionId,
        at: DateTime<Utc>,
    },
    TurnStarted {
        agent: AgentId,
        turn: u32,
    },
    /// Incremental model output. Clients append; they do not re-render from scratch.
    TextDelta {
        agent: AgentId,
        text: String,
    },
    /// Extended-thinking output, kept separate so clients can hide it independently.
    ReasoningDelta {
        agent: AgentId,
        text: String,
    },
    ToolCallStarted {
        agent: AgentId,
        call: ToolCallId,
        name: String,
        arguments: serde_json::Value,
    },
    ToolCallFinished {
        agent: AgentId,
        call: ToolCallId,
        ok: bool,
        summary: String,
        duration_ms: u64,
    },
    ApprovalRequested {
        agent: AgentId,
        approval: ApprovalId,
        call: ToolCallId,
        reason: String,
    },
    ApprovalResolved {
        agent: AgentId,
        approval: ApprovalId,
        approved: bool,
        by: String,
    },
    Usage {
        agent: AgentId,
        provider: ProviderId,
        credential: CredentialId,
        model: String,
        input_tokens: u64,
        output_tokens: u64,
        cost_usd: f64,
    },
    TurnFinished {
        agent: AgentId,
        turn: u32,
        stop: StopReason,
    },
    Error {
        agent: AgentId,
        message: String,
    },
}

impl AgentEvent {
    /// The agent this event belongs to, where one applies.
    pub fn agent(&self) -> Option<&AgentId> {
        use AgentEvent::*;
        match self {
            SessionStarted { .. } => None,
            TurnStarted { agent, .. }
            | TextDelta { agent, .. }
            | ReasoningDelta { agent, .. }
            | ToolCallStarted { agent, .. }
            | ToolCallFinished { agent, .. }
            | ApprovalRequested { agent, .. }
            | ApprovalResolved { agent, .. }
            | Usage { agent, .. }
            | TurnFinished { agent, .. }
            | Error { agent, .. } => Some(agent),
        }
    }

    /// True for events that should interrupt a human (mobile push, notification tray).
    pub fn needs_attention(&self) -> bool {
        matches!(
            self,
            AgentEvent::ApprovalRequested { .. } | AgentEvent::Error { .. }
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Completed,
    MaxTurns,
    BudgetExhausted,
    Cancelled,
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_request_needs_attention() {
        let e = AgentEvent::ApprovalRequested {
            agent: AgentId::from_raw("agt_1"),
            approval: ApprovalId::from_raw("apr_1"),
            call: ToolCallId::from_raw("tc_1"),
            reason: "writes outside workspace".into(),
        };
        assert!(e.needs_attention());
        assert_eq!(e.agent().map(|a| a.as_str()), Some("agt_1"));
    }

    #[test]
    fn text_delta_does_not_need_attention() {
        let e = AgentEvent::TextDelta {
            agent: AgentId::from_raw("agt_1"),
            text: "hi".into(),
        };
        assert!(!e.needs_attention());
    }

    #[test]
    fn session_started_has_no_agent() {
        let e = AgentEvent::SessionStarted {
            session: SessionId::from_raw("ses_1"),
            at: Utc::now(),
        };
        assert!(e.agent().is_none());
    }

    #[test]
    fn events_carry_a_stable_tag_for_wire_framing() {
        let e = AgentEvent::TextDelta {
            agent: AgentId::from_raw("agt_1"),
            text: "x".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert_eq!(v["event"], "text_delta");
    }
}

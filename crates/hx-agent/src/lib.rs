//! The agent loop, and the two things it consults before anything runs.
//!
//! ## The property this crate exists to hold
//!
//! **Nothing a model asks for happens until something has checked it.** A tool call is classified
//! against the agent's [`hx_core::capability::CapabilityToken`] — may this agent do this at all? —
//! and then against the [`hx_core::approval::ApprovalSession`] — does a human want *this* one? The
//! two are independent, and the order matters: a capability denial is auditable and cannot be
//! approved away, while an approval is a decision about a single instance of something the agent
//! was already allowed to do.
//!
//! ## Refusals are results
//!
//! A denied call, an unknown tool, unusable arguments: all three become tool results in the
//! transcript with the reason attached. A model that cannot see a refusal will retry it, or assume
//! it worked — which is how a run ends up describing work it never did.
//!
//! ## What is not here yet
//!
//! Streaming (a turn arrives whole and is emitted as one `TextDelta`), context compaction, and cost
//! accounting. Each is a gap the loop states rather than hides: usage is reported in tokens, and
//! `cost_usd` is zero because a price table belongs to the router.

pub mod agent;
pub mod approver;
pub mod model;

pub use agent::{AgentLoop, Limits, RunOutcome};
pub use approver::{
    AlwaysAllow, AlwaysDeny, ApprovalDecision, Approver, DenyWithReason, ScriptedApprover,
};
pub use model::{DirectProvider, ModelCall, RouterModel};

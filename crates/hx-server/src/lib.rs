//! The daemon's HTTP surface and shared state.
//!
//! One process owns the state; every front end is a client. That is what keeps requirement #3
//! ("a web UI that can do everything a terminal can") structurally true instead of a promise
//! that decays as features get added to one surface only.
//!
//! Exposed over HTTP: routing and limits, search, sandboxes, hosts, sessions, and the agent loop
//! itself (`POST /v1/chat` — one request, one session, one run). Not yet exposed: a WebSocket event
//! stream (events are written to the session store as a run happens and read back per session, so a
//! client can redraw; it just cannot subscribe), MCP, and an approval channel — which is why the
//! daemon's approver refuses every prompt with the reason instead of waiting for an answer that
//! cannot arrive. See `ROADMAP.md` — M1 and M2.

pub mod chat;
pub mod routes;
pub mod state;

pub use chat::{ChatReply, ChatRequest, ModelFactory, RouterModels};
pub use routes::{app, status_for, ApiError};
pub use state::{AppState, AppStateParts, HostSummary, SandboxSummary, StatusReport};

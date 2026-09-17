//! The daemon's HTTP surface and shared state.
//!
//! One process owns the state; every front end is a client. That is what keeps requirement #3
//! ("a web UI that can do everything a terminal can") structurally true instead of a promise
//! that decays as features get added to one surface only.
//!
//! Exposed over HTTP: routing and limits, search, sandboxes, hosts, sessions, the agent loop
//! itself (`POST /v1/chat` — one request, one session, one run), and the run streamed live
//! (`POST /v1/chat/stream` — the same run, with each [`hx_core::event::AgentEvent`] pushed
//! over SSE as it happens and the reply as the terminal event). Not yet exposed: a WebSocket event
//! stream (SSE is the live surface today and the WS multiplex is M2), MCP, and an approval
//! channel — which is why the daemon's approver refuses every prompt with the reason instead of
//! waiting for an answer that cannot arrive. See `ROADMAP.md` — M1 and M2.

pub mod chat;
pub mod routes;
pub mod sandbox;
pub mod state;
pub mod stream;

pub use chat::{ChatReply, ChatRequest, ModelFactory, RouterModels};
pub use routes::{app, status_for, ApiError};
pub use sandbox::{SandboxCache, SandboxFor};
pub use state::{AppState, AppStateParts, HostSummary, LiveEvent, SandboxSummary, StatusReport};

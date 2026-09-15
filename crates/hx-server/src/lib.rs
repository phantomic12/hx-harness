//! The daemon's HTTP surface and shared state.
//!
//! One process owns the state; every front end is a client. That is what keeps requirement #3
//! ("a web UI that can do everything a terminal can") structurally true instead of a promise
//! that decays as features get added to one surface only.
//!
//! Not yet exposed over HTTP: the agent loop itself, the WebSocket event stream, and MCP. See
//! `ROADMAP.md` — M1 and M2. The subsystems they depend on (routing, limits, search, sandboxes,
//! hosts, capabilities, approvals) are all live behind this API.

pub mod routes;
pub mod state;

pub use routes::{app, ApiError, status_for};
pub use state::{AppState, HostSummary, SandboxSummary, StatusReport};

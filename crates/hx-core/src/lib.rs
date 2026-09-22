//! Core domain types for `hx`.
//!
//! This crate is deliberately **IO-free**: no `tokio`, no `reqwest`, no filesystem.
//! Everything here is a plain data type or a pure function, which is what makes the
//! security-critical logic — path containment, risk classification, approval decisions —
//! cheap to test exhaustively. The tests in these modules are the specification.
//!
//! The one deliberate exception is [`allowlist`]: the `.hx/allow.toml` reader reads a file the
//! caller names, because the format's fail-closed behavior ("a malformed file grants nothing") can only
//! be tested against bytes on disk and the format's home is the crate that owns the approval types. It is
//! a single, bounded `std::fs::read`; everything else here remains IO-free.

pub mod allowlist;
pub mod api_auth;
pub mod approval;
pub mod capability;
pub mod config;
pub mod decision;
pub mod error;
pub mod event;
pub mod ids;
pub mod message;
pub mod pool;
pub mod update;

pub use api_auth::{bind_is_loopback, require_token_for_bind, ApiToken, API_TOKEN_ENV};
pub use approval::{
    classify_command, ActionRequest, ApprovalOption, ApprovalPolicy, ApprovalRequest,
    ApprovalSession, AutonomyLevel, Classification, RememberedDecision, RiskClass, Rule, Verdict,
};
pub use capability::{
    path_grant_covers, Action, Capability, CapabilityToken, Constraints, Decision, DenyReason,
    Resource,
};
pub use config::{Config, McpServerConfig, McpTransport, ModelRef, SandboxProfile, SecretRef};
pub use error::{HxError, Result};
pub use event::{AgentEvent, StopReason};
pub use ids::{
    AgentId, ApprovalId, CapabilityId, ConnectorId, CredentialId, HostId, MessageId, PoolId,
    ProviderId, SandboxId, SessionId, ToolCallId, VolumeId,
};
pub use message::{Message, Part, Role};
pub use pool::{
    DrawError, EffectiveParams, MemberHealth, ModelPool, ModelPoolMemberConfig, Param, ParamClamp,
    PoolMember, ReasoningEffort,
};
pub use update::{
    compare_versions, release_tag_name, UpdateConfig, DEFAULT_UPDATE_INTERVAL_SECS,
    DEFAULT_UPDATE_URL,
};

//! Harbor-format eval tasks on hx sandboxes.
//!
//! ## What this crate is
//!
//! [Harbor](https://github.com/harbor-framework/harbor) is the eval framework from the
//! Terminal-Bench authors. Its task format is a directory: `instruction.md`, `task.toml`,
//! `environment/` (a Dockerfile or compose file), `solution/`, `tests/`. A *trial* is: build the
//! environment, run the agent against the instruction, run the verifier, score it.
//!
//! This crate parses that format and runs it on `hx-sandbox`'s isolation ladder, so a trial gets
//! the harness's own security model — default-deny network, read-only rootfs, capability tokens,
//! approval policy — rather than the eval's defaults. The integration point is the task format,
//! not Harbor's runner: datasets authored for Harbor run here unchanged.
//!
//! ## What is deliberately not here
//!
//! RL rollout generation, GEPA/prompt optimization, cloud sandbox providers (Daytona, Modal).
//! Those are Harbor-side features. hx provides the environment and the agent; the task format is
//! the contract.

pub mod models;
pub mod runner;
pub mod task;

pub use models::RunnerModels;
pub use runner::{
    run_trial, verifier_command, AgentDriver, AgentInput, AgentSummary, RealDriver, TrialConfig,
    TrialOutcome,
};

pub use task::{EnvironmentSpec, TaskSpec, VerifierSpec};

//! What an agent can *do*: the tools it calls, and what each one requires.
//!
//! ## Two things this crate is careful about
//!
//! **1. A tool declares its requirement; it does not check it.** Every tool answers
//! [`Tool::requirement`] — the resource and action its arguments imply — and the agent loop is what
//! asks the capability token and the approval policy whether that is allowed. A tool that policed
//! itself would be a tool whose policy could be bypassed by adding another tool; keeping the check
//! in one place is what makes "every tool call is classified before it runs" a property rather than
//! a habit.
//!
//! **2. Output is bounded by the tool, not by hope.** A `cat` of a 400 MB log, or a `find /` that
//! prints a million lines, must not be the thing that fills the model's context. Every tool
//! truncates in the middle and says how much it dropped, so the model knows it is looking at an
//! excerpt rather than the whole thing.
//!
//! ## What runs where
//!
//! Filesystem and shell tools act through [`hx_remote::Host`], so they work identically on the
//! local machine, an SSH host, or a sandbox — the transport is not the tool's business. Web search
//! goes through `hx-search`'s backends, and `todo` is in-memory scratch space for the agent's own
//! plan.

pub mod fs;
pub mod registry;
pub mod shell;
pub mod todo;
pub mod tool;
pub mod trash;
pub mod web;

/// An in-memory host, for tests.
///
/// Not `#[cfg(test)]`: a downstream crate's tests of the *loop* need a host to hand to a tool,
/// and a mock library would only assert that we call the methods we think we call. The real host
/// semantics (filesystem, command output) are what make an assertion about a tool's effect mean
/// something.
pub mod testing;

pub use fs::{PatchTool, ReadFileTool, WriteFileTool};
pub use registry::{PreparedCall, ToolInfo, ToolRegistry};
pub use shell::ShellTool;
pub use todo::TodoTool;
pub use tool::{
    bound, resolve_path, Requirement, Tool, ToolContext, ToolError, ToolOutcome,
    MAX_TOOL_OUTPUT_CHARS,
};
pub use trash::DeleteTool;
pub use web::WebSearchTool;

//! The set of tools an agent has, and the two-phase call that keeps policy in one place.

use crate::tool::{Requirement, Tool, ToolContext, ToolError, ToolOutcome};
use indexmap::IndexMap;
use serde_json::Value;
use std::sync::Arc;

/// What a model is told about a tool.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    pub schema: Value,
}

/// A validated call that has not run yet.
///
/// The two phases exist so the arguments are parsed **once**: the loop needs the requirement to
/// check a capability and ask a human, and re-parsing the arguments afterwards would mean the
/// thing that ran could differ from the thing that was approved.
pub struct PreparedCall {
    tool: Arc<dyn Tool>,
    name: String,
    args: Value,
    /// `None` means the tool has no external effect — see [`Tool::requirement`].
    requirement: Option<Requirement>,
}

impl std::fmt::Debug for PreparedCall {
    /// Hand-written because `dyn Tool` is not `Debug`: the useful parts are the name and what the
    /// call would do, not the tool's internals.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedCall")
            .field("name", &self.name)
            .field("arguments", &self.args)
            .field(
                "requirement",
                &self
                    .requirement
                    .as_ref()
                    .map(|requirement| requirement.describes.as_str()),
            )
            .finish()
    }
}

impl PreparedCall {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What must be allowed before this may run.
    pub fn requirement(&self) -> Option<&Requirement> {
        self.requirement.as_ref()
    }

    /// A human-readable summary for an approval prompt or a log line.
    pub fn describe(&self) -> String {
        match &self.requirement {
            Some(requirement) => format!("{}: {}", self.name, requirement.describes),
            None => format!("{} (no external effect)", self.name),
        }
    }

    pub async fn run(self, ctx: &ToolContext) -> Result<ToolOutcome, ToolError> {
        self.tool.call(self.args, ctx).await
    }
}

/// The tools available to an agent.
#[derive(Default)]
pub struct ToolRegistry {
    tools: IndexMap<String, Arc<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a tool. Replacing is deliberate: a deployment may want to swap one
    /// implementation (a shell that runs in a sandbox, say) without rebuilding the loop.
    pub fn register(&mut self, tool: Arc<dyn Tool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Tool>> {
        self.tools.get(name).cloned()
    }

    pub fn names(&self) -> Vec<String> {
        self.tools.keys().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.tools.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Everything a model needs to decide whether a tool applies.
    pub fn describe(&self) -> Vec<ToolInfo> {
        self.tools
            .values()
            .map(|tool| ToolInfo {
                name: tool.name().to_string(),
                description: tool.description().to_string(),
                schema: tool.schema(),
            })
            .collect()
    }

    /// Validate a call without running it.
    ///
    /// An unknown tool or unusable arguments come back as an error the loop turns into a tool
    /// result, so the model sees what was wrong with its call instead of watching the run end.
    pub fn prepare(
        &self,
        name: &str,
        args: Value,
        ctx: &ToolContext,
    ) -> Result<PreparedCall, ToolError> {
        let tool = self.tools.get(name).cloned().ok_or_else(|| {
            ToolError::Unavailable(format!(
                "no tool named '{name}'. Available tools: {}",
                self.names().join(", ")
            ))
        })?;

        let requirement = tool.requirement(&args, ctx)?;

        Ok(PreparedCall {
            tool,
            name: name.to_string(),
            args,
            requirement,
        })
    }

    /// Prepare and run in one step, for callers that have nothing to check (tests, `hx tool`).
    pub async fn dispatch(
        &self,
        name: &str,
        args: Value,
        ctx: &ToolContext,
    ) -> Result<ToolOutcome, ToolError> {
        self.prepare(name, args, ctx)?.run(ctx).await
    }
}

/// A tool that does nothing, for tests in this crate and in the agent loop.
#[cfg(test)]
pub(crate) struct NoopTool {
    pub name: String,
}

#[cfg(test)]
#[async_trait::async_trait]
impl Tool for NoopTool {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "does nothing"
    }

    fn schema(&self) -> Value {
        serde_json::json!({"type": "object", "properties": {}})
    }

    fn requirement(
        &self,
        _args: &Value,
        _ctx: &ToolContext,
    ) -> Result<Option<Requirement>, ToolError> {
        Ok(None)
    }

    async fn call(&self, _args: Value, _ctx: &ToolContext) -> Result<ToolOutcome, ToolError> {
        Ok(ToolOutcome::ok("did nothing"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeHost;
    use crate::{ShellTool, TodoTool};

    fn ctx() -> ToolContext {
        ToolContext::new(Arc::new(FakeHost::unix()))
    }

    fn registry() -> ToolRegistry {
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(ShellTool::new()));
        registry.register(Arc::new(TodoTool::new()));
        registry
    }

    #[test]
    fn the_registry_describes_its_tools_for_a_model() {
        let described = registry().describe();
        let names: Vec<&str> = described.iter().map(|info| info.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["shell", "todo"],
            "registration order is preserved"
        );

        let shell = described
            .iter()
            .find(|info| info.name == "shell")
            .expect("shell is registered");
        assert!(shell.description.contains("shell command"));
        assert_eq!(shell.schema["required"][0], "cmd");
    }

    #[test]
    fn an_unknown_tool_names_the_ones_that_exist() {
        let err = registry()
            .prepare("rm_rf", serde_json::json!({}), &ctx())
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("no tool named 'rm_rf'"), "{message}");
        assert!(message.contains("shell"), "{message}");
        assert!(message.contains("todo"), "{message}");
    }

    #[test]
    fn preparing_does_not_run_anything() {
        // The whole point: the loop decides first.
        let prepared = registry()
            .prepare("shell", serde_json::json!({"cmd": "ls"}), &ctx())
            .unwrap();
        assert_eq!(prepared.name(), "shell");
        assert!(prepared.requirement().is_some());
        assert!(prepared.describe().contains("ls"));
    }

    #[test]
    fn bad_arguments_are_caught_before_preparation_succeeds() {
        let err = registry()
            .prepare("shell", serde_json::json!({}), &ctx())
            .unwrap_err();
        assert!(err.to_string().contains("missing field `cmd`"), "{err}");
    }

    #[test]
    fn a_tool_without_an_external_effect_has_no_requirement() {
        let prepared = registry()
            .prepare("todo", serde_json::json!({"action": "list"}), &ctx())
            .unwrap();
        assert!(prepared.requirement().is_none());
        assert!(prepared.describe().contains("no external effect"));
    }

    #[tokio::test]
    async fn running_a_prepared_call_uses_the_arguments_that_were_checked() {
        let host = Arc::new(FakeHost::unix().with_exec_output("ok\n", "", Some(0)));
        let ctx = ToolContext::new(host.clone());

        let prepared = registry()
            .prepare("shell", serde_json::json!({"cmd": "echo hi"}), &ctx)
            .unwrap();
        let outcome = prepared.run(&ctx).await.unwrap();

        assert!(outcome.ok);
        assert_eq!(host.commands(), vec!["echo hi".to_string()]);
    }

    #[test]
    fn registering_a_tool_twice_replaces_it() {
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(NoopTool {
            name: "thing".to_string(),
        }));
        registry.register(Arc::new(NoopTool {
            name: "thing".to_string(),
        }));
        assert_eq!(registry.len(), 1);
    }

    #[tokio::test]
    async fn dispatch_is_prepare_and_run_together() {
        let host = Arc::new(FakeHost::unix().with_exec_output("output", "", Some(0)));
        let outcome = registry()
            .dispatch(
                "shell",
                serde_json::json!({"cmd": "true"}),
                &ToolContext::new(host),
            )
            .await
            .unwrap();
        assert!(outcome.ok);
        assert!(outcome.content.contains("output"));
    }

    #[test]
    fn an_empty_registry_says_it_is_empty() {
        let registry = ToolRegistry::new();
        assert!(registry.is_empty());
        assert!(registry.describe().is_empty());
        let err = registry
            .prepare("anything", serde_json::json!({}), &ctx())
            .unwrap_err();
        assert!(err.to_string().contains("Available tools: "), "{err}");
    }

    #[test]
    fn ctx_helper_is_used() {
        // Keeps the unused-import warning away in builds where every test above is filtered out.
        let _ = ctx();
    }
}

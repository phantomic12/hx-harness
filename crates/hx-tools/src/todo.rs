//! The agent's own scratch space: a todo list it maintains while it works.

use crate::tool::{parse_args, Requirement, Tool, ToolContext, ToolError, ToolOutcome};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Op {
    Add,
    Complete,
    List,
    Clear,
}

#[derive(Debug, Deserialize)]
struct Args {
    action: Op,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    id: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Item {
    id: usize,
    text: String,
    done: bool,
}

/// A list that survives the turn it was created in.
///
/// Multi-step work is where an agent loses the thread — the fourth step gets optimised at the
/// expense of the second. Writing the plan down and re-reading it is what keeps a long task
/// pointed at the thing it was asked to do.
pub struct TodoTool {
    items: Mutex<Vec<Item>>,
    next_id: Mutex<usize>,
}

impl TodoTool {
    pub fn new() -> Self {
        Self {
            items: Mutex::new(Vec::new()),
            next_id: Mutex::new(1),
        }
    }

    fn add(&self, text: String) -> ToolOutcome {
        let mut ids = self.next_id.lock().unwrap();
        let id = *ids;
        *ids += 1;
        drop(ids);

        self.items.lock().unwrap().push(Item {
            id,
            text: text.clone(),
            done: false,
        });
        ToolOutcome::ok(format!("added #{id}: {text}"))
    }

    fn complete(&self, id: usize) -> ToolOutcome {
        let mut items = self.items.lock().unwrap();
        match items.iter_mut().find(|item| item.id == id) {
            Some(item) => {
                item.done = true;
                ToolOutcome::ok(format!("completed #{id}: {}", item.text))
            }
            // Naming the real ids is what lets the model correct itself without another round trip.
            None => ToolOutcome::failed(format!(
                "no todo with id {id}; the list is: {}",
                Self::render(&items)
            )),
        }
    }

    fn clear(&self) -> ToolOutcome {
        let mut items = self.items.lock().unwrap();
        let count = items.len();
        items.clear();
        ToolOutcome::ok(format!("cleared {count} item(s)"))
    }

    fn render(items: &[Item]) -> String {
        if items.is_empty() {
            return "(the list is empty)".to_string();
        }
        let done = items.iter().filter(|item| item.done).count();
        let mut out = format!("{}/{} done\n", done, items.len());
        for item in items {
            out.push_str(&format!(
                "[{}] #{} {}\n",
                if item.done { "x" } else { " " },
                item.id,
                item.text
            ));
        }
        out
    }
}

impl Default for TodoTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for TodoTool {
    fn name(&self) -> &str {
        "todo"
    }

    fn description(&self) -> &str {
        "Keep a plan. `add` a step, `complete` it by id, `list` what is outstanding. Use this for \
         multi-step work: writing the steps down is what stops the fourth step from being \
         optimised at the expense of the second."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "enum": ["add", "complete", "list", "clear"] },
                "text": { "type": "string", "description": "the step, when adding" },
                "id": { "type": "integer", "description": "the step's id, when completing" }
            },
            "required": ["action"]
        })
    }

    fn requirement(
        &self,
        args: &Value,
        _ctx: &ToolContext,
    ) -> Result<Option<Requirement>, ToolError> {
        let parsed: Args = parse_args(args)?;
        // No external effect at all: this is the agent's own memory for the length of a run. The
        // loop runs it without asking a capability token or a human, which is why the trait returns
        // an Option — a tool that touched the host, the network or a file would have to say so.
        match parsed.action {
            Op::Add if parsed.text.as_deref().unwrap_or("").trim().is_empty() => Err(
                ToolError::Arguments("`text` is required when adding an item".to_string()),
            ),
            Op::Complete if parsed.id.is_none() => Err(ToolError::Arguments(
                "`id` is required when completing an item".to_string(),
            )),
            _ => Ok(None),
        }
    }

    async fn call(&self, args: Value, _ctx: &ToolContext) -> Result<ToolOutcome, ToolError> {
        let parsed: Args = parse_args(&args)?;
        Ok(match parsed.action {
            Op::Add => self.add(parsed.text.unwrap_or_default().trim().to_string()),
            Op::Complete => self.complete(parsed.id.unwrap_or_default()),
            Op::List => ToolOutcome::ok(Self::render(&self.items.lock().unwrap())),
            Op::Clear => self.clear(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeHost;
    use std::sync::Arc;

    fn ctx() -> ToolContext {
        ToolContext::new(Arc::new(FakeHost::unix()))
    }

    #[tokio::test]
    async fn items_can_be_added_completed_and_listed() {
        let todo = TodoTool::new();

        todo.call(
            json!({"action": "add", "text": "read the failing test"}),
            &ctx(),
        )
        .await
        .unwrap();
        todo.call(json!({"action": "add", "text": "fix it"}), &ctx())
            .await
            .unwrap();

        let listed = todo.call(json!({"action": "list"}), &ctx()).await.unwrap();
        assert!(
            listed.content.contains("[ ] #1 read the failing test"),
            "{}",
            listed.content
        );
        assert!(listed.content.contains("[ ] #2 fix it"));
        assert!(listed.content.starts_with("0/2 done"));

        let completed = todo
            .call(json!({"action": "complete", "id": 1}), &ctx())
            .await
            .unwrap();
        assert!(completed.ok);
        assert!(completed.content.contains("read the failing test"));

        let listed = todo.call(json!({"action": "list"}), &ctx()).await.unwrap();
        assert!(listed.content.contains("[x] #1"), "{}", listed.content);
        assert!(listed.content.starts_with("1/2 done"));
    }

    #[tokio::test]
    async fn completing_an_unknown_id_lists_the_real_ones() {
        // So the model can correct itself without spending a turn asking what the ids are.
        let todo = TodoTool::new();
        todo.call(json!({"action": "add", "text": "only step"}), &ctx())
            .await
            .unwrap();

        let outcome = todo
            .call(json!({"action": "complete", "id": 99}), &ctx())
            .await
            .unwrap();
        assert!(!outcome.ok);
        assert!(
            outcome.content.contains("no todo with id 99"),
            "{}",
            outcome.content
        );
        assert!(
            outcome.content.contains("#1 only step"),
            "{}",
            outcome.content
        );
    }

    #[tokio::test]
    async fn an_empty_list_says_it_is_empty() {
        let outcome = TodoTool::new()
            .call(json!({"action": "list"}), &ctx())
            .await
            .unwrap();
        assert_eq!(outcome.content, "(the list is empty)");
    }

    #[tokio::test]
    async fn clearing_reports_how_many_were_dropped() {
        let todo = TodoTool::new();
        for step in ["a", "b"] {
            todo.call(json!({"action": "add", "text": step}), &ctx())
                .await
                .unwrap();
        }
        let cleared = todo.call(json!({"action": "clear"}), &ctx()).await.unwrap();
        assert!(
            cleared.content.contains("cleared 2 item(s)"),
            "{}",
            cleared.content
        );
    }

    #[test]
    fn the_todo_list_has_no_external_effect() {
        // No requirement means the loop neither asks a capability token nor a human: the list is
        // the agent's own memory. Anything that touched the host, a file or the network would have
        // to return one.
        let requirement = TodoTool::new()
            .requirement(&json!({"action": "list"}), &ctx())
            .unwrap();
        assert!(requirement.is_none());
    }

    #[test]
    fn adding_without_text_is_refused_with_the_reason() {
        let err = TodoTool::new()
            .requirement(&json!({"action": "add"}), &ctx())
            .unwrap_err();
        assert!(err.to_string().contains("`text` is required"), "{err}");
    }

    #[test]
    fn completing_without_an_id_is_refused() {
        let err = TodoTool::new()
            .requirement(&json!({"action": "complete"}), &ctx())
            .unwrap_err();
        assert!(err.to_string().contains("`id` is required"), "{err}");
    }

    #[test]
    fn an_unknown_action_is_an_argument_error() {
        let err = TodoTool::new()
            .requirement(&json!({"action": "delete_everything"}), &ctx())
            .unwrap_err();
        assert!(err.to_string().contains("unknown variant"), "{err}");
    }
}

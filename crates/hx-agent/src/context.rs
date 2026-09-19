//! Assembling the request a turn sends: what a model is told, and why it is that shape.
//!
//! ## The property this module exists to hold
//!
//! Every turn of every run sends a `ChatRequest` assembled from the same four facts: which model a
//! role resolved to, the system prompt, the tool schemas the tools declared, and the transcript.
//! Those four were assembled inline in the loop — six lines in the middle of the turn body, which
//! meant the *policy* about what a model is shown lived in the one place hardest to test and easiest
//! to grow a special case in. The loop is about control flow: gates, limits, events, tool dispatch.
//! What to send is a different question with a different failure mode (a request a provider refuses,
//! versus a call that ran when it should not have), so it lives here.
//!
//! ## The decisions this module owns
//!
//! - **What transcript goes out.** The audit trail and the request are different things. The loop's
//!   `transcript` is what a human reads and what the store keeps; the request gets a transcript that
//!   may have had its middle elided to stay inside the model's window. That elision is
//!   [`crate::compact`]'s job and its own module's worth of reasoning; this module is where the loop
//!   consults it, so that "what we keep" and "what we send" are decided in the same place and can be
//!   asserted together.
//! - **Whether tools are offered at all.** An empty tool list is not the same as no tool list: the
//!   adapters omit the `tools` field entirely when it is empty, and a request that declares no tools
//!   is how a run that has none behaves. The builder makes that explicit rather than incidental.
//! - **The system prompt.** Optional here because it is optional in a `ChatRequest`; a run with none
//!   sends none, rather than an empty string that a provider would render as an empty system block.
//!
//! ## What it deliberately does not do yet
//!
//! It does not summarise the elided middle with a model call (see [`crate::compact`]), does not
//! choose between several context strategies, and does not count tool-schema tokens against the
//! compaction threshold — the threshold is about the *conversation*, which is the part that grows.
//! It also does not know about providers: it builds a `ChatRequest`, and what an adapter does with
//! that is the adapter's business.
//!
//! ## Why it takes a struct rather than a long argument list
//!
//! The inputs are four named things that a caller assembles once per run and reuses every turn
//! (`ContextFacts`), plus the two that change per turn (the transcript and the reservation model).
//! Passing them positionally invited the exact bug this module prevents — a caller that put `system`
//! where `tools` belonged would still compile if both were `String`-ish, and a request with the tool
//! schemas in the system prompt is the kind of mistake that reaches a provider before anyone notices.

use hx_core::message::Message;
use hx_provider::{ChatRequest, ToolSpec};

use crate::compact::compact_at;

/// The facts about a run that do not change from turn to turn.
///
/// Assembled once when a run starts. `tools` is the *declared* schemas — what the model is offered,
/// never what it is allowed to do: permission is decided later and elsewhere
/// (`docs/approvals.md`: the tool declares its requirement, the capability token and the approval
/// policy decide). A model offered no tools simply cannot ask, which is a different statement from
/// a model whose call would be refused.
#[derive(Clone, Debug, Default)]
pub struct ContextFacts {
    /// The system prompt, when the run has one.
    pub system: Option<String>,
    /// The tool schemas to offer, as the registry declared them.
    pub tools: Vec<ToolSpec>,
    /// The output allowance for every turn of this run.
    pub max_tokens: u32,
    /// Elide the transcript's middle past this many estimated tokens for the model's benefit.
    /// `0` disables it — see [`crate::compact`].
    pub compact_at_tokens: usize,
}

/// Builds the request for one turn.
///
/// Holds the run's fixed facts and answers the one question the flow varies: given the transcript as
/// it stands and the model a role resolved to, what goes on the wire?
#[derive(Clone, Debug)]
pub struct ContextBuilder {
    facts: ContextFacts,
}

impl ContextBuilder {
    pub fn new(facts: ContextFacts) -> Self {
        Self { facts }
    }

    /// The request for this turn, given the full transcript.
    ///
    /// `transcript` is the loop's own audit trail and is **not** modified: what comes back is a
    /// request whose messages may be a compacted view of it. That separation is the reason this is a
    /// function rather than the loop editing its own transcript before sending — a loop that shrinks
    /// in place cannot then store what actually happened.
    pub fn request(&self, model: &str, transcript: &[Message]) -> ChatRequest {
        let messages = self.messages_for(transcript);

        let mut request = ChatRequest::new(model, messages).with_max_tokens(self.facts.max_tokens);
        if let Some(system) = &self.facts.system {
            request = request.with_system(system.clone());
        }
        // Offered only when there is something to offer: an adapter omits the field for an empty
        // list, and building it here keeps "no tools" one decision instead of an adapter's guess.
        if !self.facts.tools.is_empty() {
            request = request.with_tools(self.facts.tools.clone());
        }
        request
    }

    /// What the model is handed: the transcript, or its compacted view past the threshold.
    ///
    /// Split out from [`ContextBuilder::request`] because this is the half a test cares about on its
    /// own: "was the middle elided" is a question about messages, and asserting it through a whole
    /// built request would drag in the system prompt and the tool schemas for no reason.
    pub fn messages_for(&self, transcript: &[Message]) -> Vec<Message> {
        if self.facts.compact_at_tokens == 0 {
            return transcript.to_vec();
        }
        compact_at(transcript, self.facts.compact_at_tokens).messages
    }

    /// The facts this builder was given, for a caller that wants to report them.
    pub fn facts(&self) -> &ContextFacts {
        &self.facts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_core::message::Role;
    use serde_json::json;

    fn spec(name: &str) -> ToolSpec {
        ToolSpec {
            name: name.to_string(),
            description: format!("the {name} tool"),
            input_schema: json!({ "type": "object", "properties": {} }),
        }
    }

    fn facts() -> ContextFacts {
        ContextFacts {
            system: Some("be terse".to_string()),
            tools: vec![spec("shell"), spec("read_file")],
            max_tokens: 2048,
            compact_at_tokens: 0,
        }
    }

    #[test]
    fn a_run_with_a_system_prompt_sends_it_and_one_without_sends_none() {
        // An empty string is not the same as absent: a provider renders `Some("")` as an empty
        // system block, which some vendors reject and others count as a message. The distinction
        // has to be preserved rather than normalised away.
        let with = ContextBuilder::new(facts()).request("m", &[Message::user("hi")]);
        assert_eq!(with.system.as_deref(), Some("be terse"));

        let mut bare = facts();
        bare.system = None;
        let without = ContextBuilder::new(bare).request("m", &[Message::user("hi")]);
        assert!(without.system.is_none(), "no prompt means no field at all");
    }

    #[test]
    fn a_run_with_no_tools_offers_no_tools_rather_than_an_empty_list() {
        // "Offered nothing" and "offered an empty set" differ on the wire: adapters omit the field
        // for an empty list, and a caller reading the request should see the same thing the
        // provider does.
        let mut bare = facts();
        bare.tools = Vec::new();
        let request = ContextBuilder::new(bare).request("m", &[Message::user("hi")]);
        assert!(request.tools.is_empty(), "nothing to offer");

        let offered = ContextBuilder::new(facts()).request("m", &[Message::user("hi")]);
        assert_eq!(offered.tools.len(), 2, "both declared tools are offered");
    }

    #[test]
    fn the_transcript_the_loop_keeps_is_never_what_the_builder_edits() {
        // The audit trail belongs to the loop and the store. A builder that mutated it in place
        // would make a compacted view the recorded truth, which is the one thing `crate::compact`
        // exists to prevent — and it would do it through a shared slice rather than a visible
        // assignment, so nothing at the call site would look wrong.
        let mut many: Vec<Message> = (0..80)
            .map(|i| {
                Message::user(format!(
                    "message {i} with enough words to be worth counting"
                ))
            })
            .collect();
        many.push(Message::user("the latest question"));

        let mut small = facts();
        small.compact_at_tokens = 50;
        let builder = ContextBuilder::new(small);
        let before = many.len();
        let request = builder.request("m", &many);

        assert_eq!(many.len(), before, "the caller's transcript is untouched");
        assert!(
            request.messages.len() < before,
            "and what is sent really is smaller: sent={} kept={}",
            request.messages.len(),
            before
        );
    }

    #[test]
    fn a_zero_threshold_sends_the_transcript_exactly_as_it_stands() {
        // The identity path has to be exact, not merely "close": a run that configured no
        // compaction must send byte-for-byte what the loop holds, or the setting is a lie.
        let transcript = vec![Message::user("one"), Message::user("two")];
        let request = ContextBuilder::new(facts()).request("m", &transcript);
        assert_eq!(request.messages.len(), transcript.len());
        assert_eq!(request.messages[0].text(), "one");
        assert!(matches!(request.messages[1].role, Role::User));
    }

    #[test]
    fn the_model_and_the_output_allowance_are_carried_not_defaulted() {
        // `ChatRequest::new` defaults `max_tokens` to 4096. A run configured for less that silently
        // sends the default is a run whose budget is not the budget anyone set — and it would only
        // show up as a provider bill or a truncation, never as a failure here.
        let request = ContextBuilder::new(facts()).request("a-role-model", &[Message::user("hi")]);
        assert_eq!(request.model, "a-role-model");
        assert_eq!(request.max_tokens, 2048);
    }
}

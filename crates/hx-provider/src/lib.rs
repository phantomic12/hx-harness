//! Model providers, credential pools, and the limits that govern them.
//!
//! ## Why this crate is not thin
//!
//! Talking to an LLM API is a `POST` with a JSON body. Everything hard about this crate is in
//! the surrounding policy: *which* credential to spend, *how much* of it is left, and what to do
//! when the answer is "none". Three concerns, deliberately separate types:
//!
//! - [`limits::Limiter`] — the accounting. rpm / tpm / rpd / daily-USD / concurrency, all
//!   checked before a request goes out.
//! - [`pool::CredentialPool`] — the selection. Several credentials for one provider, four
//!   routing strategies, health benching on failure.
//! - [`router::ModelRouter`] — the resolution. Config-level *pools* of models and *roles*
//!   (`builder`, `scout`, …) collapse down to one concrete `(provider, credential, model)`.
//!
//! ## Reserve, then reconcile
//!
//! You cannot pre-count completion tokens. A limiter that charges only what it can measure will
//! over-admit: five concurrent requests each look affordable, then each returns 4k tokens and the
//! daily budget is blown. So [`limits::Limiter::acquire`] takes a *reservation* up front
//! ([`provider::ChatRequest::reservation_tokens`], deliberately pessimistic) and
//! [`limits::Limiter::reconcile`] settles the difference once the real [`provider::Usage`]
//! arrives — refunding the surplus or charging the overrun. A reservation that is never
//! reconciled is released at request teardown, which is what makes a crashed request stop
//! leaking budget.
//!
//! ## The wire format
//!
//! [`openai::OpenAiCompatible`] speaks `/v1/chat/completions`, which covers OpenAI itself and
//! essentially every gateway, reseller and local server. Its mapping is two pure functions
//! ([`openai::build_body`], [`openai::parse_response`]) with the HTTP call as the only impure part,
//! so the vendor quirks are asserted against literals rather than discovered in production.
//! [`anthropic::AnthropicMessages`] speaks the Anthropic Messages API (`POST /v1/messages`) with the
//! same two-pure-functions shape: top-level `system`, `tool_result` blocks, `tool_use` blocks, and
//! `stop_reason` for the finish.
//!
//! A turn can be completed whole ([`Provider::complete`]) or streamed as
//! [`StreamDelta`] ([`Provider::stream`], which defaults to replaying a completed turn and which
//! the OpenAI adapter overrides with real SSE). Streaming is opt-in so the well-tested single-shot
//! path is untouched.
//!
//! Not here yet: `GoogleGenAi`, and a retry/backoff layer.
//!
//! Note that the limits/pools/routing layers are deliberately **not** async — they are pure
//! bookkeeping, and making them `async` would buy nothing and make every test a runtime. Only the
//! adapters are async.

pub mod anthropic;
pub mod anthropic_stream;
pub mod limits;
pub mod openai;
pub mod pool;
pub mod provider;
pub mod router;

pub use anthropic::AnthropicMessages;
pub use limits::{Lease, LimitError, Limiter, TokenBucket};
pub use openai::OpenAiCompatible;
pub use pool::{CostPerMtok, CredentialPool, PoolError, Slot, SlotStatus, Ticket};
pub use provider::{
    cost_usd, ChatRequest, ChatResponse, FinishReason, Provider, ProviderRegistry, StreamDelta,
    ToolSpec, Usage,
};
pub use router::{ModelRouter, PoolStatus, Route, RouteTicket, RouterStatus};

#[cfg(test)]
mod tests {
    /// The layers are meant to compose: a router over pools over limiters, all driven from one
    /// config. This checks the seams exist and are wired, without needing a network.
    #[test]
    fn the_three_layers_compose_from_one_config() {
        use crate::{Limiter, ModelRouter};
        use hx_core::config::Config;

        let cfg = Config::from_yaml(
            r#"
providers:
  anthropic-main:
    kind: anthropic
    routing: least_loaded
    models: ["claude-sonnet-4-5", "claude-opus-4-1"]
    credentials:
      - id: cred_a
        secret: "vault:anthropic/a"
        weight: 1
pools:
  interactive:
    strategy: least_loaded
    members: ["anthropic-main/claude-*"]
roles:
  builder: interactive
"#,
        )
        .expect("config should parse");

        let now = chrono::Utc::now();
        let router = ModelRouter::from_config(&cfg, now).expect("router should build");
        assert_eq!(router.pool_for_role("builder").unwrap(), "interactive");
        assert!(router.pool("interactive").is_some());

        // A limiter stands alone too — it is not only reachable through the router.
        let limiter = Limiter::new(
            cfg.providers["anthropic-main"].credentials[0]
                .limits
                .clone(),
            now,
        );
        assert_eq!(limiter.in_flight(), 0);
    }
}

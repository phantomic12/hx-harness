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
//! ## What is not here yet
//!
//! The concrete HTTP adapters (`OpenAiCompatible`, `AnthropicMessages`, `GoogleGenAi`) are M1
//! work: they need `reqwest`, SSE parsing, and a retry/backoff layer, none of which can be
//! proven correct without a server to talk to. The trait they will implement —
//! [`provider::Provider`] — is defined here, and the registry that will hold them
//! ([`provider::ProviderRegistry`]) is real and tested.
//!
//! Note that this crate is deliberately **not** async. Limits, pools and routing are pure
//! bookkeeping; making them `async` would buy nothing and make every test a runtime.

pub mod limits;
pub mod pool;
pub mod provider;
pub mod router;

pub use limits::{Lease, LimitError, Limiter, TokenBucket};
pub use pool::{CostPerMtok, CredentialPool, PoolError, Slot, SlotStatus, Ticket};
pub use provider::{
    cost_usd, ChatRequest, ChatResponse, FinishReason, Provider, ProviderRegistry, ToolSpec, Usage,
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

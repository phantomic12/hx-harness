//! The provider abstraction.
//!
//! One trait, N adapters. The internal [`ChatRequest`]/[`ChatResponse`] shape is deliberately
//! provider-neutral so that adding a vendor never leaks into the agent loop.
//!
//! `OpenAI`-compatible chat-completions is the single highest-leverage adapter to write first:
//! it covers OpenAI itself, Azure OpenAI, OpenRouter, Together, Groq, Fireworks, vLLM, llama.cpp
//! server, Ollama, LiteLLM, and most gateways. Anthropic and Google have bespoke wire formats
//! and get their own modules.

use crate::openai::OpenAiCompatible;
use async_trait::async_trait;
use hx_core::config::{Config, Price, ProviderKind};
use hx_core::error::{HxError, Result};
use hx_core::ids::ProviderId;
use hx_core::message::{approximate_tokens, Message};
use hx_secrets::Secret;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Token accounting as reported by a provider.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Input tokens served from a provider-side prompt cache. Priced far lower on most vendors,
    /// and the clearest signal that context reuse is actually working.
    pub cached_input_tokens: u64,
    /// Thinking tokens, where a provider bills them separately.
    pub reasoning_tokens: u64,
}

impl Usage {
    pub fn total_tokens(&self) -> u64 {
        self.input_tokens + self.output_tokens
    }

    pub fn cache_hit_rate(&self) -> f64 {
        if self.input_tokens == 0 {
            0.0
        } else {
            self.cached_input_tokens as f64 / self.input_tokens as f64
        }
    }
}

/// A tool the model is allowed to call, exported as JSON Schema.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// JSON Schema for the arguments object.
    pub input_schema: serde_json::Value,
}

/// Why generation stopped, normalised across vendors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    /// Natural end of turn.
    Stop,
    /// Hit the output token ceiling.
    Length,
    /// The model wants to call a tool.
    ToolUse,
    ContentFilter,
    Other,
}

/// A request to a model.
#[derive(Clone, Debug)]
pub struct ChatRequest {
    pub model: String,
    pub system: Option<String>,
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSpec>,
    pub max_tokens: u32,
    pub temperature: Option<f32>,
}

impl ChatRequest {
    pub fn new(model: impl Into<String>, messages: Vec<Message>) -> Self {
        Self {
            model: model.into(),
            system: None,
            messages,
            tools: Vec::new(),
            max_tokens: 4096,
            temperature: None,
        }
    }

    pub fn with_system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }

    pub fn with_tools(mut self, tools: Vec<ToolSpec>) -> Self {
        self.tools = tools;
        self
    }

    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }

    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    /// What to *reserve* against the TPM ceiling before sending.
    ///
    /// Deliberately pessimistic: the full prompt plus the entire output allowance. Output
    /// length is unknowable up front, so anything less would let the limiter overshoot. The
    /// surplus is refunded on [`crate::Limiter::reconcile`] once real usage arrives.
    ///
    /// A small per-message overhead is added because every vendor wraps messages in its own
    /// framing tokens; the estimate only has to be close, since it is reconciled away.
    pub fn reservation_tokens(&self) -> u64 {
        const PER_MESSAGE_OVERHEAD: usize = 4;

        let mut prompt = approximate_tokens(&self.messages);
        prompt += self.messages.len() * PER_MESSAGE_OVERHEAD;

        if let Some(system) = &self.system {
            prompt += system.chars().count() / 4 + PER_MESSAGE_OVERHEAD;
        }
        for tool in &self.tools {
            // Tool definitions are re-sent on every call, and they are usually JSON blobs.
            let schema_len = tool.input_schema.to_string().len();
            prompt += (tool.name.len() + tool.description.len() + schema_len) / 4 + 8;
        }

        prompt as u64 + self.max_tokens as u64
    }
}

/// A model's reply.
#[derive(Clone, Debug)]
pub struct ChatResponse {
    pub message: Message,
    pub usage: Usage,
    pub finish: FinishReason,
    pub model: String,
    /// Provider payload, kept for debugging and for features not yet normalised.
    pub raw: Option<serde_json::Value>,
}

/// Price of a response at a given rate card.
pub fn cost_usd(price: &Price, usage: &Usage) -> f64 {
    let cached = usage.cached_input_tokens.min(usage.input_tokens);
    let fresh_input = usage.input_tokens - cached;
    // Cached input is conventionally billed at a fraction of the fresh rate; 10% is the common
    // figure (Anthropic and OpenAI both land near it). Reconciled against real invoices by
    // importing provider usage reports, not guessed at forever.
    const CACHE_DISCOUNT: f64 = 0.1;

    let input = fresh_input as f64 * price.input_per_mtok / 1_000_000.0;
    let cached_cost = cached as f64 * price.input_per_mtok * CACHE_DISCOUNT / 1_000_000.0;
    let output = usage.output_tokens as f64 * price.output_per_mtok / 1_000_000.0;

    input + cached_cost + output
}

/// Every vendor adapter implements this.
#[async_trait]
pub trait Provider: Send + Sync {
    fn id(&self) -> &ProviderId;

    fn kind(&self) -> ProviderKind;

    /// Model ids this provider advertises, used to expand globs in pool membership.
    fn models(&self) -> &[String];

    /// Single-shot completion. Streaming arrives as a separate method in a later milestone so
    /// that the non-streaming path can be correct and well-tested first.
    async fn complete(&self, req: ChatRequest, key: &Secret) -> Result<ChatResponse>;
}

/// Providers available to the daemon, keyed by id.
#[derive(Default)]
pub struct ProviderRegistry {
    providers: IndexMap<ProviderId, Arc<dyn Provider>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, provider: Arc<dyn Provider>) {
        self.providers.insert(provider.id().clone(), provider);
    }

    pub fn get(&self, id: &ProviderId) -> Option<Arc<dyn Provider>> {
        self.providers.get(id).cloned()
    }

    /// Build one adapter per configured provider.
    ///
    /// The client is passed in rather than built here so that a deployment's timeouts, proxy and
    /// user agent are decided in one place — a provider that quietly made its own HTTP client would
    /// be the one that ignores the proxy.
    ///
    /// A kind this build has no adapter for is **refused by name**. Speaking the wrong protocol to
    /// a provider is the failure that looks like a hundred different bugs: the request goes out,
    /// the answer is unparseable, and the error blames the model. Better to fail at startup.
    pub fn from_config(cfg: &Config, client: reqwest::Client) -> Result<Self> {
        let mut registry = Self::new();

        for (name, pc) in &cfg.providers {
            let id = ProviderId::from_raw(name);
            let base_url = pc.base_url.as_deref().ok_or_else(|| {
                HxError::Config(format!(
                    "provider '{name}' has no base_url; the adapter needs an API root \
                     (e.g. https://api.openai.com/v1)"
                ))
            })?;

            let provider: Arc<dyn Provider> = match pc.kind {
                ProviderKind::Openai | ProviderKind::Custom => Arc::new(OpenAiCompatible::new(
                    id.clone(),
                    base_url,
                    pc.models.clone(),
                    client.clone(),
                )),
                // Ollama's OpenAI-compatible surface lives under `/v1`, and the config names the
                // server rather than the API root. Normalising here is what stops every ollama user
                // from having to know that.
                ProviderKind::Ollama => Arc::new(
                    OpenAiCompatible::new(
                        id.clone(),
                        api_root_for_ollama(base_url),
                        pc.models.clone(),
                        client.clone(),
                    )
                    .without_auth(),
                ),
                ProviderKind::Anthropic => {
                    return Err(HxError::Config(format!(
                        "provider '{name}' is configured as `anthropic`, but the Anthropic Messages \
                         adapter does not exist yet (ROADMAP.md M1). Point it at an OpenAI-compatible \
                         gateway, or leave it out of the config until the adapter lands."
                    )))
                }
                ProviderKind::Google => {
                    return Err(HxError::Config(format!(
                        "provider '{name}' is configured as `google`, which has its own wire format \
                         and no adapter yet. Use an OpenAI-compatible gateway in the meantime."
                    )))
                }
            };

            registry.insert(provider);
        }

        Ok(registry)
    }

    pub fn ids(&self) -> Vec<ProviderId> {
        self.providers.keys().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.providers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// Look up a provider and confirm it advertises `model`.
    pub fn resolve(&self, id: &ProviderId, model: &str) -> Result<Arc<dyn Provider>> {
        let provider = self
            .providers
            .get(id)
            .cloned()
            .ok_or_else(|| HxError::Config(format!("unknown provider '{id}'")))?;

        let models = provider.models();
        // An empty model list means "advertises nothing" — trust the caller rather than
        // rejecting a valid model the provider simply does not enumerate.
        if !models.is_empty() && !models.iter().any(|m| m == model) {
            return Err(HxError::NoRoute(format!(
                "provider '{id}' does not list model '{model}'"
            )));
        }
        Ok(provider)
    }
}

impl std::fmt::Debug for ProviderRegistry {
    /// Hand-written because `dyn Provider` is not `Debug`: what a log line needs is which providers
    /// are configured, not the internals of each adapter.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderRegistry")
            .field("providers", &self.providers.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// The API root to speak to an Ollama server's OpenAI-compatible surface.
///
/// Ollama serves `/v1/chat/completions` on the same port as its native API, and the config names
/// the *server* (`http://127.0.0.1:11434`) because that is what every other Ollama tool wants.
/// The adapter needs the API root, so the difference is absorbed here rather than in a comment
/// nobody reads.
fn api_root_for_ollama(base_url: &str) -> String {
    let trimmed = base_url.trim_end_matches('/');
    if trimmed.ends_with("/v1") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/v1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn price(input: f64, output: f64) -> Price {
        Price {
            input_per_mtok: input,
            output_per_mtok: output,
        }
    }

    #[test]
    fn cost_uses_separate_input_and_output_rates() {
        let usage = Usage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            ..Default::default()
        };
        let c = cost_usd(&price(3.0, 15.0), &usage);
        assert!((c - 18.0).abs() < 1e-9, "got {c}");
    }

    #[test]
    fn cached_input_is_billed_at_a_discount() {
        let full = Usage {
            input_tokens: 1_000_000,
            output_tokens: 0,
            cached_input_tokens: 0,
            reasoning_tokens: 0,
        };
        let cached = Usage {
            input_tokens: 1_000_000,
            output_tokens: 0,
            cached_input_tokens: 1_000_000,
            reasoning_tokens: 0,
        };

        let cheap = cost_usd(&price(10.0, 0.0), &cached);
        let dear = cost_usd(&price(10.0, 0.0), &full);

        assert!(cheap < dear, "cache hits must be cheaper");
        assert!((cheap - 1.0).abs() < 1e-9, "10% of $10 got {cheap}");
    }

    #[test]
    fn cached_tokens_are_clamped_to_input_tokens() {
        // A provider reporting more cache hits than input tokens must not produce a negative bill.
        let usage = Usage {
            input_tokens: 100,
            output_tokens: 0,
            cached_input_tokens: 5_000,
            reasoning_tokens: 0,
        };
        let c = cost_usd(&price(10.0, 0.0), &usage);
        assert!(c >= 0.0, "cost must never go negative, got {c}");
    }

    #[test]
    fn reservation_covers_prompt_plus_full_output_allowance() {
        let req =
            ChatRequest::new("m", vec![Message::user("x".repeat(4000))]).with_max_tokens(1000);
        // 4000 chars ~= 1000 tokens, plus the 1000-token output allowance, plus overhead.
        let r = req.reservation_tokens();
        assert!(r >= 2000, "must reserve prompt + output, got {r}");
        assert!(r < 2100, "should not wildly over-reserve, got {r}");
    }

    #[test]
    fn reservation_grows_with_tools_and_system_prompt() {
        let bare = ChatRequest::new("m", vec![Message::user("hi")]).with_max_tokens(100);
        let loaded = ChatRequest::new("m", vec![Message::user("hi")])
            .with_system("y".repeat(2000))
            .with_tools(vec![ToolSpec {
                name: "search".into(),
                description: "z".repeat(2000),
                input_schema: serde_json::json!({"type": "object", "properties": {"q": {"type": "string"}}}),
            }])
            .with_max_tokens(100);

        assert!(
            loaded.reservation_tokens() > bare.reservation_tokens() + 900,
            "tool and system tokens must be counted"
        );
    }

    #[test]
    fn cache_hit_rate_is_zero_when_nothing_was_sent() {
        assert_eq!(Usage::default().cache_hit_rate(), 0.0);
    }

    #[test]
    fn total_tokens_sums_both_directions() {
        let u = Usage {
            input_tokens: 10,
            output_tokens: 5,
            ..Default::default()
        };
        assert_eq!(u.total_tokens(), 15);
    }

    // -- the provider factory ------------------------------------------------------------------

    fn client() -> reqwest::Client {
        reqwest::Client::new()
    }

    fn config_with(providers: Vec<(&str, ProviderKind, &str)>) -> Config {
        let mut config = Config::default();
        for (name, kind, base_url) in providers {
            config.providers.insert(
                name.to_string(),
                hx_core::config::ProviderConfig {
                    kind,
                    base_url: Some(base_url.to_string()),
                    credentials: Vec::new(),
                    routing: hx_core::config::Strategy::Priority,
                    models: vec![format!("{name}-model")],
                    price: None,
                    priority: 0,
                },
            );
        }
        config
    }

    #[test]
    fn the_factory_builds_one_adapter_per_openai_compatible_provider() {
        let config = config_with(vec![
            (
                "openrouter",
                ProviderKind::Openai,
                "https://openrouter.ai/api/v1",
            ),
            ("local", ProviderKind::Ollama, "http://127.0.0.1:11434"),
        ]);
        let registry = ProviderRegistry::from_config(&config, client()).unwrap();

        assert_eq!(registry.len(), 2);
        assert!(registry.get(&ProviderId::from("openrouter")).is_some());
        assert!(registry.get(&ProviderId::from("local")).is_some());
        // The adapter advertises the models the config listed, so `resolve` can check them.
        assert_eq!(
            registry
                .get(&ProviderId::from("openrouter"))
                .unwrap()
                .models(),
            ["openrouter-model"]
        );
    }

    #[test]
    fn ollama_gets_the_v1_api_root_however_the_config_spells_it() {
        // The config names the server; the OpenAI-compatible surface is under /v1. Getting this
        // wrong sends the request to `/chat/completions` on the host root, which 404s.
        assert_eq!(
            api_root_for_ollama("http://127.0.0.1:11434"),
            "http://127.0.0.1:11434/v1"
        );
        assert_eq!(
            api_root_for_ollama("http://127.0.0.1:11434/"),
            "http://127.0.0.1:11434/v1"
        );
        assert_eq!(
            api_root_for_ollama("http://127.0.0.1:11434/v1"),
            "http://127.0.0.1:11434/v1",
            "already an API root: appending again would 404"
        );
    }

    #[test]
    fn an_anthropic_provider_is_refused_by_name_rather_than_spoken_to_in_the_wrong_protocol() {
        let config = config_with(vec![(
            "anthropic",
            ProviderKind::Anthropic,
            "https://api.anthropic.com",
        )]);
        let err = ProviderRegistry::from_config(&config, client()).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("anthropic"), "{text}");
        assert!(
            text.contains("does not exist yet"),
            "the refusal should say why, and that it is temporary: {text}"
        );
    }

    #[test]
    fn a_provider_with_no_base_url_is_refused_with_the_example_in_the_message() {
        let mut config = config_with(vec![("bare", ProviderKind::Openai, "https://x/v1")]);
        config.providers.get_mut("bare").unwrap().base_url = None;

        let err = ProviderRegistry::from_config(&config, client()).unwrap_err();
        assert!(
            err.to_string().contains("https://api.openai.com/v1"),
            "{err}"
        );
    }
}

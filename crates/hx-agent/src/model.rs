//! How the loop calls a model.
//!
//! One method, deliberately: the loop does not care whether the answer came from a pool of
//! credentials with a rate limiter in front of it, from a local llama.cpp server, or from a
//! scripted double in a test. [`DirectProvider`] is the simple case — one provider, one credential
//! — and the router-backed version lands with the budget accounting.

use async_trait::async_trait;
use hx_core::error::Result;
use hx_core::ids::{CredentialId, ProviderId};
use hx_provider::{ChatRequest, ChatResponse, Provider};
use hx_secrets::Secret;
use std::sync::Arc;

#[async_trait]
pub trait ModelCall: Send + Sync {
    async fn complete(&self, req: ChatRequest) -> Result<ChatResponse>;

    /// The model id this callable targets, for the request and for logs.
    fn model(&self) -> String;

    fn provider_id(&self) -> ProviderId;

    fn credential_id(&self) -> CredentialId;
}

/// One provider, one credential.
///
/// The credential is resolved by the caller (from the vault, via the pool) and handed over for the
/// lifetime of this callable: the loop must not be able to pick a different one mid-run, because
/// "which key paid for that turn" is exactly the kind of thing that should be answerable from the
/// transcript.
pub struct DirectProvider {
    provider: Arc<dyn Provider>,
    credential: CredentialId,
    model: String,
    key: Secret,
}

impl DirectProvider {
    pub fn new(
        provider: Arc<dyn Provider>,
        credential: CredentialId,
        model: impl Into<String>,
        key: Secret,
    ) -> Self {
        Self {
            provider,
            credential,
            model: model.into(),
            key,
        }
    }
}

#[async_trait]
impl ModelCall for DirectProvider {
    async fn complete(&self, req: ChatRequest) -> Result<ChatResponse> {
        // The key travels by reference to the provider and goes no further: no `Debug`, no clone
        // into the transcript.
        self.provider.complete(req, &self.key).await
    }

    fn model(&self) -> String {
        self.model.clone()
    }

    fn provider_id(&self) -> ProviderId {
        self.provider.id().clone()
    }

    fn credential_id(&self) -> CredentialId {
        self.credential.clone()
    }
}

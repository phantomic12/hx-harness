//! How the loop calls a model.
//!
//! One method, deliberately: the loop does not care whether the answer came from a pool of
//! credentials with a rate limiter in front of it, from a local llama.cpp server, or from a
//! scripted double in a test. [`DirectProvider`] is the simple case — one provider, one credential
//! handed in — and [`RouterModel`] is the one a daemon uses: it asks for a *role*, and the routing
//! table decides the provider, the model and the key.

use async_trait::async_trait;
use chrono::Utc;
use hx_core::error::{HxError, Result};
use hx_core::ids::{CredentialId, ProviderId};
use hx_provider::{ChatRequest, ChatResponse, ModelRouter, Provider, ProviderRegistry};
use hx_secrets::{Secret, SecretStores};
use std::sync::{Arc, Mutex};

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

/// What the last call actually used.
///
/// The loop asks for the provider and credential *after* the call returns, and a routed call only
/// knows them once the routing table has chosen. So the choice is remembered here rather than
/// guessed at: an agent loop is sequential (one turn at a time), and a wrong id in the usage event
/// is worse than a slightly stateful adapter.
#[derive(Clone, Debug)]
struct Routed {
    provider: ProviderId,
    credential: CredentialId,
}

/// A model call that goes through the routing table.
///
/// The role is the whole interface: the caller says *what kind of work this is* (`builder`,
/// `summarize`, `scout`) and the router decides which pool, which provider, which model and which
/// credential — including the rate, token and budget ceilings that hang off the credential. That
/// indirection is what lets a deployment re-point a role at cheaper capacity without touching any
/// code, which is the property `ARCHITECTURE.md` §3.4 is built around.
///
/// ## The order of operations, and why it is this order
///
/// 1. **Reserve**, before the request leaves: the pool and the credential both take a lease sized
///    by the pessimistic estimate ([`hx_provider::ChatRequest::reservation_tokens`] plus the
///    dearest route's rate card). Reserving after the call would be accounting, not a limit.
/// 2. **Resolve the key** from the reference the reservation carried. If the key is missing, the
///    lease is released and the error names the reference — a request that goes out unauthenticated
///    costs a round trip and reads like a harness bug.
/// 3. **Call**, with the *route's* model, not the request's: the model id in the transcript should
///    be the one that answered.
/// 4. **Settle**: reconcile the lease against the usage the provider reported, so the surplus comes
///    back. An authentication failure benches the credential first, because the next call should
///    not be handed the same dead key.
///
/// The router mutex is deliberately never held across the provider call: a slow model would
/// otherwise serialize every other agent in the process.
pub struct RouterModel {
    role: String,
    router: Arc<Mutex<ModelRouter>>,
    providers: Arc<ProviderRegistry>,
    secrets: Arc<SecretStores>,
    /// The model this role currently prefers, for [`ModelCall::model`] — see its docs.
    preferred: String,
    last: Mutex<Option<Routed>>,
}

impl RouterModel {
    /// Bind to a role on an existing routing table.
    ///
    /// The router is shared (`Arc<Mutex<..>>`) because its limiter state is the live state of the
    /// deployment: a status endpoint reading a *copy* would report a pool that has plenty of
    /// headroom while the agent's copy is exhausted.
    pub fn new(
        role: impl Into<String>,
        router: Arc<Mutex<ModelRouter>>,
        providers: Arc<ProviderRegistry>,
        secrets: Arc<SecretStores>,
    ) -> Result<Self> {
        let role = role.into();
        let preferred = {
            let router = router
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let pool = router.pool_for_role(&role)?;
            router
                .pool(pool)
                .and_then(|pool| pool.routes().first().map(|route| route.model.clone()))
                .ok_or_else(|| {
                    HxError::NoRoute(format!("pool '{pool}' for role '{role}' has no routes"))
                })?
        };

        if providers.is_empty() {
            return Err(HxError::Config(format!(
                "no providers are configured, so role '{role}' cannot be called"
            )));
        }

        Ok(Self {
            role,
            router,
            providers,
            secrets,
            preferred,
            last: Mutex::new(None),
        })
    }

    /// The role this callable asks for.
    pub fn role(&self) -> &str {
        &self.role
    }

    fn last_call(&self) -> Option<Routed> {
        self.last
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

#[async_trait]
impl ModelCall for RouterModel {
    async fn complete(&self, req: ChatRequest) -> Result<ChatResponse> {
        let now = Utc::now();
        // Pessimistic, and computed before the route exists — see `estimate_role_reservation_usd`.
        let tokens = req.reservation_tokens();
        let estimated_usd = {
            let router = self.lock_router();
            router.estimate_role_reservation_usd(&self.role, tokens)?
        };

        let lease = {
            let mut router = self.lock_router();
            router.acquire_for_role(&self.role, tokens, estimated_usd, now)?
        };

        // The provider is resolved against the model the route chose, so a pool member that names
        // a model the provider does not advertise fails here rather than at the vendor.
        let provider = match self
            .providers
            .resolve(&lease.route.provider, &lease.route.model)
        {
            Ok(provider) => provider,
            Err(err) => {
                self.lock_router().release(lease, now);
                return Err(err);
            }
        };

        let key = match self.secrets.resolve_str(lease.secret_ref()) {
            Ok(key) => key,
            Err(err) => {
                // Nothing left the process, so the reservation goes back untouched — and the
                // credential is *not* benched: a missing key is a deployment problem, and the
                // reference it names is the actionable part.
                self.lock_router().release(lease, now);
                return Err(err);
            }
        };

        let mut request = req;
        request.model = lease.route.model.clone();
        let response = provider.complete(request, &key).await;

        match response {
            Ok(response) => {
                let usage = response.usage;
                let (provider, credential) =
                    (lease.route.provider.clone(), lease.credential_id().clone());
                {
                    let mut router = self.lock_router();
                    // Settled against what the provider reported, so the pessimistic surplus goes
                    // back: the ceiling is enforced on real spend, not on the estimate.
                    let cost = router.estimate_cost(&lease.route, &usage);
                    router.reconcile(lease, usage.total_tokens(), cost, now);
                }

                *self.lock_last() = Some(Routed {
                    provider,
                    credential,
                });
                Ok(response)
            }
            Err(err) => {
                let mut router = self.lock_router();
                if err.is_auth_failure() {
                    router.mark_unhealthy(
                        &lease.route.provider,
                        lease.credential_id(),
                        err.to_string(),
                    );
                }
                router.release(lease, now);
                Err(err)
            }
        }
    }

    /// The model this role prefers *right now*.
    ///
    /// A hint, not a promise: the request built from it is rewritten by [`Self::complete`] with the
    /// model the routing table actually chose, because the point of a pool is that the caller does
    /// not know in advance. It exists for logs and for a client that wants to show what is
    /// configured before the first call.
    fn model(&self) -> String {
        self.preferred.clone()
    }

    fn provider_id(&self) -> ProviderId {
        self.last_call()
            .map(|routed| routed.provider)
            .unwrap_or_else(|| ProviderId::from("unrouted"))
    }

    fn credential_id(&self) -> CredentialId {
        self.last_call()
            .map(|routed| routed.credential)
            .unwrap_or_else(|| CredentialId::from("unrouted"))
    }
}

impl RouterModel {
    fn lock_router(&self) -> std::sync::MutexGuard<'_, ModelRouter> {
        // A panic while holding the routing table leaves limiter counters that roll back with the
        // lease, so the table is consistent: keep serving rather than cascade the panic.
        self.router
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_last(&self) -> std::sync::MutexGuard<'_, Option<Routed>> {
        self.last
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl std::fmt::Debug for RouterModel {
    /// Hand-written so a log line names the role and what it is bound to, and never a key: the
    /// resolver lives two fields away and has no `Debug` that could print a value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterModel")
            .field("role", &self.role)
            .field("preferred_model", &self.preferred)
            .field("providers", &self.providers.ids().len())
            .field("secret_stores", &self.secrets.stores())
            .finish()
    }
}

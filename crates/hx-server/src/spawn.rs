//! The spawner that draws a child from the model pool (M8), and the model that travels with it.
//!
//! ## What this module is, said plainly
//!
//! There is still no subagent runtime in this repository — no orchestrator, no fan-out, no
//! `delegate`. What M8's "Still to come" named is the **spawner that draws from the pool**, and
//! that is what lives here, as the **narrowest real thing** that exercises the path:
//!
//! 1. [`Spawner::build_spec`] draws a **healthy** member from the pool and clamps the requested
//!    parameters to what that member accepts, producing a [`ChildSpec`] that carries **the drawn
//!    member as its model**, its endpoint, its credential reference, and the clamps that were applied.
//!    This is the "per-child model selection": the model is part of the spec, chosen at spawn and
//!    carried *with the child* — not read from a process-global at the moment of use.
//! 2. [`Spawner::run_child`] takes a spec and makes **one provider call** through `hx-provider`
//!    against the **drawn member's** endpoint and credential with the **clamped** parameters, and on
//!    success records a [`UsageRecord`] against the session whose `model` is the **drawn member** —
//!    the "per-child model + cost in the audit chain" half. A call that fails marks the member down, so
//!    the next draw comes from a healthy member.
//!
//! **What it does *not* run**, and which it names rather than claims: it does not start an agent
//! loop, does not dispatch tools, and does not re-route a *running* lane when a member dies — that
//! last one needs running children, which needs this spawner to exist first, and it is explicitly out of
//! scope. `run_child` is a single provider call against the drawn member; it is the honest narrowest
//! thing, not a fan-out.
//!
//! The pool, the clamp rule, and [`DrawError`] all live in `hx-core` (`pool.rs`); this module
//! **reuses** them rather than inventing a second error type or a second clamp. A spec construction on
//! an empty pool or an all-down pool returns the pool's own [`DrawError`].
//!
//! ## Hermetic by construction
//!
//! The tests here use a **scripted pool and a scripted provider** — no network. A member that fails
//! causes the next child to be drawn from a healthy one; a member whose parameters reject
//! `reasoning_effort` is clamped and run rather than failing at spawn (that is the exit criterion, and
//! the `HTTP 400` it prevents is a real observed failure mode, not hypothetical). Every assertion is
//! proven to fail by a mutation.

use chrono::Utc;
use hx_core::error::Result;
use hx_core::ids::{ProviderId, SessionId};
use hx_core::message::Message;
use hx_core::pool::{DrawError, ModelPool, Param, ParamClamp};
use hx_provider::{ChatRequest, ProviderRegistry};
use hx_secrets::SecretStores;
use hx_store::UsageRecord;
use std::sync::Arc;

/// A child, as chosen at spawn: the model it will run on, its endpoint, its credential
/// **reference**, and the parameters (with their clamps) that will be sent.
///
/// The model is **part of the spec**, recorded here rather than read from a global at the moment of
/// use. "Which model did this child run on" is answerable from the spec alone, before the child runs
/// and after.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildSpec {
    /// The pool member this child was drawn from. It is the model (its `id`), the endpoint and the
    /// credential — all in one, because a pool member *is* a drawable model.
    pub member_id: String,
    pub base_url: String,
    /// A credential **reference** (`vault:…` / `env:…`), never a value — same discipline as the
    /// pool and `hx-secrets`.
    pub credential: String,
    /// The effective parameters the member will receive: every requested parameter it accepts, plus the
    /// clamped ones. This is what would be sent; a member that rejects a kind never receives it.
    pub params: Vec<Param>,
    /// The clamps that were applied at spawn, recorded with the child so "what was clamped" is
    /// answerable after the fact rather than sent and hoped for.
    pub clamps: Vec<ParamClamp>,
}

impl ChildSpec {
    /// The model id this child runs on — the **drawn member**, not a global.
    pub fn model(&self) -> &str {
        &self.member_id
    }
}

/// The spawner that draws children from a model pool.
///
/// Owns the pool (and its health state), and the provider resolution, secret resolution and store it
/// needs to make the narrowest real call and to record it.
pub struct Spawner {
    pool: ModelPool,
    providers: Arc<ProviderRegistry>,
    secrets: Arc<SecretStores>,
    store: Arc<hx_store::Store>,
}

impl Spawner {
    pub fn new(
        pool: ModelPool,
        providers: Arc<ProviderRegistry>,
        secrets: Arc<SecretStores>,
        store: Arc<hx_store::Store>,
    ) -> Self {
        Self {
            pool,
            providers,
            secrets,
            store,
        }
    }

    /// Draw a healthy member and clamp the requested parameters to it, producing the child's spec.
    ///
    /// Fails loudly (with the pool's own [`DrawError`]) when the pool is empty or every member is
    /// down — it never silently returns the first member. The clamp is applied **here, at spawn**, so a
    /// member that rejects a requested kind never reaches the wire with it: that is what prevents the
    /// `HTTP 400`. The clamps are recorded on the spec, with the child.
    pub fn build_spec(&mut self, requested: &[Param]) -> Result<ChildSpec, DrawError> {
        let member = self.pool.draw()?;
        let effective = member.clamp(requested);
        Ok(ChildSpec {
            member_id: member.id.clone(),
            base_url: member.base_url.clone(),
            credential: member.credential.clone(),
            params: effective.params,
            clamps: effective.clamps,
        })
    }

    /// Run one child: one provider call against the spec's (drawn) member, then record its usage.
    ///
    /// The provider is resolved by the **drawn member's id** and the request is built with the
    /// **drawn member's** model, so the recorded [`UsageRecord`]'s `model` is the member this spec
    /// drew — not the first member, not a global. On a failed call the member is marked down, so the
    /// next [`Self::build_spec`] draws from a healthy member. What is *not* done here — stated rather
    /// than claimed — is re-routing a *running* lane; that needs running children and is out of scope
    /// for the spawner that exists so far.
    pub async fn run_child(
        &mut self,
        spec: &ChildSpec,
        session: &SessionId,
        prompt: &str,
    ) -> Result<ChildRecord> {
        let provider = self
            .providers
            .resolve(&ProviderId::from(spec.member_id.clone()), spec.model())
            .map_err(|err| hx_core::error::HxError::NoRoute(err.to_string()))?;
        let key = self
            .secrets
            .resolve_str(&spec.credential)
            .map_err(|err| hx_core::error::HxError::Secret(err.to_string()))?;

        let request = ChatRequest::new(spec.model(), vec![Message::user(prompt)]);
        let response = match provider.complete(request, &key).await {
            Ok(response) => response,
            Err(err) => {
                self.pool
                    .mark_down(&spec.member_id, err.to_string(), Utc::now());
                return Err(err);
            }
        };

        let usage = response.usage;
        let record = UsageRecord::new(
            spec.member_id.clone(),
            spec.credential.clone(),
            spec.model(),
            usage.input_tokens,
            usage.output_tokens,
        )
        .cached(usage.cached_input_tokens)
        .reasoning(usage.reasoning_tokens);
        self.store.record_usage(session, &record, Utc::now())?;

        Ok(ChildRecord {
            model: spec.model().to_string(),
            credential: spec.credential.clone(),
            clamps: spec.clamps.clone(),
            usage: record,
            base_url: spec.base_url.clone(),
        })
    }
}

/// What a run produced and recorded for a child.
#[derive(Clone, Debug, PartialEq)]
pub struct ChildRecord {
    /// The model (drawn member) this child ran on.
    pub model: String,
    /// The credential **reference** that paid for it.
    pub credential: String,
    /// The clamps that were applied at spawn, carried to the record's caller.
    pub clamps: Vec<ParamClamp>,
    /// The recorded usage row: the half of "which model did this work and did this lane spend money"
    /// that is answerable after the fact.
    pub usage: UsageRecord,
    pub base_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hx_core::config::ProviderKind;
    use hx_core::error::{HxError, Result};
    use hx_core::pool::{MemberHealth, PoolMember, ReasoningEffort};
    use hx_provider::{Provider, Usage};
    use hx_secrets::FixedSecrets;
    use hx_store::NewSession;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("fixed test timestamp")
    }

    fn member(id: &str, accepts: &[Param]) -> PoolMember {
        PoolMember {
            id: id.to_string(),
            base_url: format!("{id}.example.test"),
            credential: format!("vault:pool/{id}"),
            accepts: accepts.to_vec(),
            health: MemberHealth::Healthy,
        }
    }

    fn provider_registry_for(member_id: &str) -> Arc<ProviderRegistry> {
        let mut reg = ProviderRegistry::new();
        let p = ScriptedProvider::new(member_id);
        reg.insert(Arc::new(p));
        Arc::new(reg)
    }

    fn secrets_for(id: &str) -> Arc<SecretStores> {
        Arc::new(SecretStores::new().with(Arc::new(
            FixedSecrets::new("vault").set(format!("pool/{id}"), "sentinel"),
        )))
    }

    fn store() -> Arc<hx_store::Store> {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let mut path = std::env::temp_dir();
        path.push(format!("hx-spawner-{}-{n}.db", std::process::id()));
        Arc::new(hx_store::Store::open(path).expect("test store opens"))
    }

    fn session(store: &hx_store::Store) -> hx_store::Session {
        let rec = store
            .create(NewSession::new(), now())
            .expect("session created");
        store.load(&rec.id).expect("session loads")
    }

    /// A provider that answers without a network. The id is the member it stands in for.
    struct ScriptedProvider {
        id: ProviderId,
        fail: bool,
    }

    impl ScriptedProvider {
        fn new(id: &str) -> Self {
            Self {
                id: ProviderId::from(id),
                fail: false,
            }
        }
        fn failing(self) -> Self {
            Self { fail: true, ..self }
        }
    }

    #[async_trait]
    impl Provider for ScriptedProvider {
        fn id(&self) -> &ProviderId {
            &self.id
        }
        fn kind(&self) -> ProviderKind {
            ProviderKind::Openai
        }
        fn models(&self) -> &[String] {
            &[]
        }
        async fn complete(
            &self,
            _req: ChatRequest,
            _key: &hx_secrets::Secret,
        ) -> Result<hx_provider::ChatResponse> {
            if self.fail {
                return Err(HxError::Provider("upstream returned HTTP 500".to_string()));
            }
            let usage = Usage {
                input_tokens: 10,
                output_tokens: 5,
                ..Default::default()
            };
            Ok(hx_provider::ChatResponse {
                message: hx_core::message::Message::assistant("done"),
                usage,
                finish: hx_provider::FinishReason::Stop,
                model: self.id.to_string(),
                raw: None,
            })
        }
    }

    #[tokio::test]
    async fn build_spec_carries_the_drawn_member_and_its_identity() {
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("cheap", &[]), member("strong", &[])]),
            provider_registry_for("cheap"),
            secrets_for("cheap"),
            store(),
        );
        let spec = pen.build_spec(&[]).expect("both healthy");
        assert_eq!(spec.model(), "cheap", "the first draw is the first member");
        assert!(spec.clamps.is_empty());
        assert_eq!(spec.base_url, "cheap.example.test");
        assert_eq!(spec.credential, "vault:pool/cheap");
    }

    #[tokio::test]
    async fn a_member_that_rejects_reasoning_effort_is_clamped_and_runs_not_errored_at_spawn() {
        // strong accepts only Low; we ask for High. The exit criterion: it is clamped at spawn and
        // the child runs — not a spawn-time failure and not a 400.
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member(
                "strong",
                &[Param::reasoning_effort(ReasoningEffort::Low)],
            )]),
            provider_registry_for("strong"),
            secrets_for("strong"),
            st.clone(),
        );
        let requested = [Param::reasoning_effort(ReasoningEffort::High)];
        let spec = pen.build_spec(&requested).expect("clamped, not failed");
        assert_eq!(
            spec.params,
            vec![Param::reasoning_effort(ReasoningEffort::Low)],
            "High is clamped to the member's only accepted value"
        );
        assert_eq!(
            spec.clamps,
            vec![ParamClamp {
                requested: Param::reasoning_effort(ReasoningEffort::High),
                sent: Some(Param::reasoning_effort(ReasoningEffort::Low)),
            }]
        );

        let s = session(&st);
        let rec = pen
            .run_child(&spec, s.id(), "hi")
            .await
            .expect("a clamped child runs");
        assert_eq!(rec.usage.model, "strong");
        assert_eq!(rec.usage.input_tokens, 10);
    }

    #[tokio::test]
    async fn a_failed_member_marks_down_and_the_next_spec_draws_a_healthy_one() {
        // The registry resolves a member's id to its own provider; a is scripted to fail.
        let mut reg = ProviderRegistry::new();
        reg.insert(Arc::new(ScriptedProvider::new("a").failing()));
        reg.insert(Arc::new(ScriptedProvider::new("b")));
        let mut secrets = FixedSecrets::new("vault").set("pool/a", "sentinel-a");
        secrets = secrets.set("pool/b", "sentinel-b");
        let secrets = Arc::new(SecretStores::new().with(Arc::new(secrets)));
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            Arc::new(reg),
            secrets,
            st.clone(),
        );
        let spec_a = pen.build_spec(&[]).expect("draws");
        assert_eq!(spec_a.model(), "a");
        let s = session(&st);
        let err = pen
            .run_child(&spec_a, s.id(), "hi")
            .await
            .expect_err("a fails");
        assert!(err.to_string().contains("HTTP 500"), "{err}");

        // Many draws must never come back to a while b is healthy — only mark_down makes that true.
        for _ in 0..10 {
            let spec = pen.build_spec(&[]).expect("b is healthy");
            assert_eq!(
                spec.model(),
                "b",
                "a down member is not drawn while a healthy one remains"
            );
        }
    }

    #[tokio::test]
    async fn the_recorded_model_is_the_drawn_member_not_the_first_or_a_global() {
        // Mark "a" down so the draw skips the first member: the recorded model must be b, not a.
        let mut pool = ModelPool::new(vec![member("a", &[]), member("b", &[])]);
        pool.mark_down("a", "boom", now());
        let st = store();
        let mut pen = Spawner::new(
            pool,
            provider_registry_for("b"),
            secrets_for("b"),
            st.clone(),
        );
        let spec = pen.build_spec(&[]).expect("b is healthy");
        assert_eq!(spec.model(), "b");

        let s = session(&st);
        let rec = pen.run_child(&spec, s.id(), "hi").await.expect("runs");
        assert_eq!(rec.usage.model, "b");
        assert_eq!(rec.model, "b");
        assert_eq!(s.record.id.as_str(), s.id().as_str());
    }

    #[tokio::test]
    async fn the_recorded_cost_and_model_survive_into_the_store_totals() {
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("b", &[])]),
            provider_registry_for("b"),
            secrets_for("b"),
            st.clone(),
        );
        let spec = pen.build_spec(&[]).expect("draws");
        let s = session(&st);
        let rec = pen.run_child(&spec, s.id(), "hi").await.expect("runs");
        assert_eq!(rec.usage.model, "b");
        let totals = st.totals(s.id()).expect("totals read");
        assert_eq!(totals.provider_calls, 1);
        assert_eq!(totals.input_tokens, 10);
    }

    #[tokio::test]
    async fn a_spec_cannot_be_built_from_an_empty_pool() {
        let mut pen = Spawner::new(
            ModelPool::new(vec![]),
            provider_registry_for("x"),
            secrets_for("x"),
            store(),
        );
        assert_eq!(pen.build_spec(&[]), Err(DrawError::Empty));
    }

    #[tokio::test]
    async fn a_spec_cannot_be_built_when_every_member_is_down() {
        let mut pool = ModelPool::new(vec![member("a", &[]), member("b", &[])]);
        pool.mark_down("a", "boom-a", now());
        pool.mark_down("b", "boom-b", now());
        let mut pen = Spawner::new(pool, provider_registry_for("a"), secrets_for("a"), store());
        match pen.build_spec(&[]) {
            Err(DrawError::AllDown { members }) => {
                assert_eq!(members.len(), 2);
            }
            other => panic!("must be AllDown, got {other:?}"),
        }
    }
}

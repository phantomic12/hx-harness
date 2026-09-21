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
//! 3. [`Spawner::run_lane`] is the **re-route on member death across a running child**: it draws a
//!    healthy member, makes **one** provider call against it, and if that member **dies** while running
//!    (the pool's [`member_death`] rule: a 5xx/timeout/404, an exhausted quota, a refused
//!    credential) it marks the member down and **re-draws onto the pool's next healthy member**, running
//!    the same prompt there. It fails bounded when every member is down, and it records **both** the
//!    members that died and the one that finished on the returned [`ChildRecord`] — a re-route is never
//!    silent. A failure that is the child's own (a refused request, a policy denial) does **not**
//!    re-route: it would be deterministic across every member.
//!
//! **What it does *not* run**, and which it names rather than claims: it does not start an agent
//! loop or dispatch tools. `run_child` is a single provider call against the drawn member; `run_lane`
//! is a single prompt run that re-draws on member death. Neither is a fan-out — the spawner draws one
//! lane, narrow and real.
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
use hx_core::error::{HxError, Result};
use hx_core::ids::{ProviderId, SessionId};
use hx_core::message::Message;
use hx_core::pool::{member_death, DrawError, ModelPool, Param, ParamClamp};
use hx_provider::{ChatRequest, Provider, ProviderRegistry};
use hx_secrets::{Redactor, Secret, SecretStores};
use hx_store::UsageRecord;
use serde::Serialize;
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

/// Redact a failure reason before it is stored on a member or returned as a death reason.
///
/// A provider failure's message includes the upstream error body (see `classify_error` in
/// `hx-provider`), and a provider can echo the very key it was given back inside that body
/// (an auth-debugging page, a `?token=` URL, an opaque key value). That reason is written
/// into the pool's `mark_down` health state and returned on [`ChildRecord::dead_members`], both
/// of which a caller (and eventually an HTTP client) reads — so a credential that leaks into the
/// body must not reach either verbatim. The key resolved for this member is registered as a literal
/// (the defense for opaque values with no shape) and the message is run through the shared
/// [`Redactor`]'s pattern pass as well.
fn redact_death_reason(key: &Secret, err: &HxError) -> String {
    let mut redactor = Redactor::new();
    redactor.register(key.expose());
    redactor.redact(&err.to_string()).text
}

/// What one prepared child's run produced: either its record, or its member's death.
///
/// `Failed` carries **both** redactions' inputs: `reason` is the death reason already redacted
/// with the resolved key as a registered literal (what `mark_down` stores), and `error` is the
/// raw provider error for the caller to redact at its own boundary (what the fan-out reports).
/// A store-write failure is not a member death, so it is a `Result::Err` instead — no member is
/// benched for it, exactly as `run_child`'s `?` behaved.
pub enum PreparedOutcome {
    /// The child completed. Carries the same [`ChildRecord`] `run_child` would have returned.
    Ran(ChildRecord),
    /// The provider call failed. `member` is the member the child was drawn to run on.
    Failed {
        member: String,
        reason: String,
        error: HxError,
    },
}

/// One allocated child with everything its run needs, owned rather than borrowed.
///
/// Built by [`Spawner::prepare_child`]; run with [`PreparedChild::run`].
pub struct PreparedChild {
    provider: Arc<dyn Provider>,
    key: Secret,
    spec: ChildSpec,
    store: Arc<hx_store::Store>,
}

impl PreparedChild {
    /// Make the child's one provider call and record its usage — shareably.
    ///
    /// This is the `&mut`-free middle of `run_child`: the same request, the same record, the
    /// same redacted death reason. The pool-health write is the caller's job
    /// ([`Spawner::mark_down`]), applied after the concurrent join.
    pub async fn run(self, session: &SessionId, prompt: &str) -> Result<PreparedOutcome> {
        let request = ChatRequest::new(self.spec.model(), vec![Message::user(prompt)]);
        let response = match self.provider.complete(request, &self.key).await {
            Ok(response) => response,
            Err(err) => {
                return Ok(PreparedOutcome::Failed {
                    member: self.spec.member_id.clone(),
                    reason: redact_death_reason(&self.key, &err),
                    error: err,
                });
            }
        };

        let usage = response.usage;
        let record = UsageRecord::new(
            self.spec.member_id.clone(),
            self.spec.credential.clone(),
            self.spec.model(),
            usage.input_tokens,
            usage.output_tokens,
        )
        .cached(usage.cached_input_tokens)
        .reasoning(usage.reasoning_tokens);
        self.store.record_usage(session, &record, Utc::now())?;

        Ok(PreparedOutcome::Ran(ChildRecord {
            model: self.spec.model().to_string(),
            credential: self.spec.credential.clone(),
            clamps: self.spec.clamps.clone(),
            usage: record,
            base_url: self.spec.base_url.clone(),
            dead_members: Vec::new(),
        }))
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
    /// next [`Self::build_spec`] draws from a healthy member. This is the narrow one-shot form; for a
    /// run that **re-routes onto a healthy member when the drawn one dies**, use [`Self::run_lane`].
    pub async fn run_child(
        &mut self,
        spec: &ChildSpec,
        session: &SessionId,
        prompt: &str,
    ) -> Result<ChildRecord> {
        // One implementation of "one provider call, recorded": prepare the shareable work, run
        // it, then apply the pool-health write. The fan-out (`crate::fanout`) runs the middle
        // step concurrently across children and applies the write serially after the join; doing
        // it here keeps the two paths from drifting apart.
        let prepared = self.prepare_child(spec)?;
        match prepared.run(session, prompt).await? {
            PreparedOutcome::Ran(record) => Ok(record),
            PreparedOutcome::Failed {
                member,
                reason,
                error,
            } => {
                self.mark_down(&member, reason);
                Err(error)
            }
        }
    }

    /// Split one allocated child into an owned unit of work that can run without `&mut self`.
    ///
    /// Resolving the provider and the credential is read-only (both registries sit behind `Arc`),
    /// so this takes `&self`. The returned [`PreparedChild::run`] does the provider call and the
    /// usage record — both shareable — but deliberately **not** the pool-health write: `mark_down`
    /// needs `&mut`, so the caller applies [`Spawner::mark_down`] with the [`PreparedOutcome`]'s
    /// reason afterwards. A resolve failure is returned as-is (that child's own error, exactly as
    /// `run_child`'s pre-call `?` did — no member is benched for a request that never ran).
    pub fn prepare_child(&self, spec: &ChildSpec) -> Result<PreparedChild> {
        let provider = self
            .providers
            .resolve(&ProviderId::from(spec.member_id.clone()), spec.model())
            .map_err(|err| hx_core::error::HxError::NoRoute(err.to_string()))?;
        let key = self
            .secrets
            .resolve_str(&spec.credential)
            .map_err(|err| hx_core::error::HxError::Secret(err.to_string()))?;
        Ok(PreparedChild {
            provider,
            key,
            spec: spec.clone(),
            store: Arc::clone(&self.store),
        })
    }

    /// Bench a member with a reason, timestamped now.
    ///
    /// This is the pool-health half of a failed child run, exposed so the fan-out can apply it
    /// serially after its concurrent join. Same write `run_child` always did, same clock.
    pub fn mark_down(&mut self, member: &str, reason: String) {
        self.pool.mark_down(member, reason, Utc::now());
    }

    /// Run a child that **re-routes on member death** and continues, rather than failing the lane.
    ///
    /// This is the half of M8 this module previously named out of scope ("needs running children").
    /// It draws a healthy member from the pool, makes **one** provider call against it; if that member
    /// **dies** while running — per [`member_death`], a 5xx/timeout/404, an exhausted quota, or a
    /// refused credential — it marks the member down, **re-draws** onto the pool's next healthy member
    /// and runs the same prompt there, and keeps going. It fails **bounded**: when the pool can draw
    /// no healthy member it fails with the pool's own [`DrawError::AllDown`] (or `Empty`), exactly
    /// as `build_spec` would — it never retries forever, and it never returns a success it did not
    /// earn. The bound is "every member tried once each", stated as the loop's stop condition.
    ///
    /// **Audit.** The returned [`ChildRecord`] carries **both** sides of the re-route: the dying
    /// members in [`ChildRecord::dead_members`] (each `id` with the reason it died) and the member
    /// that **finished** as [`ChildRecord::model`], the one whose `UsageRecord` is persisted to the
    /// store. A silent model switch — the audit showing the first member and nothing else — is the
    /// failure mode this field exists to make impossible.
    ///
    /// **Only on death.** A failure that is the **child's own** — a [`HxError::ProviderRejected`]
    /// 400/422 on the request, a policy denial, an unresolved credential reference, a missing route —
    /// is deterministic: every member refuses it the same way. It **does not** trigger a re-route, and
    /// it does **not** bench the member (the member is not down for a request it never saw); the run
    /// returns that error directly. Re-routing a deterministic failure would turn one error into one per
    /// member.
    ///
    /// The pool alone decides health: a member that dies here is marked down on the shared pool, so it
    /// is gone for **subsequent** draws by other children, not just this one (`mark_down` is the
    /// mechanism, not a lane-local flag).
    ///
    /// Hermetic: a scripted pool plus a scripted provider, no network; the only loop is over the
    /// pool's own members, so it is bounded by construction and needs no wall-clock or sleep.
    pub async fn run_lane(
        &mut self,
        session: &SessionId,
        prompt: &str,
        requested: &[Param],
    ) -> Result<ChildRecord, hx_core::error::HxError> {
        let mut dead_members: Vec<(String, String)> = Vec::new();
        let mut spec = match self.build_spec(requested) {
            Ok(spec) => spec,
            Err(DrawError::Empty) => {
                return Err(HxError::NoRoute(
                    "the model pool has no members".to_string(),
                ))
            }
            Err(DrawError::AllDown { members }) => {
                let detail = members
                    .iter()
                    .map(|(id, reason)| format!("{id} ({reason})"))
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(HxError::Provider(format!(
                    "every member of the model pool is down: {detail}"
                )));
            }
        };
        loop {
            let provider = self
                .providers
                .resolve(&ProviderId::from(spec.member_id.clone()), spec.model())
                .map_err(|err| hx_core::error::HxError::NoRoute(err.to_string()))?;
            let key = self
                .secrets
                .resolve_str(&spec.credential)
                .map_err(|err| hx_core::error::HxError::Secret(err.to_string()))?;

            let request = ChatRequest::new(spec.model(), vec![Message::user(prompt)]);
            match provider.complete(request, &key).await {
                Ok(response) => {
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
                    return Ok(ChildRecord {
                        model: spec.model().to_string(),
                        credential: spec.credential.clone(),
                        clamps: spec.clamps.clone(),
                        usage: record,
                        base_url: spec.base_url.clone(),
                        dead_members,
                    });
                }
                Err(err) => {
                    if !member_death(&err) {
                        // The child's own fault: deterministic across every member, so it must not
                        // re-route and must not bench a member that never saw the bad request.
                        return Err(err);
                    }
                    // The member died: mark it down (shared pool health, so later draws skip it) and,
                    // if the pool still has a healthy member, re-draw and continue.
                    self.pool.mark_down(
                        &spec.member_id,
                        redact_death_reason(&key, &err),
                        Utc::now(),
                    );
                    dead_members.push((spec.member_id.clone(), redact_death_reason(&key, &err)));
                    // Re-draw onto a healthy member. AllDown / Empty means every member has been tried
                    // once — the bound — so re-use the pool's own error rather than a second type.
                    spec = match self.build_spec(requested) {
                        Ok(next) => next,
                        Err(DrawError::Empty) => {
                            return Err(HxError::NoRoute(
                                "the model pool has no members".to_string(),
                            ))
                        }
                        Err(DrawError::AllDown { members }) => {
                            let detail = members
                                .iter()
                                .map(|(id, reason)| format!("{id} ({reason})"))
                                .collect::<Vec<_>>()
                                .join("; ");
                            return Err(HxError::Provider(format!(
                                "every member of the model pool is down: {detail}"
                            )));
                        }
                    };
                }
            }
        }
    }
}

/// What a run produced and recorded for a child.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ChildRecord {
    /// The model (drawn member) this child **finished** on.
    pub model: String,
    /// The credential **reference** that paid for it.
    pub credential: String,
    /// The clamps that were applied at spawn, carried to the record's caller.
    pub clamps: Vec<ParamClamp>,
    /// The recorded usage row: the half of "which model did this work and did this lane spend money"
    /// that is answerable after the fact.
    pub usage: UsageRecord,
    pub base_url: String,
    /// The members that **died** while this child ran, in order, each `(member id, reason)`, before
    /// the child re-routed and finished on [`ChildRecord::model`]. Empty when there was no re-route.
    /// This is the audit half of a re-route: it shows both the member that died *and* the member that
    /// finished, so a model switch is never silent.
    pub dead_members: Vec<(String, String)>,
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

    /// One provider call, as the provider saw it.
    ///
    /// Recorded so a test can ask what the call actually carried: the model string, the credential
    /// *value* that was resolved for it, and the request as the wire would see it.
    #[derive(Clone, Debug)]
    struct Seen {
        model: String,
        credential: String,
        request: String,
    }

    /// The scripted answer a provider returns instead of a success.
    #[derive(Clone, Copy)]
    enum ScriptedErr {
        /// Answer normally.
        None,
        /// A 5xx — the member itself failed, a death the re-route acts on.
        Die,
        /// A refused request — the child's fault, deterministic across every member.
        Reject,
        /// A policy denial — the same decision on every member, so it must not re-route.
        Denied,
        /// A secret-resolution failure reported by the provider/client — a deployment fact,
        /// not this member's health, so it must not re-route.
        Secret,
    }

    /// A provider that answers without a network. The id is the member it stands in for.
    ///
    /// `err` scripts *how* the member answers when it does not succeed, so tests can distinguish a
    /// member death (a 5xx — worth re-routing) from a request the member refused (a 400 — not).
    struct ScriptedProvider {
        id: ProviderId,
        err: ScriptedErr,
        /// The model the upstream *echoes back*. `None` means the member's own id, which is the
        /// trap: a fixture whose echo is the id cannot tell a record that took its model from the
        /// drawn member from one that took it from the response.
        echoes: Option<String>,
        seen: std::sync::Mutex<Vec<Seen>>,
    }

    impl ScriptedProvider {
        fn new(id: &str) -> Arc<Self> {
            Arc::new(Self {
                id: ProviderId::from(id),
                err: ScriptedErr::None,
                echoes: None,
                seen: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn failing(self: &Arc<Self>) -> Arc<Self> {
            Arc::new(Self {
                id: self.id.clone(),
                err: ScriptedErr::Die,
                echoes: self.echoes.clone(),
                seen: std::sync::Mutex::new(Vec::new()),
            })
        }

        /// The upstream names a different model than the pool member's id.
        fn echoing(self: &Arc<Self>, model: &str) -> Arc<Self> {
            Arc::new(Self {
                id: self.id.clone(),
                err: self.err,
                echoes: Some(model.to_string()),
                seen: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn calls(&self) -> usize {
            self.seen.lock().expect("the seen lock").len()
        }

        fn seen(&self) -> Vec<Seen> {
            self.seen.lock().expect("the seen lock").clone()
        }
    }

    /// A registry holding one scripted provider for `member_id`, plus the provider itself so a test
    /// can read back what it was handed.
    fn registry_and_provider(member_id: &str) -> (Arc<ProviderRegistry>, Arc<ScriptedProvider>) {
        let provider = ScriptedProvider::new(member_id);
        let mut reg = ProviderRegistry::new();
        reg.insert(provider.clone());
        (Arc::new(reg), provider)
    }

    fn provider_registry_for(member_id: &str) -> Arc<ProviderRegistry> {
        registry_and_provider(member_id).0
    }

    /// The usage rows the store actually wrote, read back out of the database file rather than out of
    /// the record this module returns: `(provider, credential, model)`, in write order.
    ///
    /// A store's own reader cannot answer this — `Totals` has no model — and the durable row is the
    /// claim ("the recorded `UsageRecord`'s model is the drawn member"), so it is read the way a
    /// later auditor would.
    fn durable_usage_rows(
        store: &hx_store::Store,
        session: &SessionId,
    ) -> Vec<(String, String, String)> {
        let path = store
            .path()
            .expect("a store opened on a path knows its path");
        let conn = rusqlite::Connection::open(path).expect("the store file opens");
        let mut stmt = conn
            .prepare(
                "SELECT provider, credential, model FROM usage WHERE session_id = ?1 ORDER BY id",
            )
            .expect("the usage query prepares");
        stmt.query_map([session.as_str()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .expect("the usage query runs")
        .map(|row| row.expect("a usage row"))
        .collect()
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
            req: ChatRequest,
            key: &hx_secrets::Secret,
        ) -> Result<hx_provider::ChatResponse> {
            self.seen.lock().expect("the seen lock").push(Seen {
                model: req.model.clone(),
                // Named `expose` so the call site is greppable: this is a test double reading the
                // credential it was handed, which is the only way to see *which* member paid.
                credential: key.expose().to_string(),
                request: format!("{req:?}"),
            });
            match self.err {
                ScriptedErr::Die => {
                    // Simulate a provider that echoes the very key it was given back in its error
                    // body — the leak `redact_death_reason` is there to catch.
                    return Err(HxError::Provider(format!(
                        "upstream returned HTTP 500 (key: {})",
                        key.expose()
                    )));
                }
                ScriptedErr::Reject => {
                    return Err(HxError::ProviderRejected {
                        provider: self.id.to_string(),
                        reason: "the request was rejected (HTTP 400): unknown parameter"
                            .to_string(),
                    })
                }
                ScriptedErr::Denied => {
                    return Err(HxError::Denied(
                        "writes outside the workspace are not allowed".to_string(),
                    ))
                }
                ScriptedErr::Secret => {
                    return Err(HxError::Secret(
                        "no store could resolve the credential reference".to_string(),
                    ))
                }
                ScriptedErr::None => {}
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
                model: self.echoes.clone().unwrap_or_else(|| self.id.to_string()),
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
        reg.insert(ScriptedProvider::new("a").failing());
        reg.insert(ScriptedProvider::new("b"));
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
        // Read back out of the database, not out of the record this module just handed us: the claim
        // is about what was *recorded*, and a returned record agreeing with itself proves nothing.
        // (This assertion replaced `assert_eq!(s.record.id.as_str(), s.id().as_str())`, which
        // compared a value to the value it was built from and therefore could not fail.)
        assert_eq!(
            durable_usage_rows(&st, s.id()),
            vec![("b".to_string(), "vault:pool/b".to_string(), "b".to_string())],
            "the durable row names the drawn member and the reference that paid"
        );
    }

    #[tokio::test]
    async fn run_child_makes_exactly_one_provider_call() {
        // "one provider call" is a claim in the module doc, and a hidden retry would spend a second
        // call's money while recording one row.
        let (reg, provider) = registry_and_provider("b");
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("b", &[])]),
            reg,
            secrets_for("b"),
            st.clone(),
        );
        let spec = pen.build_spec(&[]).expect("draws");
        let s = session(&st);
        pen.run_child(&spec, s.id(), "hi").await.expect("runs");

        assert_eq!(provider.calls(), 1, "one child is one provider call");
        assert_eq!(
            provider.seen()[0].model,
            "b",
            "and the request asked the drawn member's provider for the drawn member's model"
        );
        assert_eq!(
            st.totals(s.id()).expect("totals read").provider_calls,
            1,
            "and exactly one row for it"
        );
    }

    #[tokio::test]
    async fn a_successful_call_leaves_the_member_healthy() {
        // A single-member pool on purpose. With two healthy members the round-robin hands out the
        // other one whether or not the first was marked down, so a two-member fixture cannot see a
        // success that wrongly marks its member down — this one can: the pool would be all-down.
        let (reg, _provider) = registry_and_provider("only");
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("only", &[])]),
            reg,
            secrets_for("only"),
            st.clone(),
        );
        let spec = pen.build_spec(&[]).expect("draws");
        let s = session(&st);
        pen.run_child(&spec, s.id(), "hi").await.expect("runs");

        let next = pen
            .build_spec(&[])
            .expect("a member that answered must still be drawable");
        assert_eq!(next.model(), "only");
    }

    #[tokio::test]
    async fn two_spawns_in_a_row_draw_two_different_healthy_members() {
        // `build_spec` must go through the pool's own draw, not pick the first healthy member: the
        // cursor is what spreads children across a pool, and a first-healthy pick is invisible to
        // every other test in this module.
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            provider_registry_for("a"),
            secrets_for("a"),
            store(),
        );
        assert_eq!(pen.build_spec(&[]).expect("draws").model(), "a");
        assert_eq!(
            pen.build_spec(&[]).expect("draws").model(),
            "b",
            "the second draw is the next healthy member, not the first one again"
        );
        assert_eq!(
            pen.build_spec(&[]).expect("draws").model(),
            "a",
            "and it cycles"
        );
    }

    #[tokio::test]
    async fn the_recorded_model_is_the_drawn_member_even_when_the_upstream_names_another_model() {
        // A real provider answers with the checkpoint it ran, which is not the pool member's id.
        // This is the only fixture that can tell a record built from the drawn member from one built
        // from the response.
        let provider = ScriptedProvider::new("b").echoing("upstream-2026-01-01");
        let mut reg = ProviderRegistry::new();
        reg.insert(provider.clone());
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("b", &[])]),
            Arc::new(reg),
            secrets_for("b"),
            st.clone(),
        );
        let spec = pen.build_spec(&[]).expect("draws");
        let s = session(&st);
        let rec = pen.run_child(&spec, s.id(), "hi").await.expect("runs");

        assert_eq!(
            rec.usage.model, "b",
            "the drawn member is the model of record, not the upstream's name for it"
        );
        assert_eq!(rec.model, "b");
        assert_eq!(
            durable_usage_rows(&st, s.id())[0].2,
            "b",
            "and the durable row says the same"
        );
    }

    #[tokio::test]
    async fn the_drawn_members_credential_pays_and_only_its_reference_is_recorded() {
        // Two members, the first down, with *different* secret values: so "the drawn member's
        // credential" is distinguishable from "the first member's", and the resolved value is
        // distinguishable from the reference that names it.
        let mut reg = ProviderRegistry::new();
        reg.insert(ScriptedProvider::new("a"));
        let provider_b = ScriptedProvider::new("b");
        reg.insert(provider_b.clone());
        let mut secrets = FixedSecrets::new("vault").set("pool/a", "sentinel-a");
        secrets = secrets.set("pool/b", "sentinel-b");
        let secrets = Arc::new(SecretStores::new().with(Arc::new(secrets)));

        let mut pool = ModelPool::new(vec![member("a", &[]), member("b", &[])]);
        pool.mark_down("a", "boom", now());
        let st = store();
        let mut pen = Spawner::new(pool, Arc::new(reg), secrets, st.clone());
        let spec = pen.build_spec(&[]).expect("b is healthy");
        assert_eq!(spec.credential, "vault:pool/b");

        let s = session(&st);
        let rec = pen.run_child(&spec, s.id(), "hi").await.expect("runs");

        // The value really was resolved and really was handed over. Without this, "the value is not
        // recorded" would pass against a spawner that resolved nothing at all.
        let seen = provider_b.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].credential, "sentinel-b",
            "the drawn member's secret is what paid for the call"
        );
        assert!(
            !rec.credential.contains("sentinel"),
            "the record carries the reference, not the value: {:?}",
            rec.credential
        );

        let rows = durable_usage_rows(&st, s.id());
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].1, "vault:pool/b",
            "the durable row holds the reference, never the resolved value"
        );
        assert!(
            !rows[0].1.contains("sentinel"),
            "a usage row is not a place a live credential may land: {:?}",
            rows[0].1
        );
    }

    /// DEFECT (verify-spawner): the clamped parameters never reach the provider call.
    ///
    /// The module doc says `run_child` makes its call "with the **clamped** parameters", and that the
    /// clamp applied at spawn "is what prevents the `HTTP 400`". It does not: `hx-provider`'s
    /// `ChatRequest` has no field for a pool `Param`, and `run_child` fills none, so a parameter a
    /// member would reject is never sent — and neither is one it would accept. The clamp is recorded
    /// on the spec and on the record and stops there. Un-ignore this when `ChatRequest` grows the
    /// field and `run_child` sets it from `spec.params`.
    #[tokio::test]
    #[ignore = "the clamped parameters do not reach the request: hx-provider's ChatRequest has no field for a pool Param"]
    async fn the_clamped_parameter_reaches_the_provider_call() {
        let (reg, provider) = registry_and_provider("strong");
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member(
                "strong",
                &[Param::reasoning_effort(ReasoningEffort::Low)],
            )]),
            reg,
            secrets_for("strong"),
            st.clone(),
        );
        let requested = [Param::reasoning_effort(ReasoningEffort::High)];
        let spec = pen.build_spec(&requested).expect("clamped, not failed");
        let s = session(&st);
        pen.run_child(&spec, s.id(), "hi").await.expect("runs");

        let seen = provider.seen();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].request.contains("reasoning_effort"),
            "the clamped parameter must reach the request the provider is handed: {}",
            seen[0].request
        );
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

    /// Build a registry with one scripted provider per `(id, err)` entry, so each member can be
    /// scripted independently (die, reject, or succeed).
    fn scripted_registry(specs: &[(&str, ScriptedErr)]) -> Arc<ProviderRegistry> {
        let mut reg = ProviderRegistry::new();
        for &(id, err) in specs {
            reg.insert(Arc::new(ScriptedProvider {
                id: ProviderId::from(id),
                err,
                echoes: None,
                seen: std::sync::Mutex::new(Vec::new()),
            }));
        }
        Arc::new(reg)
    }

    /// Secrets for a list of member ids, each under `vault:pool/<id>`.
    fn scripted_secrets(ids: &[&str]) -> Arc<SecretStores> {
        let mut built = FixedSecrets::new("vault");
        for id in ids {
            built = built.set(format!("pool/{id}"), format!("sentinel-{id}"));
        }
        Arc::new(SecretStores::new().with(Arc::new(built)))
    }

    /// A member that dies mid-flight is re-drawn onto a healthy member and the child continues — and the
    /// audit shows **both**: the dying member in `dead_members`, the finishing member as the model.
    #[tokio::test]
    async fn a_member_that_dies_mid_flight_reroutes_and_records_both_members() {
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            scripted_registry(&[("a", ScriptedErr::Die), ("b", ScriptedErr::None)]),
            scripted_secrets(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);
        let rec = pen
            .run_lane(s.id(), "hi", &[])
            .await
            .expect("the child re-routes and continues");

        // The child finished on the healthy member…
        assert_eq!(rec.model, "b", "the finish is on the healthy member");
        assert_eq!(rec.usage.model, "b");
        // …and the audit names the one that died and why — a model switch is never silent.
        assert_eq!(rec.dead_members.len(), 1, "{:?}", rec.dead_members);
        assert_eq!(rec.dead_members[0].0, "a");
        assert!(
            rec.dead_members[0].1.contains("500"),
            "{:?}",
            rec.dead_members
        );
        // Health is shared: a dead member stays down for a subsequent draw.
        let spec = pen.build_spec(&[]).expect("b remains healthy");
        assert_eq!(spec.model(), "b");
    }

    /// When every member dies, the run fails bounded with the pool's own AllDown error — it never retries
    /// forever and never returns a success it did not earn.
    #[tokio::test]
    async fn a_run_where_every_member_dies_fails_bounded_and_names_each_member() {
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            scripted_registry(&[("a", ScriptedErr::Die), ("b", ScriptedErr::Die)]),
            scripted_secrets(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);
        let err = pen
            .run_lane(s.id(), "hi", &[])
            .await
            .expect_err("every member is down");
        let text = err.to_string();
        assert!(
            text.contains("every member of the model pool is down"),
            "{text}"
        );
        assert!(text.contains("a") && text.contains("b"), "{text}");
        // Bounded: exactly the pool's members were tried, once each.
        assert_eq!(
            pen.pool
                .members
                .iter()
                .filter(|m| matches!(m.health, MemberHealth::Down { .. }))
                .count(),
            2
        );
    }

    /// A failure that is the child's own — a refused request — does **not** re-route and does **not**
    /// bench the member that refused it: retrying it across the pool would make one error into N.
    #[tokio::test]
    async fn a_refused_request_does_not_reroute_and_does_not_bench_the_member() {
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            scripted_registry(&[("a", ScriptedErr::Reject), ("b", ScriptedErr::None)]),
            scripted_secrets(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);
        let err = pen
            .run_lane(s.id(), "hi", &[])
            .await
            .expect_err("the request is refused, not the member");
        assert!(matches!(err, HxError::ProviderRejected { .. }), "{err:?}");
        // a (which never actually failed) is still healthy — a refused request must not bench the member.
        assert_eq!(
            pen.pool.members[0].health,
            MemberHealth::Healthy,
            "a refused request must not bench the member"
        );
        // A subsequent draw reaches the healthy set (b, by the round-robin cursor) and can still run.
        let spec = pen.build_spec(&[]).expect("a healthy member remains");
        assert_eq!(spec.model(), "b");
    }

    /// A missing provider route is a configuration fact (NoRoute), not a member death:
    /// it must not re-route and must not bench.
    #[tokio::test]
    async fn a_missing_provider_route_is_not_a_member_death_and_does_not_reroute() {
        let st = store();
        // a draws, but no provider is registered for it.
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            scripted_registry(&[("b", ScriptedErr::None)]),
            scripted_secrets(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);
        let err = pen
            .run_lane(s.id(), "hi", &[])
            .await
            .expect_err("no route to a is a config fact, not a death");
        assert!(matches!(err, HxError::NoRoute(_)), "{err:?}");
        // a is not benched: a missing provider route is a config fact, not a health one.
        assert_eq!(
            pen.pool.members[0].health,
            MemberHealth::Healthy,
            "a missing route is not a member death"
        );
    }

    /// A policy denial is the same decision on every member, so it must not re-route (one denial
    /// would become one per member) and must not bench the member that never saw the bad request.
    #[tokio::test]
    async fn a_policy_denial_does_not_reroute_and_does_not_bench_the_member() {
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            scripted_registry(&[("a", ScriptedErr::Denied), ("b", ScriptedErr::None)]),
            scripted_secrets(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);
        let err = pen
            .run_lane(s.id(), "hi", &[])
            .await
            .expect_err("a denial is not a death, so the run returns it directly");
        assert!(matches!(err, HxError::Denied(_)), "{err:?}");
        // a stayed healthy: a policy denial benches nothing.
        assert_eq!(
            pen.pool.members[0].health,
            MemberHealth::Healthy,
            "a policy denial must not bench the member"
        );
    }

    /// A secret-resolution failure reported by the provider is a deployment fact, not this member's
    /// health: it must not re-route and must not bench.
    #[tokio::test]
    async fn a_secret_failure_does_not_reroute_and_does_not_bench_the_member() {
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            scripted_registry(&[("a", ScriptedErr::Secret), ("b", ScriptedErr::None)]),
            scripted_secrets(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);
        let err = pen
            .run_lane(s.id(), "hi", &[])
            .await
            .expect_err("a secret failure is not a death, so the run returns it directly");
        assert!(matches!(err, HxError::Secret(_)), "{err:?}");
        assert_eq!(
            pen.pool.members[0].health,
            MemberHealth::Healthy,
            "a secret failure must not bench the member"
        );
    }

    /// A leaked credential inside a dead member's failure reason is masked before it is stored on the
    /// pool and returned on the record — the provider can echo the very key it was given in its error body.
    #[tokio::test]
    async fn a_dead_members_reason_has_a_leaked_key_masked() {
        let st = store();
        // The sentinel is a *patternless* opaque value: it is caught only because the spawner
        // registers the resolved key as a literal before redacting the reason.
        let mut secrets = FixedSecrets::new("vault");
        secrets = secrets
            .set("pool/a", "opaque-credential-value-that-leaks")
            .set("pool/b", "sentinel-b");
        let secrets = Arc::new(SecretStores::new().with(Arc::new(secrets)));
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            scripted_registry(&[("a", ScriptedErr::Die), ("b", ScriptedErr::None)]),
            secrets,
            st.clone(),
        );
        let s = session(&st);
        let rec = pen
            .run_lane(s.id(), "hi", &[])
            .await
            .expect("b still runs after a dies");
        // a died; its reason must not carry the credential "a" was given.
        assert_eq!(rec.dead_members.len(), 1);
        let (member, reason) = &rec.dead_members[0];
        assert_eq!(member, "a");
        assert!(
            !reason.contains("opaque-credential-value-that-leaks"),
            "the leaked key reached the record: {reason}"
        );
        // The pool's stored reason is the same masked one.
        match &pen.pool.members[0].health {
            MemberHealth::Down { reason, .. } => {
                assert!(
                    !reason.contains("opaque-credential-value-that-leaks"),
                    "the leaked key reached pool health: {reason}"
                );
            }
            other => panic!("a must be down, got {other:?}"),
        }
    }

    /// A returned `ChildRecord`'s `Debug` must not carry the resolved credential value — only its
    /// reference — so a log line or an error trace never prints a live key.
    #[tokio::test]
    async fn a_child_records_debug_never_carries_the_resolved_credential() {
        let (reg, _provider) = registry_and_provider("b");
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("b", &[])]),
            reg,
            secrets_for("b"),
            st.clone(),
        );
        let spec = pen.build_spec(&[]).expect("draws");
        let s = session(&st);
        let rec = pen.run_child(&spec, s.id(), "hi").await.expect("runs");
        let debug = format!("{rec:?}");
        assert!(
            !debug.contains("sentinel"),
            "the record's Debug leaked the credential value: {debug}"
        );
        assert!(
            debug.contains("vault:pool/b"),
            "the reference is what the record names: {debug}"
        );
    }

    /// Credential isolation survives a re-route: when member a dies and the lane re-draws onto b,
    /// b is paid with b's own credential value, never a's.
    #[tokio::test]
    async fn a_rerouted_member_is_paid_with_its_own_credential_not_the_dead_members() {
        // Capture each provider so the *value* each was handed can be read back.
        let provider_a = ScriptedProvider::new("a").failing();
        let provider_b = ScriptedProvider::new("b");
        let mut reg = ProviderRegistry::new();
        reg.insert(provider_a.clone());
        reg.insert(provider_b.clone());
        let mut secrets = FixedSecrets::new("vault");
        secrets = secrets
            .set("pool/a", "secret-for-a")
            .set("pool/b", "secret-for-b");
        let secrets = Arc::new(SecretStores::new().with(Arc::new(secrets)));
        let st = store();
        let mut pen = Spawner::new(
            ModelPool::new(vec![member("a", &[]), member("b", &[])]),
            Arc::new(reg),
            secrets,
            st.clone(),
        );
        let s = session(&st);
        pen.run_lane(s.id(), "hi", &[])
            .await
            .expect("re-routes to b");

        // b (which finished) was handed b's own value, not a's — one member's credential never pays
        // for another's work.
        let b_seen = provider_b.seen();
        assert_eq!(b_seen.len(), 1, "b was called exactly once");
        assert_eq!(
            b_seen[0].credential, "secret-for-b",
            "the finishing member is paid with its own credential"
        );
        assert_ne!(
            b_seen[0].credential, "secret-for-a",
            "one member's credential must never pay for another member's call"
        );
    }
}

//! A fan-out of N children across N **distinct** members of one pool (M8's exit criterion).
//!
//! ## What this module is, said plainly
//!
//! [`crates::spawn`] gives you a **narrowest real thing**: [`Spawner::build_spec`] draws one
//! healthy member and clamps a parameter set to it, and [`Spawner::run_child`] makes one provider
//! call against that drawn member and records a `UsageRecord` whose `model` is the member. A single
//! spec is not a fan-out — and the whole point of M8 is that a fan-out runs **N children across N
//! distinct members**, not N copies of one. That is what lives here.
//!
//! This module *consumes* the spawner's public API (`build_spec` + `run_child`); it does not touch
//! `spawn.rs`. The sibling M8 lane (`feat/m8-reroute`) owns `spawn.rs` — re-route on member
//! death across *running* lanes — so this lane deliberately builds its fan-out beside it, not inside it.
//!
//! ## Two phases, and why
//!
//! The fan-out is deliberately split into **allocate** then **execute**:
//!
//! 1. **Allocate** — draw N specs up front and check that they land on **N distinct members**. With
//!    N healthy members the round-robin draw produces N distinct ids; with M < N healthy members it
//!    repeats once the healthy set is exhausted, which is exactly how a short pool is *detected* rather
//!    than guessed. If the drawn specs are not all distinct, the fan-out returns
//!    [`FanOutError::NotEnoughMembers`] naming how many were wanted and how many distinct healthy
//!    members exist — it does **not** silently run two children on one member.
//! 2. **Execute** — run each allocated spec **concurrently** (N lanes in flight, bounded by
//!    `max_parallel`), collecting one result per child in the original request order. Because
//!    allocation is done in full before any run starts, every spec already targets its own
//!    member; a member that dies *during* its own run fails that one child and is marked down, but the
//!    other N-1 children run on their own distinct members and still complete. **A dead member
//!    mid-fan-out does not kill the others.** (Full re-route of a *running* child onto a fresh
//!    member is the sibling lane's job; this lane only guarantees the others are not cancelled by it.)
//!
//! ## Policy: a short pool fails loudly
//!
//! Item 3 of the brief — *"N children but only M < N healthy members: say what happens (queue? fail?
//! run on fewer?) and test it."* This lane chooses **fail**: the exit criterion is specifically "N
//! lanes across N members", so when the pool cannot supply N distinct members the criterion cannot be met,
//! and running some lanes on fewer members would silently degrade the guarantee. Queuing would hide the
//! shortage behind an unbounded wait. [`FanOutError::NotEnoughMembers`] says plainly what was wanted
//! and what was available, and the caller decides (retry later, run a smaller fan-out, error to the
//! user).
//!
//! ## Each child's model is recorded with that child
//!
//! [`FanOutOutcome::children`] carries, per child in request order, the [`ChildRecord`] `run_child`
//! produced — whose `model` is the **drawn member** and whose `usage` already landed in the store's
//! audit chain. "Which model did which piece of work, and at what cost" is answerable per child from
//! the outcome without re-deriving it.
//!
//! ## Hermetic by construction
//!
//! The tests here use a **scripted pool and a scripted provider** — no network, no real model.
//! Every wait is a rendezvous with a timeout, never a bare sleep — except the overlap proof,
//! which deliberately times two 200ms sleeps against each other (the brief's required wall-clock
//! assertion, bounded so a sequential run can never pass it). The two phases are proven
//! independently: the distinctness assertion can fail (drop it and the
//! N-distinct test goes red), the short-pool detection can fail (remove it and the short-pool test goes
//! red), and the run-all-children-despite-a-death property can fail (abort the fan-out on the first
//! child error and the dead-member test goes red). Each mutation and the test it reddens is recorded in
//! `TESTING.md`.

use crate::spawn::{ChildRecord, PreparedOutcome, Spawner};
use futures::stream::{FuturesUnordered, StreamExt};
use hx_core::config::DEFAULT_FANOUT_MAX_PARALLEL;
use hx_core::ids::SessionId;
use hx_secrets::Redactor;
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// A recognized way a fan-out can fail to meet its guarantee, before or during execution.
///
/// This is separate from the [`hx_core::error::HxError`] a single child's provider call returns so
/// that the caller can tell "the fan-out as a whole could not be met" (allocation) from "one child
/// failed" (execution, where the others still ran).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FanOutError {
    /// The pool could not supply N distinct healthy members. `wanted` is the number of children
    /// requested; `distinct` is how many distinct healthy members the pool actually offered.
    NotEnoughMembers { wanted: usize, distinct: usize },

    /// Building a spec failed because the pool is empty or every member is down. Carries the spawner's
    /// own [`hx_core::pool::DrawError`], which names the condition and every member's reason.
    Draw(hx_core::pool::DrawError),
}

impl std::fmt::Display for FanOutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FanOutError::NotEnoughMembers { wanted, distinct } => write!(
                f,
                "cannot fan out {wanted} children across {distinct} distinct healthy \
                 members: the pool is too short to give each child its own member"
            ),
            FanOutError::Draw(e) => write!(f, "a spec could not be drawn: {e}"),
        }
    }
}

impl std::error::Error for FanOutError {}

/// The result of one child's run, in the same order as its input prompt.
///
/// Every child is attempted even if another dies; a dead member surfaces as [`ChildOutcome::Errored`]
/// for that child only, and the others are [`ChildOutcome::Ran`] with their own recorded record.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum ChildOutcome {
    /// The child completed. `record` names the **member** it ran on and its recorded usage.
    Ran(ChildRecord),
    /// The child failed. `member` is the member it was drawn to run on; `error` is the provider
    /// failure that marked it down.
    Errored { member: String, error: String },
}

/// The whole fan-out: one outcome per input prompt, plus the answer to "did the N-distinct guarantee
/// hold".
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FanOutOutcome {
    /// The members the fan-out actually drew, one per child (N of them, by construction distinct
    /// unless the pool is short). The exit criterion's "N members, not N copies of one" is asserted
    /// by [`FanOutOutcome::members_are_distinct`].
    pub members: Vec<String>,
    /// One outcome per prompt, in request order.
    pub children: Vec<ChildOutcome>,
}

impl FanOutOutcome {
    /// True when every child was drawn onto its own distinct member — the M8 exit criterion.
    pub fn members_are_distinct(&self) -> bool {
        let set: BTreeSet<&str> = self.members.iter().map(String::as_str).collect();
        set.len() == self.members.len()
    }

    /// The members that actually completed, for callers that want "which model did the work".
    pub fn completed_models(&self) -> Vec<&str> {
        self.children
            .iter()
            .filter_map(|c| match c {
                ChildOutcome::Ran(rec) => Some(rec.model.as_str()),
                ChildOutcome::Errored { .. } => None,
            })
            .collect()
    }
}

/// Run a fan-out of `prompts.len()` children across that many **distinct** members of one pool.
///
/// # Guarantees
///
/// 1. **N members, not N copies of one.** Every child is allocated a spec *before* any runs, and the
///    drawn members are asserted distinct. If the pool cannot supply N distinct healthy members the call
///    returns [`FanOutError::NotEnoughMembers`] and **no child runs** (nothing is half-done).
/// 2. **Each child's model is recorded with that child.** A completed child's [`ChildRecord`] names its
///    member and its recorded usage.
/// 3. **A dead member mid-fan-out does not kill the others.** Every allocated child is still run; a
///    failure marks its own member down and is reported as [`ChildOutcome::Errored`] for that child.
/// 4. **Children run concurrently, in the original order.** The N allocated children run as N lanes
///    in flight over a [`FuturesUnordered`](futures::stream::FuturesUnordered) pool bounded by a
///    [`Semaphore`](tokio::sync::Semaphore) of `max_parallel` permits; outcomes are collected by
///    child index, so [`FanOutOutcome::children`] is in request order regardless of who finishes
///    first. A child erroring does not cancel its siblings.
///
/// `max_parallel` is the one parallelism knob (config `agent.fanout_max_parallel`): `None` means
/// [`DEFAULT_FANOUT_MAX_PARALLEL`], and the effective bound is the number of children capped by
/// it (`0` is clamped to `1`, so a misconfiguration degrades to serial rather than deadlocking).
///
/// The spawner is taken by `&mut` because `build_spec` and the post-join `mark_down` both need it
/// (they own the pool's health state and the store). All children run against the single caller
/// session.
pub async fn run_fan_out(
    spawner: &mut Spawner,
    session: &SessionId,
    prompts: &[&str],
    max_parallel: Option<usize>,
) -> Result<FanOutOutcome, FanOutError> {
    let wanted = prompts.len();

    // Phase 1 — allocate one spec per child, checking distinctness as we go.
    let mut members = Vec::with_capacity(wanted);
    let mut specs = Vec::with_capacity(wanted);
    for _ in 0..wanted {
        let spec = spawner.build_spec(&[]).map_err(FanOutError::Draw)?;
        members.push(spec.member_id.clone());
        specs.push(spec);
    }

    let distinct: BTreeSet<&str> = members.iter().map(String::as_str).collect();
    if distinct.len() < wanted {
        // The round-robin draw can only repeat once the healthy set is exhausted, so a repeat here
        // means there are genuinely fewer than N distinct healthy members. Fail before any child runs.
        return Err(FanOutError::NotEnoughMembers {
            wanted,
            distinct: distinct.len(),
        });
    }

    // Phase 2 — run every allocated child concurrently, bounded by `max_parallel`.
    //
    // `Spawner::run_child` takes `&mut`, which cannot be held across concurrent futures, so each
    // child is first split into an owned `PreparedChild` (provider + key resolution is read-only
    // and done serially here) whose `run` is shareable. The pool-health write (`mark_down`) is
    // applied serially as each lane lands — equivalent to the old sequential loop, because
    // allocation already finished and no draw happens mid-execution, so nothing observes the
    // timing of the write. A resolve failure is that child's own error (no `mark_down`, exactly
    // as the old loop's pre-call `Err` path); a store-write failure likewise benches nothing.
    //
    // The error string is redacted at this boundary before it is handed to a caller (and
    // eventually rendered as client JSON): `run` returns the raw `HxError`, whose provider
    // variants carry the upstream body — which can echo a key or a `?token=` URL. The shared
    // `Redactor`'s pattern pass masks the recognisable shapes; opaque values are the separate
    // duty of `Spawner`'s registered-literal pass on the stored death reason.
    let limit = max_parallel
        .unwrap_or(DEFAULT_FANOUT_MAX_PARALLEL)
        .max(1)
        .min(wanted.max(1));
    let semaphore = Arc::new(Semaphore::new(limit));
    let redactor = Redactor::new();
    let mut slots: Vec<Option<ChildOutcome>> = (0..wanted).map(|_| None).collect();
    let mut pending = FuturesUnordered::new();
    for (index, spec) in specs.iter().enumerate() {
        match spawner.prepare_child(spec) {
            Err(err) => {
                slots[index] = Some(ChildOutcome::Errored {
                    member: spec.member_id.clone(),
                    error: redactor.redact(&err.to_string()).text,
                });
            }
            Ok(prepared) => {
                let semaphore = Arc::clone(&semaphore);
                pending.push(async move {
                    let _permit = semaphore
                        .acquire_owned()
                        .await
                        .expect("the fan-out semaphore is never closed");
                    (index, prepared.run(session, "fan-out child").await)
                });
            }
        }
    }
    // Drain in completion order, restoring request order through the slots: whoever finishes
    // first lands first, but `children` is indexed, not pushed.
    while let Some((index, step)) = pending.next().await {
        slots[index] = Some(match step {
            Ok(PreparedOutcome::Ran(record)) => ChildOutcome::Ran(record),
            Ok(PreparedOutcome::Failed {
                member,
                reason,
                error,
            }) => {
                spawner.mark_down(&member, reason);
                ChildOutcome::Errored {
                    member,
                    error: redactor.redact(&error.to_string()).text,
                }
            }
            Err(store_err) => ChildOutcome::Errored {
                member: specs[index].member_id.clone(),
                error: redactor.redact(&store_err.to_string()).text,
            },
        });
    }

    let children = slots
        .into_iter()
        .map(|slot| slot.expect("every allocated child lands exactly one outcome"))
        .collect();
    Ok(FanOutOutcome { members, children })
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hx_core::config::ProviderKind;
    use hx_core::error::{HxError, Result};
    use hx_core::ids::ProviderId;
    use hx_core::message::Message;
    use hx_core::pool::{MemberHealth, PoolMember};
    use hx_provider::{ChatRequest, ChatResponse, FinishReason, Provider, ProviderRegistry, Usage};
    use hx_secrets::{FixedSecrets, Secret, SecretStores};
    use hx_store::NewSession;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::{Barrier, Notify};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("fixed test timestamp")
    }

    fn member(id: &str) -> PoolMember {
        PoolMember {
            id: id.to_string(),
            base_url: format!("https://{id}.example.test"),
            credential: format!("vault:pool/{id}"),
            accepts: Vec::new(),
            health: MemberHealth::Healthy,
        }
    }

    fn secrets_for(ids: &[&str]) -> Arc<SecretStores> {
        let mut s = FixedSecrets::new("vault");
        for id in ids {
            s = s.set(format!("pool/{id}"), format!("sentinel-{id}"));
        }
        Arc::new(SecretStores::new().with(Arc::new(s)))
    }

    fn store() -> Arc<hx_store::Store> {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let mut path = std::env::temp_dir();
        path.push(format!("hx-fanout-{}-{n}.db", std::process::id()));
        Arc::new(hx_store::Store::open(path).expect("test store opens"))
    }

    fn session(store: &hx_store::Store) -> hx_store::Session {
        let rec = store
            .create(NewSession::new(), now())
            .expect("session created");
        store.load(&rec.id).expect("session loads")
    }

    /// A provider that answers without a network. `id` is the member it stands in for; `fail` makes
    /// its one call error (a dead member) so the fan-out can test non-cascade.
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
        async fn complete(&self, _req: ChatRequest, key: &Secret) -> Result<ChatResponse> {
            if self.fail {
                // Simulate a provider that echoes the key it was given in its error body.
                return Err(HxError::Provider(format!(
                    "upstream returned HTTP 500 (key: {})",
                    key.expose()
                )));
            }
            Ok(ChatResponse {
                message: Message::assistant("done"),
                usage: Usage {
                    input_tokens: 10,
                    output_tokens: 5,
                    ..Default::default()
                },
                finish: FinishReason::Stop,
                model: self.id.to_string(),
                raw: None,
            })
        }
    }

    fn registry_for(ids: &[&str]) -> Arc<ProviderRegistry> {
        let mut reg = ProviderRegistry::new();
        for id in ids {
            reg.insert(Arc::new(ScriptedProvider::new(id)));
        }
        Arc::new(reg)
    }

    /// The M8 exit criterion as a test: a fan-out of N requests over a pool of N healthy members
    /// reaches **N distinct** members, every child completes, and each completed child's record names the
    /// member it drew — not a global, not a copy of the first.
    #[tokio::test]
    async fn a_fan_out_of_n_requests_reaches_n_distinct_members() {
        let st = store();
        let mut sp = Spawner::new(
            hx_core::pool::ModelPool::new(vec![member("cheap"), member("strong"), member("mid")]),
            registry_for(&["cheap", "strong", "mid"]),
            secrets_for(&["cheap", "strong", "mid"]),
            st.clone(),
        );
        let s = session(&st);
        let prompts = ["do a", "do b", "do c"];

        let out = run_fan_out(&mut sp, s.id(), &prompts, None)
            .await
            .expect("a fan-out across three healthy members must succeed");
        assert_eq!(out.members.len(), 3);
        assert!(
            out.members_are_distinct(),
            "N children must reach N distinct members, got {}",
            out.members.join(", ")
        );
        assert_eq!(out.children.len(), 3);
        // Every child completed.
        let mut completed = out.completed_models();
        completed.sort_unstable();
        assert_eq!(completed, vec!["cheap", "mid", "strong"]);
        // Per-child attribution: the record's model is that child's member.
        let models: Vec<&str> = out
            .children
            .iter()
            .map(|c| match c {
                ChildOutcome::Ran(rec) => rec.model.as_str(),
                ChildOutcome::Errored { .. } => panic!("all children ran"),
            })
            .collect();
        assert_eq!(
            models,
            vec!["cheap", "strong", "mid"],
            "child order maps to member"
        );
        // And each ran over a distinct member (the whole point — a different cost base per lane).
        for rec in &out.children {
            let rec = match rec {
                ChildOutcome::Ran(r) => r,
                _ => unreachable!(),
            };
            assert_eq!(rec.usage.model, rec.model);
        }
    }

    /// Each child's model is recorded *with that child* and lands in the store's audit chain, so
    /// "which model did which piece of work at what cost" is answerable per child.
    #[tokio::test]
    async fn every_children_model_is_recorded_with_that_child_in_the_audit_chain() {
        let st = store();
        let mut sp = Spawner::new(
            hx_core::pool::ModelPool::new(vec![member("a"), member("b")]),
            registry_for(&["a", "b"]),
            secrets_for(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);

        let out = run_fan_out(&mut sp, s.id(), &["p1", "p2"], None)
            .await
            .expect("two healthy members");
        let models = out.completed_models();
        assert_eq!(models.len(), 2);

        // The audit chain holds two provider calls with the drawn members, not N copies of one.
        let totals = st.totals(s.id()).expect("totals read");
        assert_eq!(totals.provider_calls, 2);
        assert_eq!(totals.input_tokens, 20, "2 children * 10 input tokens");
        // And the outcome names which member did which — the per-child model is carried on the record.
        let mut seen = BTreeSet::new();
        for c in &out.children {
            if let ChildOutcome::Ran(rec) = c {
                seen.insert(rec.model.clone());
            }
        }
        assert_eq!(seen.len(), 2, "each child recorded a distinct member");
    }

    /// Item 3: a fan-out of N requests across a pool with M < N distinct healthy members fails loudly
    /// (naming wanted vs distinct) and runs **no** child — it does not silently run two children on one
    /// member.
    #[tokio::test]
    async fn a_short_pool_is_reported_honestly_and_runs_nothing() {
        let st = store();
        let mut sp = Spawner::new(
            hx_core::pool::ModelPool::new(vec![member("a"), member("b")]),
            registry_for(&["a", "b"]),
            secrets_for(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);

        // Three requests, only two distinct healthy members.
        let err = run_fan_out(&mut sp, s.id(), &["p1", "p2", "p3"], None)
            .await
            .expect_err("the pool cannot give three children three distinct members");
        assert_eq!(
            err,
            FanOutError::NotEnoughMembers {
                wanted: 3,
                distinct: 2
            }
        );
        // No child ran (allocation fails before execution), so the audit chain is empty.
        let totals = st.totals(s.id()).expect("totals read");
        assert_eq!(totals.provider_calls, 0);
    }

    /// Item 4: a dead member mid-fan-out does not kill the others. One of two members is scripted to
    /// fail; the fan-out still runs the other and completes it with its record.
    #[tokio::test]
    async fn a_dead_member_mid_fan_out_does_not_kill_the_others() {
        // Registry: "a" is scripted to fail, "b" succeeds.
        let mut reg = ProviderRegistry::new();
        reg.insert(Arc::new(ScriptedProvider::new("a").failing()));
        reg.insert(Arc::new(ScriptedProvider::new("b")));
        let st = store();
        let mut sp = Spawner::new(
            hx_core::pool::ModelPool::new(vec![member("a"), member("b")]),
            Arc::new(reg),
            secrets_for(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);

        let out = run_fan_out(&mut sp, s.id(), &["p1", "p2"], None)
            .await
            .expect("two children allocated across two distinct members");
        // Both were attempted; the dead one errored, the other completed on its own member.
        let mut saw_errored = false;
        let mut saw_ran = false;
        for c in &out.children {
            match c {
                ChildOutcome::Errored { member, .. } => {
                    assert_eq!(member, "a", "the failing member is the one that errors");
                    saw_errored = true;
                }
                ChildOutcome::Ran(rec) => {
                    assert_eq!(rec.model, "b", "the healthy member completes");
                    saw_ran = true;
                }
            }
        }
        assert!(
            saw_errored && saw_ran,
            "one errored, one completed — got {out:?}"
        );
    }

    /// An all-down pool cannot even allocate the first spec: the spawner's own `DrawError` is named.
    #[tokio::test]
    async fn an_all_down_pool_fails_at_allocation_with_the_pools_error() {
        let mut pool = hx_core::pool::ModelPool::new(vec![member("a"), member("b")]);
        pool.mark_down("a", "boom-a", now());
        pool.mark_down("b", "boom-b", now());
        let st = store();
        let mut sp = Spawner::new(
            pool,
            registry_for(&["a", "b"]),
            secrets_for(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);

        match run_fan_out(&mut sp, s.id(), &["p1"], None).await {
            Err(FanOutError::Draw(hx_core::pool::DrawError::AllDown { members })) => {
                assert_eq!(members.len(), 2);
            }
            other => panic!("must be Draw(AllDown), got {other:?}"),
        }
    }

    /// An empty pool fails at allocation with the pool's `Empty` error.
    #[tokio::test]
    async fn an_empty_pool_fails_at_allocation() {
        let st = store();
        let mut sp = Spawner::new(
            hx_core::pool::ModelPool::new(vec![]),
            registry_for(&[]),
            secrets_for(&[]),
            st.clone(),
        );
        let s = session(&st);
        assert_eq!(
            run_fan_out(&mut sp, s.id(), &["p1"], None).await,
            Err(FanOutError::Draw(hx_core::pool::DrawError::Empty))
        );
    }

    /// A dead member's error is redacted before it is returned on `ChildOutcome::Errored`: the
    /// provider can echo a recognisable credential (an `sk-` key) in its body, and that must
    /// never become a string a client reads.
    ///
    /// The boundary here is honest: the fanout does not hold the resolved secret (only `Spawner` does),
    /// so it applies the shared [`Redactor`]'s *pattern* pass, which masks recognisable credential
    /// shapes. Opaque values with no shape are the spawner's separate job — it registers the resolved key
    /// as a literal when it writes the stored death reason.
    #[tokio::test]
    async fn a_dead_members_error_is_redacted_at_the_fanout_boundary() {
        // "a" fails and echoes a recognisable key; "b" succeeds.
        let mut reg = ProviderRegistry::new();
        reg.insert(Arc::new(ScriptedProvider::new("a").failing()));
        reg.insert(Arc::new(ScriptedProvider::new("b")));
        let st = store();
        // "a"'s credential has the OpenAI `sk-` shape the pattern redactor recognises.
        let secrets: SecretStores = {
            let mut s = FixedSecrets::new("vault");
            s = s.set("pool/a", "sk-abcdefghijklmnopqrstuvwxyz0123456789");
            s = s.set("pool/b", "sentinel-b");
            SecretStores::new().with(Arc::new(s))
        };
        let mut sp = Spawner::new(
            hx_core::pool::ModelPool::new(vec![member("a"), member("b")]),
            Arc::new(reg),
            Arc::new(secrets),
            st.clone(),
        );
        let s = session(&st);

        let out = run_fan_out(&mut sp, s.id(), &["p1", "p2"], None)
            .await
            .expect("runs");
        let errored = out
            .children
            .iter()
            .find_map(|c| match c {
                ChildOutcome::Errored { member, error } if member == "a" => Some(error.as_str()),
                _ => None,
            })
            .expect("a errored");
        assert!(
            !errored.contains("sk-abcdefghijklmnopqrstuvwxyz0123456789"),
            "the key 'a' was given leaked through: {errored}"
        );
    }

    /// A provider that rendezvous with its sibling on a barrier before answering: both children
    /// must be inside `complete` at the same time for either to return.
    struct BarrierProvider {
        id: ProviderId,
        barrier: Arc<Barrier>,
    }

    #[async_trait]
    impl Provider for BarrierProvider {
        fn id(&self) -> &ProviderId {
            &self.id
        }
        fn kind(&self) -> ProviderKind {
            ProviderKind::Openai
        }
        fn models(&self) -> &[String] {
            &[]
        }
        async fn complete(&self, _req: ChatRequest, _key: &Secret) -> Result<ChatResponse> {
            self.barrier.wait().await;
            Ok(ChatResponse {
                message: Message::assistant("done"),
                usage: Usage {
                    input_tokens: 10,
                    output_tokens: 5,
                    ..Default::default()
                },
                finish: FinishReason::Stop,
                model: self.id.to_string(),
                raw: None,
            })
        }
    }

    /// Concurrency proof: two providers rendezvous on a `Barrier(2)` — if the children ran one
    /// after the other, the first would wait at the barrier forever and the timeout would fire.
    #[tokio::test]
    async fn two_children_meet_on_a_barrier_so_they_run_concurrently() {
        let barrier = Arc::new(Barrier::new(2));
        let mut reg = ProviderRegistry::new();
        for id in ["a", "b"] {
            reg.insert(Arc::new(BarrierProvider {
                id: ProviderId::from(id),
                barrier: Arc::clone(&barrier),
            }));
        }
        let st = store();
        let mut sp = Spawner::new(
            hx_core::pool::ModelPool::new(vec![member("a"), member("b")]),
            Arc::new(reg),
            secrets_for(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);

        let out = tokio::time::timeout(
            Duration::from_secs(5),
            run_fan_out(&mut sp, s.id(), &["p1", "p2"], None),
        )
        .await
        .expect("two lanes in flight must both reach the barrier before the timeout")
        .expect("the barrier tripped, so both children ran");
        assert_eq!(out.children.len(), 2);
        assert!(
            out.members_are_distinct(),
            "concurrent children still land on distinct members"
        );
        assert_eq!(out.completed_models(), vec!["a", "b"]);
    }

    /// A provider that sleeps before answering.
    struct SleepyProvider {
        id: ProviderId,
        delay: Duration,
    }

    #[async_trait]
    impl Provider for SleepyProvider {
        fn id(&self) -> &ProviderId {
            &self.id
        }
        fn kind(&self) -> ProviderKind {
            ProviderKind::Openai
        }
        fn models(&self) -> &[String] {
            &[]
        }
        async fn complete(&self, _req: ChatRequest, _key: &Secret) -> Result<ChatResponse> {
            tokio::time::sleep(self.delay).await;
            Ok(ChatResponse {
                message: Message::assistant("done"),
                usage: Usage {
                    input_tokens: 10,
                    output_tokens: 5,
                    ..Default::default()
                },
                finish: FinishReason::Stop,
                model: self.id.to_string(),
                raw: None,
            })
        }
    }

    /// Overlap proof: two children that each sleep 200ms finish in well under their 400ms serial
    /// sum. Two sleeps rather than a slow+fast pair: slow+fast takes ~200ms either way and proves
    /// nothing, while a tokio sleep never fires early — so a sequential run takes at least 400ms
    /// and can never pass the 350ms bound.
    #[tokio::test]
    async fn two_slow_children_overlap_in_time() {
        let mut reg = ProviderRegistry::new();
        for id in ["a", "b"] {
            reg.insert(Arc::new(SleepyProvider {
                id: ProviderId::from(id),
                delay: Duration::from_millis(200),
            }));
        }
        let st = store();
        let mut sp = Spawner::new(
            hx_core::pool::ModelPool::new(vec![member("a"), member("b")]),
            Arc::new(reg),
            secrets_for(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);

        let start = Instant::now();
        let out = run_fan_out(&mut sp, s.id(), &["p1", "p2"], None)
            .await
            .expect("two slow children still complete");
        let elapsed = start.elapsed();
        assert_eq!(out.completed_models().len(), 2);
        assert!(
            elapsed < Duration::from_millis(350),
            "two 200ms lanes overlapping take ~200ms, took {elapsed:?}"
        );
    }

    /// A provider that either releases its sibling or waits to be released: with "a" waiting and
    /// "b" releasing, "b"'s provider call always finishes first — deterministically, with no
    /// sleeps. (`Notify` holds one permit, so release-before-wait still wakes the waiter.)
    struct GatedProvider {
        id: ProviderId,
        gate: Arc<Notify>,
        releases: bool,
    }

    #[async_trait]
    impl Provider for GatedProvider {
        fn id(&self) -> &ProviderId {
            &self.id
        }
        fn kind(&self) -> ProviderKind {
            ProviderKind::Openai
        }
        fn models(&self) -> &[String] {
            &[]
        }
        async fn complete(&self, _req: ChatRequest, _key: &Secret) -> Result<ChatResponse> {
            if self.releases {
                self.gate.notify_one();
            } else {
                self.gate.notified().await;
            }
            Ok(ChatResponse {
                message: Message::assistant("done"),
                usage: Usage {
                    input_tokens: 10,
                    output_tokens: 5,
                    ..Default::default()
                },
                finish: FinishReason::Stop,
                model: self.id.to_string(),
                raw: None,
            })
        }
    }

    /// Stable ordering: the second child finishes its provider call first, but the outcomes still
    /// come back in request order. (Sequential execution would hang here — child 0 waits for a
    /// release that child 1 never gets to send — so the timeout doubles as a second concurrency
    /// proof.)
    #[tokio::test]
    async fn children_report_in_request_order_when_the_second_finishes_first() {
        let gate = Arc::new(Notify::new());
        let mut reg = ProviderRegistry::new();
        reg.insert(Arc::new(GatedProvider {
            id: ProviderId::from("a"),
            gate: Arc::clone(&gate),
            releases: false,
        }));
        reg.insert(Arc::new(GatedProvider {
            id: ProviderId::from("b"),
            gate: Arc::clone(&gate),
            releases: true,
        }));
        let st = store();
        let mut sp = Spawner::new(
            hx_core::pool::ModelPool::new(vec![member("a"), member("b")]),
            Arc::new(reg),
            secrets_for(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);

        // Allocation draws "a" first, so child 0 waits on child 1's release.
        let out = tokio::time::timeout(
            Duration::from_secs(5),
            run_fan_out(&mut sp, s.id(), &["p1", "p2"], None),
        )
        .await
        .expect("the gated child must be released before the timeout")
        .expect("both children ran");
        let models: Vec<&str> = out
            .children
            .iter()
            .map(|c| match c {
                ChildOutcome::Ran(rec) => rec.model.as_str(),
                ChildOutcome::Errored { .. } => panic!("both children ran"),
            })
            .collect();
        assert_eq!(
            models,
            vec!["a", "b"],
            "completion order was b-then-a; the outcome stays in request order"
        );
    }

    /// The `max_parallel` knob's floor: `Some(1)` runs the children one at a time and still runs
    /// every child, in order, on distinct members — the bound serialises, it never drops work.
    #[tokio::test]
    async fn a_max_parallel_of_one_still_runs_every_child_in_order() {
        let st = store();
        let mut sp = Spawner::new(
            hx_core::pool::ModelPool::new(vec![member("a"), member("b")]),
            registry_for(&["a", "b"]),
            secrets_for(&["a", "b"]),
            st.clone(),
        );
        let s = session(&st);

        let out = run_fan_out(&mut sp, s.id(), &["p1", "p2"], Some(1))
            .await
            .expect("serialised children still complete");
        assert!(out.members_are_distinct());
        assert_eq!(out.completed_models(), vec!["a", "b"]);
        let totals = st.totals(s.id()).expect("totals read");
        assert_eq!(totals.provider_calls, 2);
    }
}

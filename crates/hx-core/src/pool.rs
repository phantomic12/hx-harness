//! A model pool a future subagent spawner draws children from (M8).
//!
//! ## Nothing draws from this pool yet — said plainly
//!
//! There is **no subagent runtime in this repository**. `ROADMAP.md`'s M8 is written as if a
//! subagent system already exists (\"today a subagent's model is a process-global `delegation.model`
//! key\"); it does not — there is no `ChildSpec`, no orchestrator, no `spawn_child` anywhere in
//! `crates/` or `apps/`. This module is the **pure routing logic** that a future spawner will draw
//! from. Nothing calls [`ModelPool`] today. That gap is the deliverable's honest shape: the routing
//! rules are the hard part, and they are worth landing and testing on their own before a spawner exists
//! to exercise them. When that spawner lands, it draws a member from here, not the other way round.
//!
//! (Recording *which model and cost* a turn spent is not this module's job either: `UsageRecord` in
//! `hx-store/src/session.rs` already carries `provider`, `credential`, `model` and `cost_usd`, so the
//! audit half of M8 is already possible per turn.)
//!
//! ## What a member is
//!
//! A [`PoolMember`] is the *configuration* of one model the harness could spawn a child against: an id,
//! a base URL, a credential and the parameters it accepts. Members are configuration, so the config-side
//! structs here (`ModelPoolMemberConfig` via [`crate::config`]) deserialize from the `hx-core` config
//! and carry [`Default`]s so existing config files keep parsing.
//!
//! The credential is a **reference, never a value** — `vault:subagent/lane-builder`, `env:…`. This
//! follows `hx-secrets`' existing reference discipline (see `credential` in `config.rs` and the MCP
//! `token` rule): a value written into a config file is a value in every copy, backup and paste of it.
//! The value itself lives in the vault/environment and is resolved by whoever actually connects — never
//! here, and never in an error or a `Debug` dump.
//!
//! ## Health-aware draw
//!
//! [`ModelPool::draw`] returns the next **healthy** member, round-robin over the healthy set. A member
//! that fails its first call is marked down ([`ModelPool::mark_down`]) with a **reason and a
//! timestamp**, and the next draw comes from a healthy member. A member that is down is never drawn while
//! a healthy one exists; when *all* are down the draw returns [`DrawError::AllDown`], which names the
//! condition and every member's reason, rather than silently returning the first member.
//!
//! ## Capability clamping
//!
//! Given a requested parameter set and a chosen member, [`PoolMember::clamp`] produces the effective set
//! by clamping a value the member does not accept to its nearest accepted one, **and returns the list of
//! clamps applied** — recorded, never sent and hoped for. The real case this exists for: one model
//! rejects `reasoning_effort` with `HTTP 400` while another accepts it. A parameter whose kind the
//! member does not support at all is dropped, and the clamp records that (`sent: None`).
//!
//! Everything in this module is pure: no network, no filesystem, no clock read by the module itself —
//! timestamps are handed in, which is what lets the tests script the pool.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A `reasoning_effort` request value, ordered low → high so \"nearest accepted\" is well-defined.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningEffort {
    Low,
    Medium,
    High,
}

/// A requestable parameter a member may or may not accept.
///
/// One variant per parameter kind. Internally tagged (`kind:` + `value:`) so it reads plainly in a
/// config file — `serde_yaml` reads externally-tagged enums as `!tags`, which nobody writing a config
/// expects (the same reason `AuthMethod` is internally tagged).
///
/// Each variant's value carries its own ordering, which is what lets clamping pick the *nearest* accepted
/// value rather than an arbitrary one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Param {
    #[serde(rename = "reasoning_effort")]
    ReasoningEffort {
        #[serde(rename = "value")]
        effort: ReasoningEffort,
    },
}

impl Param {
    /// Discriminates parameter kinds, so clamping only compares values of the same kind.
    fn kind(&self) -> ParamKind {
        match self {
            Param::ReasoningEffort { .. } => ParamKind::ReasoningEffort,
        }
    }

    /// A position on the kind's own ordering, for the "nearest" part of clamping.
    fn ordinal(&self) -> i64 {
        match self {
            Param::ReasoningEffort { effort } => match effort {
                ReasoningEffort::Low => 0,
                ReasoningEffort::Medium => 1,
                ReasoningEffort::High => 2,
            },
        }
    }

    /// The reasoning-effort value, for ergonomic construction in tests and callers.
    pub fn reasoning_effort(effort: ReasoningEffort) -> Param {
        Param::ReasoningEffort { effort }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParamKind {
    ReasoningEffort,
}

/// A record of one clamp applied to a requested parameter set.
///
/// `requested` is what the caller asked for; `sent` is what the member will actually receive. `sent`
/// is [`None`] when the parameter was **dropped** because the member supports none of that kind — the
/// honest alternative to sending a value the model would `400` on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParamClamp {
    pub requested: Param,
    pub sent: Option<Param>,
}

/// The result of clamping a requested parameter set to a member's accepted set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EffectiveParams {
    /// The effective parameters — every requested parameter the member accepts, plus the clamped ones.
    pub params: Vec<Param>,
    /// Every clamp applied, in request order. Recorded, never silently sent.
    pub clamps: Vec<ParamClamp>,
}

/// Health of a single member. Scripted by the pool driver, never by a wall-clock inside this module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemberHealth {
    Healthy,
    Down { reason: String, at: DateTime<Utc> },
}

/// One model the harness could draw a child from. Configuration plus health state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolMember {
    pub id: String,
    pub base_url: String,
    /// A credential **reference** (`vault:…`/`env:…`), never a value — see the module doc.
    pub credential: String,
    /// The parameters this member accepts. Empty means \"no parameter of any kind may be sent\".
    pub accepts: Vec<Param>,
    pub health: MemberHealth,
}

impl PoolMember {
    /// Clamp a requested parameter set to this member's accepted set, returning the effective set and
    /// every clamp applied.
    pub fn clamp(&self, requested: &[Param]) -> EffectiveParams {
        let mut out = EffectiveParams::default();
        for &p in requested {
            if self.accepts.contains(&p) {
                // Accepted as asked: keep it, no clamp.
                out.params.push(p);
                continue;
            }
            // Same-kind accepted values to clamp against.
            let same_kind: Vec<Param> = self
                .accepts
                .iter()
                .copied()
                .filter(|a| a.kind() == p.kind())
                .collect();
            if same_kind.is_empty() {
                // The member supports none of this kind — dropping is the only clamp available.
                out.clamps.push(ParamClamp {
                    requested: p,
                    sent: None,
                });
                continue;
            }
            let nearest = *same_kind
                .iter()
                .min_by_key(|a| (a.ordinal() - p.ordinal()).abs())
                .expect("same_kind is non-empty here");
            out.params.push(nearest);
            out.clamps.push(ParamClamp {
                requested: p,
                sent: Some(nearest),
            });
        }
        out
    }
}

/// Why a draw could not return a member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DrawError {
    /// There are no members at all.
    Empty,
    /// Every member is down; each entry is `(member id, reason)`.
    AllDown { members: Vec<(String, String)> },
}

impl std::fmt::Display for DrawError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DrawError::Empty => write!(f, "the model pool has no members"),
            DrawError::AllDown { members } => {
                write!(f, "every member of the model pool is down: ")?;
                for (i, (id, reason)) in members.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{id} ({reason})")?;
                }
                Ok(())
            }
        }
    }
}

/// The ordered members of one pool plus the draw policy.
///
/// The single draw policy is **round-robin over the healthy set**: each draw advances a cursor across
/// the indices that are currently healthy. This is deterministic and, because a down member is simply not
/// in the healthy set, health-awareness falls out of the same cursor — no second code path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelPool {
    /// Ordered members, in configuration/draw-priority order.
    pub members: Vec<PoolMember>,
    /// Cursor over the healthy set, advanced on every draw.
    cursor: usize,
}

impl ModelPool {
    pub fn new(members: Vec<PoolMember>) -> Self {
        Self { members, cursor: 0 }
    }

    /// Draw the next **healthy** member, round-robin over the healthy set.
    ///
    /// Fails loudly when every member is down (or there are none) rather than silently returning the
    /// first member.
    pub fn draw(&mut self) -> Result<&PoolMember, DrawError> {
        let healthy: Vec<usize> = self
            .members
            .iter()
            .enumerate()
            .filter(|(_, m)| m.health == MemberHealth::Healthy)
            .map(|(i, _)| i)
            .collect();

        if healthy.is_empty() {
            if self.members.is_empty() {
                return Err(DrawError::Empty);
            }
            let reasons: Vec<(String, String)> = self
                .members
                .iter()
                .map(|m| match &m.health {
                    MemberHealth::Healthy => (m.id.clone(), "healthy".to_string()),
                    MemberHealth::Down { reason, .. } => (m.id.clone(), reason.clone()),
                })
                .collect();
            return Err(DrawError::AllDown { members: reasons });
        }

        let idx = healthy[self.cursor % healthy.len()];
        self.cursor = self.cursor.wrapping_add(1);
        Ok(&self.members[idx])
    }

    /// Mark a member down with a reason and timestamp. Returns `true` if a member was found and marked.
    pub fn mark_down(&mut self, id: &str, reason: impl Into<String>, at: DateTime<Utc>) -> bool {
        match self.members.iter_mut().find(|m| m.id == id) {
            Some(m) => {
                m.health = MemberHealth::Down {
                    reason: reason.into(),
                    at,
                };
                true
            }
            None => false,
        }
    }

    /// Mark a member healthy again. Returns `true` if a member was found and changed.
    pub fn mark_up(&mut self, id: &str) -> bool {
        match self.members.iter_mut().find(|m| m.id == id) {
            Some(m) => {
                m.health = MemberHealth::Healthy;
                true
            }
            None => false,
        }
    }

    /// Build a pool from its config form. Every configured member starts healthy.
    pub fn from_config(members: Vec<ModelPoolMemberConfig>) -> Self {
        let members = members
            .into_iter()
            .map(PoolMember::from_config)
            .collect::<Vec<_>>();
        Self::new(members)
    }
}

/// Config-side shape of a [`PoolMember`], the deserializable half.
///
/// Separate from the runtime [`PoolMember`] so that health state and the draw cursor are never part of a
/// config document, and so `health` does not need a [`Default`]. Fields are additive (`#[serde
/// (default)]` on `accepts`) so existing config files keep parsing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPoolMemberConfig {
    pub id: String,
    pub base_url: String,
    /// A credential **reference** (`vault:…` / `env:…`), never a value.
    pub credential: String,
    #[serde(default)]
    pub accepts: Vec<Param>,
}

impl PoolMember {
    fn from_config(c: ModelPoolMemberConfig) -> Self {
        Self {
            id: c.id,
            base_url: c.base_url,
            credential: c.credential,
            accepts: c.accepts,
            health: MemberHealth::Healthy,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("fixed test timestamp")
    }

    fn member(id: &str, accepts: &[Param]) -> PoolMember {
        PoolMember {
            id: id.to_string(),
            base_url: format!("https://{id}.example.test"),
            credential: format!("vault:pool/{id}"),
            accepts: accepts.to_vec(),
            health: MemberHealth::Healthy,
        }
    }

    /// The brief's routing invariant: N draws across a pool of N healthy members reach N distinct members.
    #[test]
    fn n_draws_across_n_healthy_members_reach_n_distinct_members() {
        let mut pool = ModelPool::new(vec![
            member("cheap", &[]),
            member("strong", &[]),
            member("mid", &[]),
        ]);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..3 {
            let m = pool.draw().expect("all healthy");
            seen.insert(m.id.clone());
        }
        assert_eq!(seen.len(), 3, "round-robin must reach every member");
    }

    /// Draws keep cycling in order round-robin when all members stay healthy.
    #[test]
    fn draws_cycle_round_robin_in_order_while_all_healthy() {
        let mut pool = ModelPool::new(vec![member("a", &[]), member("b", &[])]);
        let first = pool.draw().unwrap().id.clone();
        let second = pool.draw().unwrap().id.clone();
        let third = pool.draw().unwrap().id.clone();
        let fourth = pool.draw().unwrap().id.clone();
        assert_eq!(first, "a");
        assert_eq!(second, "b");
        assert_eq!(third, "a", "the fourth draw revisits the first member");
        assert_eq!(fourth, "b");
    }

    /// A member marked down after a failure is not drawn again while a healthy member remains.
    #[test]
    fn a_down_member_is_not_drawn_while_a_healthy_one_remains() {
        let mut pool = ModelPool::new(vec![member("a", &[]), member("b", &[]), member("c", &[])]);
        // First draw reaches "a"; it fails; mark it down.
        let first = pool.draw().unwrap().id.clone();
        assert!(pool.mark_down(&first, "upstream returned HTTP 500", now()));

        // Many draws must never come back to "a" while "b"/"c" are healthy.
        for _ in 0..10 {
            let id = pool.draw().expect("b and c are still healthy").id.clone();
            assert_ne!(
                id, first,
                "a down member must not be drawn while a healthy one remains"
            );
        }
    }

    /// Marking down carries the reason and the timestamp.
    #[test]
    fn marking_down_records_a_reason_and_a_timestamp() {
        let mut pool = ModelPool::new(vec![member("a", &[])]);
        let t = now();
        assert!(pool.mark_down("a", "lazy credential", t));
        match &pool.members[0].health {
            MemberHealth::Down { reason, at } => {
                assert_eq!(reason, "lazy credential");
                assert_eq!(*at, t);
            }
            MemberHealth::Healthy => panic!("must be down"),
        }
    }

    /// The brief's explicit case: when all members are down the draw says so, rather than silently
    /// returning the first member.
    #[test]
    fn a_draw_with_every_member_down_is_a_distinguishable_error() {
        let mut pool = ModelPool::new(vec![member("a", &[]), member("b", &[]), member("c", &[])]);
        pool.mark_down("a", "boom-a", now());
        pool.mark_down("b", "boom-b", now());
        pool.mark_down("c", "boom-c", now());

        match pool.draw() {
            Err(DrawError::AllDown { members }) => {
                let ids: Vec<&str> = members.iter().map(|(id, _)| id.as_str()).collect();
                assert_eq!(ids, vec!["a", "b", "c"]);
                let text = pool.draw().unwrap_err().to_string();
                assert!(text.contains("boom-a") && text.contains("boom-c"), "{text}");
            }
            other => panic!("must be AllDown, got {other:?}"),
        }
    }

    /// A pool with no members at all draws an `Empty` error, distinct from `AllDown`.
    #[test]
    fn an_empty_pool_draws_an_empty_error() {
        let mut pool: ModelPool = ModelPool::new(vec![]);
        assert_eq!(pool.draw(), Err(DrawError::Empty));
    }

    /// A member that recovers is drawn again once marked up.
    #[test]
    fn a_member_recovers_and_is_drawn_again_after_mark_up() {
        let mut pool = ModelPool::new(vec![member("a", &[]), member("b", &[])]);
        assert!(pool.mark_down("a", "transient", now()));
        for _ in 0..5 {
            assert_eq!(pool.draw().unwrap().id, "b");
        }
        assert!(pool.mark_up("a"));
        // With both healthy again, round-robin returns a and b.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..4 {
            seen.insert(pool.draw().unwrap().id.clone());
        }
        assert!(seen.contains("a"), "a recovered member is drawn again");
        assert!(seen.contains("b"));
    }

    /// A clamped parameter is clamped to the member's **nearest** accepted value and appears in the
    /// returned clamp list; an accepted parameter produces **no** clamp.
    #[test]
    fn clamped_parameters_reach_the_nearest_accepted_value_and_are_recorded() {
        // This member accepts only Low and High, not Medium.
        let m = member(
            "strong",
            &[
                Param::reasoning_effort(ReasoningEffort::Low),
                Param::reasoning_effort(ReasoningEffort::High),
            ],
        );
        let requested = [
            Param::reasoning_effort(ReasoningEffort::Medium),
            Param::reasoning_effort(ReasoningEffort::Low), // already accepted
        ];
        let eff = m.clamp(&requested);

        // Medium (ordinal 1) is equidistant from Low (0) and High (2), so the tie resolves to the
        // first accepted value at that distance — Low, in listing order. Determinism is the property, and
        // the non-tie cases (clamping_picks_the_truly_nearest_accepted_value) make "near" unambiguous.
        assert_eq!(
            eff.params,
            vec![
                Param::reasoning_effort(ReasoningEffort::Low),
                Param::reasoning_effort(ReasoningEffort::Low),
            ],
            "the equidistant Medium is clamped deterministically and Low is unchanged"
        );
        assert_eq!(
            eff.clamps,
            vec![ParamClamp {
                requested: Param::reasoning_effort(ReasoningEffort::Medium),
                sent: Some(Param::reasoning_effort(ReasoningEffort::Low)),
            }],
            "only the clamped parameter is recorded, the accepted one records nothing"
        );
    }

    /// Nearest is the true nearest by ordinal — not "minimum accepted" and not "some accepted".
    ///
    /// Two assertions, each chosen so that the wrong implementation (`.min()`, or the first accepted)
    /// differs from nearest:
    /// - target Low (0), member accepts [Medium(1), High(2)]) → nearest is Medium; `.min()` would
    ///   also give Medium, so this alone does not catch a `.min()` regression.
    /// - target High (2), member accepts [Low(0), Medium(1)]) → nearest is Medium; `.min()` would give
    ///   Low. This is the one that actually distinguishes nearest from minimum.
    #[test]
    fn clamping_picks_the_truly_nearest_accepted_value() {
        // Case A: target Low, member accepts [Medium, High].
        let m = member(
            "m",
            &[
                Param::reasoning_effort(ReasoningEffort::Medium),
                Param::reasoning_effort(ReasoningEffort::High),
            ],
        );
        let eff = m.clamp(&[Param::reasoning_effort(ReasoningEffort::Low)]);
        assert_eq!(
            eff.clamps,
            vec![ParamClamp {
                requested: Param::reasoning_effort(ReasoningEffort::Low),
                sent: Some(Param::reasoning_effort(ReasoningEffort::Medium)),
            }]
        );
        assert_eq!(
            eff.params,
            vec![Param::reasoning_effort(ReasoningEffort::Medium)]
        );

        // Case B: target High, member accepts [Low, Medium] → nearest is Medium, `.min()` would give Low.
        let m2 = member(
            "m2",
            &[
                Param::reasoning_effort(ReasoningEffort::Low),
                Param::reasoning_effort(ReasoningEffort::Medium),
            ],
        );
        let eff2 = m2.clamp(&[Param::reasoning_effort(ReasoningEffort::High)]);
        assert_eq!(
            eff2.clamps,
            vec![ParamClamp {
                requested: Param::reasoning_effort(ReasoningEffort::High),
                sent: Some(Param::reasoning_effort(ReasoningEffort::Medium)),
            }],
            "High is nearest Medium (distance 1), not Low (distance 2)"
        );
        assert_eq!(
            eff2.params,
            vec![Param::reasoning_effort(ReasoningEffort::Medium)]
        );
    }

    /// A parameter kind the member does not support at all is dropped, and recorded with `sent: None`.
    #[test]
    fn an_unsupported_parameter_kind_is_dropped_and_recorded() {
        let m = member("no-reasoning", &[]); // accepts nothing
        let requested = [Param::reasoning_effort(ReasoningEffort::High)];
        let eff = m.clamp(&requested);
        assert!(eff.params.is_empty(), "nothing may be sent");
        assert_eq!(
            eff.clamps,
            vec![ParamClamp {
                requested: Param::reasoning_effort(ReasoningEffort::High),
                sent: None,
            }]
        );
    }

    /// A member that accepts a parameter keeps it verbatim with no clamp.
    #[test]
    fn an_accepted_parameter_is_kept_with_no_clamp() {
        let m = member("r", &[Param::reasoning_effort(ReasoningEffort::Medium)]);
        let eff = m.clamp(&[Param::reasoning_effort(ReasoningEffort::Medium)]);
        assert_eq!(
            eff.params,
            vec![Param::reasoning_effort(ReasoningEffort::Medium)]
        );
        assert!(eff.clamps.is_empty());
    }

    /// Config round-trip: a pool parsed from a config document matches the same pool built from the same
    /// member configs, and every member starts healthy.
    #[test]
    fn a_config_model_pool_round_trips_to_a_healthy_pool() {
        let cfg = crate::config::Config::from_yaml(
            r#"
model_pools:
  builder:
    - id: cheap
      base_url: https://cheap.example.test
      credential: vault:pool/cheap
      accepts:
        - { kind: reasoning_effort, value: low }
    - id: strong
      base_url: https://strong.example.test
      credential: env:STRONG_KEY
      accepts:
        - { kind: reasoning_effort, value: medium }
        - { kind: reasoning_effort, value: high }
"#,
        )
        .expect("model pool config must parse");

        assert_eq!(cfg.model_pools.len(), 1);

        let mut pool = cfg.model_pool("builder").expect("builder pool builds");
        assert_eq!(pool.members.len(), 2);
        assert_eq!(pool.members[0].id, "cheap");
        assert_eq!(pool.members[1].id, "strong");
        assert_eq!(
            pool.members[0].credential, "vault:pool/cheap",
            "the credential is a reference, verbatim"
        );
        for m in &pool.members {
            assert_eq!(
                m.health,
                MemberHealth::Healthy,
                "a member from config starts healthy"
            );
        }
        // And drawing walks the healthy set in order.
        assert_eq!(pool.draw().unwrap().id, "cheap");
        assert_eq!(pool.draw().unwrap().id, "strong");

        // A pool that is not configured is a named error.
        let err = cfg.model_pool("nope").unwrap_err().to_string();
        assert!(err.contains("nope"), "{err}");
    }

    /// Backwards compatibility: a config with no `model_pools` section at all still loads.
    #[test]
    fn a_config_with_no_model_pool_section_still_loads() {
        let cfg = crate::config::Config::from_yaml("{}\n").expect("must parse");
        assert!(cfg.model_pools.is_empty());

        // And the shipped example config — which predates this field — still parses.
        let example = include_str!("../../../hx.example.yaml");
        let cfg2 = crate::config::Config::from_yaml(example).expect("example must parse");
        assert!(cfg2.model_pools.is_empty());
    }

    /// A member config is additive: every field except `id`/`base_url`/`credential` is defaulted.
    #[test]
    fn a_member_config_with_no_accepts_parses_and_accepts_nothing() {
        let cfg = crate::config::Config::from_yaml(
            r#"
model_pools:
  p:
    - id: bare
      base_url: https://bare.example.test
      credential: vault:pool/bare
"#,
        )
        .expect("must parse");
        let pool = cfg.model_pool("p").unwrap();
        assert!(pool.members[0].accepts.is_empty());
    }
}

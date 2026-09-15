//! Credential pools.
//!
//! A pool is *several credentials for one provider*, plus a routing strategy and health state.
//! The point is that a rate-limited or revoked key degrades throughput instead of failing the
//! task: the pool fails over to the next key, and the agent above never learns it happened.
//!
//! Two levels of ceiling apply simultaneously, and both must be honoured:
//!
//! ```text
//!      pool ceilings   (e.g. "all background work: 80k TPM combined")
//!            |
//!      credential ceilings  (e.g. "key #1: 50 RPM, $25/day")
//! ```
//!
//! Pool-level checks run **first**, so a pool-wide cap does not silently consume per-credential
//! reservations it is about to reject — there is a test for exactly that.

use crate::limits::{Lease, Limiter, Limits};
use chrono::{DateTime, Utc};
use hx_core::config::Strategy;
use hx_core::error::HxError;
use hx_core::ids::{CredentialId, ProviderId};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum PoolError {
    #[error("pool {provider} has no credentials configured")]
    Empty { provider: ProviderId },

    #[error(
        "all {count} credentials for {provider} are at their limits; soonest recovery in {retry_after_secs:.0}s"
    )]
    Exhausted {
        provider: ProviderId,
        count: usize,
        retry_after_secs: f64,
    },

    #[error("all {count} credentials for {provider} are marked unhealthy")]
    AllUnhealthy { provider: ProviderId, count: usize },
}

impl From<PoolError> for HxError {
    fn from(e: PoolError) -> Self {
        // Surfaced as "no route" so the caller's retry logic treats a dry pool like any other
        // unroutable request rather than a hard failure.
        HxError::NoRoute(e.to_string())
    }
}

/// How much a single credential currently costs, for `CheapestCapable`.
pub type CostPerMtok = f64;

/// One credential and its live state.
#[derive(Debug)]
pub struct Slot {
    pub id: CredentialId,
    /// Reference like `vault:anthropic/key1`. The value itself is never held here.
    pub secret_ref: String,
    pub weight: u32,
    /// Lower runs first under `Priority`.
    pub priority: u32,
    pub cost_per_mtok: Option<CostPerMtok>,
    pub healthy: bool,
    pub unhealthy_reason: Option<String>,
    pub limiter: Limiter,
    /// nginx-style smooth-weighted-round-robin accumulator.
    pub current_weight: i64,
}

impl Slot {
    pub fn new(
        id: CredentialId,
        secret_ref: impl Into<String>,
        limits: Limits,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            secret_ref: secret_ref.into(),
            weight: 1,
            priority: 0,
            cost_per_mtok: None,
            healthy: true,
            unhealthy_reason: None,
            limiter: Limiter::new(limits, now),
            current_weight: 0,
        }
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight.max(1);
        self
    }

    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_cost(mut self, cost_per_mtok: CostPerMtok) -> Self {
        self.cost_per_mtok = Some(cost_per_mtok);
        self
    }
}

/// A granted reservation. Hand this back to [`CredentialPool::reconcile`] (normal path) or
/// [`CredentialPool::release`] (request failed before reaching the provider).
#[derive(Debug, Clone)]
pub struct Ticket {
    pub provider: ProviderId,
    pub credential: CredentialId,
    lease: Lease,
    pool_lease: Option<Lease>,
}

impl Ticket {
    pub fn reserved_tokens(&self) -> u64 {
        self.lease.reserved_tokens
    }

    pub fn reserved_usd(&self) -> f64 {
        self.lease.reserved_usd
    }
}

/// Read-only view for status surfaces (`hx status`, the web UI, `/health`).
#[derive(Debug, Clone, Serialize)]
pub struct SlotStatus {
    pub id: CredentialId,
    pub secret_ref: String,
    pub healthy: bool,
    pub unhealthy_reason: Option<String>,
    pub in_flight: u32,
    pub spent_today_usd: f64,
    pub load: f64,
}

/// A provider's credential pool.
#[derive(Debug)]
pub struct CredentialPool {
    provider: ProviderId,
    strategy: Strategy,
    slots: Vec<Slot>,
    pool_limiter: Option<Limiter>,
    cursor: u64,
}

impl CredentialPool {
    pub fn new(provider: ProviderId, strategy: Strategy, slots: Vec<Slot>) -> Self {
        Self {
            provider,
            strategy,
            slots,
            pool_limiter: None,
            cursor: 0,
        }
    }

    /// Apply a ceiling across the whole pool, on top of per-credential ceilings.
    pub fn with_pool_limits(mut self, limits: Limits, now: DateTime<Utc>) -> Self {
        self.pool_limiter = if limits.is_unbounded() {
            None
        } else {
            Some(Limiter::new(limits, now))
        };
        self
    }

    pub fn provider(&self) -> &ProviderId {
        &self.provider
    }

    pub fn strategy(&self) -> Strategy {
        self.strategy
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    /// Reserve capacity and pick a credential.
    ///
    /// Order of operations matters: the pool ceiling is checked first so that a pool-wide
    /// rejection cannot leave per-credential reservations dangling.
    pub fn acquire(
        &mut self,
        est_tokens: u64,
        est_usd: f64,
        now: DateTime<Utc>,
    ) -> Result<Ticket, PoolError> {
        if self.slots.is_empty() {
            return Err(PoolError::Empty {
                provider: self.provider.clone(),
            });
        }

        // 1. Pool-wide ceiling.
        let pool_lease = match &mut self.pool_limiter {
            Some(limiter) => match limiter.acquire(est_tokens, est_usd, now) {
                Ok(lease) => Some(lease),
                Err(e) => {
                    return Err(PoolError::Exhausted {
                        provider: self.provider.clone(),
                        count: self.slots.len(),
                        retry_after_secs: e.retry_after_secs().unwrap_or(60.0),
                    })
                }
            },
            None => None,
        };

        // 2. Preferred order for this strategy.
        let order = self.pick_order(now);

        // 3. First credential with headroom wins.
        let mut best_retry: Option<f64> = None;
        let mut saw_healthy = false;

        for idx in order {
            if !self.slots[idx].healthy {
                continue;
            }
            saw_healthy = true;

            match self.slots[idx].limiter.acquire(est_tokens, est_usd, now) {
                Ok(lease) => {
                    let credential = self.slots[idx].id.clone();
                    self.cursor = self.cursor.wrapping_add(1);
                    return Ok(Ticket {
                        provider: self.provider.clone(),
                        credential,
                        lease,
                        pool_lease,
                    });
                }
                Err(e) => {
                    let wait = e.retry_after_secs().unwrap_or(0.0);
                    best_retry = Some(best_retry.map_or(wait, |b: f64| b.min(wait)));
                }
            }
        }

        // Nothing worked — give the pool reservation back so it is not leaked.
        self.rollback(pool_lease, now);

        if saw_healthy {
            Err(PoolError::Exhausted {
                provider: self.provider.clone(),
                count: self.slots.len(),
                retry_after_secs: best_retry.unwrap_or(60.0),
            })
        } else {
            Err(PoolError::AllUnhealthy {
                provider: self.provider.clone(),
                count: self.slots.len(),
            })
        }
    }

    fn rollback(&mut self, pool_lease: Option<Lease>, now: DateTime<Utc>) {
        if let (Some(limiter), Some(lease)) = (&mut self.pool_limiter, pool_lease) {
            limiter.release(lease, now);
        }
    }

    /// Settle a ticket against actual usage, at both levels.
    pub fn reconcile(
        &mut self,
        ticket: Ticket,
        actual_tokens: u64,
        actual_usd: f64,
        now: DateTime<Utc>,
    ) {
        if let Some(slot) = self.slots.iter_mut().find(|s| s.id == ticket.credential) {
            slot.limiter
                .reconcile(ticket.lease, actual_tokens, actual_usd, now);
        }
        if let (Some(limiter), Some(lease)) = (&mut self.pool_limiter, ticket.pool_lease) {
            limiter.reconcile(lease, actual_tokens, actual_usd, now);
        }
    }

    /// Give a ticket back untouched.
    pub fn release(&mut self, ticket: Ticket, now: DateTime<Utc>) {
        if let Some(slot) = self.slots.iter_mut().find(|s| s.id == ticket.credential) {
            slot.limiter.release(ticket.lease, now);
        }
        self.rollback(ticket.pool_lease, now);
    }

    /// Take a credential out of rotation, e.g. after a hard 401/403 or a spend cut-off.
    pub fn mark_unhealthy(&mut self, id: &CredentialId, reason: impl Into<String>) -> bool {
        match self.slots.iter_mut().find(|s| &s.id == id) {
            Some(slot) => {
                slot.healthy = false;
                slot.unhealthy_reason = Some(reason.into());
                true
            }
            None => false,
        }
    }

    /// Put a credential back in rotation, e.g. after a 429 cooldown expires.
    pub fn mark_healthy(&mut self, id: &CredentialId) -> bool {
        match self.slots.iter_mut().find(|s| &s.id == id) {
            Some(slot) => {
                slot.healthy = true;
                slot.unhealthy_reason = None;
                true
            }
            None => false,
        }
    }

    pub fn healthy_count(&self) -> usize {
        self.slots.iter().filter(|s| s.healthy).count()
    }

    pub fn status(&mut self, now: DateTime<Utc>) -> Vec<SlotStatus> {
        self.slots
            .iter_mut()
            .map(|s| SlotStatus {
                id: s.id.clone(),
                secret_ref: s.secret_ref.clone(),
                healthy: s.healthy,
                unhealthy_reason: s.unhealthy_reason.clone(),
                in_flight: s.limiter.in_flight(),
                spent_today_usd: s.limiter.spent_today_usd(),
                load: s.limiter.load_score(now),
            })
            .collect()
    }

    /// Produce credential indices in preference order for the configured strategy.
    fn pick_order(&mut self, now: DateTime<Utc>) -> Vec<usize> {
        let n = self.slots.len();
        match self.strategy {
            Strategy::Priority => {
                let mut idx: Vec<usize> = (0..n).collect();
                // Stable, so equal priorities keep configuration order.
                idx.sort_by_key(|&i| self.slots[i].priority);
                idx
            }

            Strategy::RoundRobin => {
                let start = (self.cursor as usize) % n;
                (0..n).map(|k| (start + k) % n).collect()
            }

            Strategy::LeastLoaded => {
                let mut scored: Vec<(usize, f64)> = (0..n)
                    .map(|i| (i, self.slots[i].limiter.load_score(now)))
                    .collect();
                // Ascending load; ties fall back to configuration order.
                scored.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
                scored.into_iter().map(|(i, _)| i).collect()
            }

            Strategy::CheapestCapable => {
                let mut idx: Vec<usize> = (0..n).collect();
                idx.sort_by(|&a, &b| {
                    let ca = self.slots[a].cost_per_mtok.unwrap_or(f64::MAX);
                    let cb = self.slots[b].cost_per_mtok.unwrap_or(f64::MAX);
                    ca.partial_cmp(&cb)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        // Cheap-but-broken should not outrank cheap-and-working.
                        .then(self.slots[a].priority.cmp(&self.slots[b].priority))
                });
                idx
            }

            Strategy::Weighted => {
                // Smooth weighted round-robin (the nginx algorithm): each slot accrues its
                // weight, the highest accumulator wins, and the winner pays the total. Gives an
                // exact ratio over one cycle and no bursty clumping.
                debug_assert!(n > 0);
                let total: i64 = self.slots.iter().map(|s| s.weight as i64).sum();
                let mut head = 0usize;
                let mut best = i64::MIN;
                for i in 0..n {
                    let s = &mut self.slots[i];
                    s.current_weight += s.weight as i64;
                    if s.current_weight > best {
                        best = s.current_weight;
                        head = i;
                    }
                }
                self.slots[head].current_weight -= total;

                // Remaining slots ordered by weight, so fallback still respects preference.
                let mut rest: Vec<usize> = (0..n).filter(|&i| i != head).collect();
                rest.sort_by_key(|&i| std::cmp::Reverse(self.slots[i].weight));
                let mut order = vec![head];
                order.extend(rest);
                order
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn pid() -> ProviderId {
        ProviderId::from("anthropic-main")
    }

    fn cid(s: &str) -> CredentialId {
        CredentialId::from(s)
    }

    fn pool(strategy: Strategy, creds: &[(&str, Limits)]) -> CredentialPool {
        let slots = creds
            .iter()
            .map(|(id, limits)| Slot::new(cid(id), format!("vault:{id}"), limits.clone(), t0()))
            .collect();
        CredentialPool::new(pid(), strategy, slots)
    }

    #[test]
    fn empty_pool_reports_empty_rather_than_exhausted() {
        let mut p = pool(Strategy::Priority, &[]);
        assert_eq!(
            p.acquire(1, 0.0, t0()).unwrap_err(),
            PoolError::Empty { provider: pid() }
        );
    }

    #[test]
    fn priority_order_is_respected() {
        let mut p = CredentialPool::new(
            pid(),
            Strategy::Priority,
            vec![
                Slot::new(cid("second"), "vault:b", Limits::default(), t0()).with_priority(5),
                Slot::new(cid("first"), "vault:a", Limits::default(), t0()).with_priority(1),
            ],
        );
        let t = p.acquire(1, 0.0, t0()).unwrap();
        assert_eq!(
            t.credential,
            cid("first"),
            "lower priority number runs first"
        );
    }

    #[test]
    fn falls_over_to_the_next_credential_when_the_first_is_exhausted() {
        let tight = Limits {
            rpm: Some(1),
            ..Default::default()
        };
        let mut p = pool(
            Strategy::Priority,
            &[("primary", tight.clone()), ("backup", Limits::default())],
        );

        // Drain the primary.
        let t1 = p.acquire(1, 0.0, t0()).unwrap();
        assert_eq!(t1.credential, cid("primary"));
        p.reconcile(t1, 1, 0.0, t0());

        // Same instant: the primary is capped, so the pool must fall over rather than fail.
        let t2 = p.acquire(1, 0.0, t0()).expect("should fail over to backup");
        assert_eq!(t2.credential, cid("backup"));
    }

    #[test]
    fn reports_a_retry_hint_when_every_credential_is_exhausted() {
        let tight = Limits {
            rpm: Some(1),
            ..Default::default()
        };
        let mut p = pool(Strategy::Priority, &[("a", tight.clone()), ("b", tight)]);
        p.acquire(1, 0.0, t0()).unwrap();
        p.acquire(1, 0.0, t0()).unwrap();

        match p.acquire(1, 0.0, t0()).unwrap_err() {
            PoolError::Exhausted {
                count,
                retry_after_secs,
                ..
            } => {
                assert_eq!(count, 2);
                // 1 RPM => 60s of refill for one request. Must be a real number, not a panic.
                assert!(retry_after_secs > 0.0 && retry_after_secs <= 60.0);
            }
            other => panic!("expected Exhausted, got {other:?}"),
        }
    }

    #[test]
    fn unhealthy_credentials_are_skipped_and_recoverable() {
        let mut p = pool(
            Strategy::Priority,
            &[
                ("primary", Limits::default()),
                ("backup", Limits::default()),
            ],
        );

        assert!(p.mark_unhealthy(&cid("primary"), "401 unauthorized"));
        assert_eq!(p.healthy_count(), 1);

        let t = p.acquire(1, 0.0, t0()).unwrap();
        assert_eq!(t.credential, cid("backup"));

        // A cooldown expiring puts it back in rotation.
        assert!(p.mark_healthy(&cid("primary")));
        assert_eq!(p.healthy_count(), 2);
        let t = p.acquire(1, 0.0, t0()).unwrap();
        assert_eq!(t.credential, cid("primary"), "priority should be restored");
    }

    #[test]
    fn all_unhealthy_is_distinct_from_all_exhausted() {
        let mut p = pool(
            Strategy::Priority,
            &[("a", Limits::default()), ("b", Limits::default())],
        );
        p.mark_unhealthy(&cid("a"), "revoked");
        p.mark_unhealthy(&cid("b"), "revoked");

        assert_eq!(
            p.acquire(1, 0.0, t0()).unwrap_err(),
            PoolError::AllUnhealthy {
                provider: pid(),
                count: 2
            }
        );
    }

    #[test]
    fn round_robin_distributes_evenly() {
        let mut p = pool(
            Strategy::RoundRobin,
            &[
                ("a", Limits::default()),
                ("b", Limits::default()),
                ("c", Limits::default()),
            ],
        );
        let picked: Vec<String> = (0..6)
            .map(|_| {
                p.acquire(1, 0.0, t0())
                    .unwrap()
                    .credential
                    .as_str()
                    .to_string()
            })
            .collect();

        // Two full cycles.
        assert_eq!(picked, vec!["a", "b", "c", "a", "b", "c"]);
    }

    #[test]
    fn weighted_smooth_round_robin_honours_the_ratio() {
        let mut p = CredentialPool::new(
            pid(),
            Strategy::Weighted,
            vec![
                Slot::new(cid("heavy"), "vault:h", Limits::default(), t0()).with_weight(2),
                Slot::new(cid("light"), "vault:l", Limits::default(), t0()).with_weight(1),
            ],
        );

        let mut counts = std::collections::HashMap::new();
        for _ in 0..9 {
            let t = p.acquire(1, 0.0, t0()).unwrap();
            *counts.entry(t.credential.as_str().to_string()).or_insert(0) += 1;
        }

        assert_eq!(
            counts["heavy"], 6,
            "2:1 weights should be exact over 9 picks"
        );
        assert_eq!(counts["light"], 3);
    }

    #[test]
    fn weighted_order_is_not_bursty() {
        // The reason to use smooth WRR instead of random weighting: no clumping.
        let mut p = CredentialPool::new(
            pid(),
            Strategy::Weighted,
            vec![
                Slot::new(cid("heavy"), "vault:h", Limits::default(), t0()).with_weight(3),
                Slot::new(cid("light"), "vault:l", Limits::default(), t0()).with_weight(1),
            ],
        );
        let seq: Vec<String> = (0..8)
            .map(|_| {
                p.acquire(1, 0.0, t0())
                    .unwrap()
                    .credential
                    .as_str()
                    .to_string()
            })
            .collect();

        let heavy = seq.iter().filter(|s| *s == "heavy").count();
        let light = seq.iter().filter(|s| *s == "light").count();
        assert_eq!((heavy, light), (6, 2), "3:1 weights over 8 picks: {seq:?}");

        // The actual guarantee of smooth weighted round-robin: the light pick lands exactly once
        // in every full weight cycle instead of the sequence clumping. Which slot wins a tie
        // between equal accumulators is unspecified, so assert the invariant, not a fixed
        // sequence — an exact-sequence assertion here would be testing the tie-break rule.
        for cycle in seq.windows(4) {
            let lights = cycle.iter().filter(|s| *s == "light").count();
            assert_eq!(
                lights, 1,
                "every 4-pick cycle needs exactly one light pick; {cycle:?} in {seq:?}"
            );
        }
    }

    #[test]
    fn least_loaded_prefers_the_idle_credential() {
        let mut p = pool(
            Strategy::LeastLoaded,
            &[
                (
                    "busy",
                    Limits {
                        tpm: Some(1000),
                        ..Default::default()
                    },
                ),
                (
                    "idle",
                    Limits {
                        tpm: Some(1000),
                        ..Default::default()
                    },
                ),
            ],
        );

        // Load the first one up without releasing.
        let held = p.acquire(1000, 0.0, t0()).unwrap();
        assert_eq!(held.credential, cid("busy"), "ties break on config order");

        let next = p.acquire(10, 0.0, t0()).unwrap();
        assert_eq!(
            next.credential,
            cid("idle"),
            "must avoid the loaded credential"
        );
    }

    #[test]
    fn cheapest_capable_prefers_the_cheaper_credential() {
        let mut p = CredentialPool::new(
            pid(),
            Strategy::CheapestCapable,
            vec![
                Slot::new(cid("premium"), "vault:p", Limits::default(), t0()).with_cost(15.0),
                Slot::new(cid("budget"), "vault:b", Limits::default(), t0()).with_cost(0.5),
            ],
        );
        assert_eq!(p.acquire(1, 0.0, t0()).unwrap().credential, cid("budget"));
    }

    #[test]
    fn pool_ceiling_blocks_even_when_credentials_have_headroom() {
        // The motivating case: keep background work off your main quota.
        let mut p = pool(
            Strategy::Priority,
            &[("a", Limits::default()), ("b", Limits::default())],
        )
        .with_pool_limits(
            Limits {
                concurrent: Some(2),
                ..Default::default()
            },
            t0(),
        );

        let _a = p.acquire(1, 0.0, t0()).unwrap();
        let _b = p.acquire(1, 0.0, t0()).unwrap();

        // Credentials are unlimited, but the pool is capped.
        match p.acquire(1, 0.0, t0()).unwrap_err() {
            PoolError::Exhausted { .. } => {}
            other => panic!("expected the pool cap to bite, got {other:?}"),
        }
    }

    #[test]
    fn a_pool_level_rejection_does_not_consume_a_credential_reservation() {
        // Regression guard for the ordering bug this design exists to avoid: if credentials
        // were reserved before the pool check, a rejected request would leak their capacity.
        let mut p = pool(
            Strategy::Priority,
            &[(
                "a",
                Limits {
                    tpm: Some(100),
                    ..Default::default()
                },
            )],
        )
        .with_pool_limits(
            Limits {
                concurrent: Some(1),
                ..Default::default()
            },
            t0(),
        );

        let held = p.acquire(100, 0.0, t0()).unwrap();
        assert!(p.acquire(100, 0.0, t0()).is_err(), "pool cap must reject");

        // Release the outstanding one; the credential's TPM bucket must be exactly as it was
        // after the single successful reservation — no phantom consumption from the rejection.
        p.release(held, t0());
        assert!(
            p.acquire(100, 0.0, t0()).is_ok(),
            "credential capacity leaked across a pool-level rejection"
        );
    }

    #[test]
    fn reconcile_settles_both_credential_and_pool_levels() {
        let mut p = pool(
            Strategy::Priority,
            &[(
                "a",
                Limits {
                    tpm: Some(1000),
                    ..Default::default()
                },
            )],
        )
        .with_pool_limits(
            Limits {
                tpm: Some(1000),
                ..Default::default()
            },
            t0(),
        );

        let t = p.acquire(1000, 0.0, t0()).unwrap();
        p.reconcile(t, 1, 0.0, t0());

        // One token was genuinely consumed, so 999 of the 1000 remain. The fact that a
        // near-full reservation is available at all proves the other 999 were refunded at
        // *both* levels — with no refund there would be nothing left to take.
        let t = p
            .acquire(999, 0.0, t0())
            .expect("both levels should have refunded");
        p.reconcile(t, 1, 0.0, t0());

        // And the ceiling still binds: the 1000th token is really gone.
        assert!(p.acquire(1000, 0.0, t0()).is_err());
    }

    #[test]
    fn status_snapshot_exposes_load_and_spend_without_secrets() {
        let mut p = pool(
            Strategy::Priority,
            &[(
                "a",
                Limits {
                    daily_usd: Some(10.0),
                    ..Default::default()
                },
            )],
        );
        let t = p.acquire(100, 5.0, t0()).unwrap();
        p.reconcile(t, 100, 5.0, t0());

        let s = p.status(t0());
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].spent_today_usd, 5.0);
        assert_eq!(s[0].in_flight, 0);
        assert!(s[0].healthy);
        // The reference is exposed, never the value.
        assert_eq!(s[0].secret_ref, "vault:a");
    }

    #[test]
    fn marks_unknown_credential_as_not_found_rather_than_panicking() {
        let mut p = pool(Strategy::Priority, &[("a", Limits::default())]);
        assert!(!p.mark_unhealthy(&cid("ghost"), "x"));
        assert!(!p.mark_healthy(&cid("ghost")));
    }

    #[test]
    fn priority_survives_a_credential_being_exhausted_for_a_while() {
        let mut p = pool(
            Strategy::Priority,
            &[
                (
                    "primary",
                    Limits {
                        rpm: Some(1),
                        ..Default::default()
                    },
                ),
                ("backup", Limits::default()),
            ],
        );
        let t = p.acquire(1, 0.0, t0()).unwrap();
        assert_eq!(t.credential, cid("primary"));
        p.reconcile(t, 1, 0.0, t0());

        // During the cooldown the backup serves.
        let t = p.acquire(1, 0.0, t0()).unwrap();
        assert_eq!(t.credential, cid("backup"));

        // After a minute, the primary is preferred again.
        let later = t0() + Duration::seconds(61);
        let t = p.acquire(1, 0.0, later).unwrap();
        assert_eq!(
            t.credential,
            cid("primary"),
            "priority must be restored, not sticky"
        );
    }
}

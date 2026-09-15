//! Rate and budget limiting.
//!
//! ## Why reservation, not simply "count what happened"
//!
//! Output tokens are unknown before a request is sent, so a naive TPM counter only learns it
//! blew the budget *after* the provider has already returned a 429 (and, worse, after other
//! concurrent subagents have all passed the same check simultaneously). So we **reserve an
//! estimate up front, then reconcile against the actual usage** when the response lands:
//!
//! ```text
//! acquire(est = prompt + max_tokens)  ->  send  ->  reconcile(actual)
//! ```
//!
//! Reservations are refunded when the response comes back smaller than estimated, and topped
//! up (best-effort) when it comes back larger. Costs the same in the happy path, and stops the
//! thundering-herd problem when six subagents fire at once.
//!
//! ## Shape of the buckets
//!
//! Continuous-refill token buckets rather than fixed windows. A fixed window lets 2× the limit
//! through across a window boundary (the classic burst bug); continuous refill smooths that out
//! and gives an honest `retry_after` instead of "wait until the top of the minute".

use chrono::{DateTime, NaiveDate, Utc};
/// Ceilings come straight from the config layer — one `Limits` shape serves both credential and
/// pool scope. Reusing the config type rather than mirroring it means the two cannot drift.
pub use hx_core::config::Limits;

/// A continuously-refilling token bucket. Fractional tokens are kept, so a 50 RPM limit really
/// does allow one call every 1.2s rather than 50-then-nothing.
#[derive(Clone, Debug)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: DateTime<Utc>,
}

impl TokenBucket {
    pub fn new(capacity: u64, refill_per_sec: f64, now: DateTime<Utc>) -> Self {
        Self {
            capacity: capacity as f64,
            // Start full: a fresh credential should not have to wait before its first call.
            tokens: capacity as f64,
            refill_per_sec: refill_per_sec.max(f64::MIN_POSITIVE),
            last: now,
        }
    }

    /// Bucket sized for `n` calls per minute.
    pub fn per_minute(n: u64, now: DateTime<Utc>) -> Self {
        Self::new(n, n as f64 / 60.0, now)
    }

    /// Bucket sized for `n` calls per day.
    pub fn per_day(n: u64, now: DateTime<Utc>) -> Self {
        Self::new(n, n as f64 / 86_400.0, now)
    }

    fn refill(&mut self, now: DateTime<Utc>) {
        let elapsed = (now - self.last).num_milliseconds() as f64 / 1000.0;
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.last = now;
        }
    }

    /// Refill, then report whether `n` could be taken — without taking it.
    pub fn peek(&mut self, n: f64, now: DateTime<Utc>) -> Result<(), f64> {
        self.refill(now);
        // A single request larger than the whole bucket can never be satisfied by waiting, so
        // clamp it: the request is admitted, and the bucket refills from empty afterwards. The
        // alternative (refusing forever) would deadlock any request bigger than the TPM cap.
        let want = n.min(self.capacity);
        if self.tokens >= want {
            Ok(())
        } else {
            Err((want - self.tokens) / self.refill_per_sec)
        }
    }

    /// Refill, then consume `n` if available.
    pub fn try_take(&mut self, n: f64, now: DateTime<Utc>) -> Result<(), f64> {
        self.peek(n, now)?;
        self.tokens -= n.min(self.capacity);
        Ok(())
    }

    /// Give tokens back (reconciling a reservation that was too pessimistic). Never exceeds
    /// capacity — refunds must not become a way to bank unlimited credit.
    pub fn refund(&mut self, n: f64) {
        self.tokens = (self.tokens + n).min(self.capacity);
    }

    /// Consume more after the fact, best-effort. Used when actual usage exceeded the estimate;
    /// we do not fail the request retroactively, we just make the next one wait.
    pub fn consume_extra(&mut self, n: f64) {
        self.tokens = (self.tokens - n).max(0.0);
    }

    pub fn available(&mut self, now: DateTime<Utc>) -> f64 {
        self.refill(now);
        self.tokens
    }

    /// Fraction of the bucket currently available, for least-loaded routing.
    pub fn available_fraction(&mut self, now: DateTime<Utc>) -> f64 {
        if self.capacity <= 0.0 {
            return 0.0;
        }
        self.available(now) / self.capacity
    }
}

/// Ceiling arithmetic, kept next to the limiter that enforces it.
pub trait LimitsExt {
    /// Merge `other` on top of these, taking the *tighter* of each pair. Used when a pool
    /// imposes a ceiling in addition to per-credential ones.
    fn tighten(&self, other: &Limits) -> Limits;
}

impl LimitsExt for Limits {
    fn tighten(&self, other: &Limits) -> Limits {
        Limits {
            rpm: min_opt(self.rpm, other.rpm),
            tpm: min_opt(self.tpm, other.tpm),
            rpd: min_opt(self.rpd, other.rpd),
            daily_usd: min_opt_f64(self.daily_usd, other.daily_usd),
            concurrent: min_opt(self.concurrent, other.concurrent),
        }
    }
}

fn min_opt<T: Ord + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}

fn min_opt_f64(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}

/// Why a request could not be admitted.
#[derive(Clone, Debug, PartialEq)]
pub enum LimitError {
    RequestsPerMinute { retry_after_secs: f64 },
    TokensPerMinute { retry_after_secs: f64 },
    RequestsPerDay { retry_after_secs: f64 },
    DailyBudget { spent: f64, limit: f64 },
    Concurrency { in_flight: u32, limit: u32 },
}

impl LimitError {
    /// How long to wait before retrying, when that is knowable. A budget or concurrency
    /// exhaustion is not a "wait a bit" condition, so it reports `None`.
    pub fn retry_after_secs(&self) -> Option<f64> {
        match self {
            LimitError::RequestsPerMinute { retry_after_secs }
            | LimitError::TokensPerMinute { retry_after_secs }
            | LimitError::RequestsPerDay { retry_after_secs } => Some(*retry_after_secs),
            LimitError::DailyBudget { .. } | LimitError::Concurrency { .. } => None,
        }
    }

    /// Whether waiting could plausibly help. `retry_after_secs` is only a hint; this is the
    /// routing-level question: should we try the *next* credential, or the same one later?
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            LimitError::RequestsPerMinute { .. }
                | LimitError::TokensPerMinute { .. }
                | LimitError::RequestsPerDay { .. }
                | LimitError::Concurrency { .. }
        )
    }
}

impl std::fmt::Display for LimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LimitError::RequestsPerMinute { retry_after_secs } => {
                write!(f, "requests/min exhausted; retry in {retry_after_secs:.1}s")
            }
            LimitError::TokensPerMinute { retry_after_secs } => {
                write!(f, "tokens/min exhausted; retry in {retry_after_secs:.1}s")
            }
            LimitError::RequestsPerDay { retry_after_secs } => {
                write!(f, "requests/day exhausted; retry in {retry_after_secs:.0}s")
            }
            LimitError::DailyBudget { spent, limit } => {
                write!(f, "daily budget exhausted (${spent:.2} of ${limit:.2})")
            }
            LimitError::Concurrency { in_flight, limit } => {
                write!(
                    f,
                    "concurrency limit reached ({in_flight}/{limit} in flight)"
                )
            }
        }
    }
}

/// An outstanding reservation. Must be either [`Limiter::reconcile`]d (normal path) or
/// [`Limiter::release`]d (request failed before reaching the provider).
#[derive(Clone, Debug)]
pub struct Lease {
    pub reserved_tokens: u64,
    pub reserved_usd: f64,
    pub issued_at: DateTime<Utc>,
}

/// Enforces one [`Limits`] set. Single-threaded by design; callers serialise access (the pool
/// holds it behind a lock, the daemon behind a per-credential actor).
#[derive(Debug)]
pub struct Limiter {
    limits: Limits,
    rpm: Option<TokenBucket>,
    tpm: Option<TokenBucket>,
    rpd: Option<TokenBucket>,
    day: NaiveDate,
    spent_usd: f64,
    in_flight: u32,
}

impl Limiter {
    pub fn new(limits: Limits, now: DateTime<Utc>) -> Self {
        let rpm = limits.rpm.map(|n| TokenBucket::per_minute(n as u64, now));
        let tpm = limits.tpm.map(|n| TokenBucket::per_minute(n, now));
        let rpd = limits.rpd.map(|n| TokenBucket::per_day(n as u64, now));
        Self {
            limits,
            rpm,
            tpm,
            rpd,
            day: now.date_naive(),
            spent_usd: 0.0,
            in_flight: 0,
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn in_flight(&self) -> u32 {
        self.in_flight
    }

    pub fn spent_today_usd(&self) -> f64 {
        self.spent_usd
    }

    /// Roll the daily counters when the UTC date changes.
    fn roll_day(&mut self, now: DateTime<Utc>) {
        let today = now.date_naive();
        if today != self.day {
            self.day = today;
            self.spent_usd = 0.0;
            if let Some(rpd) = &mut self.rpd {
                // Fresh day, fresh day-bucket — including its capacity.
                *rpd = TokenBucket::per_day(self.limits.rpd.unwrap_or(0) as u64, now);
            }
        }
    }

    /// Two-phase admission: peek every ceiling first, then commit. This avoids having to roll
    /// back partially-consumed buckets when the third check fails.
    pub fn acquire(
        &mut self,
        est_tokens: u64,
        est_usd: f64,
        now: DateTime<Utc>,
    ) -> Result<Lease, LimitError> {
        self.roll_day(now);

        if let Some(limit) = self.limits.concurrent {
            if self.in_flight >= limit {
                return Err(LimitError::Concurrency {
                    in_flight: self.in_flight,
                    limit,
                });
            }
        }

        let tokens = est_tokens as f64;

        // Phase 1: peek.
        if let Some(rpm) = &mut self.rpm {
            rpm.peek(1.0, now)
                .map_err(|retry_after_secs| LimitError::RequestsPerMinute { retry_after_secs })?;
        }
        if let Some(tpm) = &mut self.tpm {
            tpm.peek(tokens, now)
                .map_err(|retry_after_secs| LimitError::TokensPerMinute { retry_after_secs })?;
        }
        if let Some(rpd) = &mut self.rpd {
            rpd.peek(1.0, now)
                .map_err(|retry_after_secs| LimitError::RequestsPerDay { retry_after_secs })?;
        }
        if let Some(limit) = self.limits.daily_usd {
            // Fail closed. The second clause matters: a caller that passes `est_usd = 0` (no
            // rate card configured, say) must not be able to walk past a budget that is
            // already spent. Reaching the ceiling denies everything until the day rolls over.
            if self.spent_usd + est_usd > limit || self.spent_usd >= limit {
                return Err(LimitError::DailyBudget {
                    spent: self.spent_usd,
                    limit,
                });
            }
        }

        // Phase 2: commit. Infallible after a successful peek.
        if let Some(rpm) = &mut self.rpm {
            let _ = rpm.try_take(1.0, now);
        }
        if let Some(tpm) = &mut self.tpm {
            let _ = tpm.try_take(tokens, now);
        }
        if let Some(rpd) = &mut self.rpd {
            let _ = rpd.try_take(1.0, now);
        }
        self.spent_usd += est_usd;
        self.in_flight += 1;

        Ok(Lease {
            reserved_tokens: est_tokens,
            reserved_usd: est_usd,
            issued_at: now,
        })
    }

    /// Settle a lease against real usage. Refunds the pessimistic estimate, tops up if the
    /// request was underestimated, and frees the concurrency slot.
    pub fn reconcile(
        &mut self,
        lease: Lease,
        actual_tokens: u64,
        actual_usd: f64,
        now: DateTime<Utc>,
    ) {
        self.roll_day(now);

        if let Some(tpm) = &mut self.tpm {
            if actual_tokens < lease.reserved_tokens {
                tpm.refund((lease.reserved_tokens - actual_tokens) as f64);
            } else if actual_tokens > lease.reserved_tokens {
                tpm.consume_extra((actual_tokens - lease.reserved_tokens) as f64);
            }
        }

        // Replace the reservation with the truth.
        self.spent_usd += actual_usd - lease.reserved_usd;
        if self.spent_usd < 0.0 {
            self.spent_usd = 0.0;
        }

        self.in_flight = self.in_flight.saturating_sub(1);
    }

    /// Give a lease back untouched — for requests that failed before reaching the provider.
    ///
    /// Everything the lease took is returned, RPM included: a request that never left the
    /// client should not count against the ceiling. `refund` is capped at capacity, so this
    /// restores the pre-request state rather than banking credit.
    pub fn release(&mut self, lease: Lease, now: DateTime<Utc>) {
        self.roll_day(now);

        if let Some(tpm) = &mut self.tpm {
            tpm.refund(lease.reserved_tokens as f64);
        }
        if let Some(rpm) = &mut self.rpm {
            rpm.refund(1.0);
        }
        if let Some(rpd) = &mut self.rpd {
            rpd.refund(1.0);
        }

        self.spent_usd -= lease.reserved_usd;
        if self.spent_usd < 0.0 {
            self.spent_usd = 0.0;
        }
        self.in_flight = self.in_flight.saturating_sub(1);
    }

    /// How loaded this credential is right now, as a 0.0–1.0 score where lower is better.
    /// Used by least-loaded routing.
    pub fn load_score(&mut self, now: DateTime<Utc>) -> f64 {
        self.roll_day(now);
        let mut worst: f64 = 0.0;

        if let Some(tpm) = &mut self.tpm {
            worst = worst.max(1.0 - tpm.available_fraction(now));
        }
        if let Some(rpm) = &mut self.rpm {
            worst = worst.max(1.0 - rpm.available_fraction(now));
        }
        if let Some(limit) = self.limits.concurrent {
            if limit > 0 {
                worst = worst.max(self.in_flight as f64 / limit as f64);
            }
        }
        if let Some(limit) = self.limits.daily_usd {
            if limit > 0.0 {
                worst = worst.max(self.spent_usd / limit);
            }
        }
        worst.clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn t0() -> DateTime<Utc> {
        // Fixed instant so tests are deterministic.
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn secs(n: i64) -> DateTime<Utc> {
        t0() + Duration::seconds(n)
    }

    // ---- TokenBucket ----

    #[test]
    fn fresh_bucket_is_full_so_the_first_call_never_waits() {
        let mut b = TokenBucket::per_minute(60, t0());
        assert!((b.available(t0()) - 60.0).abs() < 1e-9);
        assert!(b.try_take(60.0, t0()).is_ok());
        assert!(b.try_take(1.0, t0()).is_err(), "bucket should now be empty");
    }

    #[test]
    fn bucket_refills_continuously_at_the_configured_rate() {
        let mut b = TokenBucket::per_minute(60, t0()); // 1 token/sec
        assert!(b.try_take(60.0, t0()).is_ok());
        assert!(b.try_take(1.0, t0()).is_err());

        // After 10s, 10 tokens are available — not "still zero until the minute rolls".
        assert!((b.available(secs(10)) - 10.0).abs() < 0.5);
        assert!(b.try_take(10.0, secs(10)).is_ok());
        assert!(b.try_take(1.0, secs(10)).is_err());
    }

    #[test]
    fn refill_is_capped_at_capacity() {
        let mut b = TokenBucket::per_minute(10, t0());
        let _ = b.try_take(10.0, t0());
        // A long idle period must not bank more than the capacity.
        assert!((b.available(secs(100_000)) - 10.0).abs() < 1e-9);
    }

    #[test]
    fn retry_after_is_honest() {
        let mut b = TokenBucket::per_minute(60, t0()); // 1/sec
        assert!(b.try_take(60.0, t0()).is_ok());
        // Need 5 more seconds at 1/sec.
        let wait = b.try_take(5.0, t0()).unwrap_err();
        assert!((wait - 5.0).abs() < 0.01, "got {wait}");
    }

    #[test]
    fn oversized_request_is_clamped_not_deadlocked() {
        // A 200k-token request against a 100k TPM cap must be admitted (from a full bucket)
        // rather than refused forever.
        let mut b = TokenBucket::per_minute(100_000, t0());
        assert!(b.try_take(200_000.0, t0()).is_ok());
        assert!(b.try_take(1.0, t0()).is_err());
    }

    #[test]
    fn refund_never_exceeds_capacity_and_extra_consumes_floor_at_zero() {
        let mut b = TokenBucket::per_minute(10, t0());
        assert!(b.try_take(10.0, t0()).is_ok());
        b.refund(1_000.0);
        assert!(
            (b.available(t0()) - 10.0).abs() < 1e-9,
            "refund must not bank credit"
        );

        b.consume_extra(1_000.0);
        assert!(
            (b.available(t0()) - 0.0).abs() < 1e-9,
            "must floor at zero, not go negative"
        );
    }

    // ---- Limits ----

    #[test]
    fn unbounded_limits_are_recognised() {
        assert!(Limits::default().is_unbounded());
        assert!(!Limits {
            rpm: Some(1),
            ..Default::default()
        }
        .is_unbounded());
    }

    #[test]
    fn tighten_takes_the_tighter_of_each_ceiling() {
        let a = Limits {
            rpm: Some(100),
            tpm: Some(10_000),
            ..Default::default()
        };
        let b = Limits {
            rpm: Some(50),
            daily_usd: Some(5.0),
            ..Default::default()
        };
        let t = a.tighten(&b);
        assert_eq!(t.rpm, Some(50), "pool ceiling should win when tighter");
        assert_eq!(
            t.tpm,
            Some(10_000),
            "credential ceiling should win when pool has none"
        );
        assert_eq!(t.daily_usd, Some(5.0));
    }

    // ---- Limiter ----

    #[test]
    fn unlimited_limiter_never_blocks() {
        let mut l = Limiter::new(Limits::default(), t0());
        for _ in 0..10_000 {
            assert!(l.acquire(1_000_000, 100.0, t0()).is_ok());
        }
    }

    #[test]
    fn rpm_ceiling_blocks_then_recovers() {
        let mut l = Limiter::new(
            Limits {
                rpm: Some(3),
                ..Default::default()
            },
            t0(),
        );
        for _ in 0..3 {
            let lease = l.acquire(10, 0.0, t0()).unwrap();
            l.reconcile(lease, 10, 0.0, t0());
        }
        let err = l.acquire(10, 0.0, t0()).unwrap_err();
        assert!(matches!(err, LimitError::RequestsPerMinute { .. }));
        assert!(err.is_transient());

        // 3 RPM = one every 20s.
        assert!(l.acquire(10, 0.0, secs(21)).is_ok());
    }

    #[test]
    fn reservation_larger_than_actual_is_refunded() {
        // Reserve 1000, use 10 — the bucket should get 990 back, not leak them.
        let mut l = Limiter::new(
            Limits {
                tpm: Some(1000),
                ..Default::default()
            },
            t0(),
        );
        let lease = l.acquire(1000, 0.0, t0()).unwrap();
        l.reconcile(lease, 10, 0.0, t0());

        // If the refund happened, nearly the whole bucket is usable again immediately.
        let lease2 = l.acquire(900, 0.0, t0()).unwrap();
        l.reconcile(lease2, 900, 0.0, t0());
        assert!(
            l.acquire(100, 0.0, t0()).is_err(),
            "bucket should finally be drained"
        );
    }

    #[test]
    fn underestimating_spend_is_trued_up_on_reconcile() {
        let mut l = Limiter::new(
            Limits {
                daily_usd: Some(1.00),
                ..Default::default()
            },
            t0(),
        );
        let lease = l.acquire(10, 0.10, t0()).unwrap();
        l.reconcile(lease, 10, 0.90, t0());
        assert!((l.spent_today_usd() - 0.90).abs() < 1e-9);

        // Only $0.10 left.
        assert!(l.acquire(1, 0.10, t0()).is_ok());
        let err = l.acquire(1, 0.10, t0()).unwrap_err();
        assert!(matches!(err, LimitError::DailyBudget { .. }));
        assert!(
            !err.is_transient(),
            "a spent budget is not a wait-and-retry condition"
        );
    }

    #[test]
    fn a_zero_cost_estimate_cannot_walk_past_a_spent_budget() {
        // Regression guard. The check used to be `spent + est > limit`, which a caller passing
        // `est = 0` (no rate card configured) satisfied forever — making the ceiling nominal.
        // It now also denies on `spent >= limit`, so a spent budget fails closed.
        let mut l = Limiter::new(
            Limits {
                daily_usd: Some(1.0),
                ..Default::default()
            },
            t0(),
        );
        let lease = l.acquire(1, 1.0, t0()).unwrap();
        l.reconcile(lease, 1, 1.0, t0());

        let err = l.acquire(1, 0.0, t0()).unwrap_err();
        assert!(matches!(err, LimitError::DailyBudget { .. }), "{err}");
    }

    #[test]
    fn concurrency_slot_is_held_until_released() {
        let mut l = Limiter::new(
            Limits {
                concurrent: Some(2),
                ..Default::default()
            },
            t0(),
        );
        let a = l.acquire(1, 0.0, t0()).unwrap();
        let b = l.acquire(1, 0.0, t0()).unwrap();
        assert_eq!(l.in_flight(), 2);

        let err = l.acquire(1, 0.0, t0()).unwrap_err();
        assert!(matches!(
            err,
            LimitError::Concurrency {
                in_flight: 2,
                limit: 2
            }
        ));

        l.reconcile(a, 1, 0.0, t0());
        assert_eq!(l.in_flight(), 1);
        assert!(l.acquire(1, 0.0, t0()).is_ok());

        // `b` is still held, which is why exactly one slot came free above rather than two.
        // (Note `Lease` deliberately has no `Drop`: a slot is released by an explicit
        // `reconcile`/`release`, so a dropped lease cannot silently free capacity the caller
        // still believes it is using.)
        l.reconcile(b, 1, 0.0, t0());
        assert_eq!(l.in_flight(), 1);
    }

    #[test]
    fn releasing_a_lease_for_a_failed_request_frees_everything() {
        let mut l = Limiter::new(
            Limits {
                tpm: Some(100),
                concurrent: Some(1),
                ..Default::default()
            },
            t0(),
        );
        let lease = l.acquire(100, 0.0, t0()).unwrap();
        l.release(lease, t0());

        assert_eq!(l.in_flight(), 0);
        // The token reservation came back, so an identical request fits again.
        assert!(l.acquire(100, 0.0, t0()).is_ok());
    }

    #[test]
    fn daily_counters_roll_over_on_a_new_utc_day() {
        let mut l = Limiter::new(
            Limits {
                daily_usd: Some(1.0),
                rpd: Some(2),
                ..Default::default()
            },
            t0(),
        );
        let a = l.acquire(1, 1.0, t0()).unwrap();
        l.reconcile(a, 1, 1.0, t0());
        assert!(
            l.acquire(1, 0.0, t0()).is_err(),
            "budget and RPD both spent"
        );

        // Same instant, next day.
        let tomorrow = t0() + Duration::days(1);
        let lease = l.acquire(1, 1.0, tomorrow).expect("counters should reset");
        l.reconcile(lease, 1, 1.0, tomorrow);
    }

    #[test]
    fn rpd_ceiling_blocks_within_the_day() {
        let mut l = Limiter::new(
            Limits {
                rpd: Some(2),
                ..Default::default()
            },
            t0(),
        );
        l.acquire(1, 0.0, t0()).unwrap();
        l.acquire(1, 0.0, t0()).unwrap();
        let err = l.acquire(1, 0.0, t0()).unwrap_err();
        assert!(matches!(err, LimitError::RequestsPerDay { .. }));
    }

    #[test]
    fn load_score_rises_as_the_credential_is_used() {
        let mut l = Limiter::new(
            Limits {
                tpm: Some(1000),
                ..Default::default()
            },
            t0(),
        );
        assert!(l.load_score(t0()) < 1e-9, "a fresh credential is idle");

        let lease = l.acquire(1000, 0.0, t0()).expect("first acquire");
        assert!(
            l.load_score(t0()) > 0.99,
            "a fully-reserved credential is loaded"
        );

        l.reconcile(lease, 0, 0.0, t0());
        assert!(
            l.load_score(t0()) < 1e-9,
            "reconciling to zero usage frees it"
        );
    }

    #[test]
    fn budget_error_message_is_human_readable() {
        let err = LimitError::DailyBudget {
            spent: 4.5,
            limit: 5.0,
        };
        assert!(err.to_string().contains("4.50"), "{err}");
        assert!(err.to_string().contains("5.00"), "{err}");
        assert_eq!(err.retry_after_secs(), None);
    }
}

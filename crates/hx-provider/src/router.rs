//! Role-based routing over named pools.
//!
//! Agents never ask for a key or a model — they ask for a **role** (`builder`, `scout`,
//! `reviewer`). A role maps to a pool; a pool maps to an ordered list of concrete
//! `provider/model` routes. This indirection is what makes the whole thing operable:
//!
//! - re-point `scout` at cheaper capacity without touching agent code;
//! - give `background` a pool-wide ceiling so cron work cannot eat interactive quota;
//! - add a second key for a provider and have failover appear everywhere at once.
//!
//! ## Where the ceilings live
//!
//! Credential pools are keyed by **provider**, not by named pool, and are shared. A rate limit
//! is a property of the *key*, so two pools that both use `anthropic-main` must contend for the
//! same 50 RPM. Pool-level ceilings are a separate, additional limiter owned by the named pool.
//! Getting this backwards is the classic bug: per-pool copies of a credential limiter let N
//! pools each spend the full rate limit of one key.

use crate::limits::{Lease, Limiter, Limits};
use crate::pool::{CredentialPool, PoolError, Slot, Ticket};
use crate::provider::{cost_usd, Usage};
use chrono::{DateTime, Utc};
use hx_core::config::{glob_match, Config, ModelRef, Price, ProviderConfig};
use hx_core::error::{HxError, Result};
use hx_core::ids::{CredentialId, ProviderId};
use indexmap::IndexMap;
use serde::Serialize;

/// A concrete destination: one provider, one model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Route {
    pub provider: ProviderId,
    pub model: String,
}

/// A named pool: candidate routes in preference order, plus a ceiling spanning all of them.
#[derive(Debug)]
pub struct ResolvedPool {
    pub name: String,
    pub routes: Vec<Route>,
    limiter: Option<Limiter>,
}

impl ResolvedPool {
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }
}

/// A granted route, with reservations held at both the pool and credential levels.
#[derive(Debug)]
pub struct RouteTicket {
    pub pool: String,
    pub route: Route,
    credential: Ticket,
    pool_lease: Option<Lease>,
}

impl RouteTicket {
    pub fn credential_id(&self) -> &CredentialId {
        &self.credential.credential
    }

    /// The reference the key for the granted credential lives under.
    ///
    /// The router's caller needs exactly this and nothing more: which key to fetch, decided by the
    /// same call that reserved the capacity.
    pub fn secret_ref(&self) -> &str {
        self.credential.secret_ref()
    }

    pub fn reserved_tokens(&self) -> u64 {
        self.credential.reserved_tokens()
    }

    pub fn reserved_usd(&self) -> f64 {
        self.credential.reserved_usd()
    }
}

/// Status view for `hx status` and the web UI.
#[derive(Debug, Clone, Serialize)]
pub struct RouterStatus {
    pub pools: Vec<PoolStatus>,
    pub roles: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PoolStatus {
    pub name: String,
    pub routes: Vec<Route>,
    pub healthy_credentials: usize,
    pub total_credentials: usize,
}

/// Routes a role to a concrete provider/model and credential, enforcing every ceiling on the way.
#[derive(Debug)]
pub struct ModelRouter {
    /// One credential pool **per provider**, shared by every named pool.
    providers: IndexMap<ProviderId, CredentialPool>,
    /// Named pools: preferred routes plus a pool-wide ceiling.
    pools: IndexMap<String, ResolvedPool>,
    /// role -> pool name.
    roles: IndexMap<String, String>,
    /// Rate cards, for estimating spend before send.
    prices: IndexMap<ProviderId, Price>,
}

impl ModelRouter {
    /// Build the whole routing table from configuration.
    pub fn from_config(cfg: &Config, now: DateTime<Utc>) -> Result<Self> {
        let mut providers = IndexMap::new();
        let mut prices = IndexMap::new();

        for (name, pc) in &cfg.providers {
            let id = ProviderId::from_raw(name);
            let slots = credential_slots(pc, now);
            providers.insert(
                id.clone(),
                CredentialPool::new(id.clone(), pc.routing, slots),
            );

            if let Some(price) = &pc.price {
                prices.insert(id, price.clone());
            }
        }

        let mut pools = IndexMap::new();
        for name in cfg.pools.keys() {
            let (members, limits) = effective_members(cfg, name)?;
            let routes = expand_members(&members, &cfg.providers)?;
            if routes.is_empty() {
                return Err(HxError::Config(format!(
                    "pool '{name}' has no resolvable members; add a `members:` list"
                )));
            }
            let limiter = if limits.is_unbounded() {
                None
            } else {
                Some(Limiter::new(limits, now))
            };
            pools.insert(
                name.clone(),
                ResolvedPool {
                    name: name.clone(),
                    routes,
                    limiter,
                },
            );
        }

        // Every role must resolve, or startup should fail loudly rather than 500 at 3am.
        for (role, pool) in &cfg.roles {
            if !pools.contains_key(pool) {
                return Err(HxError::Config(format!(
                    "role '{role}' points at unknown pool '{pool}'"
                )));
            }
        }

        Ok(Self {
            providers,
            pools,
            roles: cfg.roles.clone(),
            prices,
        })
    }

    pub fn pool_for_role(&self, role: &str) -> Result<&str> {
        let name = self
            .roles
            .get(role)
            .ok_or_else(|| HxError::Config(format!("no pool bound to role '{role}'")))?;
        if !self.pools.contains_key(name) {
            return Err(HxError::Config(format!(
                "role '{role}' points at unknown pool '{name}'"
            )));
        }
        Ok(name.as_str())
    }

    pub fn pool(&self, name: &str) -> Option<&ResolvedPool> {
        self.pools.get(name)
    }

    pub fn pool_names(&self) -> Vec<String> {
        self.pools.keys().cloned().collect()
    }

    pub fn roles(&self) -> &IndexMap<String, String> {
        &self.roles
    }

    /// Reserve capacity and pick a concrete route for a role.
    pub fn acquire_for_role(
        &mut self,
        role: &str,
        est_tokens: u64,
        est_usd: f64,
        now: DateTime<Utc>,
    ) -> Result<RouteTicket> {
        let pool = self.pool_for_role(role)?.to_string();
        self.acquire(&pool, est_tokens, est_usd, now)
    }

    /// Reserve capacity and pick a concrete route from a named pool.
    ///
    /// Pool ceiling is checked first so a pool-wide rejection cannot leak per-credential
    /// reservations (mirrors the ordering inside [`CredentialPool::acquire`]).
    pub fn acquire(
        &mut self,
        pool_name: &str,
        est_tokens: u64,
        est_usd: f64,
        now: DateTime<Utc>,
    ) -> Result<RouteTicket> {
        let pool = self
            .pools
            .get_mut(pool_name)
            .ok_or_else(|| HxError::Config(format!("unknown pool '{pool_name}'")))?;

        let pool_lease = match &mut pool.limiter {
            Some(limiter) => match limiter.acquire(est_tokens, est_usd, now) {
                Ok(lease) => Some(lease),
                Err(e) => {
                    return Err(HxError::RateLimited {
                        scope: format!("pool:{pool_name}"),
                        retry_after_ms: (e.retry_after_secs().unwrap_or(60.0) * 1000.0) as u64,
                    })
                }
            },
            None => None,
        };

        // Cloned so the pool borrow ends before we reach into the credential pools.
        let routes = pool.routes.clone();
        let mut soonest: Option<f64> = None;
        let mut had_route = false;

        for route in &routes {
            let Some(credentials) = self.providers.get_mut(&route.provider) else {
                continue;
            };
            had_route = true;

            match credentials.acquire(est_tokens, est_usd, now) {
                Ok(credential) => {
                    return Ok(RouteTicket {
                        pool: pool_name.to_string(),
                        route: route.clone(),
                        credential,
                        pool_lease,
                    });
                }
                Err(PoolError::Exhausted {
                    retry_after_secs, ..
                }) => {
                    soonest =
                        Some(soonest.map_or(retry_after_secs, |s: f64| s.min(retry_after_secs)));
                }
                Err(_) => {}
            }
        }

        // Nothing served — hand the pool reservation back.
        if let (Some(limiter), Some(lease)) = (
            self.pools
                .get_mut(pool_name)
                .and_then(|p| p.limiter.as_mut()),
            pool_lease,
        ) {
            limiter.release(lease, now);
        }

        if !had_route {
            return Err(HxError::NoRoute(format!(
                "pool '{pool_name}' has routes but none of their providers are configured"
            )));
        }

        Err(HxError::NoRoute(format!(
            "pool '{pool_name}': every route is at its limit (soonest recovery ~{:.0}s)",
            soonest.unwrap_or(60.0)
        )))
    }

    /// Settle a ticket against actual usage, at both levels.
    pub fn reconcile(
        &mut self,
        ticket: RouteTicket,
        actual_tokens: u64,
        actual_usd: f64,
        now: DateTime<Utc>,
    ) {
        if let Some(credentials) = self.providers.get_mut(&ticket.route.provider) {
            credentials.reconcile(ticket.credential, actual_tokens, actual_usd, now);
        }
        if let (Some(limiter), Some(lease)) = (
            self.pools
                .get_mut(&ticket.pool)
                .and_then(|p| p.limiter.as_mut()),
            ticket.pool_lease,
        ) {
            limiter.reconcile(lease, actual_tokens, actual_usd, now);
        }
    }

    /// Give a ticket back untouched, e.g. the request failed before leaving the process.
    pub fn release(&mut self, ticket: RouteTicket, now: DateTime<Utc>) {
        if let Some(credentials) = self.providers.get_mut(&ticket.route.provider) {
            credentials.release(ticket.credential, now);
        }
        if let (Some(limiter), Some(lease)) = (
            self.pools
                .get_mut(&ticket.pool)
                .and_then(|p| p.limiter.as_mut()),
            ticket.pool_lease,
        ) {
            limiter.release(lease, now);
        }
    }

    /// Take a key out of rotation after a hard auth failure.
    pub fn mark_unhealthy(
        &mut self,
        provider: &ProviderId,
        credential: &CredentialId,
        reason: impl Into<String>,
    ) -> bool {
        self.providers
            .get_mut(provider)
            .map(|p| p.mark_unhealthy(credential, reason))
            .unwrap_or(false)
    }

    pub fn mark_healthy(&mut self, provider: &ProviderId, credential: &CredentialId) -> bool {
        self.providers
            .get_mut(provider)
            .map(|p| p.mark_healthy(credential))
            .unwrap_or(false)
    }

    /// Estimated cost of a response on a route, from the provider's rate card.
    pub fn estimate_cost(&self, route: &Route, usage: &Usage) -> f64 {
        self.cost_for(&route.provider, usage)
    }

    /// The same, for a provider known by id rather than a route.
    ///
    /// The loop reports usage per turn without a route — a price table is not its business — so the
    /// daemon prices those turns with this. `0.0` when no rate card is configured, which is the
    /// absence of a price rather than a claim that the call was free.
    pub fn cost_for(&self, provider: &ProviderId, usage: &Usage) -> f64 {
        self.prices
            .get(provider)
            .map(|price| cost_usd(price, usage))
            .unwrap_or(0.0)
    }

    /// Rough cost of a request before it is sent, for budget reservation.
    ///
    /// Uses only the input rate: output length is unknown, and the spend ceiling is trued up on
    /// reconcile. Under-reserving slightly is preferable to blocking on a phantom estimate.
    pub fn estimate_reservation_usd(&self, route: &Route, tokens: u64) -> f64 {
        self.prices
            .get(&route.provider)
            .map(|p| tokens as f64 * p.input_per_mtok / 1_000_000.0)
            .unwrap_or(0.0)
    }

    /// The same estimate for a *role*, before a route has been chosen.
    ///
    /// The dearest route in the pool sets the number. That is the only pessimistic choice
    /// available: the reservation is taken before the route is picked, so anything cheaper would
    /// under-reserve whenever routing happens to land on the expensive member — which is exactly
    /// how a day's spend ceiling gets quietly exceeded. A pool whose routes have no rate card
    /// estimates `0.0`, which the limiter still refuses to let past an already-spent budget.
    pub fn estimate_role_reservation_usd(&self, role: &str, tokens: u64) -> Result<f64> {
        let name = self.pool_for_role(role)?;
        // `pool_for_role` has just checked that this pool exists.
        let Some(pool) = self.pools.get(name) else {
            return Err(HxError::NoRoute(format!(
                "pool '{name}' is bound to role '{role}' but missing from the routing table"
            )));
        };

        Ok(pool
            .routes
            .iter()
            .map(|route| self.estimate_reservation_usd(route, tokens))
            .fold(0.0_f64, f64::max))
    }

    pub fn status(&self) -> RouterStatus {
        RouterStatus {
            pools: self
                .pools
                .values()
                .map(|p| {
                    // De-duplicate providers first: a pool with two models from one provider
                    // shares a single credential pool, and must not count it twice.
                    let mut seen = std::collections::HashSet::new();
                    let credential_pools: Vec<_> = p
                        .routes
                        .iter()
                        .filter(|r| seen.insert(r.provider.as_str().to_string()))
                        .filter_map(|r| self.providers.get(&r.provider))
                        .collect();

                    PoolStatus {
                        name: p.name.clone(),
                        routes: p.routes.clone(),
                        healthy_credentials: credential_pools
                            .iter()
                            .map(|c| c.healthy_count())
                            .sum(),
                        total_credentials: credential_pools.iter().map(|c| c.len()).sum(),
                    }
                })
                .collect(),
            roles: self.roles.clone(),
        }
    }
}

fn credential_slots(pc: &ProviderConfig, now: DateTime<Utc>) -> Vec<Slot> {
    pc.credentials
        .iter()
        .map(|c| {
            let mut slot = Slot::new(c.id.clone(), c.secret.clone(), c.limits.clone(), now)
                .with_weight(c.weight)
                .with_priority(pc.priority);
            if let Some(price) = &pc.price {
                slot = slot.with_cost(price.input_per_mtok);
            }
            slot
        })
        .collect()
}

/// Walk the `inherits` chain to find the effective member list and ceiling.
///
/// Cycle detection is not paranoia: `a inherits b`, `b inherits a` in a hand-edited config
/// would otherwise hang startup.
fn effective_members(cfg: &Config, name: &str) -> Result<(Vec<String>, Limits)> {
    let mut chain: Vec<String> = Vec::new();
    let mut current = name.to_string();
    let mut members: Option<Vec<String>> = None;
    let mut limits: Option<Limits> = None;

    loop {
        if chain.contains(&current) {
            chain.push(current);
            return Err(HxError::Config(format!(
                "pool inheritance cycle: {}",
                chain.join(" -> ")
            )));
        }
        chain.push(current.clone());

        let pc = cfg.pools.get(&current).ok_or_else(|| {
            HxError::Config(format!(
                "pool '{name}' inherits from unknown pool '{current}'"
            ))
        })?;

        // Nearest declaration wins, so a child can override its parent.
        if members.is_none() && !pc.members.is_empty() {
            members = Some(pc.members.clone());
        }
        if limits.is_none() && !pc.limits.is_unbounded() {
            limits = Some(pc.limits.clone());
        }

        match &pc.inherits {
            Some(parent) => current = parent.clone(),
            None => break,
        }
    }

    Ok((members.unwrap_or_default(), limits.unwrap_or_default()))
}

/// Turn `provider/model-glob` members into concrete routes.
fn expand_members(
    members: &[String],
    providers: &IndexMap<String, ProviderConfig>,
) -> Result<Vec<Route>> {
    let mut out: Vec<Route> = Vec::new();

    for member in members {
        let parsed = ModelRef::parse(member)?;
        let pname = parsed.provider.as_str().to_string();

        let pc = providers.get(&pname).ok_or_else(|| {
            HxError::Config(format!(
                "pool member {member:?} references unknown provider '{pname}'"
            ))
        })?;

        let is_glob = parsed.model.contains('*') || parsed.model.contains('?');
        if is_glob {
            let matched: Vec<String> = pc
                .models
                .iter()
                .filter(|m| glob_match(&parsed.model, m))
                .cloned()
                .collect();

            if matched.is_empty() {
                return Err(HxError::Config(format!(
                    "pool member {member:?} matched no models on provider '{pname}' \
                     (provider lists {} model(s): {:?})",
                    pc.models.len(),
                    pc.models
                )));
            }
            for model in matched {
                out.push(Route {
                    provider: parsed.provider.clone(),
                    model,
                });
            }
        } else {
            out.push(Route {
                provider: parsed.provider.clone(),
                model: parsed.model.clone(),
            });
        }
    }

    // De-duplicate while preserving preference order.
    let mut seen = std::collections::HashSet::new();
    out.retain(|r| seen.insert((r.provider.as_str().to_string(), r.model.clone())));

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Usage;

    const CFG: &str = r#"
providers:
  anthropic-main:
    kind: anthropic
    base_url: https://api.anthropic.com
    models: ["claude-opus-4-7", "claude-sonnet-4-7"]
    price: { input_per_mtok: 3.0, output_per_mtok: 15.0 }
    routing: least_loaded
    credentials:
      - { id: a1, secret: "vault:anthropic/a1", limits: { rpm: 50, tpm: 40000 } }
      - { id: a2, secret: "vault:anthropic/a2", limits: { rpm: 50, tpm: 40000 }, weight: 2 }
  local-llama:
    kind: ollama
    base_url: http://127.0.0.1:11434
    models: ["qwen3-32b"]
    routing: priority
    credentials:
      - { id: l1, secret: "vault:local/none" }

pools:
  interactive:
    members: ["anthropic-main/claude-*"]
    strategy: least_loaded
  background:
    members: ["local-llama/qwen3-32b"]
    strategy: priority
    limits: { concurrent: 2 }
  fast:
    inherits: background
  coding:
    members: ["anthropic-main/claude-opus-4-7", "local-llama/qwen3-32b"]
    strategy: priority

roles:
  builder: interactive
  scout: background
  reviewer: interactive
  fallback: coding
"#;

    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn router() -> ModelRouter {
        let cfg = Config::from_yaml(CFG).expect("test config must parse");
        ModelRouter::from_config(&cfg, t0()).expect("router must build")
    }

    #[test]
    fn builds_pools_and_resolves_roles() {
        let r = router();
        assert_eq!(r.pool_for_role("builder").unwrap(), "interactive");
        assert_eq!(r.pool_for_role("scout").unwrap(), "background");
        assert_eq!(r.pool_for_role("fallback").unwrap(), "coding");
    }

    #[test]
    fn glob_membership_expands_against_the_provider_model_list() {
        let r = router();
        let interactive = r.pool("interactive").unwrap();
        let models: Vec<&str> = interactive
            .routes()
            .iter()
            .map(|r| r.model.as_str())
            .collect();
        assert_eq!(models, vec!["claude-opus-4-7", "claude-sonnet-4-7"]);
    }

    #[test]
    fn inherited_pool_takes_members_and_ceiling_from_its_parent() {
        let r = router();
        let fast = r.pool("fast").unwrap();
        assert_eq!(fast.routes().len(), 1, "fast inherits background's member");
        assert_eq!(fast.routes()[0].model, "qwen3-32b");
    }

    #[test]
    fn unknown_role_is_a_config_error_not_a_panic() {
        let r = router();
        let err = r.pool_for_role("nonexistent").unwrap_err();
        assert!(err.to_string().contains("no pool bound to role"), "{err}");
    }

    #[test]
    fn acquiring_for_a_role_picks_the_pools_first_route() {
        let mut r = router();

        let t = r.acquire_for_role("scout", 100, 0.0, t0()).unwrap();
        assert_eq!(t.route.provider.as_str(), "local-llama");
        assert_eq!(t.route.model, "qwen3-32b");
        assert_eq!(t.pool, "background");

        let t = r.acquire_for_role("builder", 100, 0.0, t0()).unwrap();
        assert_eq!(t.route.provider.as_str(), "anthropic-main");
        assert_eq!(t.route.model, "claude-opus-4-7", "first listed model wins");
    }

    #[test]
    fn fails_over_to_the_next_provider_when_the_first_key_is_disabled() {
        let mut r = router();
        let anthropic = ProviderId::from_raw("anthropic-main");

        // Disable both of the anthropic keys.
        assert!(r.mark_unhealthy(&anthropic, &CredentialId::from("a1"), "401"));
        assert!(r.mark_unhealthy(&anthropic, &CredentialId::from("a2"), "401"));

        let t = r.acquire_for_role("fallback", 100, 0.0, t0()).unwrap();
        assert_eq!(
            t.route.provider.as_str(),
            "local-llama",
            "should have fallen over to the other provider"
        );
    }

    #[test]
    fn a_pool_wide_ceiling_blocks_even_with_idle_credentials() {
        let mut r = router();

        // background has concurrent: 2 and one credential.
        let _a = r.acquire_for_role("scout", 10, 0.0, t0()).unwrap();
        let _b = r.acquire_for_role("scout", 10, 0.0, t0()).unwrap();

        let err = r.acquire_for_role("scout", 10, 0.0, t0()).unwrap_err();
        assert!(
            matches!(err, HxError::RateLimited { .. }),
            "pool ceiling should report as rate limiting, got {err:?}"
        );
    }

    #[test]
    fn interactive_work_is_unaffected_by_a_saturated_background_pool() {
        // The whole point of separate pools: a busy cron job must not block you.
        let mut r = router();
        let _a = r.acquire_for_role("scout", 10, 0.0, t0()).unwrap();
        let _b = r.acquire_for_role("scout", 10, 0.0, t0()).unwrap();
        assert!(r.acquire_for_role("scout", 10, 0.0, t0()).is_err());

        assert!(
            r.acquire_for_role("builder", 10, 0.0, t0()).is_ok(),
            "interactive pool must stay available"
        );
    }

    #[test]
    fn credential_limits_are_shared_across_pools_that_use_the_same_key() {
        // Regression guard for the classic bug: if each named pool held its own copy of a
        // credential's limiter, two pools would each get the full rate limit of one key.
        let cfg = Config::from_yaml(CFG).unwrap();
        let mut r = ModelRouter::from_config(&cfg, t0()).unwrap();

        // interactive and coding both route to anthropic-main. Drain key a1/a2 via `builder`
        // so that a *different* pool sharing the key must also see the ceiling.
        let mut served = 0;
        for _ in 0..200 {
            match r.acquire_for_role("builder", 1, 0.0, t0()) {
                Ok(t) => {
                    served += 1;
                    r.reconcile(t, 1, 0.0, t0());
                }
                Err(_) => break,
            }
        }
        // 2 keys x 50 RPM = 100 requests, and no more, across the provider.
        assert_eq!(
            served, 100,
            "the provider-wide limit must be shared, not per-pool"
        );

        // The other pool that shares this provider must also see the ceiling: it falls through
        // to its non-anthropic route rather than being handed a fresh 100 requests. That is the
        // observable consequence of the credential pool being keyed by provider.
        let t = r.acquire_for_role("fallback", 1, 0.0, t0()).unwrap();
        assert_eq!(
            t.route.provider.as_str(),
            "local-llama",
            "anthropic's ceiling must be shared with every pool that uses the key"
        );
    }

    #[test]
    fn reconcile_returns_unused_reservation_to_both_levels() {
        let mut r = router();
        let t = r.acquire_for_role("scout", 10_000, 0.0, t0()).unwrap();
        r.reconcile(t, 5, 0.0, t0());

        // Both the credential and the pool concurrent slot must be free again.
        for _ in 0..3 {
            let t = r.acquire_for_role("scout", 10_000, 0.0, t0()).unwrap();
            r.reconcile(t, 5, 0.0, t0());
        }
    }

    #[test]
    fn cost_estimation_uses_the_provider_rate_card() {
        let r = router();
        let route = Route {
            provider: ProviderId::from_raw("anthropic-main"),
            model: "claude-opus-4-7".into(),
        };
        let usage = Usage {
            input_tokens: 1_000_000,
            output_tokens: 0,
            ..Default::default()
        };
        assert!((r.estimate_cost(&route, &usage) - 3.0).abs() < 1e-9);
    }

    #[test]
    fn unknown_provider_in_a_pool_member_fails_configuration() {
        let cfg = Config::from_yaml(
            r#"
providers:
  p1: { kind: openai, models: ["m1"], credentials: [{ id: c1, secret: "vault:x" }] }
pools:
  bad: { members: ["nope/m1"] }
roles: { r: bad }
"#,
        )
        .unwrap();
        let err = ModelRouter::from_config(&cfg, t0()).unwrap_err();
        assert!(err.to_string().contains("unknown provider"), "{err}");
    }

    #[test]
    fn a_glob_that_matches_nothing_is_rejected_with_a_helpful_message() {
        let cfg = Config::from_yaml(
            r#"
providers:
  p1: { kind: openai, models: ["gpt-x"], credentials: [{ id: c1, secret: "vault:x" }] }
pools:
  bad: { members: ["p1/claude-*"] }
roles: { r: bad }
"#,
        )
        .unwrap();
        let err = ModelRouter::from_config(&cfg, t0()).unwrap_err();
        assert!(err.to_string().contains("matched no models"), "{err}");
    }

    #[test]
    fn inheritance_cycles_are_detected_rather_than_hanging() {
        let cfg = Config::from_yaml(
            r#"
providers: {}
pools:
  a: { inherits: b }
  b: { inherits: a }
roles: {}
"#,
        )
        .unwrap();
        let err = ModelRouter::from_config(&cfg, t0()).unwrap_err();
        assert!(err.to_string().contains("cycle"), "{err}");
    }

    #[test]
    fn a_role_pointing_at_a_missing_pool_fails_at_startup() {
        let cfg = Config::from_yaml(
            r#"
providers:
  p1: { kind: openai, models: ["m1"], credentials: [{ id: c1, secret: "vault:x" }] }
pools:
  real: { members: ["p1/m1"] }
roles: { broken: ghost }
"#,
        )
        .unwrap();
        let err = ModelRouter::from_config(&cfg, t0()).unwrap_err();
        assert!(err.to_string().contains("unknown pool 'ghost'"), "{err}");
    }

    #[test]
    fn status_reports_routes_and_credential_counts() {
        let r = router();
        let s = r.status();
        assert_eq!(s.pools.len(), 4);
        let interactive = s.pools.iter().find(|p| p.name == "interactive").unwrap();
        assert_eq!(interactive.routes.len(), 2);
        assert_eq!(interactive.total_credentials, 2);
        assert_eq!(interactive.healthy_credentials, 2);
        assert_eq!(s.roles.get("scout").map(String::as_str), Some("background"));
    }

    #[test]
    fn explicit_model_member_does_not_require_a_model_list() {
        let cfg = Config::from_yaml(
            r#"
providers:
  ollama: { kind: ollama, credentials: [{ id: c1, secret: "vault:none" }] }
pools:
  local: { members: ["ollama/llama3:8b"] }
roles: { default: local }
"#,
        )
        .unwrap();
        let r = ModelRouter::from_config(&cfg, t0()).unwrap();
        assert_eq!(r.pool("local").unwrap().routes()[0].model, "llama3:8b");
    }
}

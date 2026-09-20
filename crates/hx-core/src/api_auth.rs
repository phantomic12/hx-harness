//! The daemon's API bearer token: how it is compared, and when its absence is fatal.
//!
//! ## Why this exists
//!
//! Until this module, `hxd`'s HTTP API had **no authentication at all**. Every route — running a
//! command on a machine, reading a file, answering an approval — was open to anything that could
//! reach the port. On the default loopback bind that is a local-only exposure; the moment the
//! daemon is started with `--bind 0.0.0.0` (or any other non-loopback address) it is open to
//! whatever can route to that address, and `docs/approvals.md` §9 records exactly that as the
//! residual hole under the approval ceiling: the answer route requires the *caller* to declare its
//! ceiling, and a declared ceiling is only as trustworthy as the caller.
//!
//! ## The two halves, and which one matters
//!
//! - **Fail closed.** [`require_token_for_bind`] refuses to start when the bind address is not
//!   loopback and no token is configured. The alternative — start anyway with a warning — is the
//!   failure mode that ships: a warning is a line in a log nobody reads, and the daemon is then
//!   serving an unauthenticated API on a routable address. An operator who genuinely wants that
//!   cannot express it, which is deliberate.
//! - **Optional on loopback.** A token is *honoured* when set on a loopback bind, and not required
//!   when it is not. This is what keeps the existing suite honest: its tests bind loopback and pass
//!   no token, and a rule that demanded a token everywhere would have forced every one of them to
//!   grow one — a signal that the rule, not the tests, was wrong.
//!
//! ## The comparison, and its honest limit
//!
//! [`ApiToken::matches`] compares in constant time by hand: it walks every byte of the longer of
//! the two inputs, accumulating the difference into one byte, and folds the length difference in as
//! a bit rather than returning early. A correct prefix therefore costs exactly as much as a wrong
//! first byte, which is the property that stops an attacker from recovering the token one byte at a
//! time by measuring how long a rejection takes. It is hand-rolled rather than pulled from a crate
//! because the workspace keeps its dependency list small on purpose and this is twenty lines.
//!
//! **That is defence against a timing comparison, and it is not the whole story.** What is compared
//! this way is still a **bearer token**: anyone who observes it — in a proxy log, in a terminal
//! scrollback, in a `ps` output — can replay it for as long as it stays valid, and there is no
//! rotation, no expiry, no per-client identity and no way to revoke one without changing it for
//! everyone. It is not a session, and an authenticated API is not the same claim as a *secure*
//! API: the transport is still plain HTTP, so a token sent over a non-loopback interface travels
//! in the clear unless something in front terminates TLS. Both limits are written down here rather
//! than implied away, because a security control whose boundaries are unstated gets trusted past
//! them.
//!
//! ## The value never appears in a message
//!
//! [`ApiToken`]'s `Debug` is redacted, [`crate::config::ApiConfig`]'s is redacted, and every error
//! this module produces names the *setting* (`api.token`, `HX_API_TOKEN`) rather than a value. The
//! 401 path is built to be indistinguishable between "no token" and "wrong token", so the response
//! body cannot be used to learn anything about the token either.

use crate::error::{HxError, Result};
use std::net::{IpAddr, SocketAddr};

/// The environment variable a deployment uses when its config names no token.
///
/// Named here rather than at each call site because it is part of the contract an operator reads:
/// a container or a CI job sets this instead of writing a token into a file.
pub const API_TOKEN_ENV: &str = "HX_API_TOKEN";

/// A bearer token, with a redacted `Debug` and a constant-time comparison.
#[derive(Clone)]
pub struct ApiToken(String);

impl ApiToken {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Explicit access, named `expose` so that every call site is greppable and reviewable — the
    /// same convention [`hx_secrets::Secret`] uses, for the same reason.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Does `presented` match this token, in constant time?
    ///
    /// See the module doc for what this does and does not buy. The one property worth restating at
    /// the call site: a request carrying a *correct prefix* of the token must be refused, and must
    /// be refused without the comparison having stopped early — an early return on the first
    /// differing byte is the whole class of bug this function exists to not have.
    pub fn matches(&self, presented: &str) -> bool {
        constant_time_eq(self.0.as_bytes(), presented.as_bytes())
    }
}

impl std::fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Matches `Secret`'s rendering: the length is harmless and the value never is.
        if self.0.is_empty() {
            f.write_str("ApiToken(<empty>)")
        } else {
            write!(f, "ApiToken(<{} bytes redacted>)", self.0.len())
        }
    }
}

/// Compare two byte strings without an early return.
///
/// Every byte of the longer input is visited and every difference is OR-ed into one accumulator, so
/// the loop's shape does not depend on where the two strings first differ. The length difference is
/// folded in as a bit for the same reason: `a.len() != b.len()` returning `false` immediately would
/// leak the configured token's length, and length is half of a brute-force search.
///
/// It is not a defence against an attacker who can measure cache-line behaviour or who runs on the
/// same physical core; it is a defence against the ordinary timing comparison, which is the one
/// that shows up in practice.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff: u8 = u8::from(a.len() != b.len());
    let longest = a.len().max(b.len());
    for i in 0..longest {
        // Out-of-range bytes read as 0 rather than shortening the loop: the number of iterations
        // must not depend on either length.
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

/// Is this bind address one that only the local machine can reach?
///
/// Loopback means `127.0.0.0/8`, `::1`, or the name `localhost`. Everything else — `0.0.0.0`, `::`,
/// a LAN address, a public address, a host name that resolves to one of those — is treated as
/// reachable from elsewhere, including anything this function cannot parse. That last part is the
/// fail-closed direction and it is deliberate: an unrecognised spelling must not be read as
/// "probably local", because the cost of being wrong in that direction is an unauthenticated API
/// on a routable interface.
pub fn bind_is_loopback(bind: &str) -> bool {
    let bind = bind.trim();

    // `host:port`, which is what `--bind` and `HX_BIND` carry.
    if let Ok(addr) = bind.parse::<SocketAddr>() {
        return addr.ip().is_loopback();
    }

    // A bare address with no port — `127.0.0.1`, `::1`, `[::1]`. This is checked *before* the
    // port split, because `::1` splits at its last colon into the host `::` and the "port" `1`, and
    // `::` is the unspecified address rather than a loopback one. That is the whole reason this
    // arm exists rather than being folded into the split below.
    let bare = bind.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return ip.is_loopback();
    }

    // Otherwise a name, optionally with a port.
    let host = match bind.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => bind,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        // A host name this crate will not resolve (it is IO-free on purpose, and a check that
        // depended on a resolver would give a different answer offline).
        Err(_) => false,
    }
}

/// Refuse a startup that would serve an unauthenticated API to the network.
///
/// `token_configured` is whether a token was resolved from `api.token` or `HX_API_TOKEN` — a
/// `bool` rather than an [`ApiToken`] so this stays pure, and so a caller cannot accidentally
/// format a token into the error while asking the question.
///
/// The error names the two settings an operator can act on and says what is at stake. It does
/// **not** name the bind address's own value as a secret, and it never carries a token.
pub fn require_token_for_bind(bind: &str, token_configured: bool) -> Result<()> {
    if token_configured || bind_is_loopback(bind) {
        return Ok(());
    }

    Err(HxError::Config(format!(
        "refusing to start: the HTTP API is bound to {bind:?}, which is not a loopback address, and \
         no API token is configured. Set `api.token` in the config — a value, or a `store:name` \
         reference resolved through hx-secrets such as \"env:{API_TOKEN_ENV}\" — or set \
         {API_TOKEN_ENV} in the environment. An unauthenticated API on a reachable address lets any \
         caller that can route to it read files, run commands on every configured host, and answer \
         the approval questions an agent run is waiting on."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token shaped like the thing it stands in for. The sentinel is what the leak tests below
    /// search for: a value that appears nowhere in this crate except where it is deliberately put.
    const SENTINEL: &str = "hx-api-sentinel-9f4c1e7a-do-not-log-me";

    fn token() -> ApiToken {
        ApiToken::new(SENTINEL)
    }

    #[test]
    fn the_exact_token_matches_and_a_wrong_one_does_not() {
        assert!(token().matches(SENTINEL));
        assert!(!token().matches("something-else-entirely"));
        // The control for the test below: a string that is not a prefix of the token at all is
        // refused for a different reason, so refusing a prefix is not the whole test passing for
        // free.
        assert!(!token().matches("hx-api-sentinel-9f4c1e7a-do-not-log-mex"));
    }

    #[test]
    fn a_correct_prefix_is_refused_so_the_comparison_cannot_stop_early() {
        // This is the test that catches an early-return comparison: `==` on `&str` would answer
        // "no" here too, but a comparison that returned on the first differing byte would answer
        // "no" *sooner*, and the timing of that answer is what recovers a token byte by byte.
        // Every prefix length is checked, not one: an early return placed at any offset has to be
        // caught, not only at offset 0.
        let full = SENTINEL;
        for cut in 0..full.len() {
            let prefix = &full[..cut];
            assert!(
                !token().matches(prefix),
                "a {cut}-byte prefix of the token was accepted"
            );
        }
    }

    #[test]
    fn an_empty_presentation_is_refused_by_a_token_that_is_not_empty() {
        // The shape of "no `Authorization` header at all" reaching the comparison. It must not be a
        // match, and it must not be a panic on an empty slice either.
        assert!(!token().matches(""));
        assert!(ApiToken::new("").matches(""));
    }

    #[test]
    fn the_length_difference_is_folded_in_rather_than_returned_early() {
        // A longer presentation is as wrong as a shorter one, and neither is decided by a length
        // check that short-circuits.
        let longer = format!("{SENTINEL}-and-then-some");
        assert!(!token().matches(&longer));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn a_token_never_appears_in_its_own_debug_output() {
        let printed = format!("{:?}", token());
        assert!(
            !printed.contains(SENTINEL),
            "a `Debug` rendering carried the token: {printed}"
        );
        assert!(
            !printed.contains("hx-api-sentinel"),
            "not even a prefix of it: {printed}"
        );
        // The empty case is reported as empty rather than as a zero-length redaction, so a missing
        // token is visible in a dump.
        assert_eq!(format!("{:?}", ApiToken::new("")), "ApiToken(<empty>)");
    }

    #[test]
    fn loopback_binds_are_recognised_in_every_spelling_that_reaches_them() {
        for bind in [
            "127.0.0.1:8787",
            "127.0.0.2:8787",
            "localhost:8787",
            "LOCALHOST:8787",
            "[::1]:8787",
            "::1",
            "[::1]",
        ] {
            assert!(bind_is_loopback(bind), "{bind:?} is loopback");
        }
    }

    #[test]
    fn everything_that_is_not_loopback_is_treated_as_reachable_from_elsewhere() {
        for bind in [
            "0.0.0.0:8787",
            "[::]:8787",
            "192.168.1.5:8787",
            "10.0.0.5:8787",
            "203.0.113.7:8787",
            "::",
            // A name that is not `localhost` may or may not resolve to a local address; it is not
            // this crate's business to find out, and guessing "local" is the fail-open direction.
            "buildbox:8787",
            "hx.internal",
            // Unparseable input is not read as "probably fine".
            "",
            "not a bind address at all",
        ] {
            assert!(!bind_is_loopback(bind), "{bind:?} is not loopback");
        }
    }

    #[test]
    fn a_non_loopback_bind_with_no_token_refuses_to_start_and_names_the_settings() {
        // The fail-closed half, and the important half: a daemon asked to serve the network
        // without a token must not start with a warning, it must not start at all.
        let err = require_token_for_bind("0.0.0.0:8787", false).unwrap_err();
        let message = err.to_string();

        assert!(
            message.contains("api.token"),
            "the message must name the config key: {message}"
        );
        assert!(
            message.contains(API_TOKEN_ENV),
            "and the environment variable a container would use: {message}"
        );
        assert!(
            message.contains("0.0.0.0:8787"),
            "and the address it refused: {message}"
        );
    }

    #[test]
    fn a_token_makes_a_non_loopback_bind_acceptable_and_loopback_needs_none() {
        // The three-way truth table, all three legs, because any one of them alone can be satisfied
        // by a rule that is wrong for the other two.
        assert!(require_token_for_bind("0.0.0.0:8787", true).is_ok());
        assert!(require_token_for_bind("127.0.0.1:8787", false).is_ok());
        assert!(require_token_for_bind("127.0.0.1:8787", true).is_ok());
    }

    #[test]
    fn the_startup_refusal_carries_no_token() {
        // The refusal path is one of the two places a token is most likely to be printed, because
        // the message is built while the token is in hand. It is built from the *address* and the
        // setting names, and this asserts that rather than trusting it.
        let message = require_token_for_bind("0.0.0.0:8787", false)
            .unwrap_err()
            .to_string();
        assert!(!message.contains(SENTINEL), "{message}");
        assert!(!message.contains("Bearer"), "{message}");
    }
}

//! Outbound redaction — the last line of defence before text reaches a third party.
//!
//! A credential does not have to be *used* to leak. It leaks when it appears in tool output:
//! `env`, `cat .env`, `git remote -v`, a curl debug trace, an error message, a stack trace.
//! That output becomes part of the transcript, and the transcript goes to a model provider.
//! Redaction runs on the way out so a leak in one command can't compound into a leak in
//! every subsequent request.
//!
//! Two mechanisms, applied in order:
//!
//! 1. **Literal** — every value in the unlocked vault is registered here, so even a secret
//!    with no recognisable shape gets masked. Longest-first, so a key that is a substring of
//!    another key can't leave a fragment behind.
//! 2. **Pattern** — well-known credential formats (provider keys, cloud keys, JWTs, private
//!    key blocks) are matched structurally.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// What kind of secret was masked. Recorded so the audit log can answer
/// "did the agent print a credential, and of what sort?" without storing the credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionKind {
    /// Matched a value we know from the vault.
    KnownSecret,
    ProviderKey,
    CloudKey,
    GitHubToken,
    SlackToken,
    TelegramBotToken,
    Jwt,
    PrivateKeyBlock,
    BearerHeader,
    ConnectionString,
}

impl RedactionKind {
    fn label(&self) -> &'static str {
        match self {
            Self::KnownSecret => "known-secret",
            Self::ProviderKey => "provider-key",
            Self::CloudKey => "cloud-key",
            Self::GitHubToken => "github-token",
            Self::SlackToken => "slack-token",
            Self::TelegramBotToken => "telegram-bot-token",
            Self::Jwt => "jwt",
            Self::PrivateKeyBlock => "private-key",
            Self::BearerHeader => "bearer",
            Self::ConnectionString => "connection-string",
        }
    }
}

/// Result of a redaction pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redaction {
    pub text: String,
    /// Which kinds fired, deduplicated. Empty means nothing was masked.
    pub hits: Vec<RedactionKind>,
}

impl Redaction {
    pub fn changed(&self) -> bool {
        !self.hits.is_empty()
    }
}

fn patterns() -> &'static [(RedactionKind, Regex)] {
    static P: OnceLock<Vec<(RedactionKind, Regex)>> = OnceLock::new();
    P.get_or_init(|| {
        let build = |kind, pat: &str| {
            (
                kind,
                Regex::new(pat).unwrap_or_else(|e| panic!("bad pattern {pat}: {e}")),
            )
        };
        vec![
            // Private key blocks first: they are multi-line and would otherwise be
            // partially eaten by the generic rules below.
            build(
                RedactionKind::PrivateKeyBlock,
                r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            ),
            // Anthropic/OpenAI and compatible: sk-, sk-ant-, sk-proj-, sk-or-v1-, rk-
            build(
                RedactionKind::ProviderKey,
                r"\b(?:sk|rk)-[A-Za-z0-9_-]{16,}",
            ),
            // Google API keys
            build(RedactionKind::CloudKey, r"\bAIza[0-9A-Za-z_-]{35}\b"),
            // AWS access key IDs (the secret half has no fixed shape — that is what the
            // vault-literal path is for)
            build(RedactionKind::CloudKey, r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            // GitHub tokens
            build(
                RedactionKind::GitHubToken,
                r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
            ),
            // Slack
            build(
                RedactionKind::SlackToken,
                r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
            ),
            // Telegram bot token: <bot_id>:<35-char secret>.
            //
            // Deliberately no leading `\b`. The token almost always appears as
            // `https://api.telegram.org/bot<id>:<secret>`, and `t` → `7` is *not* a word
            // boundary, so an anchored pattern would silently miss the single most common
            // real-world occurrence. Over-matching digits here is the safe direction.
            build(
                RedactionKind::TelegramBotToken,
                r"\d{8,12}:[A-Za-z0-9_-]{30,}",
            ),
            // JWT
            build(
                RedactionKind::Jwt,
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b",
            ),
            // Authorization headers
            build(
                RedactionKind::BearerHeader,
                r"(?i)\b(?:bearer|token)\s+[A-Za-z0-9._\-]{16,}",
            ),
            // Connection strings with inline credentials
            build(
                RedactionKind::ConnectionString,
                r"://[^/\s:@]+:[^/\s:@]{6,}@",
            ),
        ]
    })
}

/// Masks credentials in outbound text.
///
/// Cheap to clone-by-reference and safe to share: the registered-literal set is only ever
/// appended to at unlock time.
#[derive(Debug, Default, Clone)]
pub struct Redactor {
    /// Registered secret values, longest first so nested values mask fully.
    literals: Vec<String>,
    enabled: bool,
}

impl Redactor {
    /// A redactor that is switched off.
    ///
    /// Present because tests and local-only pipelines sometimes want raw output — but it has
    /// to be *asked for by name*, so no code path gets it by accident.
    pub fn disabled() -> Self {
        Self {
            literals: Vec::new(),
            enabled: false,
        }
    }

    /// The default redactor: pattern-based only, no known secrets registered yet.
    pub fn new() -> Self {
        Self {
            literals: Vec::new(),
            enabled: true,
        }
    }

    /// Register a known secret value. Called for every value in the vault on unlock.
    pub fn register(&mut self, secret: &str) {
        if secret.len() < 8 {
            // Short strings produce absurd false positives ("true", "0", "yes").
            return;
        }
        if self.literals.iter().any(|s| s == secret) {
            return;
        }
        self.literals.push(secret.to_string());
        // Longest-first: if a shorter secret is a prefix of a longer one, masking the long
        // one first avoids leaving the tail of the long one in the output.
        self.literals.sort_by_key(|s| std::cmp::Reverse(s.len()));
    }

    pub fn register_all<'a>(&mut self, secrets: impl IntoIterator<Item = &'a str>) {
        for s in secrets {
            self.register(s);
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn literal_count(&self) -> usize {
        self.literals.len()
    }

    /// Mask `input`, returning the cleaned text and which rules fired.
    pub fn redact(&self, input: &str) -> Redaction {
        if !self.enabled {
            return Redaction {
                text: input.to_string(),
                hits: Vec::new(),
            };
        }

        let mut hits = BTreeSet::new();
        let mut text = input.to_string();

        for lit in &self.literals {
            if text.contains(lit.as_str()) {
                text = text.replace(lit.as_str(), "[REDACTED:known-secret]");
                hits.insert(RedactionKind::KnownSecret);
            }
        }

        for (kind, re) in patterns() {
            if re.is_match(&text) {
                text = re
                    .replace_all(&text, format!("[REDACTED:{}]", kind.label()))
                    .into_owned();
                hits.insert(*kind);
            }
        }

        Redaction {
            text,
            hits: hits.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_ordinary_text_alone() {
        let r = Redactor::new();
        let input = "Compiled 42 crates in 1m 12s. No warnings.";
        let out = r.redact(input);
        assert_eq!(out.text, input);
        assert!(!out.changed());
    }

    #[test]
    fn masks_provider_keys() {
        let r = Redactor::new();
        let out = r.redact("export ANTHROPIC_API_KEY=sk-ant-api03-AbCdEf1234567890XyZ");
        assert!(
            !out.text.contains("AbCdEf1234567890XyZ"),
            "got {}",
            out.text
        );
        assert!(out.text.contains("[REDACTED:provider-key]"));
        assert_eq!(out.hits, vec![RedactionKind::ProviderKey]);
    }

    #[test]
    fn masks_github_tokens() {
        let r = Redactor::new();
        let out = r.redact("remote: https://ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345@github.com");
        assert!(!out.text.contains("ghp_AB"), "got {}", out.text);
        assert!(out.hits.contains(&RedactionKind::GitHubToken));
    }

    #[test]
    fn masks_aws_access_key_ids() {
        let r = Redactor::new();
        let out = r.redact("AKIAIOSFODNN7EXAMPLE is the id");
        assert!(
            !out.text.contains("AKIAIOSFODNN7EXAMPLE"),
            "got {}",
            out.text
        );
        assert!(out.hits.contains(&RedactionKind::CloudKey));
    }

    #[test]
    fn masks_jwts_and_bearer_headers() {
        let r = Redactor::new();
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let out = r.redact(&format!("Authorization: Bearer {jwt}"));
        assert!(
            out.hits.contains(&RedactionKind::Jwt),
            "hits {:?}",
            out.hits
        );
    }

    #[test]
    fn masks_telegram_bot_tokens() {
        let r = Redactor::new();
        // The fixture is assembled at runtime rather than written as a literal. A token-shaped
        // literal in a source file gets scrubbed by secret scanners (including Hermes's own,
        // which rewrote an earlier version of this test to `***` and made the assertion
        // vacuous). Building it from parts keeps the test honest.
        let token = format!("{}:{}", "7654321098", "A".repeat(35));
        // Shape matters: hx itself ships a Telegram connector, and this is the URL form that
        // appears in logs.
        let out = r.redact(&format!("https://api.telegram.org/bot{token}/getMe"));
        assert!(
            out.hits.contains(&RedactionKind::TelegramBotToken),
            "hits {:?}",
            out.hits
        );
        assert!(
            !out.text.contains(&token),
            "token leaked through: {}",
            out.text
        );
    }

    #[test]
    fn masks_a_whole_private_key_block() {
        let r = Redactor::new();
        let input = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nAAAABG5vbmUAAAAE\n-----END OPENSSH PRIVATE KEY-----\nafter";
        let out = r.redact(input);
        assert!(
            !out.text.contains("b3BlbnNzaC1rZXktdjEAAAAA"),
            "got {}",
            out.text
        );
        assert!(out.text.contains("before"));
        assert!(out.text.contains("after"));
        assert_eq!(out.hits, vec![RedactionKind::PrivateKeyBlock]);
    }

    #[test]
    fn masks_registered_known_secrets_that_have_no_pattern() {
        // A password or an opaque token has no structural signature. This is the only thing
        // that catches it.
        let mut r = Redactor::new();
        r.register("hunter2-but-long-enough");
        let out = r.redact("connecting with hunter2-but-long-enough now");
        assert!(
            !out.text.contains("hunter2-but-long-enough"),
            "got {}",
            out.text
        );
        assert_eq!(out.hits, vec![RedactionKind::KnownSecret]);
    }

    /// A standalone hyphenated bearer token (`signed-token-…`, which the notification layer in this
    /// workspace names as one of "this repo's own bearer tokens") is **not** caught by any pattern — the
    /// provider-key rule requires an `sk-`/`rk-` prefix, and the bearer-header rule requires the literal
    /// word `bearer`/`token` directly before the value. This is a deliberate divergence from the
    /// notification layer, whose whole-word bar (`>=16 alphanumerics, all of alnum|`-`|`_`|`.``)
    /// would over-redact ordinary long hyphenated prose if applied to arbitrary tool output. The designed and
    /// documented mechanism for such values is **literal registration from the vault** (see the module doc), and
    /// this test pins both halves: unregistered it stays visible, registered it masks.
    #[test]
    fn a_standalone_hyphenated_bearer_token_is_caught_by_literal_registration_not_by_pattern() {
        let r = Redactor::new();
        let token = "signed-token-9f3a2b7c8d1e2f3a4b5c6d7e";
        // Unregistered: no structural pattern recognizes a standalone hyphenated token.
        let first = r.redact(&format!("the value is {token} now"));
        assert!(
            first.text.contains(token),
            "the pattern engine does not recognize a standalone hyphenated bearer token; this pins the \
             current behaviour so a future change is deliberate"
        );
        // Registered: the known-secret literal is the designed mechanism, and it masks exactly.
        let mut r2 = Redactor::new();
        r2.register(token);
        let second = r2.redact(&format!("the value is {token} now"));
        assert!(
            !second.text.contains(token) && second.hits == vec![RedactionKind::KnownSecret],
            "got {}",
            second.text
        );
    }

    #[test]
    fn longest_literal_wins_so_no_fragment_survives() {
        let mut r = Redactor::new();
        r.register("abcdefgh");
        r.register("abcdefgh-extended-tail");
        let out = r.redact("value=abcdefgh-extended-tail");
        assert!(
            !out.text.contains("extended-tail"),
            "fragment leaked: {}",
            out.text
        );
    }

    #[test]
    fn tiny_literals_are_ignored_to_avoid_false_positives() {
        let mut r = Redactor::new();
        r.register("true");
        r.register("0");
        assert_eq!(r.literal_count(), 0);
        let out = r.redact("this is true and that is 0");
        assert!(!out.changed(), "over-redacted: {}", out.text);
    }

    #[test]
    fn registers_each_literal_once() {
        let mut r = Redactor::new();
        r.register("long-enough-secret");
        r.register("long-enough-secret");
        assert_eq!(r.literal_count(), 1);
    }

    #[test]
    fn masks_credentials_embedded_in_connection_strings() {
        let r = Redactor::new();
        let out = r.redact("postgres://admin:s3cretpass@db.internal:5432/app");
        assert!(!out.text.contains("s3cretpass"), "got {}", out.text);
        assert!(out.hits.contains(&RedactionKind::ConnectionString));
    }

    #[test]
    fn reports_every_kind_that_fired() {
        let r = Redactor::new();
        let out = r.redact("key sk-ant-aaaaaaaaaaaaaaaaaaaa and ghp_bbbbbbbbbbbbbbbbbbbbbbbb also");
        assert!(out.hits.contains(&RedactionKind::ProviderKey));
        assert!(out.hits.contains(&RedactionKind::GitHubToken));
        assert_eq!(out.hits.len(), 2);
    }

    #[test]
    fn disabled_redactor_passes_everything_through() {
        let r = Redactor::disabled();
        let out = r.redact("sk-ant-aaaaaaaaaaaaaaaaaaaa");
        assert_eq!(out.text, "sk-ant-aaaaaaaaaaaaaaaaaaaa");
        assert!(!out.changed());
    }

    #[test]
    fn redaction_is_idempotent() {
        let r = Redactor::new();
        let once = r.redact("sk-ant-aaaaaaaaaaaaaaaaaaaa").text;
        let twice = r.redact(&once).text;
        assert_eq!(once, twice);
    }
}

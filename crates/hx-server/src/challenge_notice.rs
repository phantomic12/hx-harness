//! Telling the operator a challenge is waiting — and letting them answer it without the daemon's
//! master token.
//!
//! ## The gap this closes
//!
//! A challenge is a *question for one person*. Before this module the daemon asked it the way a
//! noticeboard asks: [`crate::pane::Challenges`] listed it, and whoever happened to have the daemon's
//! page open saw a banner. An operator who stepped away never learned that a run was blocked, and the
//! budget expired while nobody was looking at anything.
//!
//! ## Where it goes
//!
//! To the channel the *addressed* operator configured for exactly this kind of ping: a generic
//! webhook, the same shape [`crate::phone`] uses for approvals and the completion push uses for
//! finished runs. A relay that forwards approvals to a phone can forward this with the same code,
//! and one that wants to drop these can tell them apart by `kind` alone.
//!
//! There may be more than one such operator (see [`hx_core::config::Config::challenge_operators`]),
//! and that is the difference from a noticeboard: `screen.operators` gives each person their own
//! `push_url`, and this module pushes to **only** the one the challenge is addressed to. The
//! resolution goes the same way, so a second person's phone is not woken by a run they were never
//! asked about. Who a challenge is for is decided by the pane before this module is called, and
//! travels as [`ChallengeSummary::operator`] — the name is the address, which is why a roster with a
//! repeated name is collapsed in the config rather than here.
//!
//! ## Why the notification carries a token
//!
//! The whole point of a notification is to reach a person somewhere the daemon's *bearer* token is
//! not: a lock screen, a chat relay, a laptop that is not the daemon's host. Handing that channel the
//! master credential would trade a five-minute wait for a permanent one. So each challenge mints a
//! **one-time** token (see [`NoticeToken`]), the notification's `respond_url` carries it, and
//! `POST /v1/challenges/{id}?token=…` accepts it *instead of* the bearer header
//! ([`crate::auth`]). Answering spends it — the challenge is over either way, so a leaked
//! `respond_url` cannot answer a second one.
//!
//! The token is **redacted in logs**, exactly as the phone's respond token is: everything this module
//! writes strips the query string from a URL before printing it, and [`NoticeToken`]'s `Debug`/`Display`
//! are `<redacted>`.
//!
//! ## Fire and forget, and bounded
//!
//! A challenge that is announced is a challenge someone can answer; a *push* that fails must not
//! become a fetch that fails. So both pushes here are spawned and their failures logged, like
//! [`crate::phone::push_completion`] and unlike the approval push — which is deliberately synchronous
//! and inside the deadline, because an *approval* nobody saw must deny rather than wait.

use std::sync::Arc;

use serde::Serialize;
use uuid::Uuid;

use crate::pane::ChallengeSummary;
use crate::phone::SanitizedUrl;
use hx_core::config::ChallengeOperator;

/// A one-time secret minted per challenge, for the notification's `respond_url`.
///
/// A newtype so a challenge notice token and an API bearer token cannot be confused. Its only
/// `Debug`/`Display` is `<redacted>`, so a stray `{:?}` can never print it — the same rule as
/// [`crate::phone::RespondToken`], for the same reason.
#[derive(Clone)]
pub struct NoticeToken(String);

impl NoticeToken {
    pub fn new() -> Self {
        Self(Uuid::new_v4().simple().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for NoticeToken {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for NoticeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoticeToken(<redacted>)")
    }
}

impl std::fmt::Display for NoticeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// The JSON body announcing a challenge. It lives here so the doc and the wire shape cannot drift.
///
/// Every field is something a person looking at a lock screen needs in order to decide whether to get
/// up: *whose* run is blocked, *what site* refused it, *why the machines gave up*, *how long* is left,
/// and where to go. The two URLs are the two things they can do about it.
#[derive(Clone, Serialize)]
pub struct ChallengeNotice {
    /// Literal `"challenge"`, so a relay can route these independently of approvals and completions.
    pub kind: &'static str,
    /// The challenge id, which is also the screen's id.
    pub id: String,
    /// The screen to watch. `page_url` opens the daemon's page on it.
    pub screen: String,
    /// The session that is blocked, so the notification answers "whose work is this?".
    pub session: String,
    /// The site, in redacted form — the contract's decision, passed through unchanged.
    pub url: String,
    /// Why the automated rungs gave up, in the rungs' own words.
    pub reason: String,
    /// Whole seconds until the rung abandons the wait.
    pub seconds_left: u64,
    /// Who the question is for ([`hx_core::config::Config::challenge_operator`]).
    pub operator: String,
    /// The daemon's page, deep-linked to the screen the person has to clear the wall in. A person
    /// *clears the wall* on the screen; the answer only reports that they did.
    pub page_url: String,
    /// The URL the notification's answer button hits, carrying the one-time `token=`.
    pub respond_url: String,
}

/// The `Debug` is hand-written so the token inside `respond_url` is never printed.
impl std::fmt::Debug for ChallengeNotice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeNotice")
            .field("id", &self.id)
            .field("screen", &self.screen)
            .field("session", &self.session)
            .field("url", &self.url)
            .field("operator", &self.operator)
            .field("seconds_left", &self.seconds_left)
            .field("page_url", &SanitizedUrl(self.page_url.as_str()))
            .field("respond_url", &SanitizedUrl(self.respond_url.as_str()))
            .finish()
    }
}

/// The JSON body saying a challenge is over.
///
/// The second half of the promise, and the reason it is not a nicety: a person told to hurry is owed
/// the news that they can stop. A resolution is pushed for every outcome — answered, declined, the
/// budget expired, the screen closed — because "it is over" is one fact about one challenge and a
/// relay should not have to infer it from silence.
#[derive(Clone, Serialize)]
pub struct ChallengeResolved {
    /// Literal `"challenge_resolved"`.
    pub kind: &'static str,
    pub id: String,
    pub screen: String,
    pub session: String,
    /// Who the question was for.
    pub operator: String,
    /// How it ended: `solved`, `abandoned`, or `withdrawn`.
    pub outcome: String,
    /// The person's own note when they declined; empty otherwise. The reason `abandoned` exists, and
    /// the reason it reaches the same channel they were asked on.
    pub note: String,
}

impl std::fmt::Debug for ChallengeResolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeResolved")
            .field("id", &self.id)
            .field("session", &self.session)
            .field("operator", &self.operator)
            .field("outcome", &self.outcome)
            .field("note", &self.note)
            .finish()
    }
}

/// Where a new challenge is announced, so the pane's own tests can watch what would be sent.
///
/// The seam exists for the same reason [`crate::pane::ScreenHost`] does: everything worth asserting
/// here — that a token is minted once per challenge and answers exactly it, that the person is named,
/// that an unanswered challenge is reported as withdrawn — is a property of the *question*, and none
/// of it needs a socket to be true.
///
/// Both methods return nothing on purpose. A push that could fail the fetch would be a fetch whose
/// outcome depends on a relay's uptime, and the rung's budget is the only thing allowed to end a wait.
pub trait ChallengeNotices: Send + Sync {
    /// Tell the operator a challenge is waiting, addressed by `token`.
    fn announce(&self, challenge: &ChallengeSummary, token: &NoticeToken);

    /// Tell them it is over, and how.
    fn resolved(&self, challenge: &ChallengeSummary, outcome: &Outcome);

    /// Whether *this* operator can be reached on a channel of their own.
    ///
    /// Asked per challenge, not per daemon, because a roster can hold a person with a webhook and a
    /// person without one: "nobody was told" is only true of the person the question went to. The
    /// answer lands on the listing as [`crate::pane::ChallengeSummary::notified`], and that is worth
    /// reporting rather than hiding, because the two states are different instructions to whoever is
    /// reading the page — *someone has this* and *you are the only chance this run has*.
    fn reaches(&self, operator: &str) -> bool;

    /// Whether anyone at all can be reached.
    ///
    /// The daemon-level question, and only a summary of it: a notifier with no route to anybody is a
    /// notifier every challenge will report as unheard. It belongs in a `Debug` and a startup
    /// warning, not in a per-challenge answer — see [`ChallengeNotices::reaches`] for that.
    fn reachable(&self) -> bool;
}

/// How a challenge ended, in the words the notification uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A person cleared the wall.
    Solved,
    /// A person declined, with their note.
    Abandoned { note: String },
    /// Nobody answered: the budget expired, the fetch was cancelled, or the screen was closed.
    Withdrawn,
}

impl Outcome {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Solved => "solved",
            Self::Abandoned { .. } => "abandoned",
            Self::Withdrawn => "withdrawn",
        }
    }

    /// The note that reaches the notification, empty when there is nothing a person wrote to quote.
    pub fn note(&self) -> String {
        match self {
            Self::Abandoned { note } => note.clone(),
            _ => String::new(),
        }
    }
}

/// One operator's channel: the name a challenge is addressed by, and where that person is reached.
///
/// Split out from [`WebhookNotices`] so the routing table is a thing with a `name`, and a lookup that
/// returns a whole address rather than half of one. An operator with no `push_url` simply has no
/// `Route` — they are a person the daemon can address but not ring, which is a *state* the pane
/// reports rather than an absence this has to represent.
#[derive(Clone)]
struct Route {
    name: String,
    push_url: String,
}

/// The real notifier: each operator's own webhook, through the same client and the same redaction
/// rules as every other push.
///
/// A table, not a URL, because there is more than one person to reach. The lookup is by **name**
/// because that is what travels on the challenge ([`ChallengeSummary::operator`]): the pane decides
/// who is being asked, and this module's only job is to put that question in front of *that* person.
/// A shared table is also what keeps the two from drifting — there is no way to name a challenge for
/// one operator and push it to another's channel, because the address is derived from the addressee.
pub struct WebhookNotices {
    /// Only the operators who have a channel. Order is the config's, and does not matter here: a
    /// challenge names one person.
    routes: Vec<Route>,
    /// The daemon's public origin, prefixed into every `respond_url` and `page_url`.
    respond_base: String,
}

/// A webhook reduced to its origin, for a `Debug`.
///
/// Stronger than [`SanitizedUrl`], and deliberately so. That one strips the query, because the URL
/// it is applied to is one a person can follow. A relay URL is the opposite: its *path* is the
/// credential — `https://hooks.example/services/T00/B00/XYZ` is a posting key, and a `Debug` that
/// kept the path would put somebody's chat-room credential into every bug report pasted from a log.
struct RedactedWebhook<'a>(&'a str);

// The `Debug` is hand-written to *not* be the derived one: `#[derive(Debug)]` on a tuple struct
// prints the inner string, which is the whole thing this type exists to hide.
impl std::fmt::Debug for RedactedWebhook<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl std::fmt::Display for RedactedWebhook<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let url = self.0;
        let Some((scheme, rest)) = url.split_once("://") else {
            // Not a URL this can take apart. Printing it would be printing the secret, so print its
            // shape instead — a reader learns that a path was configured and nothing else.
            return write!(f, "<not a URL>");
        };
        let origin_len = rest
            .find(['/', '?', '#'])
            .unwrap_or(rest.len());
        write!(f, "{scheme}://{}", &rest[..origin_len])
    }
}

impl std::fmt::Debug for WebhookNotices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookNotices")
            .field(
                "routes",
                &self
                    .routes
                    .iter()
                    .map(|route| (route.name.as_str(), RedactedWebhook(&route.push_url)))
                    .collect::<Vec<_>>(),
            )
            .field("respond_base", &SanitizedUrl(&self.respond_base))
            .finish()
    }
}

impl WebhookNotices {
    /// A notifier for a whole roster (`screen.operators`, or the single implicit operator the config
    /// folds into it), announcing answers under `respond_base`.
    ///
    /// A repeated name keeps the first webhook and an operator with a blank name or a blank URL is
    /// left out. The config has already dropped those rows — this repeats the rule because the
    /// routing table is where a duplicate would actually do harm, and a constructor that trusted its
    /// input to be tidy is one refactor away from a person's questions going to two phones.
    pub fn new(operators: &[ChallengeOperator], respond_base: String) -> Arc<Self> {
        let mut routes: Vec<Route> = Vec::new();
        for operator in operators {
            let name = operator.name.trim();
            if name.is_empty() || routes.iter().any(|route| route.name == name) {
                continue;
            }
            let Some(push_url) = operator
                .push_url
                .as_deref()
                .map(str::trim)
                .filter(|url| !url.is_empty())
            else {
                continue;
            };
            routes.push(Route {
                name: name.to_string(),
                push_url: push_url.to_string(),
            });
        }
        Arc::new(Self {
            routes,
            respond_base,
        })
    }

    /// The channel that reaches `operator`, or `None` when they have none.
    ///
    /// The one place a name becomes a URL, which is why a challenge addressed to a person can never
    /// be delivered to somebody else: there is no argument here for "whoever" to get wrong.
    fn route_for(&self, operator: &str) -> Option<&str> {
        self.routes
            .iter()
            .find(|route| route.name == operator)
            .map(|route| route.push_url.as_str())
    }

    /// The notice as it goes on the wire, for one challenge and one token.
    ///
    /// Built separately from the send so a test can pin the shape — the token inside `respond_url`,
    /// the deep link, the addressee — without a socket, which is the same reason
    /// [`crate::phone::PushPayload`] is built where it is.
    pub fn notice(
        &self,
        challenge: &ChallengeSummary,
        token: &NoticeToken,
    ) -> ChallengeNotice {
        ChallengeNotice {
            kind: "challenge",
            id: challenge.id.clone(),
            screen: challenge.screen.clone(),
            session: challenge.session.clone(),
            url: challenge.url.clone(),
            reason: challenge.reason.clone(),
            seconds_left: challenge.seconds_left,
            operator: challenge.operator.clone(),
            page_url: format!("{}/#screen={}", self.respond_base, challenge.screen),
            respond_url: format!(
                "{}/v1/challenges/{}?token={}",
                self.respond_base,
                challenge.id,
                token.as_str()
            ),
        }
    }

    /// The resolution as it goes on the wire.
    pub fn resolution(
        &self,
        challenge: &ChallengeSummary,
        outcome: &Outcome,
    ) -> ChallengeResolved {
        ChallengeResolved {
            kind: "challenge_resolved",
            id: challenge.id.clone(),
            screen: challenge.screen.clone(),
            session: challenge.session.clone(),
            operator: challenge.operator.clone(),
            outcome: outcome.label().to_string(),
            note: outcome.note(),
        }
    }
}

impl ChallengeNotices for WebhookNotices {
    fn announce(&self, challenge: &ChallengeSummary, token: &NoticeToken) {
        let Some(push_url) = self.route_for(&challenge.operator) else {
            // Debug, not warn: an operator who configured no `push_url` has not failed, they have
            // said where they can be reached, and the answer is the daemon's page. The listing carries
            // the honest "nobody was told", which is where a person looks.
            tracing::debug!(
                challenge = %challenge.id,
                operator = %challenge.operator,
                "this operator has no push_url of their own; the challenge is only on the daemon's                  page for them"
            );
            return;
        };
        let payload = self.notice(challenge, token);
        tracing::debug!(
            challenge = %challenge.id,
            operator = %payload.operator,
            url = %SanitizedUrl(push_url),
            "pushing a challenge to the operator's own webhook"
        );
        push(push_url.to_string(), payload, "challenge");
    }

    fn resolved(&self, challenge: &ChallengeSummary, outcome: &Outcome) {
        // The same lookup, and for the same reason: a person told to hurry is the person who has to
        // be told it stopped, and a roster means "that person" is a routing decision rather than a
        // constant. Nobody else hears about it.
        let Some(push_url) = self.route_for(&challenge.operator) else {
            return;
        };
        let payload = self.resolution(challenge, outcome);
        tracing::debug!(
            challenge = %challenge.id,
            outcome = %payload.outcome,
            url = %SanitizedUrl(push_url),
            "pushing a challenge's resolution to the operator's own webhook"
        );
        push(push_url.to_string(), payload, "challenge resolution");
    }

    fn reaches(&self, operator: &str) -> bool {
        self.route_for(operator).is_some()
    }

    fn reachable(&self) -> bool {
        !self.routes.is_empty()
    }
}

/// POST a payload on a spawned task, logging a failure and dropping it.
///
/// Spawned because the fetch must not wait for a relay, and logged because a push that quietly never
/// arrived is the same silent failure this module exists to remove.
///
/// A push with **no runtime to run on** is dropped rather than a panic: one of the two callers is
/// [`crate::pane::PaneGuard`]'s `Drop`, which runs when the rung's budget expires or the fetch is
/// cancelled — including during a daemon's own shutdown. `tokio::spawn` there would panic from inside
/// a `Drop`, and a lost notification is the correct thing to lose: the fetch is over either way.
fn push<T: Serialize + Send + Sync + 'static>(push_url: String, payload: T, what: &'static str) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::debug!(
            what,
            url = %SanitizedUrl(&push_url),
            "no runtime to push on; the notification is dropped"
        );
        return;
    };
    handle.spawn(async move {
        match crate::phone::post_payload(&push_url, &payload).await {
            Ok(()) => {}
            Err(err) => {
                tracing::warn!(
                    what,
                    url = %SanitizedUrl(&push_url),
                    error = %err,
                    "the challenge push failed; the question is still on the daemon's page"
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary() -> ChallengeSummary {
        ChallengeSummary {
            id: "chal-1".to_string(),
            screen: "chal-1".to_string(),
            session: "browser_abc".to_string(),
            url: "https://example.test/verify".to_string(),
            reason: "the automated rungs could not clear the site's challenge".to_string(),
            seconds_left: 42,
            operator: "yoav".to_string(),
            notified: true,
        }
    }

    /// The same question, addressed to somebody else — the only field routing turns on.
    fn summary_for(operator: &str) -> ChallengeSummary {
        ChallengeSummary {
            operator: operator.to_string(),
            ..summary()
        }
    }

    /// One person with a channel of their own.
    fn operator(name: &str, push_url: &str) -> ChallengeOperator {
        ChallengeOperator {
            name: name.to_string(),
            push_url: Some(push_url.to_string()),
        }
    }

    /// A person the daemon can address but not ring.
    fn silent(name: &str) -> ChallengeOperator {
        ChallengeOperator {
            name: name.to_string(),
            push_url: None,
        }
    }

    #[test]
    fn the_notice_says_whose_question_it_is_and_how_to_answer_it() {
        let notices = WebhookNotices::new(
            &[operator("yoav", "https://relay.test/hook")],
            "https://daemon.test".to_string(),
        );
        let token = NoticeToken::new();
        let notice = notices.notice(&summary(), &token);

        assert_eq!(notice.kind, "challenge", "a relay routes by this and nothing else");
        assert_eq!(notice.operator, "yoav", "addressed to a person, not to a page");
        assert_eq!(notice.session, "browser_abc");
        assert_eq!(notice.url, "https://example.test/verify");
        assert_eq!(notice.seconds_left, 42);
        assert_eq!(
            notice.page_url, "https://daemon.test/#screen=chal-1",
            "the deep link a person follows to *clear* the wall"
        );
        assert_eq!(
            notice.respond_url,
            format!(
                "https://daemon.test/v1/challenges/chal-1?token={}",
                token.as_str()
            ),
            "and the one-time URL that answers it without the daemon's bearer token"
        );

        // The same builder, for somebody else's question: the addressee is read off the challenge
        // rather than held by the notifier, so a payload cannot carry a name the pane did not pick.
        let other = notices.notice(&summary_for("dana"), &token);
        assert_eq!(other.operator, "dana", "{other:?}");
        assert_eq!(other.id, notice.id, "everything else is the same question");
        assert_eq!(
            notices.resolution(&summary_for("dana"), &Outcome::Solved).operator,
            "dana",
            "and so is the resolution, which is a separate payload built the same way"
        );
    }

    #[test]
    fn a_challenge_goes_to_the_channel_of_the_person_it_names_and_nobody_elses() {
        // The claim the roster exists to make. Two people, two webhooks, and the only thing that
        // decides where a push lands is the name the challenge carries — so "somebody else's relay"
        // is not a state this can be in.
        let notices = WebhookNotices::new(
            &[
                operator("yoav", "https://relay.test/yoav"),
                operator("dana", "https://relay.test/dana"),
            ],
            "https://daemon.test".to_string(),
        );

        assert_eq!(
            notices.route_for("dana"),
            Some("https://relay.test/dana"),
            "the second person's challenge goes to the second person's webhook"
        );
        assert_eq!(
            notices.route_for("yoav"),
            Some("https://relay.test/yoav"),
            "and the first person's to the first person's, not to whichever is listed first"
        );
        assert_eq!(
            notices.route_for("sam"),
            None,
            "and a name that is not on the roster is not a channel to guess at"
        );

        // Both are reachable, so neither challenge is a silent one.
        assert!(notices.reachable());
        assert!(notices.reaches("yoav"));
        assert!(notices.reaches("dana"));
        assert!(!notices.reaches("sam"));
    }

    #[test]
    fn one_operator_having_a_channel_does_not_make_the_others_reachable() {
        // A roster is allowed to mix the two, and the listing's `notified` is per person. If it were
        // a daemon-level flag, a challenge addressed to the silent half of a roster would claim
        // somebody was told when nobody was.
        let notices = WebhookNotices::new(
            &[operator("yoav", "https://relay.test/yoav"), silent("dana")],
            "https://daemon.test".to_string(),
        );

        assert!(
            notices.reachable(),
            "one of them can be rung, so the daemon is not mute"
        );
        assert!(notices.reaches("yoav"));
        assert!(
            !notices.reaches("dana"),
            "and the person with no webhook of their own is exactly as told as they would be on a              daemon with nobody configured"
        );
        assert_eq!(notices.route_for("dana"), None);

        // The reverse case is the interesting one: a roster where *nobody* has a channel must not
        // report itself as reachable, or the page would claim someone was told.
        let muted = WebhookNotices::new(
            &[
                ChallengeOperator {
                    name: String::new(),
                    push_url: None,
                },
                operator("yoav", ""),
            ],
            "https://daemon.test".to_string(),
        );
        assert!(!muted.reachable(), "{muted:?}");
        assert!(!muted.reaches("yoav"));
    }

    #[test]
    fn a_repeated_name_would_ring_twice_so_the_first_channel_wins() {
        // The config collapses these, and so does the constructor: the routing table is where a
        // duplicate would actually send one person's questions to two phones, and a `Debug` is the
        // first thing anybody pastes into a bug report.
        let notices = WebhookNotices::new(
            &[
                operator("yoav", "https://relay.test/first"),
                operator("yoav", "https://relay.test/second"),
                operator("dana", "https://relay.test/dana"),
            ],
            "https://daemon.test".to_string(),
        );
        assert_eq!(notices.route_for("yoav"), Some("https://relay.test/first"));
        assert_eq!(notices.routes.len(), 2, "and the table holds two people, not three rows");

        // Every webhook is redacted in a `Debug`, because a relay URL is a credential for somebody's
        // chat room far more often than it is a public address.
        let printed = format!("{notices:?}");
        for url in [
            "https://relay.test/first",
            "https://relay.test/second",
            "https://relay.test/dana",
        ] {
            assert!(!printed.contains(url), "{url} leaked into {printed}");
        }
        assert!(printed.contains("yoav"), "the names are identifiers, and are worth logging: {printed}");
    }

    #[test]
    fn the_token_reaches_the_wire_and_never_a_log_line() {
        // The token has exactly one home: inside `respond_url`. If it also appeared in `Debug`, a
        // single `tracing::debug!(?payload)` would put a live credential in a log file — which is the
        // failure `crate::phone`'s manual `Debug` exists to prevent, restated here because this
        // module mints its own secret rather than reusing that one.
        let notices = WebhookNotices::new(&[], "https://daemon.test".to_string());
        let token = NoticeToken::new();
        let printed = format!("{:?}", notices.notice(&summary(), &token));

        assert!(!printed.contains(token.as_str()), "{printed}");
        assert!(!printed.contains("token="), "{printed}");
        assert!(
            printed.contains("https://daemon.test/v1/challenges/chal-1"),
            "the URL that is left is the one worth logging: {printed}"
        );
        assert_eq!(format!("{token}"), "<redacted>");
        assert_eq!(format!("{token:?}"), "NoticeToken(<redacted>)");

        // And the resolution, which carries a person's own words rather than a secret, is still
        // bounded by what it prints.
        let done = notices.resolution(
            &summary(),
            &Outcome::Abandoned {
                note: "not solving a CAPTCHA for a scraper".to_string(),
            },
        );
        assert_eq!(done.kind, "challenge_resolved");
        assert_eq!(done.outcome, "abandoned");
        assert_eq!(done.note, "not solving a CAPTCHA for a scraper");
    }

    #[test]
    fn a_daemon_with_no_webhook_cannot_reach_anyone_and_says_so() {
        // The state, not an absence: the pane reports it into the listing, so a person reading the
        // page knows they are the only chance the run has.
        let nobody = WebhookNotices::new(&[], "http://127.0.0.1:7721".to_string());
        assert!(!nobody.reachable());
        assert!(!nobody.reaches("yoav"), "and there is no one to reach, by name or otherwise");

        let blank = WebhookNotices::new(
            &[operator("yoav", "   ")],
            "http://127.0.0.1:7721".to_string(),
        );
        assert!(
            !blank.reachable(),
            "a webhook an operator left blank is an operator who configured nothing"
        );

        let named = WebhookNotices::new(
            &[operator("yoav", "https://relay.test/hook")],
            "http://127.0.0.1:7721".to_string(),
        );
        assert!(named.reachable());
        assert!(named.reaches("yoav"));
    }

    #[test]
    fn every_outcome_has_a_word_for_the_notification() {
        assert_eq!(Outcome::Solved.label(), "solved");
        assert_eq!(Outcome::Withdrawn.label(), "withdrawn");
        assert_eq!(Outcome::Solved.note(), "", "nothing a person wrote to quote");
        assert_eq!(
            Outcome::Abandoned {
                note: "no thanks".to_string()
            }
            .note(),
            "no thanks"
        );
    }
}

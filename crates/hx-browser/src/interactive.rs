//! The human-in-the-loop escalation contract.
//!
//! The last rung of the ladder is a person. This module is the *interface* to one — what a pane
//! receives, what it returns, what happens when it does not answer — and the rung that fails closed
//! when there is no pane at all. There is deliberately no browser UI here.
//!
//! ## The contract, in full
//!
//! **What the pane receives.** One [`HumanChallenge`]: an id to correlate its own UI and logs, the
//! session, the site in *redacted* form, the profile directory its browser must be pointed at, why
//! the automated rungs gave up, and the budget it has. The profile directory is the session's own —
//! a pane that opened a browser profile of its own choosing would silently break the isolation the
//! whole pool is built on, so the pane is *given* the path rather than left to pick one.
//!
//! **What the pane returns.** [`HumanOutcome::Solved`] when the wall is cleared — a login made, a
//! CAPTCHA answered by a person, a consent page accepted — or [`HumanOutcome::Abandoned`] with a
//! note when the person declines. A pane that obtained a cookie for the non-browser rung may record
//! it with [`crate::profile::SessionProfile::write_cookies`], which is how the two halves of the ladder hand a
//! cleared session to each other; anything a browser keeps goes in the profile directory, where the
//! browser puts it.
//!
//! **What happens on a timeout.** The *rung* enforces the budget, not the pane. When it expires the
//! pane's future is dropped and the attempt ends as [`FetchError::Interactive`] naming the budget.
//! Two consequences the contract asks of an implementation: `present` must be **cancellable** — a
//! pane that holds a lock, or spawns a task it never joins, across an unbounded wait makes the
//! budget meaningless — and a pane that answers *after* the drop is answering nobody. Nothing waits
//! for a person indefinitely, and nothing hangs: that is the property the tests below pin.
//!
//! **Absence fails closed.** With no pane attached, the rung does not wait, does not retry and does
//! not invent a result: it returns [`FetchError::Unavailable`], which the ladder reports and moves
//! past. The alternative — a pane-shaped hole that silently blocks until a human appears — is how a
//! research task ends up hanging for an afternoon.
//!
//! ## What is deliberately NOT built
//!
//! No pane, and no CDP driver. The rung is present and fail-closed, and a person clearing a
//! challenge leaves the cleared session in the profile — but reading the page afterwards needs a
//! browser under this crate's control, which does not exist yet, so a `Solved` outcome ends the rung
//! with a reason that says exactly that rather than pretending to have the page. Building the driver
//! is the next step, not a hidden gap.

use crate::error::{FetchError, RefusalReason};
use crate::rung::{FetchRequest, Fetcher, RungKind, UntrustedPage};
use async_trait::async_trait;
use hx_core::ids::SessionId;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How long a person is given, unless a caller says otherwise.
///
/// Five minutes: long enough to log in somewhere and answer a challenge, short enough that a
/// forgotten challenge does not hold a session open for an afternoon.
pub const DEFAULT_HUMAN_BUDGET: Duration = Duration::from_secs(300);

/// What a human pane is handed when a fetch needs a person.
#[derive(Clone, Debug)]
pub struct HumanChallenge {
    /// Identifies this challenge so a pane's UI and its logs can be correlated.
    ///
    /// Unique within the process, and **not** a security token: it is a label, minted from a
    /// counter, and nothing should be authorised by knowing it.
    pub id: String,

    /// The session being helped. Shown to the person so they know which task they are unblocking.
    pub session: SessionId,

    /// The site, in **redacted** form. Never the query string: a challenge URL routinely carries a
    /// return-to token, and a pane is exactly the sort of place a URL gets logged or screenshotted.
    pub url: String,

    /// The profile directory the person's browser must be pointed at.
    ///
    /// The *session's* profile, so a login or a cleared challenge stays with that session and reaches
    /// no other. See [`crate::profile`].
    pub profile_dir: PathBuf,

    /// Why the automated rungs gave up, in the rungs' own words — a challenge marker, a status, a
    /// missing browser. A pane can show it, and a person can decide whether the site is worth
    /// helping with.
    pub reason: String,

    /// How long the person has. The pane should show a countdown; the rung enforces the same budget
    /// and abandons the challenge when it expires, whether or not the pane noticed.
    pub budget: Duration,
}

/// What the person did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HumanOutcome {
    /// The wall is cleared. The session's profile now holds whatever the site granted.
    Solved,

    /// The person declined, or the site asked for something this harness will not do.
    ///
    /// The note reaches the report, so *"I am not solving a CAPTCHA for a scraper"* is recorded as
    /// the reason rather than as a mystery.
    Abandoned { note: String },
}

/// Why a pane could not do its job.
#[derive(Debug, thiserror::Error)]
pub enum PaneError {
    #[error("no human pane is attached")]
    NotAttached,

    #[error("the pane failed: {0}")]
    Failed(String),
}

/// The surface a human-in-the-loop browser pane plugs into.
///
/// The contract is in this module's documentation: what [`present`](HumanPane::present) receives,
/// what it returns, and why it must be cancellable.
#[async_trait]
pub trait HumanPane: Send + Sync {
    /// A stable name for reports — `"no-pane"`, `"tui-browser"`. Must not contain a URL or a
    /// credential: this string reaches a model.
    fn name(&self) -> &str;

    /// Present a challenge and wait for the person.
    ///
    /// **Must be cancellable.** The caller drops this future when the budget expires; a pane that
    /// holds a lock or spawns an unjoined task across an unbounded wait makes the budget
    /// meaningless, and a fetch that never returns.
    async fn present(&self, challenge: HumanChallenge) -> Result<HumanOutcome, PaneError>;
}

/// The pane that is not there.
///
/// Presenting anything is an error, so a rung wired with no pane fails closed instead of waiting for
/// a person who will never arrive. This is the default, and it is the default on purpose.
#[derive(Debug, Default)]
pub struct NoPane;

#[async_trait]
impl HumanPane for NoPane {
    fn name(&self) -> &str {
        "no-pane"
    }

    async fn present(&self, _challenge: HumanChallenge) -> Result<HumanOutcome, PaneError> {
        Err(PaneError::NotAttached)
    }
}

/// The interactive rung: hand the wall to a person, and fail closed when there is no person.
pub struct InteractiveFetcher {
    pane: Option<Arc<dyn HumanPane>>,
    budget: Duration,
}

impl InteractiveFetcher {
    /// The fail-closed rung: no pane, so every fetch ends as unavailable.
    ///
    /// This is the constructor a daemon with no browser UI should use, and the reason it exists is
    /// that the alternative default — a rung that waits — is the one that hangs.
    pub fn unattached() -> Self {
        Self {
            pane: None,
            budget: DEFAULT_HUMAN_BUDGET,
        }
    }

    /// The rung with a pane behind it.
    pub fn with_pane(pane: Arc<dyn HumanPane>, budget: Duration) -> Self {
        Self {
            pane: Some(pane),
            budget,
        }
    }

    /// How long a person is given.
    pub fn budget(&self) -> Duration {
        self.budget
    }
}

impl std::fmt::Debug for InteractiveFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InteractiveFetcher")
            .field("attached", &self.pane.is_some())
            .field("budget", &self.budget)
            .finish()
    }
}

#[async_trait]
impl Fetcher for InteractiveFetcher {
    fn kind(&self) -> RungKind {
        RungKind::Interactive
    }

    fn name(&self) -> &str {
        "interactive-cdp"
    }

    async fn fetch(&self, request: &FetchRequest) -> Result<UntrustedPage, FetchError> {
        let Some(pane) = &self.pane else {
            return Err(FetchError::Unavailable {
                rung: RungKind::Interactive,
                reason: "no human pane is attached, so the interactive rung fails closed rather \
                         than waiting for a person who will never arrive"
                    .to_string(),
            });
        };

        let challenge = HumanChallenge {
            id: next_challenge_id(),
            session: request.profile.session_id().clone(),
            url: request.target.redacted(),
            profile_dir: request.profile.dir().to_path_buf(),
            reason: describe_refusal(),
            budget: self.budget,
        };

        // The deadline is enforced *here*, not by the pane: a pane that ignores its budget must not
        // be able to hold a session's fetch open. Dropping the future is the cancellation the
        // contract asks a pane to survive.
        match tokio::time::timeout(self.budget, pane.present(challenge)).await {
            Ok(Ok(HumanOutcome::Solved)) => Err(FetchError::Interactive {
                reason: format!(
                    "{} cleared the challenge; the session's profile is now unblocked, so re-run \
                     the ladder in this session. The interactive rung does not read the page itself: \
                     no CDP driver is wired yet",
                    pane.name()
                ),
            }),

            Ok(Ok(HumanOutcome::Abandoned { note })) => Err(FetchError::Interactive {
                reason: format!("{} abandoned the challenge: {note}", pane.name()),
            }),

            Ok(Err(PaneError::NotAttached)) => Err(FetchError::Unavailable {
                rung: RungKind::Interactive,
                reason: format!("{} reports no pane is attached", pane.name()),
            }),

            Ok(Err(PaneError::Failed(why))) => Err(FetchError::Interactive {
                reason: format!("{} failed: {why}", pane.name()),
            }),

            Err(_elapsed) => Err(FetchError::Interactive {
                reason: format!(
                    "nobody answered within {}s, so the challenge was abandoned",
                    self.budget.as_secs_f64()
                ),
            }),
        }
    }
}

/// What the pane is told about why it is being asked.
///
/// A constant rather than the real chain of failures: the rung is handed one request and not the
/// ladder's history, and the report — which does carry every attempt — is what a caller reads to see
/// the chain. Saying so here rather than inventing a plausible chain is the honest version.
fn describe_refusal() -> String {
    format!(
        "the automated rungs could not clear the site's challenge ({})",
        RefusalReason::Challenge {
            marker: "a challenge page or a bot wall".to_string()
        }
    )
}

/// A label unique within the process. A counter is enough for a UI to correlate with, and a random
/// id would invite someone to treat it as a capability.
static CHALLENGE_SEQ: AtomicUsize = AtomicUsize::new(0);

fn next_challenge_id() -> String {
    format!("chal-{}", CHALLENGE_SEQ.fetch_add(1, Ordering::Relaxed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{PoolRoot, SessionProfile};
    use crate::target::{Admission, TargetUrl};
    use std::sync::Mutex;

    struct Fixture {
        _temp: tempfile::TempDir,
        root: PoolRoot,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("a temp directory");
            let root = PoolRoot::new(temp.path().join("pool")).expect("a pool root");
            Self { _temp: temp, root }
        }

        fn profile(&self, name: &str) -> Arc<SessionProfile> {
            Arc::new(
                self.root
                    .session(&SessionId::from_raw(name))
                    .expect("a session profile"),
            )
        }

        /// A request aimed at a loopback stub, which is what the hermetic suite uses.
        fn request(&self, profile: Arc<SessionProfile>) -> FetchRequest {
            FetchRequest {
                target: TargetUrl::parse_with(
                    Admission::AllowLocal,
                    "http://127.0.0.1:9/x?token=SECRETVALUE",
                )
                .expect("a loopback target under AllowLocal"),
                profile,
                timeout: Duration::from_secs(5),
            }
        }
    }

    /// A pane that records what it was handed and answers however the test says.
    struct RecordingPane {
        answer: Answer,
        seen: Mutex<Option<HumanChallenge>>,
    }

    enum Answer {
        Solved,
        Abandoned(&'static str),
        Failed(&'static str),
        Never,
    }

    impl RecordingPane {
        fn new(answer: Answer) -> Arc<Self> {
            Arc::new(Self {
                answer,
                seen: Mutex::new(None),
            })
        }

        fn seen(&self) -> HumanChallenge {
            self.seen
                .lock()
                .expect("the seen lock")
                .clone()
                .expect("the pane was presented with a challenge")
        }
    }

    #[async_trait]
    impl HumanPane for RecordingPane {
        fn name(&self) -> &str {
            "recording-pane"
        }

        async fn present(&self, challenge: HumanChallenge) -> Result<HumanOutcome, PaneError> {
            *self.seen.lock().expect("the seen lock") = Some(challenge);
            match self.answer {
                Answer::Solved => Ok(HumanOutcome::Solved),
                Answer::Abandoned(note) => Ok(HumanOutcome::Abandoned {
                    note: note.to_string(),
                }),
                Answer::Failed(why) => Err(PaneError::Failed(why.to_string())),
                // Never resolves. Only the rung's budget can end this, which is the point.
                Answer::Never => std::future::pending().await,
            }
        }
    }

    fn rung_with(pane: Arc<dyn HumanPane>, budget: Duration) -> InteractiveFetcher {
        InteractiveFetcher::with_pane(pane, budget)
    }

    // ---------------------------------------------------------------------------------
    // Absence fails closed
    // ---------------------------------------------------------------------------------

    #[tokio::test]
    async fn the_interactive_rung_fails_closed_when_no_pane_is_attached() {
        // The default a daemon with no browser UI gets. It must not wait, retry, or invent a result.
        let fixture = Fixture::new();
        let err = InteractiveFetcher::unattached()
            .fetch(&fixture.request(fixture.profile("ses_one")))
            .await
            .expect_err("no pane means no page");

        match &err {
            FetchError::Unavailable { rung, reason } => {
                assert_eq!(*rung, RungKind::Interactive);
                assert!(reason.contains("no human pane is attached"), "{reason}");
            }
            other => panic!("expected an unavailable rung, got {other:?}"),
        }
        // The ladder reports the gap and moves on rather than stopping the fetch outright.
        assert_eq!(err.disposition(), crate::error::Disposition::Escalate);
    }

    #[tokio::test]
    async fn a_pane_that_reports_itself_absent_is_the_same_as_having_none() {
        let fixture = Fixture::new();
        let pane = Arc::new(NoPane);
        let err = rung_with(pane, Duration::from_millis(50))
            .fetch(&fixture.request(fixture.profile("ses_one")))
            .await
            .expect_err("an absent pane means no page");

        assert!(matches!(err, FetchError::Unavailable { .. }), "{err:?}");
        assert!(err.to_string().contains("no pane is attached"), "{err}");
    }

    // ---------------------------------------------------------------------------------
    // Nothing hangs
    // ---------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_pane_that_never_answers_is_abandoned_on_the_budget_rather_than_hanging() {
        // The property the whole rung exists for. The outer timeout is the assertion: if the rung's
        // own budget did not fire, the outer one would, and the error would not be `Interactive`.
        let fixture = Fixture::new();
        let pane = RecordingPane::new(Answer::Never);
        let rung = rung_with(pane, Duration::from_millis(50));

        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            rung.fetch(&fixture.request(fixture.profile("ses_one"))),
        )
        .await
        .expect("the rung must return within its own budget, not hang until the caller gives up");

        let err = outcome.expect_err("a person who never answers means no page");
        assert!(err.to_string().contains("nobody answered within"), "{err}");
        assert!(
            err.to_string().contains("0.05s"),
            "the message must name the budget that expired: {err}"
        );
    }

    #[tokio::test]
    async fn the_budget_the_pane_is_told_is_the_budget_the_rung_enforces() {
        // A pane that shows a countdown and a rung that enforces something else would disagree in
        // the one direction that matters: the person would be mid-answer when it was abandoned.
        let fixture = Fixture::new();
        let pane = RecordingPane::new(Answer::Never);
        let budget = Duration::from_millis(40);
        let rung = rung_with(pane.clone(), budget);

        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            rung.fetch(&fixture.request(fixture.profile("ses_one"))),
        )
        .await;

        assert_eq!(pane.seen().budget, budget);
        assert_eq!(rung.budget(), budget);
    }

    // ---------------------------------------------------------------------------------
    // What the pane is handed
    // ---------------------------------------------------------------------------------

    #[tokio::test]
    async fn the_challenge_carries_the_sessions_own_profile_and_a_redacted_url() {
        let fixture = Fixture::new();
        let profile = fixture.profile("ses_help");
        let pane = RecordingPane::new(Answer::Solved);

        let _ = rung_with(pane.clone(), Duration::from_millis(50))
            .fetch(&fixture.request(Arc::clone(&profile)))
            .await;

        let seen = pane.seen();
        assert_eq!(
            seen.profile_dir,
            profile.dir(),
            "the pane must drive the session's own profile, or the isolation is broken by the pane"
        );
        assert_eq!(&seen.session, profile.session_id());
        assert_eq!(seen.url, "http://127.0.0.1:9/x");
        assert!(
            !seen.url.contains("SECRETVALUE"),
            "a challenge URL carries a return-to token; the pane must not be handed one: {}",
            seen.url
        );
        assert!(!seen.id.is_empty());
        assert!(seen.reason.contains("challenge"), "{}", seen.reason);
    }

    #[tokio::test]
    async fn two_challenges_get_distinct_ids() {
        // A pane's UI needs to tell one request apart from the next.
        let fixture = Fixture::new();
        let pane = RecordingPane::new(Answer::Solved);
        let rung = rung_with(pane.clone(), Duration::from_millis(50));
        let request = fixture.request(fixture.profile("ses_one"));

        let _ = rung.fetch(&request).await;
        let first = pane.seen().id;
        let _ = rung.fetch(&request).await;
        let second = pane.seen().id;

        assert_ne!(first, second);
    }

    // ---------------------------------------------------------------------------------
    // What the person did
    // ---------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_person_who_clears_the_challenge_ends_the_rung_by_saying_what_to_do_next() {
        // No CDP driver exists yet, so the rung cannot read the page a person just unblocked. It
        // says so, rather than returning an empty page or a success that means nothing.
        let fixture = Fixture::new();
        let pane = RecordingPane::new(Answer::Solved);
        let err = rung_with(pane, Duration::from_millis(50))
            .fetch(&fixture.request(fixture.profile("ses_one")))
            .await
            .expect_err("no driver, so no page");

        assert!(err.to_string().contains("cleared the challenge"), "{err}");
        assert!(err.to_string().contains("re-run the ladder"), "{err}");
        assert!(err.to_string().contains("no CDP driver"), "{err}");
        assert_eq!(err.disposition(), crate::error::Disposition::Stop);
    }

    #[tokio::test]
    async fn a_person_who_declines_is_recorded_with_their_own_note() {
        let fixture = Fixture::new();
        let pane = RecordingPane::new(Answer::Abandoned("not solving a CAPTCHA for a scraper"));
        let err = rung_with(pane, Duration::from_millis(50))
            .fetch(&fixture.request(fixture.profile("ses_one")))
            .await
            .expect_err("a declined challenge means no page");

        assert!(
            err.to_string()
                .contains("not solving a CAPTCHA for a scraper"),
            "{err}"
        );
        assert_eq!(err.disposition(), crate::error::Disposition::Stop);
    }

    #[tokio::test]
    async fn a_pane_that_errors_is_reported_rather_than_swallowed() {
        let fixture = Fixture::new();
        let pane = RecordingPane::new(Answer::Failed("the terminal was closed"));
        let err = rung_with(pane, Duration::from_millis(50))
            .fetch(&fixture.request(fixture.profile("ses_one")))
            .await
            .expect_err("a failed pane means no page");

        assert!(err.to_string().contains("the terminal was closed"), "{err}");
        assert!(err.to_string().contains("recording-pane"), "{err}");
    }

    #[tokio::test]
    async fn the_rung_identifies_itself_as_the_last_one() {
        let rung = InteractiveFetcher::unattached();
        assert_eq!(rung.kind(), RungKind::Interactive);
        assert_eq!(rung.name(), "interactive-cdp");
        assert_eq!(rung.budget(), DEFAULT_HUMAN_BUDGET);
        // `Debug` says whether a pane is attached and nothing about its internals.
        assert!(format!("{rung:?}").contains("attached: false"));
    }
}

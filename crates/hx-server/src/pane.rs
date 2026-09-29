//! The human in the loop: the daemon's screen pane standing behind `hx-browser`'s interactive rung.
//!
//! ## The loop this closes
//!
//! `hx-browser`'s ladder ends with a person. The plain-HTTP rung is refused, the Chromium rung is
//! refused, and the third rung hands the wall to a [`HumanPane`] — what a person is shown, what they
//! return, and why a pane must be cancellable are all stated in `crates/hx-browser/src/interactive.rs`
//! and not repeated here. What was missing is on this side: the only implementation of that trait was
//! `NoPane`, the pane that is not there, so a climb that needed a person failed closed and nobody was
//! ever asked. This module is the pane, and it is built out of the screen the daemon already owns: a
//! real browser, streamed frame by frame to the web client's `screen` pane, with the watcher's clicks
//! and keystrokes going back up. A person clears the wall *in the browser the daemon is showing them*,
//! which is the same session the ladder will re-run in.
//!
//! ## Who owns what
//!
//! The browser is the daemon's, for the reason [`crate::screen`] gives: it outlives the tab watching
//! it, so a person who reloads mid-login is looking at the same browser rather than at a new one. The
//! *challenge* is this module's: it exists exactly while someone is waiting for an answer, and the
//! `hx-browser` rung owns the deadline. Three consequences, and they are the whole design:
//!
//! - **The profile is the challenge's, not the pane's.** The pane is handed the session's own profile
//!   directory and points the browser at it. A pane that chose its own would look identical and break
//!   the isolation the pool is built on: a login made in a profile of the pane's choosing is one the
//!   session's later fetches never see.
//! - **The URL is redacted, and a person still needs to get to the site.** The contract hands over the
//!   page without its query string, because a challenge URL routinely carries a return-to token. The
//!   pane opens that redacted address and the person navigates from it; query strings are state, not
//!   address, and in practice the redacted URL is the challenge page itself.
//! - **Nobody is waited for forever.** The rung's budget is enforced by the rung: when it expires the
//!   `present` future is dropped mid-`await`, and [`PaneGuard`] is what turns that drop into a
//!   withdrawn challenge and a browser that is gone.
//!
//! ## Why the cleanup does not spawn a task
//!
//! Dropping the future is the *cancellation* the contract asks a pane to survive, and it arrives at a
//! `Drop`, where nothing can be awaited. The obvious shape — take a runtime handle and spawn the
//! close — is wrong twice over: `Handle::spawn` panics on a runtime that is shutting down (which is
//! exactly when a daemon tears a fetch down), and it leaves the browser's death for someone who may
//! never be scheduled. So [`ScreenHost`] exposes a **synchronous** `forget`, and the browser dies
//! because dropping the last handle to a screen kills its child — `ScreenSource`'s own `Drop` sends
//! the kill and `kill_on_drop` guarantees it. The pane hands the id back and is done.
//!
//! ## Addressed to a person, and they are told
//!
//! A question for one person should be delivered to that person rather than put on a noticeboard. Each
//! challenge names its operator and the pane hands it to a [`ChallengeNotices`] the moment it is
//! presented, which is what pushes it to that operator's own channel with a **one-time token** so the
//! notification itself can answer without carrying the daemon's master credential. That module —
//! [`crate::challenge_notice`] — holds the wire shapes, the token and the fire-and-forget rule; what
//! this module owns is the *sequencing*: the question is announced after it is registered (so an
//! announcement can never name a challenge nobody can answer), the token is minted by the registry
//! (one per challenge, so two announcements cannot disagree), and a resolution is pushed on every way
//! the wait can end, including the `Drop` path where nothing can be awaited.
//!
//! ## Which person, when there are several
//!
//! A daemon can have more than one operator (`screen.operators`, each with their own webhook), and
//! then *someone* has to decide which of them a given run interrupts. The pane is that decision, and
//! it is the simplest one that keeps the promise above intact: **rotate**. Each challenge is
//! addressed to the next name in the roster, and to exactly one of them, so two runs in a row do not
//! land on the same phone and a challenge is never pushed to somebody who was not named on it.
//!
//! The alternatives were worse, and worth recording. Broadcasting to all of them would make "addressed
//! to a person" a lie — the name would be a decoration on a page-wide announcement — and would race:
//! every resolution would go to N phones, N−1 of which are told about a run they could not have
//! helped. Weighting by anything real (who asked, which session, who is logged in) needs a fact this
//! daemon does not have; rotation needs only the roster, is deterministic, and — because the roster is
//! never empty — cannot leave a run unaddressed. It is also the only one a reader can predict from
//! the config alone: a daemon with two operators always asks yoav, then dana, then yoav again.
//!
//! The cursor is a counter on the pane, not on the config ([`PaneOptions::next_operator`]): a
//! config that advanced would make the operator depend on how many times it had been re-read.
//!
//! ## Deliberately not built
//!
//! A challenge reaches the operator's own notification channel, but it is not routed back to the chat
//! its session arrived on: the daemon does not know which chat a run came from. The screen is not
//! behind the ladder's admission (see `crates/hx-browser/src/screen.rs`), and a challenge is not a
//! *permission* — it is a person clearing a wall the site put up, and it grants nothing the session
//! could not already do. Neither is a challenge answerable *from* the notification: clearing a wall
//! means driving the screen, and the token can only report that a person did.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use hx_browser::screen::{ScreenOptions, BROWSER_SCREEN_STARTUP_TIMEOUT};
use hx_browser::{HumanChallenge, HumanOutcome, HumanPane, PaneError};
use hx_core::config::{ChallengeOperator, Config};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::challenge_notice::{ChallengeNotices, NoticeToken, Outcome};
use crate::screen::Screens;

/// How the pane launches its browsers, from `screen` in the config.
///
/// The same viewport and quality a client-requested screen gets, because a person clearing a
/// challenge is doing the same job a watcher is: looking at a page.
#[derive(Clone, Debug)]
pub struct PaneOptions {
    /// The browser binary, or `None` to search the platform's usual places.
    pub browser: Option<PathBuf>,
    pub width: u32,
    pub height: u32,
    pub quality: u8,
    /// Everyone a challenge may be addressed to, in the order they are asked. Resolved once, here, so
    /// the name on a listing and the name in a notification cannot be two readings of the config.
    /// Never empty — see [`Config::challenge_operators`].
    pub operators: Vec<ChallengeOperator>,
}

impl PaneOptions {
    /// The pane's launch options from the config: the `screen` section, plus the roster a challenge
    /// is addressed into.
    pub fn from_config(config: &Config) -> Self {
        Self {
            browser: config
                .screen
                .browser
                .as_deref()
                .map(str::trim)
                .filter(|path| !path.is_empty())
                .map(PathBuf::from),
            width: config.screen.width,
            height: config.screen.height,
            quality: config.screen.quality,
            operators: config.challenge_operators(),
        }
    }

    /// The operator the next challenge is for, advancing `cursor` by one.
    ///
    /// Wrapping rather than stopping at the end is the point: a roster of two that asked yoav, dana,
    /// and then nobody is a daemon that eventually stops telling anyone, which is the exact failure
    /// this path exists to remove. The modulo is on a length the config guarantees is non-zero, so
    /// there is no `None` case to handle at the one place that could not afford to.
    ///
    /// `Relaxed` is the right order here and the reason is not contention: the counter's only job is
    /// to hand out *different* names, and two fetches racing to present at once must not be given the
    /// same one. A relaxed increment still hands each of them a distinct value, which is all the
    /// rotation promises.
    fn next_operator(&self, cursor: &AtomicUsize) -> &ChallengeOperator {
        &self.operators[cursor.fetch_add(1, Ordering::Relaxed) % self.operators.len()]
    }

    /// The options for one challenge: the person's page, in the *session's* profile.
    fn for_challenge(&self, challenge: &HumanChallenge) -> ScreenOptions {
        ScreenOptions {
            browser: self.browser.clone(),
            url: challenge.url.clone(),
            user_data_dir: challenge.profile_dir.clone(),
            width: self.width,
            height: self.height,
            quality: self.quality,
            startup_timeout: BROWSER_SCREEN_STARTUP_TIMEOUT,
        }
    }
}

impl Default for PaneOptions {
    fn default() -> Self {
        Self::from_config(&Config::default())
    }
}

/// One challenge a person has been handed and has not answered.
///
/// What a client renders: which screen to look at, what is being asked, and how long is left. The
/// countdown comes from the daemon rather than being counted by a client, because the *rung* is what
/// enforces the budget — a client's own timer would drift from the deadline that actually ends the
/// wait, and would tell a person they had time when they did not.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChallengeSummary {
    /// The challenge's id, which is also its screen's id.
    pub id: String,
    /// The screen the person looks at: watch it, and clear the wall in it.
    pub screen: String,
    /// Which session is blocked on this, so a person knows what they are unblocking.
    pub session: String,
    /// The site, in redacted form — the contract's decision, passed through unchanged.
    pub url: String,
    /// Why the automated rungs gave up, in the rungs' own words.
    pub reason: String,
    /// Whole seconds until the rung abandons the wait, measured from now.
    pub seconds_left: u64,
    /// Who the question is for: the operator the pane picked out of `screen.operators` when it was
    /// presented. A client shows it, so a person can tell whose run is blocked before they get up —
    /// and, on a daemon with several operators, so the *wrong* person knows not to go.
    pub operator: String,
    /// Whether **this** operator was *told*: `true` when a notification went to their own channel,
    /// `false` when they configured no `push_url` and the page is the only place the question exists
    /// for them.
    ///
    /// Reported rather than inferred by a client, because the two states mean different things to the
    /// person reading the banner — *someone has this* versus *you are the only chance this run has*.
    pub notified: bool,
}

/// What a person did, on the wire.
///
/// `solved` clears the wall — a login made, a challenge answered, a consent page accepted — and
/// `abandoned` declines it, with the person's own note reaching the report. The note is the reason
/// `Abandoned` exists at all: *"I am not solving a CAPTCHA for a scraper"* should be recorded as a
/// decision rather than look like a mysterious failure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum AnswerBody {
    /// The wall is cleared.
    Solved,
    /// The person declined. An empty note is refused: "abandoned" with no reason is the mystery this
    /// variant exists to prevent.
    Abandoned { note: String },
}

impl AnswerBody {
    /// Whether this is a usable answer, and why not when it is not.
    ///
    /// Checked here rather than in the route so the rule lives with the body it constrains.
    pub fn check(&self) -> Result<(), String> {
        match self {
            Self::Solved => Ok(()),
            Self::Abandoned { note } => {
                if note.trim().is_empty() {
                    Err("an abandoned challenge must carry a note saying why; a decision with no \
                         reason is the mystery this records against"
                        .to_string())
                } else {
                    Ok(())
                }
            }
        }
    }

    /// The outcome this answer carries, for the registry to hand to the waiting pane.
    pub fn outcome(&self) -> HumanOutcome {
        match self {
            Self::Solved => HumanOutcome::Solved,
            Self::Abandoned { note } => HumanOutcome::Abandoned {
                note: note.trim().to_string(),
            },
        }
    }
}

/// What happened to an answer.
///
/// Four answers to one click, and collapsing any two would make the endpoint lie: a person whose
/// click landed *after* the rung gave up must not be told they cleared a wall nothing is waiting on,
/// and a one-time token that belongs to another challenge must not be treated as an answer at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerOutcome {
    /// The pane was still waiting and has been told.
    Delivered,
    /// The pane is gone: the budget expired, the fetch was dropped, or the screen was closed. Its
    /// browser has been (or is being) taken away, and the challenge is over.
    NobodyWaiting,
    /// No challenge with that id.
    Unknown,
    /// The answer carried a notice token that is not this challenge's. Refused, and the challenge is
    /// left exactly as it was: a wrong token is a request that misnamed its question, not an answer to
    /// it, and spending the wait on it would let a stale link end a live one.
    WrongToken,
}

/// One waiting pane, with everything the registry needs to describe and end it.
struct Waiting {
    id: String,
    screen: String,
    session: String,
    url: String,
    reason: String,
    /// Who the question is for, stamped by the pane from the config.
    operator: String,
    /// Whether a notification was pushed to the operator's channel. The pane's answer at presentation
    /// time, kept so the listing reports the same fact the announcement did.
    notified: bool,
    /// The one-time token this challenge's notification carries. Minted by the registry in `open`, so
    /// one challenge has exactly one, and an answer can be checked against the question it names.
    token: NoticeToken,
    /// The session's profile, kept so two challenges cannot point one browser profile at each other.
    profile_dir: PathBuf,
    /// When the rung will stop waiting. The rung's own deadline, not a copy: the budget it hands the
    /// pane is what it enforces.
    deadline: Instant,
    /// The answer, once a person gives one — or the reason there will not be one.
    answer: oneshot::Sender<Result<HumanOutcome, PaneError>>,
}

impl Waiting {
    fn summary(&self) -> ChallengeSummary {
        ChallengeSummary {
            id: self.id.clone(),
            screen: self.screen.clone(),
            session: self.session.clone(),
            url: self.url.clone(),
            reason: self.reason.clone(),
            seconds_left: self
                .deadline
                .saturating_duration_since(Instant::now())
                .as_secs(),
            operator: self.operator.clone(),
            notified: self.notified,
        }
    }
}

/// How many finished challenges are remembered, so a late answer can be told *which* way it is late.
///
/// Bounded because nothing here is worth growing without one: an id is a short string minted per
/// challenge, and a daemon that ran for a month would accumulate every one of them. Sixty-four is
/// far more than the handful a person could plausibly still have a tab open for.
const FINISHED_REMEMBERED: usize = 64;

/// The challenges a person has been handed and has not answered, keyed by id.
///
/// Separate from [`crate::screen::Screens`] rather than a field on a screen: a screen is a browser
/// anyone may watch, a challenge is a *question*, and only some screens have one. Two registries also
/// keep the screen listing's shape stable for the client that draws it.
///
/// A challenge that is over is **remembered** for a while, and that is the difference between the two
/// ways an answer can fail to land. "No such challenge" and "that challenge is over" are different
/// facts, and a person who clicks *Solved* a second after the budget expired is owed the second one:
/// telling them the id never existed would send them looking for a mistake they did not make.
#[derive(Default)]
pub struct Challenges {
    inner: Mutex<HashMap<String, Waiting>>,
    /// Which challenges have ended, newest last. See [`FINISHED_REMEMBERED`].
    finished: Mutex<VecDeque<String>>,
}

impl Challenges {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a challenge, or refuse it with the reason it cannot be presented, returning the
    /// one-time token its announcement carries.
    ///
    /// The token is minted *here* rather than by the caller so that "one challenge, one token" is a
    /// property of the registry instead of a convention two call sites could break: a second mint
    /// would be a second answer URL for one question, and the first one handed out would stop working
    /// with no way to tell which announcement was the stale one.
    ///
    /// Two refusals, and both are about not showing a person something broken:
    ///
    /// - **The id is already in use.** Two panes under one id is one challenge nobody can answer,
    ///   because the answer names the id.
    /// - **Another live challenge already holds this profile.** A browser profile has one lock
    ///   (`SingletonLock`), so a second browser pointed at the same directory is refused by the
    ///   engine, or worse, silently joins the first. Answering *that* wall is answering it for a
    ///   different fetch, so it is refused by name instead.
    fn open(&self, waiting: Waiting) -> Result<NoticeToken, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "the challenge registry lock is poisoned".to_string())?;
        if inner.contains_key(&waiting.id) {
            return Err(format!(
                "challenge {} is already being presented",
                waiting.id
            ));
        }
        if let Some(held) = inner
            .values()
            .find(|other| other.profile_dir == waiting.profile_dir)
        {
            return Err(format!(
                "another challenge ({}) is already being presented in this session's browser \
                 profile, and one profile cannot hold two browsers",
                held.id
            ));
        }
        let token = NoticeToken::new();
        let mut waiting = waiting;
        waiting.token = token.clone();
        inner.insert(waiting.id.clone(), waiting);
        Ok(token)
    }

    /// Take a challenge out of the registry, whichever way it is ending, and remember that it ended.
    ///
    /// The single place a challenge stops existing, so "it is over" cannot be true in one path and
    /// false in another: answering, withdrawing, expiring and closing the screen all come through
    /// here, and all of them leave the id behind as a finished one.
    fn take(&self, id: &str) -> Option<Waiting> {
        let taken = self.inner.lock().ok().and_then(|mut m| m.remove(id));
        if taken.is_some() {
            self.note_finished(id);
        }
        taken
    }

    /// Record that `id` is over, for a late answer to be told so.
    fn note_finished(&self, id: &str) {
        let Ok(mut finished) = self.finished.lock() else {
            return;
        };
        if finished.iter().any(|seen| seen == id) {
            return;
        }
        finished.push_back(id.to_string());
        while finished.len() > FINISHED_REMEMBERED {
            finished.pop_front();
        }
    }

    /// Whether `id` was presented and is over. Distinguishes "too late" from "never existed".
    fn is_finished(&self, id: &str) -> bool {
        self.finished
            .lock()
            .map(|finished| finished.iter().any(|seen| seen == id))
            .unwrap_or(false)
    }

    /// Remove a challenge the pane is done with. Idempotent: the answering path and the cancelling
    /// path both come through here, and whichever runs second must not fail.
    pub fn remove(&self, id: &str) -> bool {
        self.take(id).is_some()
    }

    /// Every challenge still waiting, oldest answer last.
    ///
    /// Entries whose pane is gone are dropped on the way past rather than listed: a receiver with no
    /// sender means nobody is waiting, and showing that as a live question would invite a person to
    /// answer a challenge that ended — which the answer endpoint would then have to refuse anyway.
    pub fn pending(&self) -> Vec<ChallengeSummary> {
        let expired: Vec<String> = {
            let mut inner = match self.inner.lock() {
                Ok(inner) => inner,
                Err(_) => return Vec::new(),
            };
            let expired: Vec<String> = inner
                .iter()
                .filter(|(_, waiting)| waiting.answer.is_closed())
                .map(|(id, _)| id.clone())
                .collect();
            for id in &expired {
                inner.remove(id);
            }
            // Remembered as finished rather than merely dropped, so the answer that arrives a moment
            // after the pane gave up is still told that the challenge is over.
            expired
        };
        for id in &expired {
            self.note_finished(id);
        }
        let Ok(inner) = self.inner.lock() else {
            return Vec::new();
        };
        let mut pending: Vec<_> = inner.values().map(Waiting::summary).collect();
        // Sorted so a listing is stable for a client that polls it: shortest deadline first, which is
        // also the one a person should look at first.
        pending.sort_by(|a, b| {
            a.seconds_left
                .cmp(&b.seconds_left)
                .then_with(|| a.id.cmp(&b.id))
        });
        pending
    }

    /// Whether anything is waiting.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Deliver an answer from a client that authenticated as the daemon's own operator.
    pub fn answer(&self, id: &str, outcome: HumanOutcome) -> AnswerOutcome {
        self.answer_by(id, outcome, None)
    }

    /// Deliver an answer that presents the one-time token from the challenge's own notification.
    ///
    /// The token is what makes the answer *addressed*: it is minted per challenge, delivered only to
    /// the operator's notification channel, and spent by the answer. A token that names a different
    /// challenge is refused **without taking the question away** — see [`AnswerOutcome::WrongToken`].
    pub fn answer_with_token(&self, id: &str, token: &str, outcome: HumanOutcome) -> AnswerOutcome {
        self.answer_by(id, outcome, Some(token))
    }

    /// Whether `token` is the one minted for a challenge that is still waiting under `id`.
    ///
    /// The middleware's read-only half of the token path ([`crate::auth`]): a request whose only
    /// credential is `?token=` is let through on the strength of this, and the answer route is what
    /// checks it for real and spends it. Peeking rather than consuming here keeps the decision in one
    /// place — a token that passed a check but whose request then failed to parse would otherwise be
    /// burned by a request that answered nothing.
    pub fn accepts_token(&self, id: &str, token: &str) -> bool {
        self.inner
            .lock()
            .map(|inner| {
                inner
                    .get(id)
                    .is_some_and(|waiting| waiting.token.as_str() == token)
            })
            .unwrap_or(false)
    }

    fn answer_by(
        &self,
        id: &str,
        outcome: HumanOutcome,
        token: Option<&str>,
    ) -> AnswerOutcome {
        // The token is judged *before* the entry is taken, so a misnamed one cannot end the wait it
        // named: the question is still there for the person who was actually asked. A `None` here
        // means the id is unknown or already over, which is judged below with the same distinction a
        // tokenless answer gets — the token is not what is wrong with it.
        //
        // The check is a *statement* rather than a `return` from inside the `match`, and that is
        // load-bearing: a `MutexGuard` from the scrutinee lives to the end of the `match`, so a return
        // from an arm would take the answer path with the registry lock still held — and the answer
        // path takes the same lock. That is a deadlock that only a request naming an id *with* a token
        // would reach, which is exactly what an integration test found. See `deliver`'s own rule about
        // ordering against the lock.
        if let Some(presented) = token {
            let verdict = match self.inner.lock() {
                Ok(inner) => inner
                    .get(id)
                    .map(|waiting| waiting.token.as_str() == presented),
                Err(_) => return AnswerOutcome::Unknown,
            };
            if verdict == Some(false) {
                return AnswerOutcome::WrongToken;
            }
        }
        self.answer_without_token(id, outcome)
    }

    fn answer_without_token(&self, id: &str, outcome: HumanOutcome) -> AnswerOutcome {
        let Some(waiting) = self.take(id) else {
            // Two different facts, and a person is owed the right one: an id that was presented and
            // is over is a person who was too late; an id that was never one is a bad request.
            return if self.is_finished(id) {
                AnswerOutcome::NobodyWaiting
            } else {
                AnswerOutcome::Unknown
            };
        };
        deliver(waiting.answer, Ok(outcome))
    }

    /// A screen was closed. Any challenge presented on it ends, saying so.
    ///
    /// A person who closes a screen has walked away from the question, and the alternative to
    /// noticing is the one this must not do: keep asking for five minutes about a page that is no
    /// longer on screen.
    pub fn screen_closed(&self, screen: &str) -> bool {
        let waiting = {
            let mut inner = match self.inner.lock() {
                Ok(inner) => inner,
                Err(_) => return false,
            };
            let id = inner
                .iter()
                .find(|(_, waiting)| waiting.screen == screen)
                .map(|(id, _)| id.clone());
            id.and_then(|id| inner.remove(&id))
        };
        match waiting {
            Some(waiting) => {
                let _ = deliver(
                    waiting.answer,
                    Err(PaneError::Failed(
                        "the screen the challenge was presented on was closed without an answer"
                            .to_string(),
                    )),
                );
                true
            }
            None => false,
        }
    }
}

/// Hand an answer to the waiting pane, saying whether anyone took it.
///
/// Deliberately *outside* the registry lock at every call site: `send` wakes the pane, and the pane's
/// cleanup takes the same lock to remove its own entry. Sending while holding it would have this
/// function and the guard in a deadlock that only shows up under a real person's timing.
fn deliver(
    answer: oneshot::Sender<Result<HumanOutcome, PaneError>>,
    outcome: Result<HumanOutcome, PaneError>,
) -> AnswerOutcome {
    match answer.send(outcome) {
        Ok(()) => AnswerOutcome::Delivered,
        // The receiver is gone: the rung gave up between the listing and the click, so there is
        // nobody to tell. Reported rather than swallowed, so a client can say so.
        Err(_) => AnswerOutcome::NobodyWaiting,
    }
}

/// How a wait ended, in the words a notification uses.
///
/// A failed wait is `withdrawn` rather than a category of its own: from the operator's side the two
/// are the same fact — *nobody answered and the question is gone* — and the reason a person would want
/// more than that is already in the daemon's log, not on a lock screen.
fn notice_outcome(outcome: &Result<HumanOutcome, PaneError>) -> Outcome {
    match outcome {
        Ok(HumanOutcome::Solved) => Outcome::Solved,
        Ok(HumanOutcome::Abandoned { note }) => Outcome::Abandoned { note: note.clone() },
        Err(_) => Outcome::Withdrawn,
    }
}

/// What the pane needs from the daemon's screens, so its own logic is testable without a browser.
///
/// The pane's job is the *waiting* — who is being asked what, for how long, and what has to happen
/// when the wait is dropped — and none of that needs a browser to be true. This seam is what lets the
/// cancellation tests assert that a dropped challenge hands its screen back, which the contract calls
/// out as the property a pane most easily gets wrong.
#[async_trait]
pub trait ScreenHost: Send + Sync {
    /// Launch a browser and register it as the screen `id`.
    async fn launch(&self, id: &str, options: ScreenOptions) -> Result<(), String>;

    /// Close the screen and wait for its browser to be gone.
    ///
    /// The path an *answered* challenge takes, so that when the rung is told an outcome there is
    /// genuinely no browser left.
    async fn close(&self, id: &str);

    /// Take the screen out of the daemon **without waiting for the browser**.
    ///
    /// The path a *cancelled* challenge takes, and it cannot be awaited: it is called from `Drop`.
    /// Dropping the last handle to a screen kills its child (`ScreenSource`'s own `Drop` sends the
    /// kill and `kill_on_drop` guarantees it), so handing the id back is the whole job.
    fn forget(&self, id: &str) -> bool;
}

#[async_trait]
impl ScreenHost for Screens {
    async fn launch(&self, id: &str, options: ScreenOptions) -> Result<(), String> {
        // The handle is dropped immediately: the registry owns the screen, and a challenge that kept
        // a second handle would keep its browser alive after `forget`.
        self.create(id, options).await.map(|_| ()).map_err(|err| err.to_string())
    }

    async fn close(&self, id: &str) {
        self.remove(id).await;
    }

    fn forget(&self, id: &str) -> bool {
        // Fully qualified on purpose: this trait method shares its name with the inherent one it
        // forwards to, and `self.forget(id)` would be correct only by the precedence rule that an
        // inherent method wins — which is a load-bearing subtlety to leave a reader guessing at.
        Screens::forget(self, id)
    }
}

/// What has to happen when the pane stops waiting, however it stops.
///
/// Armed while the pane is waiting and disarmed the moment it has cleaned up itself, so the ordinary
/// path and the cancelled path cannot both do it — and, more importantly, so the cancelled path
/// cannot *fail* to. Nothing here awaits and nothing here spawns: see the module docs.
struct PaneGuard {
    challenges: Arc<Challenges>,
    screens: Arc<dyn ScreenHost>,
    /// Where the "it is over" notice goes. Held here rather than reached through the pane because a
    /// `Drop` cannot borrow the pane: the future being dropped *is* its `present`.
    notices: Arc<dyn ChallengeNotices>,
    /// The question as it was announced, so the resolution names the same session, screen and operator
    /// the operator was asked about.
    summary: ChallengeSummary,
    id: String,
    /// `Some` while the guard is armed. A flag rather than a bool because the id has to be cloned out
    /// in `Drop`, where borrowing from `self` is not allowed.
    armed: bool,
}

impl PaneGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PaneGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.challenges.remove(&self.id);
        self.screens.forget(&self.id);
        // A person told to hurry is owed the news that they can stop, and this is the path where that
        // is easiest to forget: nothing here can await, so the push is fire-and-forget by construction
        // (`challenge_notice`). Sent *before* the browser is taken back, so a relay that reads the
        // notice finds the challenge over rather than racing the registry.
        self.notices
            .resolved(&self.summary, &Outcome::Withdrawn);
        tracing::warn!(
            challenge = %self.id,
            "the pane stopped waiting before it was answered; the challenge is withdrawn and its \
             browser is being closed"
        );
    }
}

/// The pane: a person, a browser showing them the wall, and a question they can answer.
pub struct ScreenPane {
    screens: Arc<dyn ScreenHost>,
    challenges: Arc<Challenges>,
    notices: Arc<dyn ChallengeNotices>,
    options: PaneOptions,
    /// How far through the roster the rotation has got. On the pane rather than in the config or the
    /// registry, so who the *next* run interrupts is a fact about this pane's history rather than
    /// something two components have to agree about. See the module docs on rotation.
    next_operator: AtomicUsize,
}

impl ScreenPane {
    pub fn new(
        screens: Arc<dyn ScreenHost>,
        challenges: Arc<Challenges>,
        notices: Arc<dyn ChallengeNotices>,
        options: PaneOptions,
    ) -> Self {
        Self {
            screens,
            challenges,
            notices,
            options,
            next_operator: AtomicUsize::new(0),
        }
    }

    /// Everyone a challenge may be addressed to, for a client that wants to show the roster.
    pub fn operators(&self) -> &[ChallengeOperator] {
        &self.options.operators
    }

    /// The registry a client's answer arrives at.
    pub fn challenges(&self) -> &Arc<Challenges> {
        &self.challenges
    }
}

impl std::fmt::Debug for ScreenPane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The options and the registry, never the screens: a `Debug` that walked into the screen
        // registry would print a handle to a process. The name is what reaches a report.
        f.debug_struct("ScreenPane")
            .field("name", &self.name())
            .field("viewport", &(self.options.width, self.options.height))
            .field(
                "operators",
                &self
                    .options
                    .operators
                    .iter()
                    .map(|operator| operator.name.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("told", &self.notices.reachable())
            .field("waiting", &self.challenges.len())
            .finish()
    }
}

#[async_trait]
impl HumanPane for ScreenPane {
    fn name(&self) -> &str {
        "screen-pane"
    }

    async fn present(&self, challenge: HumanChallenge) -> Result<HumanOutcome, PaneError> {
        let id = challenge.id.clone();

        // The browser first, then the question: a person told to look at a screen that does not exist
        // yet would answer a challenge they cannot see. A browser that will not start is a pane that
        // cannot present anything, which is a failure to report rather than a wait to begin.
        self.screens
            .launch(&id, self.options.for_challenge(&challenge))
            .await
            .map_err(|err| {
                PaneError::Failed(format!(
                    "could not show the challenge at {} in a browser: {err}",
                    challenge.url
                ))
            })?;

        // Who this run interrupts, chosen now and stamped onto the question: everything downstream
        // — the listing, the notification, the resolution — reads it off the challenge rather than
        // asking the roster again, so a rotation that moved on mid-flight cannot send a person news
        // about somebody else's run.
        let operator = self
            .options
            .next_operator(&self.next_operator)
            .clone();

        let (answer, waiting) = oneshot::channel();
        let entry = Waiting {
            id: id.clone(),
            screen: id.clone(),
            session: challenge.session.as_str().to_string(),
            url: challenge.url.clone(),
            reason: challenge.reason.clone(),
            operator: operator.name.clone(),
            // Filled in by `open`, which is what knows whether a notification could be delivered at
            // all — and asked about *this* operator, since a roster can hold people with a channel
            // and people without one. See `ChallengeNotices::reaches` and the listing's `notified`.
            notified: self.notices.reaches(&operator.name),
            token: NoticeToken::default(),
            profile_dir: challenge.profile_dir.clone(),
            deadline: Instant::now() + challenge.budget,
            answer,
        };
        // The question as a client sees it, taken before `open` consumes the entry and reused for the
        // resolution notice, so the two announcements cannot describe different questions.
        let summary = entry.summary();

        let token = match self.challenges.open(entry) {
            Ok(token) => token,
            Err(refused) => {
                // Refused after the browser was already launched, so the browser has to go before the
                // error does: this is the one path where a pane would otherwise leave a window open
                // that no challenge mentions.
                self.screens.close(&id).await;
                return Err(PaneError::Failed(refused));
            }
        };

        // Announced *after* the registry holds it, never before: a notification that named a challenge
        // nobody could answer would be a person walking to a screen that is not there.
        self.notices.announce(&summary, &token);
        tracing::info!(
            challenge = %id,
            session = %challenge.session.as_str(),
            url = %challenge.url,
            operator = %summary.operator,
            budget_secs = challenge.budget.as_secs(),
            operators = self.options.operators.len(),
            told = summary.notified,
            "handed a challenge to a person; watching for an answer on the screen pane"
        );

        let mut guard = PaneGuard {
            challenges: Arc::clone(&self.challenges),
            screens: Arc::clone(&self.screens),
            notices: Arc::clone(&self.notices),
            summary,
            id: id.clone(),
            armed: true,
        };

        let answered = waiting.await;

        // Cleaned up here, before the rung is told anything, so that "the pane returned an outcome"
        // and "there is no browser left" are the same instant. The guard covers the path this line
        // never reaches: the future dropped mid-await, which is exactly the budget expiring.
        guard.disarm();
        self.challenges.remove(&id);
        self.screens.close(&id).await;

        let outcome = match answered {
            Ok(outcome) => outcome,
            Err(_recv) => Err(PaneError::Failed(
                "the challenge was withdrawn before anyone answered it".to_string(),
            )),
        };
        self.notices
            .resolved(&guard.summary, &notice_outcome(&outcome));

        match outcome {
            Ok(outcome) => {
                tracing::info!(challenge = %id, "a person answered the challenge");
                Ok(outcome)
            }
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_core::ids::SessionId;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// A screen host that launches nothing and remembers what it was told.
    ///
    /// The point of the seam: every property worth asserting about the pane — what is waiting, who
    /// may answer, and that a cancelled wait hands its screen back — is a property of the *waiting*,
    /// and none of it needs a browser to be true.
    #[derive(Default)]
    struct FakeScreens {
        launched: Mutex<Vec<String>>,
        closed: Mutex<Vec<String>>,
        forgotten: Mutex<Vec<String>>,
        launches: AtomicUsize,
    }

    impl FakeScreens {
        fn launched(&self) -> Vec<String> {
            self.launched.lock().expect("the launch log").clone()
        }

        fn forgotten(&self) -> Vec<String> {
            self.forgotten.lock().expect("the forget log").clone()
        }
    }

    #[async_trait]
    impl ScreenHost for FakeScreens {
        async fn launch(&self, id: &str, _options: ScreenOptions) -> Result<(), String> {
            self.launches.fetch_add(1, Ordering::SeqCst);
            self.launched
                .lock()
                .expect("the launch log")
                .push(id.to_string());
            Ok(())
        }

        async fn close(&self, id: &str) {
            self.closed
                .lock()
                .expect("the close log")
                .push(id.to_string());
        }

        fn forget(&self, id: &str) -> bool {
            self.forgotten
                .lock()
                .expect("the forget log")
                .push(id.to_string());
            true
        }
    }

    /// A host whose browser will not start, for the path where the pane has nothing to show.
    struct RefusingScreens;

    #[async_trait]
    impl ScreenHost for RefusingScreens {
        async fn launch(&self, _id: &str, _options: ScreenOptions) -> Result<(), String> {
            Err("no Chromium-class browser was found".to_string())
        }

        async fn close(&self, _id: &str) {}

        fn forget(&self, _id: &str) -> bool {
            false
        }
    }

    fn challenge(id: &str, profile: &str, budget: Duration) -> HumanChallenge {
        HumanChallenge {
            id: id.to_string(),
            session: SessionId::from_raw("ses_help"),
            url: "http://127.0.0.1:9/verify".to_string(),
            profile_dir: PathBuf::from(profile),
            reason: "the automated rungs could not clear the site's challenge".to_string(),
            budget,
        }
    }

    /// A notifier that launches nothing and remembers what it was told.
    ///
    /// The same seam `FakeScreens` is: an announcement is a *property of the question* — one token per
    /// challenge, the operator's name on it, a resolution for every way the wait can end — and none of
    /// that needs a socket to be true.
    #[derive(Default)]
    struct FakeNotices {
        announcements: Mutex<Vec<(ChallengeSummary, String)>>,
        resolutions: Mutex<Vec<(String, Outcome)>>,
        /// `true` when a notifier is attached and reaches whoever is asked of it — the
        /// single-operator shape, where the answer is always yes.
        wired: bool,
        /// Who else this notifier can ring, by name. A `wired` notifier ignores it; a mute one
        /// consults nothing else, so a test that builds one by accident gets a challenge nobody was
        /// told rather than one everybody was.
        reachable: Vec<String>,
    }

    impl FakeNotices {
        fn wired() -> Self {
            Self {
                wired: true,
                ..Self::default()
            }
        }

        /// A notifier that can only reach the people it is given, by name.
        ///
        /// The per-operator half is what makes the roster tests mean anything: a fake that answered
        /// `reaches()` for everyone would agree with any routing, including none.
        fn reaching(names: &[&str]) -> Self {
            Self {
                // Not `wired`: this one is the case where the whole roster is *not* uniformly
                // reachable, which is exactly what `wired` claims.
                wired: false,
                reachable: names.iter().map(|name| name.to_string()).collect(),
                ..Self::default()
            }
        }

        fn announcements(&self) -> Vec<(ChallengeSummary, String)> {
            self.announcements
                .lock()
                .expect("the announcement log")
                .clone()
        }

        fn resolutions(&self) -> Vec<(String, Outcome)> {
            self.resolutions
                .lock()
                .expect("the resolution log")
                .clone()
        }

        /// Take the oldest announcement *out* of the log, so a test that walks two challenges sees
        /// each one once.
        fn take(&self) -> (ChallengeSummary, String) {
            self.announcements
                .lock()
                .expect("the announcement log")
                .remove(0)
        }
    }

    impl ChallengeNotices for FakeNotices {
        fn announce(&self, challenge: &ChallengeSummary, token: &NoticeToken) {
            self.announcements
                .lock()
                .expect("the announcement log")
                .push((challenge.clone(), token.as_str().to_string()));
        }

        fn resolved(&self, challenge: &ChallengeSummary, outcome: &Outcome) {
            self.resolutions
                .lock()
                .expect("the resolution log")
                .push((challenge.id.clone(), outcome.clone()));
        }

        fn reaches(&self, operator: &str) -> bool {
            self.wired || self.reachable.iter().any(|name| name == operator)
        }

        fn reachable(&self) -> bool {
            self.wired || !self.reachable.is_empty()
        }
    }

    fn pane(screens: Arc<dyn ScreenHost>, challenges: Arc<Challenges>) -> ScreenPane {
        ScreenPane::new(
            screens,
            challenges,
            Arc::new(FakeNotices::wired()),
            PaneOptions::default(),
        )
    }

    /// A pane whose announcements are captured, for the tests that assert on them.
    fn watched(
        screens: Arc<dyn ScreenHost>,
        challenges: Arc<Challenges>,
        notices: Arc<FakeNotices>,
    ) -> ScreenPane {
        ScreenPane::new(
            screens,
            challenges,
            notices,
            PaneOptions::default(),
        )
    }

    // ---------------------------------------------------------------------------------
    // The pane presents, and a person answers
    // ---------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_presented_challenge_is_listed_and_a_person_can_answer_it() {
        let screens = Arc::new(FakeScreens::default());
        let challenges = Arc::new(Challenges::new());
        let pane = Arc::new(pane(Arc::clone(&screens) as Arc<dyn ScreenHost>, Arc::clone(&challenges)));

        let answering = {
            let pane = Arc::clone(&pane);
            let challenges = Arc::clone(&challenges);
            tokio::spawn(async move {
                // Long enough that the answer below is certainly the thing that ends the wait, and
                // short enough that a broken test fails quickly rather than hanging the suite.
                let outcome = pane
                    .present(challenge("chal-1", "/tmp/pool/ses_help", Duration::from_secs(30)))
                    .await;
                assert_eq!(outcome.expect("a person answered"), HumanOutcome::Solved);
                challenges
            })
        };

        // The listing is what the web client polls, so waiting for it is how the test knows the pane
        // is actually waiting rather than merely spawned.
        let listed = wait_for_challenge(&challenges, "chal-1").await;
        assert_eq!(listed.screen, "chal-1", "the challenge names the screen to watch");
        assert_eq!(listed.session, "ses_help");
        assert_eq!(listed.url, "http://127.0.0.1:9/verify");
        assert_eq!(screens.launched(), vec!["chal-1".to_string()]);

        assert_eq!(
            challenges.answer("chal-1", HumanOutcome::Solved),
            AnswerOutcome::Delivered
        );

        answering.await.expect("the pane task");
        assert!(
            challenges.pending().is_empty(),
            "an answered challenge is not pending any more"
        );
        assert!(
            screens.forgotten().is_empty(),
            "the answered path waits for the browser itself; it must not take the `Drop` path"
        );
    }

    #[tokio::test]
    async fn an_abandoned_answer_carries_the_persons_own_note() {
        let screens = Arc::new(FakeScreens::default());
        let challenges = Arc::new(Challenges::new());
        let pane = Arc::new(pane(Arc::clone(&screens) as Arc<dyn ScreenHost>, Arc::clone(&challenges)));

        let answering = {
            let pane = Arc::clone(&pane);
            tokio::spawn(async move {
                pane.present(challenge("chal-2", "/tmp/pool/ses_a", Duration::from_secs(30)))
                    .await
            })
        };

        wait_for_challenge(&challenges, "chal-2").await;
        assert_eq!(
            challenges.answer(
                "chal-2",
                HumanOutcome::Abandoned {
                    note: "not solving a CAPTCHA for a scraper".to_string()
                }
            ),
            AnswerOutcome::Delivered
        );

        let outcome = answering
            .await
            .expect("the pane task")
            .expect("a declined challenge is still an outcome, not a pane failure");
        assert_eq!(
            outcome,
            HumanOutcome::Abandoned {
                note: "not solving a CAPTCHA for a scraper".to_string()
            }
        );
    }

    // ---------------------------------------------------------------------------------
    // Nothing is waited for after the wait is over
    // ---------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_dropped_wait_withdraws_the_challenge_and_hands_the_screen_back() {
        // The property the contract names as the one a pane gets wrong. The rung drops this future
        // when its budget expires; a pane that kept waiting, or kept a browser, would leave a window
        // on someone's machine that nothing can see, name, or close.
        let screens = Arc::new(FakeScreens::default());
        let challenges = Arc::new(Challenges::new());
        let pane = pane(Arc::clone(&screens) as Arc<dyn ScreenHost>, Arc::clone(&challenges));

        {
            // Never answered, never resolved: the `select` drops it, which is what the rung's timeout
            // does to the same future.
            let presenting =
                pane.present(challenge("chal-3", "/tmp/pool/ses_b", Duration::from_secs(300)));
            tokio::pin!(presenting);
            tokio::select! {
                _ = &mut presenting => panic!("an unanswered challenge must not resolve on its own"),
                _ = wait_for_challenge(&challenges, "chal-3") => {}
            }
        }

        assert!(
            challenges.pending().is_empty(),
            "a withdrawn challenge is not pending: {:?}",
            challenges.pending()
        );
        assert_eq!(
            screens.forgotten(),
            vec!["chal-3".to_string()],
            "the drop path must take the screen back synchronously — it cannot await, and it cannot \
             spawn onto a runtime that may be shutting down"
        );
    }

    #[tokio::test]
    async fn answering_a_challenge_that_is_over_says_nobody_is_waiting() {
        // A person clicking a second too late. Telling them their click cleared a wall would be a
        // lie about the one thing this endpoint exists to report, and telling them the id never
        // existed would send them looking for a mistake they did not make.
        let challenges = Arc::new(Challenges::new());
        let screens = Arc::new(FakeScreens::default());
        let pane = pane(
            Arc::clone(&screens) as Arc<dyn ScreenHost>,
            Arc::clone(&challenges),
        );

        {
            let presenting =
                pane.present(challenge("chal-4", "/tmp/pool/ses_c", Duration::from_secs(300)));
            tokio::pin!(presenting);
            tokio::select! {
                _ = &mut presenting => panic!("an unanswered challenge must not resolve on its own"),
                _ = wait_for_challenge(&challenges, "chal-4") => {}
            }
        }

        assert_eq!(
            challenges.answer("chal-4", HumanOutcome::Solved),
            AnswerOutcome::NobodyWaiting,
            "the challenge was presented and is over — which is not the same fact as an id that \
             was never one"
        );
        assert_eq!(
            challenges.answer("chal-never-existed", HumanOutcome::Solved),
            AnswerOutcome::Unknown,
            "and an id nobody ever minted is a different answer"
        );
    }

    #[test]
    fn a_finished_challenge_is_remembered_only_so_far() {
        // The memory of finished challenges is bounded, and the bound is what keeps an id from being
        // remembered forever by a daemon that runs for months. What it must not do is forget while a
        // person could still plausibly have the tab open — see `FINISHED_REMEMBERED`.
        let challenges = Challenges::new();
        for n in 0..(FINISHED_REMEMBERED + 10) {
            challenges.note_finished(&format!("chal-{n}"));
        }

        assert!(
            challenges.is_finished(&format!("chal-{}", FINISHED_REMEMBERED + 9)),
            "the newest is remembered"
        );
        assert!(
            !challenges.is_finished("chal-0"),
            "the oldest has been forgotten rather than accumulating"
        );
        assert_eq!(
            challenges.answer("chal-0", HumanOutcome::Solved),
            AnswerOutcome::Unknown,
            "and a forgotten id is unknown again, which is the honest answer once it is no longer \
             distinguishable from one that never existed"
        );
    }

    #[test]
    fn the_same_finished_id_is_not_remembered_twice() {
        // Answering and withdrawing both come through `take`, so a challenge that is finished twice
        // would otherwise evict a different id with a duplicate.
        let challenges = Challenges::new();
        for _ in 0..5 {
            challenges.note_finished("chal-dup");
        }
        assert!(challenges.is_finished("chal-dup"));
        let remembered = challenges.finished.lock().expect("the finished list").len();
        assert_eq!(remembered, 1, "recorded once, however many paths reported it");
    }

    #[tokio::test]
    async fn closing_the_screen_ends_the_challenge_with_the_reason_it_ended() {
        // A person who closes the screen has walked away from the question. The alternative to
        // noticing is asking for five minutes about a page that is no longer on screen.
        let screens = Arc::new(FakeScreens::default());
        let challenges = Arc::new(Challenges::new());
        let pane = Arc::new(pane(
            Arc::clone(&screens) as Arc<dyn ScreenHost>,
            Arc::clone(&challenges),
        ));

        let answering = {
            let pane = Arc::clone(&pane);
            tokio::spawn(async move {
                pane.present(challenge("chal-5", "/tmp/pool/ses_d", Duration::from_secs(300)))
                    .await
            })
        };

        wait_for_challenge(&challenges, "chal-5").await;
        assert!(
            challenges.screen_closed("chal-5"),
            "the challenge presented on this screen ends with it"
        );
        assert!(!challenges.screen_closed("chal-5"), "and only once");

        let err = answering
            .await
            .expect("the pane task")
            .expect_err("a closed screen means no answer");
        assert!(err.to_string().contains("closed without an answer"), "{err}");
    }

    #[tokio::test]
    async fn a_screen_that_is_not_a_challenge_ends_nothing() {
        let screens = Arc::new(FakeScreens::default());
        let challenges = Arc::new(Challenges::new());
        let pane = Arc::new(pane(
            Arc::clone(&screens) as Arc<dyn ScreenHost>,
            Arc::clone(&challenges),
        ));

        let answering = {
            let pane = Arc::clone(&pane);
            tokio::spawn(async move {
                pane.present(challenge("chal-6", "/tmp/pool/ses_e", Duration::from_secs(300)))
                    .await
            })
        };
        wait_for_challenge(&challenges, "chal-6").await;

        assert!(!challenges.screen_closed("a-screen-a-person-opened"));
        assert_eq!(challenges.pending().len(), 1, "the challenge is still waiting");

        assert_eq!(
            challenges.answer("chal-6", HumanOutcome::Solved),
            AnswerOutcome::Delivered
        );
        answering.await.expect("the pane task").expect("an answer");
    }

    // ---------------------------------------------------------------------------------
    // The pane refuses what it cannot present
    // ---------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_browser_that_will_not_start_is_reported_rather_than_waited_on() {
        let challenges = Arc::new(Challenges::new());
        let pane = pane(Arc::new(RefusingScreens), Arc::clone(&challenges));

        let err = pane
            .present(challenge("chal-7", "/tmp/pool/ses_f", Duration::from_secs(30)))
            .await
            .expect_err("nothing to show means nothing to ask");

        assert!(err.to_string().contains("no Chromium-class browser"), "{err}");
        assert!(
            challenges.pending().is_empty(),
            "a pane that cannot show the page must not leave a question waiting"
        );
    }

    #[tokio::test]
    async fn two_challenges_cannot_share_one_browser_profile() {
        // A browser profile holds one lock, and one profile cannot hold two browsers. Presenting the
        // second under the same profile would either fail in the engine or, worse, silently join the
        // first browser — and then answering it would answer the wrong fetch's wall.
        let challenges = Arc::new(Challenges::new());
        let screens = Arc::new(FakeScreens::default());
        let pane = Arc::new(pane(
            Arc::clone(&screens) as Arc<dyn ScreenHost>,
            Arc::clone(&challenges),
        ));

        let first = {
            let pane = Arc::clone(&pane);
            tokio::spawn(async move {
                pane.present(challenge("chal-8", "/tmp/pool/ses_g", Duration::from_secs(300)))
                    .await
            })
        };
        wait_for_challenge(&challenges, "chal-8").await;

        let err = pane
            .present(challenge("chal-9", "/tmp/pool/ses_g", Duration::from_secs(300)))
            .await
            .expect_err("one profile, one browser");
        assert!(err.to_string().contains("one profile cannot hold"), "{err}");
        assert_eq!(challenges.pending().len(), 1, "the first is untouched");

        assert_eq!(
            challenges.answer("chal-8", HumanOutcome::Solved),
            AnswerOutcome::Delivered
        );
        first.await.expect("the pane task").expect("an answer");
    }

    // ---------------------------------------------------------------------------------
    // What a client is told
    // ---------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_listing_carries_the_reason_and_the_time_left_in_the_rungs_own_budget() {
        let challenges = Arc::new(Challenges::new());
        let screens = Arc::new(FakeScreens::default());
        let pane = Arc::new(pane(
            Arc::clone(&screens) as Arc<dyn ScreenHost>,
            Arc::clone(&challenges),
        ));

        let answering = {
            let pane = Arc::clone(&pane);
            tokio::spawn(async move {
                pane.present(challenge("chal-10", "/tmp/pool/ses_h", Duration::from_secs(60)))
                    .await
            })
        };

        let listed = wait_for_challenge(&challenges, "chal-10").await;
        assert!(
            listed.reason.contains("could not clear"),
            "the person is told why they are being asked: {}",
            listed.reason
        );
        assert!(
            listed.seconds_left <= 60,
            "the countdown cannot exceed the budget the rung enforces: {}",
            listed.seconds_left
        );

        assert_eq!(
            challenges.answer("chal-10", HumanOutcome::Solved),
            AnswerOutcome::Delivered
        );
        answering.await.expect("the pane task").expect("an answer");
    }

    // ---------------------------------------------------------------------------------
    // Addressed to one operator, and announced to them
    // ---------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_challenge_is_announced_to_its_operator_with_the_token_that_answers_it() {
        // The whole point of the token: the person who is *told* can answer without the daemon's
        // master credential. So the test does exactly that — reads the token out of the announcement
        // and answers with nothing else.
        let screens = Arc::new(FakeScreens::default());
        let challenges = Arc::new(Challenges::new());
        let notices = Arc::new(FakeNotices::wired());
        let pane = Arc::new(watched(
            Arc::clone(&screens) as Arc<dyn ScreenHost>,
            Arc::clone(&challenges),
            Arc::clone(&notices),
        ));

        let answering = {
            let pane = Arc::clone(&pane);
            tokio::spawn(async move {
                pane.present(challenge("chal-11", "/tmp/pool/ses_i", Duration::from_secs(60)))
                    .await
            })
        };
        wait_for_challenge(&challenges, "chal-11").await;

        let announced = notices.announcements();
        assert_eq!(announced.len(), 1, "one question, one announcement: {announced:?}");
        let (summary, token) = &announced[0];
        assert_eq!(summary.id, "chal-11");
        assert_eq!(
            summary.operator, "admin",
            "the pane names the operator from the config, which defaults to the daemon's account"
        );
        assert!(summary.notified, "and reports that they were reached");
        assert!(!token.is_empty(), "the announcement carries a token");
        assert!(
            challenges.accepts_token("chal-11", token),
            "which is the one the registry minted for this challenge"
        );

        assert_eq!(
            challenges.answer_with_token("chal-11", token, HumanOutcome::Solved),
            AnswerOutcome::Delivered,
            "the notification's own token answers the question it announced"
        );
        answering.await.expect("the pane task").expect("an answer");

        let resolutions = notices.resolutions();
        assert_eq!(
            resolutions,
            vec![("chal-11".to_string(), Outcome::Solved)],
            "and the operator is told it is over, which is what lets them stop"
        );
    }

    #[tokio::test]
    async fn a_token_from_another_challenge_is_refused_and_leaves_this_one_waiting() {
        // A stale link, or a token pasted into the wrong challenge. Refusing it is not enough: the
        // wait has to survive it, because the question was still open and the person who was asked is
        // still the one who has to answer.
        let screens = Arc::new(FakeScreens::default());
        let challenges = Arc::new(Challenges::new());
        let notices = Arc::new(FakeNotices::wired());
        let pane = Arc::new(watched(
            Arc::clone(&screens) as Arc<dyn ScreenHost>,
            Arc::clone(&challenges),
            Arc::clone(&notices),
        ));

        let answering = {
            let pane = Arc::clone(&pane);
            tokio::spawn(async move {
                pane.present(challenge("chal-12", "/tmp/pool/ses_j", Duration::from_secs(60)))
                    .await
            })
        };
        wait_for_challenge(&challenges, "chal-12").await;
        let (_, token) = notices.take();

        assert_eq!(
            challenges.answer_with_token("chal-12", "not-the-token", HumanOutcome::Solved),
            AnswerOutcome::WrongToken
        );
        assert_eq!(
            challenges.pending().len(),
            1,
            "a misnamed token is not an answer, so the question is still being asked"
        );

        assert_eq!(
            challenges.answer_with_token("chal-12", &token, HumanOutcome::Solved),
            AnswerOutcome::Delivered,
            "and the token that does name it still works"
        );
        answering.await.expect("the pane task").expect("an answer");
    }

    #[test]
    fn a_token_against_an_id_that_is_not_waiting_is_answered_not_hung_on() {
        // A token plus an id nobody is waiting under. The verdict is the tokenless one — unknown, or
        // over — and the *point* is that `Challenges::answer` is reached at all: the check must not
        // hold the registry lock while calling into the registry, or this test hangs instead of
        // failing. That is not hypothetical; it is what a live API test found.
        let challenges = Challenges::new();
        assert_eq!(
            challenges.answer_with_token("chal-never", "abc", HumanOutcome::Solved),
            AnswerOutcome::Unknown
        );
        assert!(
            !challenges.accepts_token("chal-never", "abc"),
            "and nothing became addressable by asking"
        );

        challenges.note_finished("chal-over");
        assert_eq!(
            challenges.answer_with_token("chal-over", "abc", HumanOutcome::Solved),
            AnswerOutcome::NobodyWaiting,
            "an id that was presented and is over is still a different fact from one that never was"
        );
    }

    #[tokio::test]
    async fn a_challenge_is_announced_once_and_its_resolutions_are_its_own() {
        // Two challenges, to pin that a token is the *question's* rather than the pane's: one notice
        // each, one outcome each, and neither can answer the other.
        let screens = Arc::new(FakeScreens::default());
        let challenges = Arc::new(Challenges::new());
        let notices = Arc::new(FakeNotices::wired());
        let pane = Arc::new(watched(
            Arc::clone(&screens) as Arc<dyn ScreenHost>,
            Arc::clone(&challenges),
            Arc::clone(&notices),
        ));

        let first = {
            let pane = Arc::clone(&pane);
            tokio::spawn(async move {
                pane.present(challenge("chal-13", "/tmp/pool/ses_k", Duration::from_secs(60)))
                    .await
            })
        };
        wait_for_challenge(&challenges, "chal-13").await;
        let (_, first_token) = notices.take();

        let second = {
            let pane = Arc::clone(&pane);
            tokio::spawn(async move {
                pane.present(challenge("chal-14", "/tmp/pool/ses_l", Duration::from_secs(60)))
                    .await
            })
        };
        wait_for_challenge(&challenges, "chal-14").await;
        let (_, second_token) = notices.take();

        assert_ne!(first_token, second_token, "one mint per challenge");
        assert_eq!(
            challenges.answer_with_token("chal-14", &first_token, HumanOutcome::Solved),
            AnswerOutcome::WrongToken,
            "the first challenge's token answers the first challenge"
        );

        assert_eq!(
            challenges.answer_with_token("chal-13", &first_token, HumanOutcome::Solved),
            AnswerOutcome::Delivered
        );
        first.await.expect("the pane task").expect("an answer");
        assert_eq!(
            challenges.answer_with_token(
                "chal-14",
                &second_token,
                HumanOutcome::Abandoned {
                    note: "not solving a CAPTCHA for a scraper".to_string()
                }
            ),
            AnswerOutcome::Delivered
        );
        second.await.expect("the pane task").expect("an outcome");

        assert_eq!(
            notices.resolutions(),
            vec![
                ("chal-13".to_string(), Outcome::Solved),
                (
                    "chal-14".to_string(),
                    Outcome::Abandoned {
                        note: "not solving a CAPTCHA for a scraper".to_string()
                    }
                ),
            ],
            "each resolution is the question it belongs to, with the person's own words kept"
        );
    }

    #[tokio::test]
    async fn a_withdrawn_challenge_is_reported_to_the_operator_as_over() {
        // The `Drop` path, which is where a notification is easiest to forget: nothing there can
        // await, and the person is standing in front of a browser that is about to disappear.
        let screens = Arc::new(FakeScreens::default());
        let challenges = Arc::new(Challenges::new());
        let notices = Arc::new(FakeNotices::wired());

        {
            let pane = watched(
                Arc::clone(&screens) as Arc<dyn ScreenHost>,
                Arc::clone(&challenges),
                Arc::clone(&notices),
            );
            let presenting =
                pane.present(challenge("chal-15", "/tmp/pool/ses_m", Duration::from_secs(300)));
            tokio::pin!(presenting);
            tokio::select! {
                _ = &mut presenting => panic!("an unanswered challenge must not resolve on its own"),
                _ = wait_for_challenge(&challenges, "chal-15") => {}
            }
        }

        assert_eq!(
            notices.announcements().len(),
            1,
            "it was announced before it was withdrawn"
        );
        assert!(!notices.take().1.is_empty(), "and carried a token");
        assert_eq!(
            notices.resolutions(),
            vec![("chal-15".to_string(), Outcome::Withdrawn)],
            "and the person who was told to hurry is told that they can stop"
        );
        assert_eq!(challenges.pending().len(), 0);
    }

    #[tokio::test]
    async fn a_daemon_that_cannot_reach_anyone_says_so_on_the_listing() {
        // The state a person reading the page cares about: *someone has been told* and *nobody has,
        // you are the only chance this run has* are different things, and the listing reports which.
        let screens = Arc::new(FakeScreens::default());
        let challenges = Arc::new(Challenges::new());
        let silent = Arc::new(ScreenPane::new(
            Arc::clone(&screens) as Arc<dyn ScreenHost>,
            Arc::clone(&challenges),
            Arc::new(FakeNotices::default()),
            PaneOptions {
                operators: vec![ChallengeOperator {
                    name: "yoav".to_string(),
                    push_url: Some("https://relay.test/yoav".to_string()),
                }],
                ..PaneOptions::default()
            },
        ));

        let announcing = {
            let silent = Arc::clone(&silent);
            tokio::spawn(async move {
                silent
                    .present(challenge("chal-16", "/tmp/pool/ses_n", Duration::from_secs(60)))
                    .await
            })
        };
        let listed = wait_for_challenge(&challenges, "chal-16").await;
        assert_eq!(listed.operator, "yoav", "the operator is named by the config");
        assert!(
            !listed.notified,
            "and the listing admits the operator was not told"
        );

        assert_eq!(
            challenges.answer("chal-16", HumanOutcome::Solved),
            AnswerOutcome::Delivered
        );
        announcing.await.expect("the pane task").expect("an answer");
    }

    #[test]
    fn an_abandoned_answer_without_a_reason_is_refused() {
        // A decision with no reason is the mystery the outcome exists to prevent.
        assert!(AnswerBody::Solved.check().is_ok());
        assert!(AnswerBody::Abandoned {
            note: "   ".to_string()
        }
        .check()
        .is_err());
        assert!(AnswerBody::Abandoned {
            note: " this site wants a phone number ".to_string()
        }
        .check()
        .is_ok());
        assert_eq!(
            AnswerBody::Abandoned {
                note: " this site wants a phone number ".to_string()
            }
            .outcome(),
            HumanOutcome::Abandoned {
                note: "this site wants a phone number".to_string()
            },
            "the note is trimmed, and it is the person's words rather than a category"
        );
    }

    #[test]
    fn the_wire_shapes_are_what_a_client_sends() {
        // The client's side of this is `index.html`; a rename here is a pane that silently stops
        // answering, so the shape is pinned rather than assumed.
        let solved: AnswerBody = serde_json::from_str(r#"{"outcome":"solved"}"#).expect("a solved answer");
        assert_eq!(solved, AnswerBody::Solved);
        let abandoned: AnswerBody =
            serde_json::from_str(r#"{"outcome":"abandoned","note":"no thanks"}"#).expect("a decline");
        assert_eq!(
            abandoned,
            AnswerBody::Abandoned {
                note: "no thanks".to_string()
            }
        );
        assert!(
            serde_json::from_str::<AnswerBody>(r#"{"outcome":"maybe"}"#).is_err(),
            "an outcome the daemon does not know is a parse error, not a default"
        );

        let summary = ChallengeSummary {
            id: "chal-1".to_string(),
            screen: "chal-1".to_string(),
            session: "ses_x".to_string(),
            url: "http://127.0.0.1:9/verify".to_string(),
            reason: "a wall".to_string(),
            seconds_left: 42,
            operator: "yoav".to_string(),
            notified: true,
        };
        let json = serde_json::to_string(&summary).expect("a summary serializes");
        assert!(json.contains(r#""seconds_left":42"#), "{json}");
        assert!(json.contains(r#""screen":"chal-1""#), "{json}");
        assert!(
            json.contains(r#""operator":"yoav""#) && json.contains(r#""notified":true"#),
            "a client is told who the question is for and whether they were told: {json}"
        );
    }

    // ---------------------------------------------------------------------------------
    // Which person, when the config names several
    // ---------------------------------------------------------------------------------

    /// A pane whose options name `names`, in that order, each with a webhook of their own.
    fn staffed(
        screens: Arc<dyn ScreenHost>,
        challenges: Arc<Challenges>,
        names: &[&str],
    ) -> (Arc<ScreenPane>, Arc<FakeNotices>) {
        let notices = Arc::new(FakeNotices::reaching(names));
        let pane = Arc::new(ScreenPane::new(
            screens,
            challenges,
            Arc::clone(&notices) as Arc<dyn ChallengeNotices>,
            PaneOptions {
                operators: names
                    .iter()
                    .map(|name| ChallengeOperator {
                        name: name.to_string(),
                        push_url: Some(format!("https://relay.test/{name}")),
                    })
                    .collect(),
                ..PaneOptions::default()
            },
        ));
        (pane, notices)
    }

    /// Present a challenge, read who it was addressed to off the listing, and answer it.
    ///
    /// Each one gets its own profile and its own id, because the registry refuses a second challenge
    /// on a profile already in use — which is a refusal about browsers, not about operators, and
    /// would otherwise make a rotation test fail for the wrong reason.
    async fn ask(
        pane: &Arc<ScreenPane>,
        challenges: &Arc<Challenges>,
        id: &str,
    ) -> ChallengeSummary {
        let borrowed = id.to_string();
        let owned = borrowed.clone();
        let answering = {
            let pane = Arc::clone(pane);
            tokio::spawn(async move {
                pane.present(challenge(
                    &owned,
                    &format!("/tmp/pool/{owned}"),
                    Duration::from_secs(30),
                ))
                .await
            })
        };
        let listed = wait_for_challenge(challenges, &borrowed).await;
        assert_eq!(
            challenges.answer(&borrowed, HumanOutcome::Solved),
            AnswerOutcome::Delivered
        );
        answering.await.expect("the pane task").expect("an answer");
        listed
    }

    /// A pane over a roster where only the *first* operator can be rung, so the rotation produces one
    /// challenge somebody was told about and one they were not.
    fn mixed(challenges: &Arc<Challenges>) -> (Arc<FakeScreens>, Arc<FakeNotices>, Arc<ScreenPane>) {
        let screens = Arc::new(FakeScreens::default());
        let notices = Arc::new(FakeNotices::reaching(&["yoav"]));
        let pane = ScreenPane::new(
            Arc::clone(&screens) as Arc<dyn ScreenHost>,
            Arc::clone(challenges),
            Arc::clone(&notices) as Arc<dyn ChallengeNotices>,
            PaneOptions {
                operators: vec![
                    ChallengeOperator {
                        name: "yoav".to_string(),
                        push_url: Some("https://relay.test/yoav".to_string()),
                    },
                    ChallengeOperator {
                        name: "dana".to_string(),
                        push_url: None,
                    },
                ],
                ..PaneOptions::default()
            },
        );
        (screens, notices, Arc::new(pane))
    }

    #[tokio::test]
    async fn each_challenge_is_addressed_to_the_next_operator_in_the_roster() {
        // The rotation, end to end through the pane: three questions go to three different people in
        // the config's order. The alternative — always the first — is a roster where only the first
        // name matters, which is a list that does nothing.
        let screens: Arc<dyn ScreenHost> = Arc::new(FakeScreens::default());
        let challenges = Arc::new(Challenges::new());
        let (pane, _notices) = staffed(
            Arc::clone(&screens),
            Arc::clone(&challenges),
            &["yoav", "dana", "sam"],
        );

        let mut asked = Vec::new();
        for id in ["chal-a", "chal-b", "chal-c"] {
            asked.push(ask(&pane, &challenges, id).await.operator);
        }
        assert_eq!(
            asked,
            vec!["yoav", "dana", "sam"],
            "one question each, in the order the config wrote them: {asked:?}"
        );
    }

    #[tokio::test]
    async fn the_rotation_wraps_rather_than_running_out_of_people_to_ask() {
        // A roster of two that asked yoav, dana and then stopped would eventually leave a run
        // unaddressed — the precise failure this path exists to prevent, arriving slowly enough that
        // nobody would notice it was a bug.
        let screens: Arc<dyn ScreenHost> = Arc::new(FakeScreens::default());
        let challenges = Arc::new(Challenges::new());
        let (pane, _notices) =
            staffed(Arc::clone(&screens), Arc::clone(&challenges), &["yoav", "dana"]);

        let mut asked = Vec::new();
        for id in ["chal-a", "chal-b", "chal-c", "chal-d", "chal-e"] {
            asked.push(ask(&pane, &challenges, id).await.operator);
        }
        assert_eq!(
            asked,
            vec!["yoav", "dana", "yoav", "dana", "yoav"],
            "and a reader can predict the whole sequence from the config: {asked:?}"
        );
    }

    #[tokio::test]
    async fn a_roster_of_one_asks_the_same_person_every_time() {
        // The ordinary case, unchanged: a daemon that configures one operator has not opted into
        // anything and must not be handed a rotation it did not ask for.
        let screens = Arc::new(FakeScreens::default());
        let challenges = Arc::new(Challenges::new());
        let pane = Arc::new(watched(
            Arc::clone(&screens) as Arc<dyn ScreenHost>,
            Arc::clone(&challenges),
            Arc::new(FakeNotices::wired()),
        ));
        assert_eq!(pane.operators().len(), 1);
        assert_eq!(
            pane.operators()[0].name, "admin",
            "a daemon that names nobody still has the account it authenticates"
        );

        let mut asked = Vec::new();
        for id in ["chal-a", "chal-b"] {
            asked.push(ask(&pane, &challenges, id).await.operator);
        }
        assert_eq!(asked, vec!["admin", "admin"], "{asked:?}");
    }

    #[tokio::test]
    async fn being_told_is_about_the_person_named_and_not_about_the_daemon() {
        // The `notified` flag is the one thing a person reads to decide whether they are the only
        // chance this run has. With a roster it must answer "was *this* person told", because a
        // daemon-level flag would leave dana believing her run had pinged somebody.
        let challenges = Arc::new(Challenges::new());
        let (_screens, _notices, pane) = mixed(&challenges);

        let told = ask(&pane, &challenges, "chal-a").await;
        assert_eq!(told.operator, "yoav");
        assert!(
            told.notified,
            "yoav has a webhook of their own, so they really were pushed to"
        );

        let silent = ask(&pane, &challenges, "chal-b").await;
        assert_eq!(silent.operator, "dana");
        assert!(
            !silent.notified,
            "and dana is not told she was told, because no webhook of hers was rung: {silent:?}"
        );
    }

    #[tokio::test]
    async fn a_resolution_reaches_the_person_the_question_was_addressed_to() {
        // The other half of the promise: a person told to hurry is owed the news that they can stop,
        // and on a roster "they" is a routing decision. An announcement and its resolution that
        // disagreed about who would put the second notification in front of somebody else's run.
        let screens: Arc<dyn ScreenHost> = Arc::new(FakeScreens::default());
        let challenges = Arc::new(Challenges::new());
        let (pane, notices) = staffed(Arc::clone(&screens), Arc::clone(&challenges), &["yoav", "dana"]);

        // One answered, one left to be withdrawn: both ends of a wait, both on the wire.
        ask(&pane, &challenges, "chal-a").await;
        {
            let presenting =
                pane.present(challenge("chal-b", "/tmp/pool/b", Duration::from_secs(300)));
            tokio::pin!(presenting);
            tokio::select! {
                _ = &mut presenting => panic!("an unanswered challenge must not resolve on its own"),
                _ = wait_for_challenge(&challenges, "chal-b") => {}
            }
        }

        let announced: Vec<String> = notices
            .announcements()
            .into_iter()
            .map(|(summary, _)| summary.operator)
            .collect();
        assert_eq!(announced, vec!["yoav", "dana"], "{announced:?}");

        let resolved: Vec<(String, String)> = notices
            .resolutions()
            .into_iter()
            .map(|(id, outcome)| (id, outcome.label().to_string()))
            .collect();
        assert_eq!(
            resolved,
            vec![
                ("chal-a".to_string(), "solved".to_string()),
                ("chal-b".to_string(), "withdrawn".to_string()),
            ],
            "and every end of a wait is reported, carrying the name of whoever it was addressed to"
        );
    }

    /// Wait until the challenge `id` is listed, or give up loudly.
    ///
    /// A poll rather than a sleep, and bounded: the pane opens the challenge on its way into the
    /// wait, so this either happens immediately or never — and a test that waited forever on a bug
    /// would hang the suite instead of reporting it.
    async fn wait_for_challenge(challenges: &Arc<Challenges>, id: &str) -> ChallengeSummary {
        for _ in 0..200 {
            if let Some(found) = challenges.pending().into_iter().find(|c| c.id == id) {
                return found;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("the challenge {id} was never listed");
    }
}

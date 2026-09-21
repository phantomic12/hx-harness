//! Browser pool: an escalation ladder over interchangeable fetch rungs, one isolated profile per
//! session.
//!
//! ## The ladder
//!
//! Fetching a page has three costs, and the design assumes the cheap one is usually enough:
//!
//! | Rung | What it is | What it costs |
//! |---|---|---|
//! | [`RungKind::Http`] | a plain HTTP client | milliseconds, no process |
//! | [`RungKind::Stealth`] | a real browser with a stealth fingerprint | a process launch |
//! | [`RungKind::Interactive`] | a browser a **person** drives | a human's attention |
//!
//! The ladder climbs only when the site *refused*: a challenge page, a bot check, a 403/429/503.
//! That decision is [`FetchError::disposition`], and it is the whole design:
//!
//! - a **success** ends the climb — the dearer rungs are never launched;
//! - a **refusal** escalates, because a different fingerprint is exactly what the wall is asking
//!   for;
//! - a **transport error is not a bot wall**. A DNS failure, a refused connection, a TLS error and
//!   a timeout all mean the site never spoke. Escalating those launches a browser — and eventually
//!   summons a person — to look at a host that is down. They stop the climb.
//! - a **refused target** never escalates either. An admission refusal (a `file://` URL, a
//!   link-local address) is a judgement about the target, not about the site's fingerprint, and
//!   pointing a browser at it would be the same mistake with a bigger engine.
//!
//! One rung failing does not fail the fetch. Every attempt is recorded in a [`FetchReport`], the
//! same discipline `hx-search`'s fan-out applies to its backends, so a caller can say *"the cheap
//! rung was refused, the stealth rung is not installed, nobody was available to help"* instead of
//! presenting an empty result as an answer.
//!
//! ## Fetched content is untrusted input
//!
//! A page is **data, never instruction**, and that is held by the type rather than by remembering:
//! a rung returns an [`UntrustedPage`], whose body is reachable only through
//! [`UntrustedPage::body_untrusted`]. There is no `Deref<Target = str>`, no `Display` and no
//! `Into<String>`, so a call site cannot use the text without the word *untrusted* in front of it.
//! A page full of imperative sentences addressed to the reader is still a page. The tool layer that
//! hands a body to a model is responsible for framing it as quoted data; this crate only refuses to
//! make forgetting easy.
//!
//! ## Profile isolation is a security boundary
//!
//! Every session gets its own directory ([`profile`]), its own cookie hand-off file and its own
//! browser storage, and two sessions can never resolve to the same path. That is what makes the
//! pool safe to run in parallel, and it is a *security* property rather than tidiness: a shared
//! profile is a shared cookie jar, and a shared cookie jar is one session's logged-in session
//! leaking into another session's fetch. It is asserted by the tests in [`profile`], not assumed.
//!
//! ## What is deliberately not built
//!
//! No browser UI. [`interactive`] defines the contract a human-in-the-loop pane plugs into — what
//! it receives, what it returns, what happens on a timeout — and the rung is present and
//! fail-closed, but there is no pane and no CDP driver in this crate: a page a person has unblocked
//! is read by re-running the ladder in that session, and driving Chromium over CDP to read it is
//! the next step. The stealth rung is real plumbing — it launches a process and reads its stdout —
//! but whether the browser it launches defeats any given detector is not something this crate can
//! assert, and nothing here claims a real browser was driven.

pub mod error;
pub mod interactive;
pub mod ladder;
pub mod pool;
pub mod profile;
pub mod rung;
pub mod rungs;
pub mod target;

pub use error::{Disposition, FetchError, RefusalReason};
pub use interactive::{
    HumanChallenge, HumanOutcome, HumanPane, InteractiveFetcher, NoPane, PaneError,
    DEFAULT_HUMAN_BUDGET,
};
pub use ladder::{Attempt, FetchReport, Ladder, DEFAULT_RUNG_TIMEOUT};
pub use pool::BrowserPool;
pub use profile::{PoolRoot, ProfileError, SessionProfile, COOKIE_FILE};
pub use rung::{FetchRequest, Fetcher, RungKind, UntrustedPage};
pub use rungs::{ChromiumRung, HttpRung, StealthRung};
pub use target::{
    Admission, BlockReason, HostResolver, PinnedTarget, SystemResolver, TargetRefusal, TargetUrl,
};

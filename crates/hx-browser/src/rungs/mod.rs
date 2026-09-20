//! The rungs, in ladder order: a plain HTTP client, then a stealth browser.
//!
//! Each rung is a real implementation of [`crate::rung::Fetcher`] rather than a scripted double, and
//! each fails loudly on input nobody scripted. The *decision* to escalate is tested against scripted
//! rungs in [`crate::ladder`]; these are the things it escalates to.
//!
//! The third rung, a browser a person drives, lives in [`crate::interactive`] — it is not a subprocess
//! this crate launches but a pane an operator is looking at, so it is a different shape and is not
//! here.

pub mod http;
pub mod stealth;

pub use http::HttpRung;
pub use stealth::StealthRung;
pub mod chromium;

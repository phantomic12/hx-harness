//! What can go wrong on a rung, and what the ladder does about it.
//!
//! ## Why this is a taxonomy rather than a message
//!
//! The ladder's whole job is to decide whether to spend a dearer rung, and that decision cannot be
//! made from a string. [`FetchError::disposition`] *is* the decision: [`Disposition::Escalate`] for a
//! refusal, [`Disposition::Stop`] for everything else.
//!
//! The distinction that matters most is refusal-versus-transport, and it is the one easiest to get
//! wrong by collapsing both into "the fetch failed":
//!
//! - a **refusal** is the site saying *not like that*. A different client is the answer, so it
//!   escalates.
//! - a **transport error** is the site not answering — DNS, connect, TLS, a timeout. Escalating it
//!   launches a browser to look at a host that is down, and if that also fails it asks a *person* to
//!   look at a host that is down. Two expensive rungs spent on a dead DNS entry.
//!
//! A retry-on-anything ladder reads as robust and is actually a machine for burning the dear rungs.
//! So the kind of the error is the contract, and [`FetchError`] is deliberately not `Clone`-able into
//! a string before the ladder has read its disposition.

use crate::rung::RungKind;
use crate::target::TargetRefusal;

/// Why a site would not serve a page to an automated client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefusalReason {
    /// A challenge or interstitial page was served in place of content.
    ///
    /// `marker` names the *string* that identified it — never the page. The page is untrusted input,
    /// may be megabytes, and is evidence of nothing except its own text; putting it in an error is
    /// how attacker-controlled content reaches a log or a model.
    Challenge { marker: String },

    /// The site answered with a status that is a wall rather than an answer — a 403, a 429, a 503.
    Status { status: u16 },
}

impl std::fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefusalReason::Challenge { marker } => {
                write!(f, "a challenge page was served ({marker})")
            }
            RefusalReason::Status { status } => write!(f, "the site answered HTTP {status}"),
        }
    }
}

/// What a rung failed to do — and, in the type, whether that is worth a dearer rung.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The site said *not like that*. The one failure that escalates.
    #[error("the {rung} rung was refused: {reason}")]
    Refused {
        rung: RungKind,
        reason: RefusalReason,
    },

    /// The site never spoke: DNS, connect, TLS, reset, timeout. Not a bot wall.
    #[error("the {rung} rung could not reach the host: {reason}")]
    Transport { rung: RungKind, reason: String },

    /// The site answered with a status that is neither a page nor a wall — a 404, a 500. The site
    /// spoke; it just does not have this.
    #[error("the {rung} rung got HTTP {status}, which is neither a page nor a wall")]
    Http { rung: RungKind, status: u16 },

    /// The site answered with something that is not text — an image, a video, a zip.
    #[error("the {rung} rung got {content_type}, which is not text")]
    NotText {
        rung: RungKind,
        content_type: String,
    },

    /// The rung could not run at all: no browser binary, no human pane attached.
    #[error("the {rung} rung is unavailable: {reason}")]
    Unavailable { rung: RungKind, reason: String },

    /// A person was asked for help and the attempt ended without a page — a timeout, an abandoned
    /// challenge, or a challenge cleared whose page needs a driver this crate does not have.
    #[error("the interactive rung stopped: {reason}")]
    Interactive { reason: String },

    /// Admission refused the target. Carries the redacted form of what was refused.
    #[error(transparent)]
    Blocked(#[from] TargetRefusal),
}

/// What the ladder does with a rung's failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Try the next, dearer rung.
    Escalate,
    /// Stop, and report this failure as the outcome.
    Stop,
}

impl FetchError {
    /// Whether this failure is worth a dearer rung.
    pub fn disposition(&self) -> Disposition {
        match self {
            // The site said *not like that*: a different fingerprint is exactly what it is asking
            // for.
            FetchError::Refused { .. } => Disposition::Escalate,

            // The rung could not run. That is a capability gap rather than a verdict on the site —
            // a missing camoufox says nothing about whether a person could get the page — so the
            // ladder moves on, and the gap is reported so a caller can see it.
            FetchError::Unavailable { .. } => Disposition::Escalate,

            // The site never spoke. Escalating spends a browser, and then a person, on a host that
            // is down.
            FetchError::Transport { .. } => Disposition::Stop,

            // The site spoke and said "not this". A browser would get the same 404.
            FetchError::Http { .. } | FetchError::NotText { .. } => Disposition::Stop,

            // A person already looked. Asking again is a loop, and the interactive rung is the last
            // one anyway.
            FetchError::Interactive { .. } => Disposition::Stop,

            // A judgement about the *target*, not about the site's fingerprint. Pointing a browser
            // at a refused target is the same mistake with a bigger engine — and a browser pointed
            // at `file:///etc/passwd` is a local file read with extra steps.
            FetchError::Blocked(_) => Disposition::Stop,
        }
    }

    /// Which rung produced this, or `None` for a failure that never reached one.
    pub fn rung(&self) -> Option<RungKind> {
        match self {
            FetchError::Refused { rung, .. }
            | FetchError::Transport { rung, .. }
            | FetchError::Http { rung, .. }
            | FetchError::NotText { rung, .. }
            | FetchError::Unavailable { rung, .. } => Some(*rung),
            FetchError::Interactive { .. } | FetchError::Blocked(_) => None,
        }
    }

    /// True for the one failure that escalates. A shortcut for the common question, and the place a
    /// new variant gets classified rather than defaulted.
    pub fn is_refusal(&self) -> bool {
        self.disposition() == Disposition::Escalate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{BlockReason, TargetUrl};

    #[test]
    fn a_refusal_escalates_and_a_transport_error_does_not() {
        // The pair the whole design turns on. If these two ever classify the same way, the ladder is
        // either useless or expensive.
        let refused = FetchError::Refused {
            rung: RungKind::Http,
            reason: RefusalReason::Status { status: 403 },
        };
        let unreachable = FetchError::Transport {
            rung: RungKind::Http,
            reason: "dns failure".to_string(),
        };

        assert_eq!(refused.disposition(), Disposition::Escalate);
        assert_eq!(unreachable.disposition(), Disposition::Stop);
        assert!(refused.is_refusal());
        assert!(!unreachable.is_refusal());
    }

    #[test]
    fn an_http_status_and_a_non_text_body_stop_the_climb() {
        assert_eq!(
            FetchError::Http {
                rung: RungKind::Http,
                status: 404
            }
            .disposition(),
            Disposition::Stop
        );
        assert_eq!(
            FetchError::NotText {
                rung: RungKind::Http,
                content_type: "image/png".to_string()
            }
            .disposition(),
            Disposition::Stop
        );
    }

    #[test]
    fn an_unavailable_rung_continues_because_it_is_a_capability_gap_not_a_verdict() {
        let err = FetchError::Unavailable {
            rung: RungKind::Stealth,
            reason: "no camoufox on PATH".to_string(),
        };
        assert_eq!(err.disposition(), Disposition::Escalate);
        assert_eq!(err.rung(), Some(RungKind::Stealth));
        assert!(err.to_string().contains("no camoufox"), "{err}");
    }

    #[test]
    fn a_blocked_target_never_escalates() {
        // The security half of the decision: a refused target must not be laundered into a browser
        // fetch, which would be the same local-file read with a bigger engine.
        let blocked = FetchError::Blocked(TargetRefusal {
            reason: BlockReason::Scheme {
                scheme: "file".to_string(),
            },
            display: "file:///etc/passwd".to_string(),
        });
        assert_eq!(blocked.disposition(), Disposition::Stop);
        assert_eq!(blocked.rung(), None);
    }

    #[test]
    fn an_interactive_stop_never_escalates_because_a_person_already_looked() {
        let err = FetchError::Interactive {
            reason: "timed out after 120s".to_string(),
        };
        assert_eq!(err.disposition(), Disposition::Stop);
    }

    #[test]
    fn a_challenge_reason_names_the_marker_and_never_the_page() {
        // The marker is a string this crate chose to look for; the page is attacker-controlled text.
        let reason = RefusalReason::Challenge {
            marker: "cf-challenge".to_string(),
        };
        assert!(reason.to_string().contains("cf-challenge"), "{reason}");
        assert!(RefusalReason::Status { status: 503 }
            .to_string()
            .contains("503"));
    }

    #[test]
    fn a_rung_is_known_for_every_failure_that_happened_on_one() {
        assert_eq!(
            FetchError::Refused {
                rung: RungKind::Interactive,
                reason: RefusalReason::Status { status: 403 }
            }
            .rung(),
            Some(RungKind::Interactive)
        );
        assert_eq!(
            FetchError::Transport {
                rung: RungKind::Stealth,
                reason: "reset".into()
            }
            .rung(),
            Some(RungKind::Stealth)
        );
    }

    #[test]
    fn a_blocked_error_carries_the_redacted_display_rather_than_the_raw_url() {
        // A `FetchError` is formatted into a report a model reads, and `Blocked` is the one variant
        // that carries a URL. It carries the admission refusal's redacted display.
        let err = FetchError::Blocked(
            TargetUrl::parse("http://169.254.169.254/latest?token=SECRETVALUE")
                .expect_err("a link-local address is refused"),
        );
        assert!(!err.to_string().contains("SECRETVALUE"), "{err}");
        assert!(!format!("{err:?}").contains("SECRETVALUE"), "{err:?}");
        assert!(err.to_string().contains("169.254.169.254"), "{err}");
        assert_eq!(err.disposition(), Disposition::Stop);
    }
}

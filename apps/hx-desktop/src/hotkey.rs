//! Global hotkey — a system-wide shortcut that summons the window.
//!
//! ## Headless testing limits
//!
//! A global shortcut is registered with the OS desktop session; a headless environment has no
//! display server and no way to assert that the OS accepted or refused a binding. So the **two
//! things that are testable without a display** are separated out and asserted directly:
//!
//! 1. **String parsing** — a raw shortcut like `"Control+Shift+Space"` either parses into a
//!    [`Shortcut`] or is rejected with a named reason. Pure; no OS involved.
//! 2. **Outcome handling** — when the OS *refuses* a binding (the shortcut is already taken, or the
//!    compositor will not grant it), the refusal must be **surfaced**, never silently swallowed. The
//!    registration sits behind the [`HotkeyBackend`] trait so a fake backend can refuse on demand, and
//!    [`attempt_registration`] maps that refusal to a [`HotkeyOutcome::Refused`] the caller must
//!    acknowledge.
//!
//! What is **not** tested here: that the real plugin actually installs a working binding with the
//! compositor. That is a live desktop-session concern and cannot run headless; [`register_plugin_shortcut`]
//! is the real path and is only compiled, never exercised in CI.

use tauri::{AppHandle, Runtime};

use crate::tray::show_main_window;

/// A parsed global-shortcut specification. Re-exported from the global-shortcut plugin so a caller
/// never has to depend on the underlying `global_hotkey` crate directly.
pub type Shortcut = tauri_plugin_global_shortcut::Shortcut;

/// Where a raw shortcut string is installed. The OS may refuse the binding, and that refusal is
/// returned rather than swallowed.
///
/// Implemented by a fake in tests and by a thin adapter over the Tauri plugin in production.
pub trait HotkeyBackend {
    /// Attempt to register `parsed` with the OS. `Ok(())` means the OS accepted the binding;
    /// `Err(reason)` is the surfaced refusal.
    fn try_register(&self, parsed: &Shortcut) -> Result<(), String>;
}

/// The outcome of attempting to install a global shortcut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HotkeyOutcome {
    /// The OS accepted the binding. Carries the canonical string form of the shortcut.
    Registered(String),
    /// The OS refused the binding — it is already taken, or the environment will not grant it.
    /// The reason is surfaced so the caller can tell the user, because a hotkey that silently fails
    /// to register is worse than none.
    Refused {
        /// The canonical string form of the shortcut that was refused.
        spec: String,
        /// Why the OS refused it.
        reason: String,
    },
}

/// A hotkey string could not even be parsed, so no registration was attempted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HotkeyError {
    #[error("invalid hotkey '{0}': {1}")]
    Invalid(String, String),
}

/// Parse a raw hotkey string and attempt to register it, surfacing a refusal.
///
/// This is the whole decision, factored out of the plugin wiring so a fake backend can prove the
/// refusal is surfaced and not swallowed:
/// - a string that does not parse is a [`HotkeyError::Invalid`];
/// - a parseable string the OS refuses is [`HotkeyOutcome::Refused`] **with the reason** — it is
///   never dropped, and never re-reported as [`HotkeyOutcome::Registered`];
/// - a parseable string the OS accepts is [`HotkeyOutcome::Registered`].
pub fn attempt_registration(
    raw: &str,
    backend: &dyn HotkeyBackend,
) -> Result<HotkeyOutcome, HotkeyError> {
    let parsed: Shortcut = raw
        .parse()
        .map_err(|e: <Shortcut as std::str::FromStr>::Err| {
            HotkeyError::Invalid(raw.to_string(), e.to_string())
        })?;
    match backend.try_register(&parsed) {
        Ok(()) => Ok(HotkeyOutcome::Registered(parsed.into_string())),
        Err(reason) => Ok(HotkeyOutcome::Refused {
            spec: parsed.into_string(),
            reason,
        }),
    }
}

/// The production adapters: the real global-shortcut plugin, owned by an [`AppHandle`].
struct PluginHotkeyBackend<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> HotkeyBackend for PluginHotkeyBackend<R> {
    fn try_register(&self, parsed: &Shortcut) -> Result<(), String> {
        use tauri_plugin_global_shortcut::GlobalShortcutExt;
        let summon_app = self.app.clone();
        self.app
            .global_shortcut()
            .on_shortcut(*parsed, move |app, _shortcut, _event| {
                show_main_window(app);
                let _ = summon_app;
            })
            .map_err(|e| e.to_string())
    }
}

/// Register `raw` with the real global-shortcut plugin, degrading gracefully.
///
/// A refused or unparseable binding returns a [`HotkeyOutcome`] the caller **must** report (log / warn)
/// rather than treat as success. It never prevents the window from starting — a missing hotkey degrades to a
/// working window with a reported warning, which is the contract this crate promises.
pub fn register_plugin_shortcut<R: Runtime>(app: &AppHandle<R>, raw: &str) -> HotkeyOutcome {
    match attempt_registration(raw, &PluginHotkeyBackend { app: app.clone() }) {
        Ok(outcome) => outcome,
        Err(HotkeyError::Invalid(spec, reason)) => HotkeyOutcome::Refused { spec, reason },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend that records what it was asked to install and answers on demand.
    struct ScriptedBackend {
        /// `Some(reason)` makes every registration attempt refuse with that reason.
        refuse_with: Option<&'static str>,
        attempts: std::cell::RefCell<Vec<String>>,
    }

    impl HotkeyBackend for ScriptedBackend {
        fn try_register(&self, parsed: &Shortcut) -> Result<(), String> {
            self.attempts.borrow_mut().push(parsed.into_string());
            match self.refuse_with {
                Some(reason) => Err(reason.to_string()),
                None => Ok(()),
            }
        }
    }

    #[test]
    fn a_refused_hotkey_binding_is_surfaced_not_swallowed() {
        // The whole point of this module: when the OS refuses a binding, the outcome must be Refused with
        // the reason, not Registered and not silently dropped.
        let backend = ScriptedBackend {
            refuse_with: Some("the shortcut is already in use by another application"),
            attempts: std::cell::RefCell::new(Vec::new()),
        };
        let outcome = attempt_registration("Control+Shift+Space", &backend)
            .expect("a parseable string must not be an error even when refused");
        match outcome {
            HotkeyOutcome::Refused { spec, reason } => {
                assert_eq!(
                    reason,
                    "the shortcut is already in use by another application"
                );
                // The surfaced spec is the shortcut that was refused, and stays parseable.
                assert!(
                    spec.parse::<Shortcut>().is_ok(),
                    "the surfaced spec must be a real shortcut: {spec}"
                );
            }
            other => panic!("expected Refused, got: {other:?}"),
        }
        // And it really did attempt the binding — it was refused, not skipped.
        assert_eq!(
            *backend.attempts.borrow(),
            vec!["shift+control+Space".to_string()]
        );
    }

    #[test]
    fn a_registered_hotkey_returns_the_canonical_string() {
        let backend = ScriptedBackend {
            refuse_with: None,
            attempts: std::cell::RefCell::new(Vec::new()),
        };
        let outcome = attempt_registration("Control+Shift+H", &backend)
            .expect("a parseable, accepted string must not be an error");
        assert!(matches!(outcome, HotkeyOutcome::Registered(_)));
        if let HotkeyOutcome::Registered(canonical) = outcome {
            // The canonical form round-trips and re-parses.
            let reparsed: Shortcut = canonical
                .parse()
                .expect("canonical form must stay parseable");
            assert_eq!(reparsed.into_string(), canonical);
        }
    }

    #[test]
    fn an_invalid_hotkey_string_is_an_error_named_by_reason() {
        // A string that cannot be a hotkey at all is an error, not a refusal — there is nothing to
        // register, so there is nothing to report as refused.
        let backend = ScriptedBackend {
            refuse_with: None,
            attempts: std::cell::RefCell::new(Vec::new()),
        };
        let err = attempt_registration("not a hotkey at all", &backend)
            .expect_err("garbage must be an error");
        assert!(matches!(err, HotkeyError::Invalid(_, _)));
        // Nothing was even attempted against the backend.
        assert!(backend.attempts.borrow().is_empty());
    }
}

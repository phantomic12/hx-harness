//! Native file picker — an OS dialog to point the app at a workspace directory.
//!
//! A user should be able to *choose* a workspace directory with the OS dialog rather than typing a
//! path. This module follows the same shape as the tray, hotkey and notification: the **decision
//! logic is a pure, headlessly-testable core**, and the OS dialog is a **thin shell** around it.
//!
//! ## The pure core
//!
//! [`decide_picker`] takes the dialog's answer — an optional absolute path — and a validity check,
//! and returns a [`PickerDecision`]:
//!
//! - A **cancelled** dialog (no path) is **not an error** and must not be reported as one — it
//!   maps to [`PickerRefusal::Cancelled`], leaving the previous workspace unchanged.
//! - A chosen path is validated against the **same rule the rest of the app uses for a workspace
//!   root**: a workspace root is, at minimum, a non-empty host path that is a real directory (the
//!   sandbox spec's `workspace_host_path` rule, `crates/hx-sandbox/src/spec.rs`). A chosen
//!   path that is blank or not a valid workspace root maps to [`PickerRefusal::Invalid`] and leaves
//!   the previous workspace unchanged.
//! - A valid choice maps to [`PickerDecision::Choose`] with the path, which the caller applies as the
//!   new workspace.
//!
//! The validity check is **injected** ([`decide_picker`]'s `is_valid_workspace` argument) so
//! the whole decision — including the not-a-directory case — is testable headlessly without touching the
//! filesystem. [`is_workspace_root`] is the production check it is normally fed.
//!
//! ## Headless testing limits
//!
//! The dialog itself is an OS dialog (a portal / GTK host); it needs a live desktop session and
//! cannot be exercised in CI. What is asserted here is the decision logic over scripted dialog answers.
//! The real path [`run_picker`] / [`plugin_picker`] is thin and only compiles here, exactly as
//! `build_tray` and `register_plugin_shortcut` are not exercised.
//!
//! ## Degradation
//!
//! If the picker **cannot run** — headless, or the platform lacks a dialog — [`run_picker`] returns
//! [`PickerRun::Unavailable`] with the reason. The caller reports a warning and continues with a
//! working window; a missing picker must never prevent the app from starting. This is the same
//! degrade-to-a-working-window contract the tray, hotkey and notification already keep.

use std::path::Path;

/// Why the picker is leaving the workspace unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PickerRefusal {
    /// The dialog was cancelled / dismissed. Expected — **not an error**, reported as nothing more
    /// than a note, and never reported as a failure. The previous workspace stays unchanged.
    Cancelled,
    /// A path was chosen but it is not a usable workspace root (blank, or not a directory).
    /// The previous workspace stays unchanged, and the caller should tell the user why.
    Invalid,
}

/// What the picker decided, as a pure function of the dialog's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PickerDecision {
    /// Accept `path` as the new workspace root.
    Choose(String),
    /// Keep the previous workspace, for the named reason.
    Keep(PickerRefusal),
}

impl PickerDecision {
    /// The path to apply as the new workspace, if any — `None` on every refused or cancelled path.
    pub fn chosen(&self) -> Option<&str> {
        match self {
            Self::Choose(p) => Some(p.as_str()),
            Self::Keep(_) => None,
        }
    }

    /// Whether this decision is a silent keep — the dialog was simply dismissed.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Keep(PickerRefusal::Cancelled))
    }
}

/// The production check for a usable workspace root.
///
/// This reuses the rule the rest of the app uses for a workspace root (`crates/hx-sandbox`'s
/// `workspace_host_path`): a workspace root is a **non-empty** host path that is a **real directory**
/// that exists on disk. A blank or non-directory path is rejected rather than accepted as a workspace.
pub fn is_workspace_root(path: &str) -> bool {
    !path.trim().is_empty() && Path::new(path.trim()).is_dir()
}

/// The pure decision: what to do with the dialog's answer.
///
/// - `None` (the dialog returned no path) is a **cancel** — expected, not an error, and it keeps
///   the previous workspace.
/// - `Some(path)` is validated against `is_valid_workspace`; a path that fails is an
///   [`PickerRefusal::Invalid`] (still leaves the previous workspace unchanged); a passing path is
///   [`PickerDecision::Choose`].
///
/// The check is injected so the not-a-directory and blank cases are testable headlessly. Production
/// feeds [`is_workspace_root`].
pub fn decide_picker(
    chosen: Option<&str>,
    is_valid_workspace: impl Fn(&str) -> bool,
) -> PickerDecision {
    match chosen {
        None => PickerDecision::Keep(PickerRefusal::Cancelled),
        Some(path) => {
            let trimmed = path.trim();
            if trimmed.is_empty() || !is_valid_workspace(trimmed) {
                PickerDecision::Keep(PickerRefusal::Invalid)
            } else {
                PickerDecision::Choose(trimmed.to_string())
            }
        }
    }
}

/// The OS dialog, behind a trait so a fake can script its answers headlessly.
///
/// Implemented by a fake in tests and by the Tauri dialog plugin in production.
pub trait PickerBackend {
    /// Show a folder-selection dialog. `Ok(Some(path))` is a chosen absolute path;
    /// `Ok(None)` is a cancel — expected; `Err(reason)` is the dialog failing to run (headless, or
    /// the platform provides no dialog).
    fn pick_directory(&self) -> Result<Option<String>, String>;
}

/// How a picker run resolved when the real dialog was used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PickerRun {
    /// The dialog ran and produced a (possibly cancelled / rejected) decision.
    Decided(PickerDecision),
    /// The dialog could not run at all; the caller must report a warning and carry on with a
    /// working window.
    Unavailable(String),
}

/// Run a picker through any [`PickerBackend`] and fold the result into a run-level outcome.
///
/// A dialog that *runs* — even one that returns a rejected or cancelled choice — is
/// [`PickerRun::Decided`]; only a dialog that **cannot run** is [`PickerRun::Unavailable`], which
/// the caller degrades on with a warning.
pub fn run_picker(
    backend: &dyn PickerBackend,
    is_valid_workspace: impl Fn(&str) -> bool,
) -> PickerRun {
    match backend.pick_directory() {
        Ok(chosen) => PickerRun::Decided(decide_picker(chosen.as_deref(), is_valid_workspace)),
        Err(reason) => PickerRun::Unavailable(reason),
    }
}

/// The production adapter: the Tauri dialog plugin, owned by an [`tauri::AppHandle`].
struct PluginPickerBackend<R: tauri::Runtime> {
    app: tauri::AppHandle<R>,
}

impl<R: tauri::Runtime> PickerBackend for PluginPickerBackend<R> {
    fn pick_directory(&self) -> Result<Option<String>, String> {
        use tauri_plugin_dialog::DialogExt;
        self.app
            .dialog()
            .file()
            .blocking_pick_folder()
            .map(|path| {
                path.into_path()
                    .map(|p| p.display().to_string())
                    .map_err(|e| e.to_string())
            })
            .transpose()
    }
}

/// Show the real OS folder picker and fold the result, degrading gracefully.
///
/// The dialog requires a live desktop session (a portal / GTK host); headless or on a platform
/// without a dialog it returns [`PickerRun::Unavailable`], which the caller must report as a warning
/// and continue with a working window — a missing picker never prevents the app from starting. The dialog
/// itself is not exercised in CI; the decision it feeds [`decide_picker`] is.
pub fn plugin_picker<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> PickerRun {
    run_picker(&PluginPickerBackend { app: app.clone() }, is_workspace_root)
}

/// A convenience for callers: run the real picker, apply a chosen workspace, or degrade.
///
/// Returns `Some(path)` when the user chose a valid workspace, `None` on cancel / rejection, and
/// reports an unavailable dialog as a returned error-reason the caller can warn on. The previous
/// workspace is left unchanged in every `None`/degraded case, which is the contract this module
/// promises.
pub fn choose_workspace<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
) -> Result<Option<String>, String> {
    match plugin_picker(app) {
        PickerRun::Decided(PickerDecision::Choose(path)) => Ok(Some(path)),
        // Cancelled or invalid: the previous workspace is unchanged, and neither is an error.
        PickerRun::Decided(PickerDecision::Keep(_)) => Ok(None),
        PickerRun::Unavailable(reason) => Err(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend whose answers are scripted.
    struct ScriptedBackend {
        answer: Result<Option<String>, String>,
    }

    impl PickerBackend for ScriptedBackend {
        fn pick_directory(&self) -> Result<Option<String>, String> {
            self.answer.clone()
        }
    }

    /// A validity check that accepts a directory path and refuses everything else — the headless stand-in
    /// for the filesystem `is_dir` the production code uses.
    fn valid_dir(path: &str) -> bool {
        path.starts_with("/ws/")
    }

    #[test]
    fn a_cancelled_dialog_is_not_an_error_and_changes_nothing() {
        // The whole point: cancel is expected, not a failure, and it must not produce a path.
        let out = run_picker(&ScriptedBackend { answer: Ok(None) }, valid_dir);
        match out {
            PickerRun::Decided(decision) => {
                assert!(decision.is_cancelled(), "a cancel must be a silent keep");
                assert_eq!(decision.chosen(), None);
            }
            other => panic!("a running dialog must be Decided, got: {other:?}"),
        }
    }

    #[test]
    fn a_chosen_valid_directory_is_used_as_the_new_workspace() {
        let out = run_picker(
            &ScriptedBackend {
                answer: Ok(Some("/ws/alpha".to_string())),
            },
            valid_dir,
        );
        assert_eq!(
            out,
            PickerRun::Decided(PickerDecision::Choose("/ws/alpha".to_string()))
        );
    }

    #[test]
    fn a_chosen_path_that_is_not_a_directory_keeps_the_previous_workspace() {
        // The brief's explicit case: a chosen path that is not a directory must be refused (kept
        // previous), never silently adopted.
        let out = run_picker(
            &ScriptedBackend {
                answer: Ok(Some("/not/a/dir".to_string())),
            },
            valid_dir,
        );
        match out {
            PickerRun::Decided(decision) => {
                assert_eq!(
                    decision,
                    PickerDecision::Keep(PickerRefusal::Invalid),
                    "a non-directory must be refused, not chosen"
                );
                assert_eq!(decision.chosen(), None);
                assert!(!decision.is_cancelled());
            }
            other => panic!("a running dialog must be Decided, got: {other:?}"),
        }
    }

    #[test]
    fn a_blank_chosen_path_is_refused_not_whitespace_accepted() {
        // A path of only whitespace must not become a workspace root. The trim happens once, in the
        // decision, so a blank string is Invalid rather than an accidental empty workspace.
        let out = run_picker(
            &ScriptedBackend {
                answer: Ok(Some("   ".to_string())),
            },
            valid_dir,
        );
        assert_eq!(
            out,
            PickerRun::Decided(PickerDecision::Keep(PickerRefusal::Invalid))
        );
    }

    #[test]
    fn an_unavailable_dialog_is_reported_and_changes_nothing() {
        // Headless or no dialog backend: the caller must learn of it (and can warn) and continue
        // with a working window — it is not a swallow and not a fake success.
        let out = run_picker(
            &ScriptedBackend {
                answer: Err("no display server".to_string()),
            },
            valid_dir,
        );
        assert_eq!(out, PickerRun::Unavailable("no display server".to_string()));
    }

    #[test]
    fn the_validity_check_is_what_decides_between_choose_and_invalid() {
        // The same path can be Choose under one validity rule and Invalid under another — proving the
        // decision depends on the injected check, not on the raw string.
        let path = "/ws/beta";
        assert_eq!(
            decide_picker(Some(path), |_| true),
            PickerDecision::Choose(path.to_string())
        );
        assert_eq!(
            decide_picker(Some(path), |_| false),
            PickerDecision::Keep(PickerRefusal::Invalid)
        );
    }

    #[test]
    fn is_workspace_root_accepts_a_real_directory_and_refuses_the_rest() {
        // The production check: a real, existing directory is a valid workspace root; a blank path or a
        // non-directory is not. Exercised here over a temporary directory.
        let dir = tempfile::tempdir().expect("a temp dir for the workspace-root check");
        let valid = dir.path().display().to_string();
        assert!(
            is_workspace_root(&valid),
            "a real directory is a valid workspace root"
        );

        assert!(
            !is_workspace_root(""),
            "a blank path is not a workspace root"
        );
        assert!(
            !is_workspace_root(&format!("{}/does-not-exist", valid)),
            "a non-existent path is not a workspace root"
        );

        // A real file is not a directory, so it is not a workspace root either.
        let file = dir.path().join("f.txt");
        std::fs::write(&file, b"x").expect("write the probe file");
        assert!(
            !is_workspace_root(file.to_string_lossy().as_ref()),
            "a file is not a directory, so not a workspace root"
        );
    }
}

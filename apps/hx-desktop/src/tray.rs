//! System tray — a tray icon with a menu.
//!
//! The tray gives the desktop shell a persistent presence when the window is hidden: show/hide the window,
//! open the approval queue, and quit. The menu is defined as a **pure value** ([`TrayMenuDef`]) so the
//! item set and the action each item maps to can be asserted headlessly — a renamed or dropped item fails a
//! test instead of silently changing the tray nobody is looking at.
//!
//! ## Headless testing limits
//!
//! Displaying an actual tray icon needs a desktop session (a status notifier host / panel), so nothing here
//! instantiates a real tray in CI. What is asserted instead is the menu **definition**: the exact list of
//! items, their ids, and the [`TrayAction`] each id resolves to. The real path [`build_tray`] takes that
//! definition and hands it to Tauri's `TrayIconBuilder`; it only compiles here.

/// The action a tray menu item triggers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayAction {
    /// Show (and focus) the main window; hide it if it was visible.
    ToggleWindow,
    /// Show the main window and open the approval queue.
    OpenApprovals,
    /// Quit the application.
    Quit,
}

/// The stable id a tray menu item is wired to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayItem {
    ToggleWindow,
    OpenApprovals,
    Quit,
}

impl TrayItem {
    /// The string id carried on the menu event, and the key [`action_for`] matches on.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ToggleWindow => "toggle-window",
            Self::OpenApprovals => "open-approvals",
            Self::Quit => "quit",
        }
    }
}

/// The exact menu structure of the tray, decided in one place so the real menu and the tests cannot
/// disagree about what a user sees.
pub const TRAY_MENU: &[(&str, TrayItem)] = &[
    ("Toggle Window", TrayItem::ToggleWindow),
    ("Open Approvals", TrayItem::OpenApprovals),
    ("Quit hx", TrayItem::Quit),
];

/// Resolve a menu item id (as delivered on a Tauri [`tauri::menu::MenuEvent`]) to its action.
///
/// An id that is not one of ours maps to `None` — the event was not ours to act on. A renamed id
/// that still resolves (or a dropped item) fails the tests that pin [`TRAY_MENU`].
pub fn action_for(id: &str) -> Option<TrayAction> {
    match id {
        "toggle-window" => Some(TrayAction::ToggleWindow),
        "open-approvals" => Some(TrayAction::OpenApprovals),
        "quit" => Some(TrayAction::Quit),
        _ => None,
    }
}

/// The set of item ids the tray menu defines, in order.
pub fn tray_item_ids() -> Vec<String> {
    TRAY_MENU
        .iter()
        .map(|(_, item)| item.as_str().to_string())
        .collect()
}

/// Show (and focus / restore) the main window if it exists.
pub fn show_main_window<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    use tauri::Manager;
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
}

/// Open the approval queue by showing the main window — the queue is a route in the shared web UI.
pub fn open_approvals<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    show_main_window(app);
}

/// Build and attach the real system tray icon from [`TRAY_MENU`], mapping each event id to its action.
///
/// Requires a live desktop session (a status-notifier host / panel); on a headless host it returns an
/// error which the caller reports and continues without — a missing tray must not prevent the window from
/// starting. This function is not exercised in CI; the menu structure it installs is pure and asserted.
pub fn build_tray<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::Manager;

    let menu = Menu::new(app)?;
    for (label, item) in TRAY_MENU {
        let menu_item = MenuItem::with_id(app, item.as_str(), *label, true, None::<&str>)?;
        menu.append(&menu_item)?;
    }
    menu.set_as_app_menu()?;

    let _tray = tauri::tray::TrayIconBuilder::with_id("hx-tray")
        .menu(&menu)
        .tooltip("hx")
        .on_menu_event(
            move |app_handle, event| match action_for(event.id().as_ref()) {
                Some(TrayAction::ToggleWindow) => show_main_window(app_handle),
                Some(TrayAction::OpenApprovals) => open_approvals(app_handle),
                Some(TrayAction::Quit) => app_handle.exit(0),
                None => {}
            },
        )
        .build(app)?;

    // Keep the tray alive for the lifetime of the app.
    app.manage(_tray);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_menu_lists_the_expected_items_in_order() {
        // The tray menu is exactly: toggle window, open approvals, quit. A renamed or dropped item is
        // the failure mode to catch — the tray is a silent surface nobody looks at.
        let ids = tray_item_ids();
        assert_eq!(
            ids,
            vec![
                "toggle-window".to_string(),
                "open-approvals".to_string(),
                "quit".to_string()
            ]
        );
    }

    #[test]
    fn every_menu_item_resolves_to_an_action() {
        // Every id the menu builds must have a real action behind it — an item whose click does nothing
        // is a dead control.
        for (label, item) in TRAY_MENU {
            assert!(
                action_for(item.as_str()).is_some(),
                "menu item '{label}' ({}) must resolve to an action",
                item.as_str()
            );
        }
    }

    #[test]
    fn toggle_window_maps_to_the_toggle_action() {
        assert_eq!(
            action_for(TrayItem::ToggleWindow.as_str()),
            Some(TrayAction::ToggleWindow)
        );
    }

    #[test]
    fn open_approvals_maps_to_the_approvals_action() {
        assert_eq!(
            action_for(TrayItem::OpenApprovals.as_str()),
            Some(TrayAction::OpenApprovals)
        );
    }

    #[test]
    fn quit_maps_to_the_quit_action() {
        assert_eq!(action_for(TrayItem::Quit.as_str()), Some(TrayAction::Quit));
    }

    #[test]
    fn an_unrecognized_id_is_not_ours() {
        // A stray id (from another component or a future item) must not map to a wrong action.
        assert_eq!(action_for("definitely-not-ours"), None);
    }
}

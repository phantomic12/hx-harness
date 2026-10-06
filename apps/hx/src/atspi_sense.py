#!/usr/bin/env python3
"""Walk the AT-SPI desktop tree and print a JSON frame for `hx drive --gui`.

Output: {"text": "<human-readable screen>", "elements": [{"id","role","name",
"x","y","w","h","text"}]} — elements are the actionable widgets (buttons,
fields, menu items, links) with absolute screen coordinates, so the driver
can click the one the model picks.
"""
import argparse
import json
import sys

import pyatspi

# Roles worth offering as click targets — everything a person can press,
# check, pick from, or type into.
ACTIONABLE = {
    "push button", "toggle button", "check box", "radio button",
    "menu item", "radio menu item", "check menu item",
    "text", "entry", "password text", "combo box", "spin button",
    "list item", "link", "page tab", "menu", "tree item", "table cell",
    "slider", "split button",
}
# Roles whose *contents* belong in the screen text (what the user can read).
TEXTY = {"text", "entry", "password text", "terminal", "document frame",
         "document web", "paragraph", "label", "static"}


def walk(node, app_name, out, elements, cap, depth=0, max_depth=12,
         skip_roles=frozenset()):
    if depth > max_depth or len(elements) >= cap:
        return
    try:
        role = node.getRoleName()
    except Exception:
        role = ""
    if role in skip_roles:
        # Skip the element AND its subtree — uniform grid rows (file lists,
        # big tables) would otherwise flood the element cap and the model's
        # context with rows it never needs to click.
        return
    try:
        name = node.name or ""
    except Exception:
        name = ""
    try:
        st = node.getState()
        showing = st.contains(pyatspi.STATE_SHOWING)
    except Exception:
        showing = True
    try:
        ext = node.queryComponent().getExtents(pyatspi.XY_SCREEN)
        x, y, w, h = ext.x, ext.y, ext.width, ext.height
    except Exception:
        x = y = w = h = 0

    snippet = ""
    if role in TEXTY or (role in ACTIONABLE and not name):
        try:
            t = node.queryText()
            snippet = (t.getText(0, 300) or "").strip().replace("\n", " ")
        except Exception:
            snippet = ""

    # A showing drop-down is the only reliable signal a menu is open — its
    # items are indistinguishable from same-named toolbar buttons otherwise.
    # The popup is unnamed; its parent (e.g. the 'File' menubar item) names it.
    if role in ("menu", "popup menu") and showing:
        owner = name
        if not owner:
            try:
                owner = node.parent.name or ""
            except Exception:
                owner = ""
        out.append(f"    drop-down menu under {owner or '?'} is open:")

    if role in ACTIONABLE and showing and w > 0 and h > 0 and x >= 0 and y >= 0:
        eid = f"e{len(elements)}"
        elements.append(
            {"id": eid, "role": role, "name": name, "x": x, "y": y,
             "w": w, "h": h, "text": snippet[:120]}
        )
        line = f"[{eid}] {role} {name!r} at ({x},{y})"
        if snippet:
            line += f" — shows {snippet[:80]!r}"
        out.append(line)
    elif role in TEXTY and (name or snippet):
        out.append(f"    {role} shows {name or snippet[:80]!r}")

    try:
        n = node.childCount
    except Exception:
        n = 0
    for i in range(min(n, 40)):
        try:
            walk(node.getChildAtIndex(i), app_name, out, elements, cap,
                 depth + 1, max_depth, skip_roles)
        except Exception:
            continue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", default="", help="case-insensitive app name filter")
    ap.add_argument(
        "--window",
        default="",
        help="only descend into frames whose name contains this "
        "(case-insensitive); when no frame matches, the whole app is "
        "walked — sensing a dialog window while it is up and the app "
        "again once it closes",
    )
    ap.add_argument("--max", type=int, default=18)
    ap.add_argument(
        "--skip-roles",
        default="",
        help="comma-separated roles to drop with their subtrees — e.g. "
        "'table cell,list item' shrinks a file chooser's row grid",
    )
    args = ap.parse_args()
    skip = frozenset(r.strip() for r in args.skip_roles.split(",") if r.strip())

    desktop = pyatspi.Registry.getDesktop(0)
    out, elements = [], []
    for i in range(desktop.childCount):
        app = desktop.getChildAtIndex(i)
        try:
            name = app.name or ""
        except Exception:
            name = ""
        if args.app and args.app.lower() not in name.lower():
            continue
        out.append(f"# app {name!r}")
        if args.window:
            matched = False
            try:
                n = app.childCount
            except Exception:
                n = 0
            for c in range(n):
                try:
                    frame = app.getChildAtIndex(c)
                    fname = frame.name or ""
                except Exception:
                    continue
                if args.window.lower() in fname.lower():
                    matched = True
                    walk(frame, name, out, elements, args.max,
                         skip_roles=skip)
            if matched:
                continue
        walk(app, name, out, elements, args.max, skip_roles=skip)
    json.dump({"text": "\n".join(out), "elements": elements}, sys.stdout)


if __name__ == "__main__":
    main()

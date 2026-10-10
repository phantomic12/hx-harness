#!/bin/bash
# Verify: an article is showing — a page-tab and document-web share a title
# that is not any of the non-article pages (homepage/restore/welcome/newtab).
export DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1000/bus"
python3 - <<'EOF'
import sys, json, re, subprocess
out = subprocess.run(
    ["python3", "/home/ubuntu/laya-work/apps/hx/src/atspi_sense.py",
     "--app", "firefox", "--max", "40"],
    capture_output=True, text=True).stdout
try:
    text = json.loads(out).get("text", "")
except Exception:
    sys.exit(1)
tabs = re.findall(r"page tab '([^']+)'", text)
docs = re.findall(r"document web shows '([^']+)'", text)
DENY = ("Breaking News", "Restore Session", "Welcome to Firefox", "New Tab",
        "Mozilla Firefox", "Firefox Privacy Notice", "about:")
docs_joined = "|".join(docs)
bad = lambda t: any(d in t for d in DENY) or len(t) < 8
ok = any(t[:30] in docs_joined and not bad(t) for t in tabs)
sys.exit(0 if ok else 1)
EOF

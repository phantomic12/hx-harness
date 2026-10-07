#!/usr/bin/env python3
"""OSWorld-adapted drive queue: run each task's setup, drive, and verifier.

Mirrors OSWorld's own shape — a setup fixture, an agent phase (hx drive),
and an execution-based evaluation (verify.sh reads the filesystem/process
state, not the agent's claims). Each task dir holds:

    task.json   — the hx drive spec
    setup.sh    — fixture + app launch (runs before the drive)
    verify.sh   — exit 0 = task accomplished

Usage: run_queue.py [queue-dir] [--only name,name] [--timeout secs]
Writes scorecard.md + per-task <name>.log beside this script.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

HX = "/home/ubuntu/laya-work/target/debug/hx"
HX_CWD = "/home/ubuntu/laya-work"  # hx.yaml lives here
HERE = Path(__file__).resolve().parent


def run(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)


def main():
    queue_dir = HERE
    only = None
    timeout = 180
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--only":
            only = set(args[i + 1].split(","))
            i += 2
        elif args[i] == "--timeout":
            timeout = int(args[i + 1])
            i += 2
        else:
            queue_dir = Path(args[i]).resolve()
            i += 1

    tasks = sorted(
        d for d in queue_dir.iterdir()
        if d.is_dir() and (d / "task.json").exists()
    )
    if only:
        tasks = [t for t in tasks if t.name in only]
    if not tasks:
        sys.exit("no tasks found")

    env = dict(os.environ)
    env.setdefault("DISPLAY", ":0")
    env.setdefault("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")

    rows = []
    for task in tasks:
        name = task.name
        log = task / f"{name}.log"
        print(f"== {name}")
        with log.open("w") as lf:
            setup = run(f"bash {task/'setup.sh'}", env=env, timeout=60)
            lf.write(f"--- setup (rc={setup.returncode})\n{setup.stdout}{setup.stderr}\n")
            t0 = time.time()
            try:
                drive = subprocess.run(
                    [HX, "drive", str(task / "task.json")],
                    capture_output=True, text=True, env=env, timeout=timeout,
                    cwd=HX_CWD,
                )
                drive_out = drive.stdout + drive.stderr
                outcome = "done" if "done —" in drive_out or ": done" in drive_out else "stopped"
            except subprocess.TimeoutExpired as e:
                drive_out = (e.stdout or "") + (e.stderr or "")
                drive_out = drive_out.decode() if isinstance(drive_out, bytes) else drive_out
                outcome = "timeout"
            elapsed = time.time() - t0
            verify = run(f"bash {task/'verify.sh'}", env=env, timeout=60)
            passed = verify.returncode == 0
            lf.write(f"--- drive (outcome={outcome}, {elapsed:.1f}s)\n{drive_out}\n")
            lf.write(f"--- verify (pass={passed})\n{verify.stdout}{verify.stderr}\n")
        rows.append((name, outcome, passed, elapsed))
        print(f"   {outcome:<8} verify={'PASS' if passed else 'FAIL'}  {elapsed:.1f}s")

    passed_n = sum(1 for r in rows if r[2])
    lines = [
        "# Drive queue scorecard",
        "",
        f"{passed_n}/{len(rows)} tasks verified",
        "",
        "| task | drive outcome | verified | time |",
        "|---|---|---|---|",
    ]
    for name, outcome, passed, elapsed in rows:
        lines.append(f"| {name} | {outcome} | {'PASS' if passed else 'FAIL'} | {elapsed:.1f}s |")
    (HERE / "scorecard.md").write_text("\n".join(lines) + "\n")
    print(f"\n{passed_n}/{len(rows)} verified — scorecard.md")


if __name__ == "__main__":
    main()

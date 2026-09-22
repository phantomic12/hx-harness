# Devlog

Working notes on how this project is built and shipped. The policy record is `ROADMAP.md`
(what we are building) and `TESTING.md` (what is verified); this file is the *why* behind
the way we work. One invariant runs through all three.

## The invariant: verified means it ran, for real

A feature is not "done" when its unit tests pass. Unit tests prove the logic is coherent
in-process — nothing more. A feature is done when it has **reached the other side of the seam**:
a real model answered it, a real daemon enforced it, a real container held it, a real release
installed it.

This is the gap TESTING.md's audit exposed and keeps codifying as four tiers:

| Tier | Meaning |
|---|---|
| **A — Executed** | Ran for real against a real service, output observed |
| **B — Unit-tested** | Pure logic asserted in-process, I/O replaced by fakes |
| **C — Compiles only** | Real call sites no test ever reaches |
| **D — Absent** | Not written |

The gap that bites is **B → C**, and it is silent both ways: `cargo test` being green says
nothing about the code that never actually connected, and a feature that merely compiled looks done. The
history is full of defects that only a real run caught:

- a security option the engine rejects (so *every* hostile-code sandbox failed to start) while the unit
  suite stayed green;
- an egress allowlist that was accepted and ignored — nothing enforced it;
- a `cd '/host/path'` baked into a shell command that could not exist inside the container, while every
  hermetic test passed;
- an SSH write that deadlocked from inside a WebSocket task, failing 6 of 8 live runs;
- a `session ?` / `0 turn(s)` render because the streaming client read the envelope instead of the reply.

None of those were visible to the hermetic suite. **That is the point of testing by using.**
A test that drives a real model, a real daemon, and a real host is the only one that can call
something done. The number that matters is how many tiers are non-empty, not how green `cargo test`
is — and TESTING.md's own audit of the suite (a declared 56 `#[test]`s, 33 actually compiled)
shows even the count can lie.

## Ship on the latest commit

Releases are always cut from the **latest `main` commit** — never from a stale snapshot mixed with old
work. The release pipeline tags the tip of `main` and builds exactly that tree, so the artifact a user
installs is byte-for-byte the commit that passed CI. `--locked` everywhere in the build keeps the
dependencies the exact set that was tested, not whatever resolves today.

This is the same invariant as above, moved to the distribution seam: a release that is not built from
the latest verified commit is a tier-C artifact — it compiles, but nobody tested that exact tree.

## Working rules

- Prove it ran, then say so. Record the measured observation (`combined.txt` held both lines in order; a
  separate `wc -l` said 2), not the claim that it works.
- A test that cannot fail is not evidence. Each security tripwire proves its sentinel is genuinely on the
  path *before* asserting it never renders.
- A failing test must not also leak (a `Drop` guard sweeps a live sandbox on the panic path).
- Distinguish "verified" from "compiles" everywhere a green run could masquerade as assurance.

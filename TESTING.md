# Testing roadmap — what is verified, and what only looks verified

Status: 2026-09-15. Companion to `ROADMAP.md` (which tracks features); this file tracks **evidence**.

```console
$ cargo test --workspace
347 passed; 0 failed; 0 ignored          # 8 crates with code
0 integration tests                      # every test is an inline #[cfg(test)] unit test
0 #[ignore]d tests                       # nothing is even *marked* as needing a real environment
```

Those last two numbers are the important ones. A green suite here means **the logic is right**, not
that the system has ever talked to a real machine. Nothing in the suite would notice if the SSH
handshake were broken, and nothing is scheduled to notice later.

## The four tiers

Every claim in the repo falls into one of these. The gap that bites is B→C.

| Tier | Meaning | Evidence |
|---|---|---|
| **A — Executed** | Ran for real against a real service, output observed | Manual, this session. **Not in CI.** |
| **B — Unit-tested** | Pure logic asserted in-process, I/O replaced by fakes | `cargo test`, in CI |
| **C — Compiles only** | Real network/socket/daemon call sites no test ever reaches | none |
| **D — Absent** | Not written | none |

### Tier A — executed and observed (once, by hand)

These are the only things in the repo with real-world evidence. All were run manually during
development; **none are automated**, so a regression here is invisible until someone repeats them.

- `hxd` boots, binds, and serves over `axum::serve` — verified with live HTTP requests.
- `/healthz` → `200 ok`; `/v1/status`, `/v1/pools`, `/v1/hosts`, `/v1/sandboxes` → `200` + expected JSON.
- Unknown route → `404`; `/v1/chat` → `501` with an explanatory body (the agent loop does not exist yet).
- `hx doctor`, `hx pools`, `hx hosts`, `hx sandbox profiles`, `hx sandbox spec <profile>` → correct output.
- `hx doctor` correctly reported the container engine as **FAIL** (daemon not running) instead of crashing.
- **`/v1/search` against the live internet**: SearXNG was down → reported `connection refused`; DuckDuckGo
  served a bot check → **detected and reported as a failure** rather than returning an empty list.

That last one is the single most valuable observation in this file: it is the only place where the
graceful-degradation design met hostile reality, and it held.

### Tier B — unit-tested (in CI)

| Crate | Tests | LOC | What the tests actually prove |
|---|---|---|---|
| `hx-core` | 83 | 4092 | ID monotonicity, error taxonomy, **capability path grants** (incl. the empty-grant-means-root regression), approval policy incl. unattended budgets, message/event round-trips, config parsing and rejection of unknown keys |
| `hx-provider` | 61 | 2820 | Token-bucket timing, **budget fail-closed on a zero estimate**, credential pool round-robin, shared-limiter identity across pools, routing and fallthrough |
| `hx-remote` | 56 | 1838 | Platform caps parsing (`uname`/`ver`), path translation, shell quoting incl. injection attempts, risky-command classification, mid-truncation, **approval round-trip against the local host** |
| `hx-sandbox` | 53 | 1789 | Isolation ladder ordering, spec↔YAML round-trip, `SandboxSpec`→`HostConfig` mapping, registry/TTL bookkeeping |
| `hx-search` | 45 | 1732 | RRF rank fusion, HTML extraction, entity decoding, per-backend failure isolation (with **fake** backends) |
| `hx-secrets` | 27 | 893 | Argon2id+XChaCha20 round-trip, tamper detection, redaction patterns |
| `hx-server` | 11 | 739 | Route dispatch via `oneshot`, `HxError`→HTTP status mapping |
| `hx` | 11 | — | Renderers for pools/hosts/sandbox-spec, CLI parsing |

### Tier C — compiles, never executed

Every one of these is a real call to a real external surface. A typo, a wrong API field, a bad
auth flow, or a protocol misunderstanding would only surface the first time it runs in anger.

| Call site | Why it has never run | Risk if wrong |
|---|---|---|
| `hx-remote/src/ssh.rs` — `SshHost::connect`, auth, handshake, SFTP read/write/list | Needs a real server + key | **High.** The entire SSH feature is unproven; 12 tests cover only string parsing |
| `SshHost` host-key verification | Same | **High.** Currently permissive (accepts any key) — see below |
| `hx-sandbox/src/docker.rs` — `create`/`start`/`stop`/`remove`/`exec`/`logs` | Needs a Docker daemon | **High.** Only the *pure* `to_host_config`/`to_container_config` mappers are tested; the lifecycle is not |
| Sandbox concurrency cap rejecting the N+1th container | Needs a daemon | Medium |
| TTL reaper actually expiring and removing a container | Needs a daemon | Medium — the bookkeeping is tested, the removal is not |
| `hx-search` real backends — SearXNG + DuckDuckGo HTTP fetch | Needs network | Medium. Only fixture-parsed; the one live run hit failures on both |
| Provider HTTP calls to a real model API | Needs keys | Medium |
| Vault written to disk and reopened in a **new process** | Untested | Medium — in-process round-trip only |
| `hxd` reaper loop, `axum::serve` under load | Manual only | Low |

### Tier D — absent

Six crates are one line each — placeholder `lib.rs` with a doc comment and nothing else:

`hx-agent` · `hx-browser` · `hx-gateway` · `hx-mcp` · `hx-store` · `hx-tools`

They are declared as workspace members, so `cargo test` reports nothing for them and the build is
green. **A green suite says nothing about them.** Also absent: the web UI, Tauri desktop/mobile apps.

## The defect this audit found in the suite itself

`hx-remote` reported 56 `#[test]` attributes but only 33 ran. Cause: `lib.rs` declared only
`host` and `local` — **`ssh.rs` and `runner.rs` were never compiled**. They were orphan files that
looked like implementations.

`ssh.rs` was fine and is now wired in (+12 tests). `runner.rs` **did not compile** — 6 errors —
including an approval API mismatch (`resolve` returns `Verdict`, not `Result`) and a test asserting
a `RiskClass::Safe` variant that does not exist. Fixed, wired in, and the approval path is now
tested: an approval with nothing outstanding is denied rather than accepted.

Two claims in the README were false and are corrected: the SSH transport had never been built, and
the runner had never been built. Both now build and are tested — but their **handshakes and
container lifecycles remain Tier C.**

## Roadmap: closing the gaps, in priority order

Ordered by (security impact × likelihood of silent breakage), not by effort.

**1 — SSH host-key verification (Tier C, security).** `check_server_key` accepts any key, so the
harness is *less* safe than the shell it replaces: a MITM is silent. Fix: `known_hosts` parsing +
trust-on-first-use, and a test that a *changed* key is rejected. This is the only place the harness
is a regression on `ssh`, and it is the highest-value test in this document.

**2 — A real Docker integration test (Tier C).** The isolation ladder is the containment story and
its enforcement has never executed. Needs a daemon-gated test (`#[ignore]` by default, run in a job
with Docker) asserting: the container starts, `network=none` really blocks egress, the pids limit
fires, a read-only rootfs rejects writes, and the reaper removes the container. Until then,
"isolated" is a mapping function, not a verified property.

**3 — A real SSH integration test (Tier C).** `russh` handshake, key auth, exec, SFTP, and the
Windows/PowerShell wrapping path against a real box. Highest chance of a protocol-level surprise.

**4 — Mark the untested paths so the suite cannot lie.** Add `#[ignore = "requires docker"]` /
`"requires ssh"` / `"requires network"` integration tests and a CI job that runs them. The current
suite's real weakness is not low coverage — it is that **nothing distinguishes "verified" from
"compiles"**, so a green run reads as more assurance than it is.

**5 — Live search canary.** A scheduled test that hits one real backend and *fails loudly* on a bot
check. The design correctly reports bot checks as failures; nothing yet notices when it happens.

**6 — End-to-end agent test.** Blocked on M1. The moment the loop exists it should drive one real
task against a real sandbox — that becomes the first true integration test in the repo.

## Running the suite

```bash
cargo test --workspace          # 347 unit tests, no external dependencies
cargo test -p hx-remote         # 56 — includes ssh parsing + approval round-trip
cargo build --workspace         # clean: 0 warnings, 0 deprecations
cargo clippy --workspace        # clean
```

## Summary

- **8 crates with logic**: unit-tested at the level of pure functions and in-process lifecycles.
- **6 crates**: empty. The green suite does not cover them.
- **0 integration tests**: nothing in CI has ever opened a socket, a container, or a model API.
- **The one live run** (search) behaved exactly as designed under real-world failure.
- **The most-tested thing** is pure logic; **the least-tested thing** is whether any of it connects.

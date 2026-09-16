# Testing roadmap — what is verified, and what only looks verified

Status: 2026-09-15. Companion to `ROADMAP.md` (which tracks features); this file tracks **evidence**.

```console
$ cargo test --workspace
381 passed; 0 failed; 5 ignored          # 8 crates with code
5 integration tests                      # all #[ignore]d: crates/hx-remote/tests/ssh_live.rs

$ HX_SSH_TEST_HOST=… HX_SSH_TEST_USER=… HX_SSH_TEST_KEY=… \
  cargo test -p hx-remote --test ssh_live -- --ignored
5 passed; 0 failed                       # against a real machine, by hand, not in CI
```

The counts matter in both directions. A green `cargo test` still means **the logic is right**, and
those 5 ignored tests are the only ones that have ever reached another machine — so the suite would
not notice if the handshake broke tomorrow. What changed since the last audit: the SSH transport is
no longer in the "never executed" column. Everything about it below is a transcript, not a claim.

## The four tiers

Every claim in the repo falls into one of these. The gap that bites is B→C.

| Tier | Meaning | Evidence |
|---|---|---|
| **A — Executed** | Ran for real against a real service, output observed | Manual, via an `#[ignore]`d test. **Not in CI.** |
| **B — Unit-tested** | Pure logic asserted in-process, I/O replaced by fakes | `cargo test`, in CI |
| **C — Compiles only** | Real network/socket/daemon call sites no test ever reaches | none |
| **D — Absent** | Not written | none |

### Tier A — executed and observed

Not scheduled, therefore not regression-proof — but executed, with the output in hand.

**The daemon, by hand (earlier session, M0)**

- `hxd` boots, binds, and serves over `axum::serve` — verified with live HTTP requests.
- `/healthz` → `200 ok`; `/v1/status`, `/v1/pools`, `/v1/hosts`, `/v1/sandboxes` → `200` + expected JSON.
- Unknown route → `404`; `/v1/chat` → `501` with an explanatory body (the agent loop does not exist yet).
- `hx doctor`, `hx pools`, `hx hosts`, `hx sandbox profiles`, `hx sandbox spec <profile>` → correct output.
- `hx doctor` correctly reported the container engine as **FAIL** (daemon not running) instead of crashing.
- **`/v1/search` against the live internet**: SearXNG was down → reported `connection refused`; DuckDuckGo
  served a bot check → **detected and reported as a failure** rather than returning an empty list.

**The SSH transport, against a real Linux host (`crates/hx-remote/tests/ssh_live.rs`)**

Against an Ubuntu 24.04 box on the LAN, key auth, with each test given its own `known_hosts` in a
temp directory so nothing touches a developer's own trust store. The server offers `ssh-rsa`,
`ecdsa-sha2-nistp256` and `ssh-ed25519`; the connection negotiated and recorded `ssh-ed25519`.

| What ran | Observed |
|---|---|
| Connect, authenticate, probe capabilities | `SshHost::connect` returned; `caps.os == Linux` from the remote `uname`; `home_dir` populated; `describe()` → `ssh <user>@<host>:22 (linux, x86_64)` |
| Trust on first use | The server's key was appended to a `known_hosts` that did not exist before: one line, mode `0600` |
| Reconnect | Verified against the recorded line and **not** re-appended — still one line after two connections |
| exec, both streams and the exit status | `stdout` and `stderr` captured separately; `exit 7` surfaced as `Some(7)` |
| write → read of a binary file | 8 bytes including `0x00 0xff 0xfe 0x80` came back byte-identical (a `cat`-based transfer would have mangled this) |
| list a directory | The file listed with the right size and an absolute path; a missing directory was an error, not an empty list |
| **Refuse an unknown host under `Strict`** | Refused **before authentication**, no trust entry written: `refused to connect to …:22 — no known_hosts entry for …:22 in /tmp/…/known_hosts; refusing under strict host key checking (add the key with ssh-keyscan, or use HostKeyPolicy::Tofu)` |
| **Refuse a changed key (the MITM case)** | Refused, and the planted entry left untouched: `refused to connect to …:22 — the host key for …:22 does not match the one recorded at /tmp/…/known_hosts:1 (recorded …IJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ, offered ssh-ed25519); a changed host key is what a man-in-the-middle looks like, and a rebuilt server looks identical — remove that entry if the change is expected` |

The last two rows are the ones that were missing before this work: previously *both* connections
would have succeeded, silently, and the substituted key would have been used for authentication.
This is the only place in the repo where a security control has been observed doing its job against
a real peer rather than against a fixture.

Still not covered by any run: a Windows SSH server, a jump host, and `ssh-agent` auth (which returns
an explicit "not implemented" error rather than a wrong answer).

### Tier B — unit-tested (in CI)

| Crate | Tests | LOC | What the tests actually prove |
|---|---|---|---|
| `hx-core` | 83 | 4092 | ID monotonicity, error taxonomy, **capability path grants** (incl. the empty-grant-means-root regression), approval policy incl. unattended budgets, message/event round-trips, config parsing and rejection of unknown keys |
| `hx-provider` | 61 | 2820 | Token-bucket timing, **budget fail-closed on a zero estimate**, credential pool round-robin, shared-limiter identity across pools, routing and fallthrough |
| `hx-remote` | 90 | 3104 | Platform caps parsing (`uname`/`ver`), path translation, shell quoting incl. injection attempts, risky-command classification, mid-truncation, approval round-trip against the local host, and **`known_hosts`**: hashed host fields (HMAC-SHA1), globs, negation, `@revoked` beating trust regardless of line order, a different key type reading as first use rather than substitution, plus the policy's fail-closed behaviour and the wording of every refusal |
| `hx-sandbox` | 53 | 1793 | Isolation ladder ordering, spec↔YAML round-trip, `SandboxSpec`→`HostConfig` mapping, registry/TTL bookkeeping |
| `hx-search` | 45 | 1732 | RRF rank fusion, HTML extraction, entity decoding, per-backend failure isolation (with **fake** backends) |
| `hx-secrets` | 27 | 901 | Argon2id+XChaCha20 round-trip, tamper detection, redaction patterns |
| `hx-server` | 11 | 739 | Route dispatch via `oneshot`, `HxError`→HTTP status mapping |
| `hx` | 11 | — | Renderers for pools/hosts/sandbox-spec, CLI parsing |

The host key tests deserve a note, because the cases that matter are the ones where the obvious
implementation is wrong. A file `ssh` wrote with `HashKnownHosts` (the default on Debian and Ubuntu)
looks empty to a parser that only compares host strings — which turns a *changed* key into a *first*
connection, and trust-on-first-use then pins the attacker's key. `@revoked` is the same shape of
trap: unhandled, a revoked key is indistinguishable from an unknown host, and TOFU re-records it.
Both are covered, along with the rule that a host offering a second key type is first use rather than
substitution (otherwise the first ed25519 connection to an RSA-pinned host would fail), and that a
trust store which cannot be read or written refuses the connection instead of downgrading to trust.

### Tier C — compiles, never executed

Every one of these is a real call to a real external surface. A typo, a wrong API field, a bad
auth flow, or a protocol misunderstanding would only surface the first time it runs in anger.

| Call site | Why it has never run | Risk if wrong |
|---|---|---|
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
green. **A green suite says nothing about them.** Also absent: the web UI, the Tauri desktop/mobile
apps, host certificates, `ssh-agent` auth, `WinRMHost`, and file transfer over SSH to a Windows host
(the POSIX-only paths are guarded by a capability check, so they refuse rather than misbehave).

## The defect this audit found in the suite itself

`hx-remote` reported 56 `#[test]` attributes but only 33 ran. Cause: `lib.rs` declared only
`host` and `local` — **`ssh.rs` and `runner.rs` were never compiled**. They were orphan files that
looked like implementations.

`ssh.rs` was fine and is now wired in (+12 tests). `runner.rs` **did not compile** — 6 errors —
including an approval API mismatch (`resolve` returns `Verdict`, not `Result`) and a test asserting
a `RiskClass::Safe` variant that does not exist. Fixed, wired in, and the approval path is now
tested: an approval with nothing outstanding is denied rather than accepted.

The lesson generalises: a test that is never compiled is indistinguishable from a passing test, and
neither the count nor the badge catches it. Anything in this file marked "tested" should be
verifiable from `cargo test -p <crate>` output.

## Roadmap: closing the gaps, in priority order

Ordered by (security impact × likelihood of silent breakage), not by effort.

**1 — SSH host-key verification.**

✅ **Done.** `check_server_key` accepted any key, so the harness was *less* safe than the `ssh` it
replaces: a MITM was silent. Now `crates/hx-remote/src/known_hosts.rs` parses the real format
(hashed fields, globs, negation, `@revoked`, `@cert-authority`), and `HostKeyPolicy` is
`Strict` / `Tofu` / `Insecure` — explicit, because accepting anything should be a decision rather
than a default that happens because verification was absent. A changed key is refused with the
recorded key and the line number in the message; TOFU records *before* it accepts, so a key that
cannot be pinned is not accepted; a server presenting a certificate is refused, because the
authority behind it is not verified. 34 new unit tests, plus the two live refusals recorded above.

**2 — A real Docker integration test (Tier C).** The isolation ladder is the containment story and
its enforcement has never executed. Needs a daemon-gated test (`#[ignore]` by default, run in a job
with Docker) asserting: the container starts, `network=none` really blocks egress, the pids limit
fires, a read-only rootfs rejects writes, and the reaper removes the container. Until then,
"isolated" is a mapping function, not a verified property.

**3 — A real SSH integration test (Tier C → A).**

✅ **Written and run.** `crates/hx-remote/tests/ssh_live.rs`, five tests, driven by environment
variables, `#[ignore]`d by default. Still not *scheduled*: nothing runs it on a branch, so it is a
tool an operator points at a machine, not a regression gate. The honest fix is a CI job with a
throwaway `sshd` container, which needs no external host — that is the remaining half of this item.

**4 — Mark the untested paths so the suite cannot lie.**

◐ **Started.** The SSH integration tests carry `#[ignore = "requires a real SSH host …"]`, so
`cargo test --workspace` now reports `5 ignored` instead of implying full coverage. The
docker/network/key-material paths still need the same treatment, plus the CI job that runs the ones
CI is able to run. The suite's real weakness was never low coverage — it is that **nothing
distinguishes "verified" from "compiles"**, so a green run reads as more assurance than it is.

**5 — Live search canary.** A scheduled test that hits one real backend and *fails loudly* on a bot
check. The design correctly reports bot checks as failures; nothing yet notices when it happens.

**6 — End-to-end agent test.** Blocked on M1. The moment the loop exists it should drive one real
task against a real sandbox — that becomes the first true end-to-end test in the repo.

## Running the suite

```bash
cargo test --workspace          # 381 unit tests + 5 ignored integration tests
cargo test -p hx-remote         # 90 — includes known_hosts parsing and the host key policy
cargo build --workspace         # clean: 0 warnings, 0 deprecations
cargo clippy --workspace        # clean

# the ones that need a machine (any SSH server will do; this is the run recorded above)
HX_SSH_TEST_HOST=<host> HX_SSH_TEST_USER=<user> HX_SSH_TEST_KEY=~/.ssh/id_ed25519 \
  cargo test -p hx-remote --test ssh_live -- --ignored --test-threads=1
```

## Summary

- **8 crates with logic**: unit-tested at the level of pure functions and in-process lifecycles.
- **6 crates**: empty. The green suite does not cover them.
- **5 integration tests**, all `#[ignore]`d, all in `hx-remote` — the first tests in this repo that
  have ever opened a socket.
- **The SSH transport is now tier A**: handshake, auth, capability probing, exec, binary-safe file
  transfer, and — the point of the exercise — the refusal of an unknown host and of a *changed* host
  key, each with its observed message.
- **What is still tier C is the sandbox**: the isolation ladder is the containment story and none of
  it has run. That is next.
- **Nothing in CI reaches tier A**, so a regression there is invisible until someone repeats the
  run. That gap is what item 4 exists to shrink.

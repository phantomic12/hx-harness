# Testing roadmap — what is verified, and what only looks verified

Status: 2026-09-15. Companion to `ROADMAP.md` (which tracks features); this file tracks **evidence**.

```console
$ cargo test --workspace
386 passed; 0 failed; 13 ignored         # 8 crates with code

# The 13 that need a real server, run by `.github/workflows/integration.yml`:
$ cargo test -p hx-sandbox --test docker_live -- --ignored --test-threads=1
8 passed; 0 failed                       # a real Docker daemon
$ cargo test -p hx-remote --test ssh_live -- --ignored --test-threads=1
5 passed; 0 failed                       # a real sshd, real key auth
```

The counts matter in both directions. A green `cargo test` alone still means **the logic is right**;
those 13 ignored tests are the ones that have reached another process, and the only ones here that
could catch a protocol mistake. They now run in CI, which is the difference between "verified once"
and "stays verified".

## The four tiers

Every claim in the repo falls into one of these. The gap that bites is B→C.

| Tier | Meaning | Evidence |
|---|---|---|
| **A — Executed** | Ran for real against a real service, output observed | `integration.yml` in CI, plus the manual runs recorded below |
| **B — Unit-tested** | Pure logic asserted in-process, I/O replaced by fakes | `cargo test`, in CI |
| **C — Compiles only** | Real network/socket/daemon call sites no test ever reaches | none |
| **D — Absent** | Not written | none |

### Tier A — executed and observed

**The isolation ladder, against a real Docker daemon** (`crates/hx-sandbox/tests/docker_live.rs`)

Eight tests against Docker 29 on Ubuntu 24.04 with cgroup v2. This suite exists because the ladder
was a *mapping* — `SandboxSpec` → `HostConfig`, asserted field by field — and a mapping proves
intent, not that the engine accepts it.

| What ran | Observed |
|---|---|
| L2 create, and the daemon's own record of it | `inspect_container` reports `network_mode: none`, `readonly_rootfs: true`, `pids_limit: 128`, `cap_drop: ["ALL"]`, `privileged: false`, `userns_mode: private`, `memory == memory_swap`, and `config.user == 1000:1000` |
| It is a working container, not just an accepted one | `id -u` → `1000`; `echo alive` → `alive` |
| `network=none` really blocks egress | TCP to `1.1.1.1:80` → `BLOCKED`; `getent hosts example.com` → `NO_DNS`; `ip -o link` → **0** interfaces |
| Read-only root, usable scratch space | `touch /definitely-not-allowed` → non-zero; `touch /tmp/ok` → succeeds; a binary copied to `/tmp` → `Permission denied`, `exit=126` (the `noexec` mount) |
| The workspace bind is real | A write inside the container appears in the host directory |
| The pid ceiling, and the kernel | `/sys/fs/cgroup/pids.max` → `64`; 200 process spawns → `sh: 0: Cannot fork`; the sandbox still answers `echo` afterwards |
| TTL reaper | After 2 s with a 1 s TTL, `reap()` returns the id and `inspect_container` **404s** — the container is gone, not merely forgotten |
| Destroy, twice | Container gone, slot released, second call is a no-op |
| The concurrency cap | The N+1th spawn fails with `1 of 1` and the daemon's container count is unchanged — refused, not created-then-cleaned |
| A missing image | Fails naming the image, tracks nothing, consumes no slot, leaves no container |

**Three defects the live runs found, none of them visible to 384 green unit tests:**

1. `security_opt: userns=keep-id` — podman's spelling. Docker: `invalid --security-opt 2:
   "userns=keep-id"`. Every L2 and L3 sandbox failed at create — exactly the levels meant to hold
   hostile code — while `hx sandbox spec` printed the profile as configured.
2. `security_opt: seccomp=default` — not a value; the daemon expects a profile path or
   `unconfined` and answered `Decoding seccomp profile failed: invalid character 'd' looking for
   beginning of value`. An engine already applies its default seccomp profile to every container, so
   the option could only ever *change* it, and this spelling changed it into a failure.
3. **An egress allowlist that nothing enforced.** `network: true` plus four hostnames produced a
   container with a full bridge network. `hx.example.yaml` shipped that combination.

The first two are fixed and expressed through mechanisms that exist (`HostConfig.UsernsMode`, and
nothing at all for the engine's default seccomp), with a unit test that fails if either string comes
back. The third is now *refused* — `SpecError::EgressNotEnforced`, which says what to do instead —
rather than accepted and ignored, and the example config no longer claims a constraint it cannot
keep. The first failing run also happened to demonstrate the rollback invariant against a real
engine: seven spawns failed at *start* after a successful create, and every one reported
`it has been removed`.

**The SSH transport, against a real sshd** (`crates/hx-remote/tests/ssh_live.rs`)

Against an Ubuntu 24.04 host by hand, and against a throwaway `sshd` on a non-default port in CI —
the port matters, because that is what exercises the bracketed `[host]:port` form in `known_hosts`.
Each test gets its own trust store in a temp directory, so nothing touches a developer's
`~/.ssh/known_hosts`. The server offers `ssh-rsa`, `ecdsa-sha2-nistp256` and `ssh-ed25519`; the
connection negotiated and recorded `ssh-ed25519`.

| What ran | Observed |
|---|---|
| Connect, authenticate, probe capabilities | `caps.os == Linux` from the remote `uname`; `home_dir` populated; `describe()` → `ssh <user>@<host> (linux, x86_64)` |
| Trust on first use | The server's key appended to a `known_hosts` that did not exist before: one line, mode `0600` |
| Reconnect | Verified against the recorded line and **not** re-appended — still one line after two connections |
| exec, both streams, exit status | `stdout` and `stderr` captured separately; `exit 7` surfaced as `Some(7)` |
| write → read of a binary file | 8 bytes including `0x00 0xff 0xfe 0x80`, byte-identical (a `cat`-based transfer would mangle this) |
| list a directory | The file listed with the right size and absolute path; a missing directory is an error, not an empty list |
| **Unknown host under `Strict`** | Refused **before authentication**, nothing written: `refused to connect to … — no known_hosts entry for …; refusing under strict host key checking (add the key with ssh-keyscan, or use HostKeyPolicy::Tofu)` |
| **A changed key (the MITM case)** | Refused, planted entry untouched: `the host key for … does not match the one recorded at /tmp/…/known_hosts:1 (recorded …IJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ, offered ssh-ed25519); a changed host key is what a man-in-the-middle looks like, and a rebuilt server looks identical — remove that entry if the change is expected` |

Still not covered by any run: a Windows SSH server, a jump host, and `ssh-agent` auth (which returns
an explicit "not implemented" error rather than a wrong answer).

**The daemon, by hand (earlier session, M0)** — `hxd` boots and serves (`/healthz` 200, unknown route
404, `/v1/chat` 501 with an explanation), the `hx` subcommands render correctly, `hx doctor` reported
a dead container engine as `FAIL` rather than crashing, and `/v1/search` against the live internet
reported SearXNG's `connection refused` and DuckDuckGo's bot check as **failures** rather than
returning an empty list.

### Tier B — unit-tested (in CI)

| Crate | Tests | LOC | What the tests actually prove |
|---|---|---|---|
| `hx-core` | 83 | 4092 | ID monotonicity, error taxonomy, **capability path grants** (incl. the empty-grant-means-root regression), approval policy incl. unattended budgets, message/event round-trips, config parsing and rejection of unknown keys |
| `hx-provider` | 61 | 2820 | Token-bucket timing, **budget fail-closed on a zero estimate**, credential pool round-robin, shared-limiter identity across pools, routing and fallthrough |
| `hx-remote` | 90 | 3108 | Platform caps parsing (`uname`/`ver`), path translation, shell quoting incl. injection attempts, risky-command classification, mid-truncation, approval round-trip against the local host, and **`known_hosts`**: hashed host fields (HMAC-SHA1), globs, negation, `@revoked` beating trust regardless of line order, a different key type reading as first use rather than substitution, plus the policy's fail-closed behaviour and the wording of every refusal |
| `hx-sandbox` | 58 | 1948 | Isolation ladder ordering and monotonicity, spec↔YAML round-trip, `SandboxSpec`→`HostConfig` mapping field by field, **no engine-rejected security option** (`userns=`, `seccomp=default`), an egress allowlist that cannot be enforced, registry/TTL bookkeeping, the concurrency cap, and rollback on a failed start |
| `hx-search` | 45 | 1732 | RRF rank fusion, HTML extraction, entity decoding, per-backend failure isolation (with **fake** backends) |
| `hx-secrets` | 27 | 901 | Argon2id+XChaCha20 round-trip, tamper detection, redaction patterns |
| `hx-server` | 11 | 739 | Route dispatch via `oneshot`, `HxError`→HTTP status mapping |
| `hx` | 11 | — | Renderers for pools/hosts/sandbox-spec, CLI parsing |

Two families in that table are worth naming, because in both the obvious implementation is wrong and
the failure is silent:

- **`known_hosts` parsing.** A file `ssh` wrote with `HashKnownHosts` — the default on Debian and
  Ubuntu — looks empty to a parser that only compares host strings. That turns a *changed* key into a
  *first* connection, and trust-on-first-use then pins the attacker's key. `@revoked` is the same
  shape of trap: unhandled, a revoked key is indistinguishable from an unknown host, and TOFU
  re-records it.
- **Engine spellings.** A security setting is only a setting if the engine accepts the string. Both
  of the first two tier A defects were of this kind, so the strings now have tests that fail if they
  return.

### Tier C — compiles, never executed

| Call site | Why it has never run | Risk if wrong |
|---|---|---|
| **L3 sandbox** (`runtime: runsc`) | Nothing installs gVisor, including CI | **High** — the level exists to deny the sandbox the host kernel, and no container has ever started on it |
| **Egress filtering** | Not implemented: no proxy, no firewall rule. Now *refused* rather than ignored (`SpecError::EgressNotEnforced`), so it cannot silently mean "open internet" |
| `hx-search` real backends — SearXNG + DuckDuckGo HTTP fetch | Needs network | Medium. Only fixture-parsed; the one live run hit failures on both |
| Provider HTTP calls to a real model API | Needs keys | Medium |
| Vault written to disk and reopened in a **new process** | Untested | Medium — in-process round-trip only |
| `hxd` reaper loop, `axum::serve` under load | Manual only | Low |

### Tier D — absent

Six crates are one line each — placeholder `lib.rs` with a doc comment and nothing else:

`hx-agent` · `hx-browser` · `hx-gateway` · `hx-mcp` · `hx-store` · `hx-tools`

They are declared as workspace members, so `cargo test` reports nothing for them and the build is
green. **A green suite says nothing about them.** Also absent: the web UI, the Tauri desktop/mobile
apps, host certificates, `ssh-agent` auth, `WinRMHost`, SSH file transfer to a Windows host (the
POSIX-only paths refuse via a capability check), and the egress proxy.

## The defect this audit found in the suite itself

`hx-remote` reported 56 `#[test]` attributes but only 33 ran. Cause: `lib.rs` declared only
`host` and `local` — **`ssh.rs` and `runner.rs` were never compiled**. They were orphan files that
looked like implementations.

`ssh.rs` was fine and is now wired in (+12 tests). `runner.rs` **did not compile** — 6 errors —
including an approval API mismatch (`resolve` returns `Verdict`, not `Result`) and a test asserting
a `RiskClass::Safe` variant that does not exist. Fixed, wired in, and the approval path is now
tested: an approval with nothing outstanding is denied rather than accepted.

The lesson generalises twice over. A test that is never compiled is indistinguishable from a passing
test. And a suite with no integration tests cannot tell "verified" from "compiles" — which is how two
settings the engine rejects, and one security control that did nothing, survived 347 green tests and
shipped in a config an operator would read as hardened.

## Roadmap: closing the gaps, in priority order

Ordered by (security impact × likelihood of silent breakage), not by effort.

**1 — SSH host-key verification. ✅ Done.** `check_server_key` accepted any key, so the harness was
*less* safe than the `ssh` it replaces: a MITM was silent. Now `crates/hx-remote/src/known_hosts.rs`
parses the real format (hashed fields, globs, negation, `@revoked`, `@cert-authority`), and
`HostKeyPolicy` is `Strict` / `Tofu` / `Insecure` — explicit, because accepting anything should be a
decision rather than a default that happens because verification was absent. A changed key is refused
with the recorded key and the line number in the message; TOFU records *before* it accepts, so a key
that cannot be pinned is not accepted; a certificate is refused, because the authority behind it is
not verified.

**2 — A real Docker integration test. ✅ Done.** `crates/hx-sandbox/tests/docker_live.rs`, eight
tests, run in CI on `ubuntu-latest`. The ladder is no longer a mapping function: the daemon's own
view of the container is asserted, `network=none` is probed from inside, the pid ceiling is read from
the cgroup and then attacked, and the reaper is checked against `docker inspect` rather than against
its own bookkeeping.

**3 — A real SSH integration test. ✅ Done, and scheduled.** Five tests against a throwaway `sshd` in
CI, on a non-default port so the bracketed `known_hosts` form is exercised. It is not a second
machine and not a Windows host — that is item 7.

**4 — Mark the untested paths so the suite cannot lie. ✅ Done for both live surfaces.**
`cargo test --workspace` reports `13 ignored` instead of implying full coverage, and
`.github/workflows/integration.yml` runs them where CI can host them. The remaining tier C paths —
L3, the egress proxy, real search backends — should get the same treatment as they gain tests; the
suite's real weakness was never low coverage but that **nothing distinguished "verified" from
"compiles"**, so a green run read as more assurance than it was.

**5 — Live search canary.** A scheduled test that hits one real backend and *fails loudly* on a bot
check. The design correctly reports bot checks as failures; nothing yet notices when it happens.

**6 — End-to-end agent test.** Blocked on M1. The moment the loop exists it should drive one real
task against a real sandbox — that becomes the first true end-to-end test in the repo.

**7 — L3, and a non-Linux remote.** Two things the ladder and the transport claim and nothing has
run: a sandbox on a VM-backed runtime (`runsc`), and the transport against a Windows host, where the
shell wrapping and the POSIX-only file-transfer guards have never met a real server.

## Running the suite

```bash
cargo test --workspace          # 386 unit tests + 13 ignored integration tests
cargo test -p hx-sandbox        # 58 — includes the ladder and the rollback invariants
cargo test -p hx-remote         # 90 — includes known_hosts parsing and the host key policy
cargo build --workspace         # clean: 0 warnings, 0 deprecations
cargo clippy --workspace        # clean

# the ones that need a real service (this is the shape CI runs them in)
cargo test -p hx-sandbox --test docker_live -- --ignored --test-threads=1
HX_SSH_TEST_HOST=<host> HX_SSH_TEST_USER=<user> HX_SSH_TEST_KEY=~/.ssh/id_ed25519 \
  cargo test -p hx-remote --test ssh_live -- --ignored --test-threads=1
```

## Summary

- **8 crates with logic**: unit-tested at the level of pure functions and in-process lifecycles.
- **6 crates**: empty. The green suite does not cover them.
- **13 integration tests**, all `#[ignore]`d by default and all run in CI: a real Docker daemon and a
  real `sshd`.
- **The SSH transport and the sandbox lifecycle are tier A, and regress loudly**: host key refusals
  observed against a real server, and a container whose egress, pid ceiling, read-only root, bind
  mount and reaper were each verified against the daemon rather than against our own bookkeeping.
- **Running them found three defects** that 384 unit tests had not seen: two security options the
  engine rejects (so every L2/L3 sandbox failed to start) and an egress allowlist that was accepted
  and ignored. Two are fixed and pinned by tests; the third is now refused instead of pretended.
- **What is still tier C is the sandbox's strongest claim**: L3 has never run, because nothing
  installs gVisor. That is next, with the egress proxy behind it.

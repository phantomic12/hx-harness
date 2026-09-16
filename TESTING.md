# Testing roadmap — what is verified, and what only looks verified

Status: 2026-09-16. Companion to `ROADMAP.md` (which tracks features); this file tracks **evidence**.

```console
$ cargo test --workspace
663 tests, 0 failed                       # 13 hermetic HTTP + 4 that reopen the database + 14 that run the loop over HTTP
22 ignored                               # live: Docker, SSH, search, a real model

# The 22 that need a real server, run by `.github/workflows/integration.yml`
# and `.github/workflows/canary.yml`:
$ cargo test -p hx-sandbox --test docker_live -- --ignored --test-threads=1
9 passed; 0 failed                       # a real Docker daemon, with gVisor installed
$ HX_OPENAI_TEST_BASE_URL=… HX_OPENAI_TEST_MODEL=… HX_OPENAI_TEST_KEY=… \
  cargo test -p hx-provider --test openai_live -- --ignored --test-threads=1
4 passed; 0 failed                       # a real model, through a real gateway
$ cargo test -p hx-remote --test ssh_live -- --ignored --test-threads=1
5 passed; 0 failed                       # a real sshd, real key auth
$ HX_SEARXNG_URL=http://127.0.0.1:8888 HX_SEARCH_EXPECT_RESULTS=searxng \
  cargo test -p hx-search --test search_live -- --ignored --test-threads=1
4 passed; 0 failed                       # a real SearXNG, real internet
```

The counts matter in both directions. A green `cargo test` alone still means **the logic is right**;
those 22 ignored tests are the ones that have reached another process, and the only ones here that
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

Nine tests against Docker 29 on Ubuntu 24.04 with cgroup v2 and gVisor registered. This suite exists because the ladder
was a *mapping* — `SandboxSpec` → `HostConfig`, asserted field by field — and a mapping proves
intent, not that the engine accepts it.

| What ran | Observed |
|---|---|
| L2 create, and the daemon's own record of it | `inspect_container` reports `network_mode: none`, `readonly_rootfs: true`, `pids_limit: 128`, `cap_drop: ["ALL"]`, `privileged: false`, `userns_mode: private`, `memory == memory_swap`, and `config.user` equal to the workspace's owner — never root |
| It is a working container, not just an accepted one | `id -u` → `1000`; `echo alive` → `alive` |
| `network=none` really blocks egress | TCP to `1.1.1.1:80` → `BLOCKED`; `getent hosts example.com` → `NO_DNS`; `ip -o link` → **0** interfaces |
| Read-only root, usable scratch space | `touch /definitely-not-allowed` → non-zero; `touch /tmp/ok` → succeeds; a binary copied to `/tmp` → `Permission denied`, `exit=126` (the `noexec` mount) |
| The workspace bind is real | A write inside the container appears in the host directory |
| The pid ceiling, and the kernel | `/sys/fs/cgroup/pids.max` → `64`; 200 process spawns → `sh: 0: Cannot fork`; the sandbox still answers `echo` afterwards |
| TTL reaper | After 2 s with a 1 s TTL, `reap()` returns the id and `inspect_container` **404s** — the container is gone, not merely forgotten |
| Destroy, twice | Container gone, slot released, second call is a no-op |
| The concurrency cap | The N+1th spawn fails with `1 of 1` and the daemon's container count is unchanged — refused, not created-then-cleaned |
| A missing image | Fails naming the image, tracks nothing, consumes no slot, leaves no container |
| **L3 on a VM-backed runtime** | `inspect_container` reports `runtime: runsc`, `network_mode: none`, read-only root; the sandbox sees kernel **`4.19.0-gvisor`** while the host is on `7.0.0-30-generic`; non-root; a write through the bind mount reaches the host from inside gVisor; a write to the root is refused |

**Four defects the live runs found, none of them visible to the unit suite:**

1. `security_opt: userns=keep-id` — podman's spelling. Docker: `invalid --security-opt 2:
   "userns=keep-id"`. Every L2 and L3 sandbox failed at create — exactly the levels meant to hold
   hostile code — while `hx sandbox spec` printed the profile as configured.
2. `security_opt: seccomp=default` — not a value; the daemon expects a profile path or
   `unconfined` and answered `Decoding seccomp profile failed: invalid character 'd' looking for
   beginning of value`. An engine already applies its default seccomp profile to every container, so
   the option could only ever *change* it, and this spelling changed it into a failure.
3. **An egress allowlist that nothing enforced.** `network: true` plus four hostnames produced a
   container with a full bridge network. `hx.example.yaml` shipped that combination.
4. **A hardcoded sandbox uid.** `SANDBOX_UID = "1000:1000"` cannot write a bind-mounted workspace
   owned by anybody else, so on a host whose user is not uid 1000 — GitHub's runner is 1001 — the
   sandbox started, the mount succeeded, and every write into the workspace failed with
   `Permission denied`. The first CI run of this suite is what caught it; on the development host
   the uid happened to match. `SandboxSpec::user` is now overridable and
   `SandboxSpec::adopt_workspace_owner()` is the supported way to set it, so the sandbox runs as
   whoever owns the mount.

All four are fixed and expressed through mechanisms that exist (`HostConfig.UsernsMode`, and
nothing at all for the engine's default seccomp), with a unit test that fails if either string comes
back. The third is now *refused* — `SpecError::EgressNotEnforced`, which says what to do instead —
rather than accepted and ignored, and the example config no longer claims a constraint it cannot
keep. The first failing run also happened to demonstrate the rollback invariant against a real
engine: seven spawns failed at *start* after a successful create, and every one reported
`it has been removed`.

**A real model, through a real gateway** (`crates/hx-provider/tests/openai_live.rs`)

Four tests against a hosted gateway (OpenAI-compatible `/v1`), model `gemini/gemini-3.1-flash-lite`,
key from the deployment's env file and never echoed:

| What ran | Observed |
|---|---|
| A completion, with usage | `finish=Stop in=11 out=1 text="Ok"` — real token accounting, not an estimate |
| A tool call, and its result going back | The model emitted `ls({"path":"/tmp"})`, the arguments parsed into an object, the result was appended as a tool message, and the follow-up turn answered in prose: *"The contents of `/tmp` are: cargo-target, rustc-log.txt, hx-workspace"* — the exact cycle the agent loop will run |
| Multi-turn context | Two turns, the second referring to the first, answered `"41"` — the transcript is not being dropped by the adapter |
| A wrong credential | Clean `401` classified as an authentication failure, with the provider's own message quoted and no key material in it |

The same suite has a hermetic sibling (`openai_http.rs`, 11 tests, runs on every commit) which points
the adapter at a stub server and asserts the real request line, headers and body: `arguments` as a
JSON *string*, `content: null` for a tool-only assistant turn, one `tool` message per call id, and
`Retry-After` honoured on a `429`.

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

**Search, against a real SearXNG and the real internet** (`crates/hx-search/tests/search_live.rs`)

A SearXNG in Docker, JSON output enabled, the canary pointed at it: **10 fused results for one
query**, `answered: searxng`, every result carrying the backend that produced it, no redirect
wrappers, and a nonsense query correctly reported as five results rather than as a failure. In the
same run DuckDuckGo was asked, refused with an `anomaly` challenge, and appeared in the report as
`unavailable: duckduckgo` — which is the whole point of per-backend failure reporting: the search
still worked, and the caller knows what was missing.

**The daemon, by hand (earlier session, M0)** — `hxd` boots and serves (`/healthz` 200, unknown route
404, `/v1/chat` 501 with an explanation), the `hx` subcommands render correctly, `hx doctor` reported
a dead container engine as `FAIL` rather than crashing, and `/v1/search` against the live internet
reported SearXNG's `connection refused` and DuckDuckGo's bot check as **failures** rather than
returning an empty list.

### Tier B — unit-tested (in CI)

| Crate | Tests | LOC | What the tests actually prove |
|---|---|---|---|
| `hx-core` | 85 | 4142 | ID monotonicity, error taxonomy (**a rejected credential is an auth failure, and a 500 is not**, so a pool retries one and benches the other), **capability path grants** (incl. the empty-grant-means-root regression), approval policy incl. unattended budgets, message/event round-trips, config parsing and rejection of unknown keys |
| `hx-provider` | 102 | 4091 | Token-bucket timing, **budget fail-closed on a zero estimate**, credential pool round-robin, shared-limiter identity across pools, routing and fallthrough, a granted ticket carrying the credential's `secret_ref`, a role's reservation estimated from the **dearest** route, and the provider factory refusing a kind it has no adapter for |
| `hx-remote` | 90 | 3108 | Platform caps parsing (`uname`/`ver`), path translation, shell quoting incl. injection attempts, risky-command classification, mid-truncation, approval round-trip against the local host, and **`known_hosts`**: hashed host fields (HMAC-SHA1), globs, negation, `@revoked` beating trust regardless of line order, a different key type reading as first use rather than substitution, plus the policy's fail-closed behaviour and the wording of every refusal |
| `hx-sandbox` | 62 | 2057 | Isolation ladder ordering and monotonicity, spec↔YAML round-trip, `SandboxSpec`→`HostConfig` mapping field by field, **no engine-rejected security option** (`userns=`, `seccomp=default`), an egress allowlist that cannot be enforced, registry/TTL bookkeeping, the concurrency cap, and rollback on a failed start |
| `hx-search` | 45 | 1732 | RRF rank fusion, HTML extraction, entity decoding, per-backend failure isolation (with **fake** backends) |
| `hx-secrets` | 36 | 1302 | Argon2id+XChaCha20 round-trip, tamper detection, redaction patterns, and **credential resolution**: a `store:name` reference resolved through `vault:`/`env:`/a fixed map, an empty environment variable refused like an absent one, an unknown store listing the stores that *are* configured, and every error message asserted **not** to contain a value |
| `hx-agent` | 35 | 1027 | The loop's gate, in one file of integration tests: a **capability denial is a result the model reads and cannot be approved away** (an approver willing to say yes is never asked), an approval denial is reported and the command never reaches the host, `allow for chat` stops the second prompt while a remembered denial is not re-asked, a tool declaring no external effect is never prompted about, a refused call does not stop its sibling, unknown tools and unusable arguments return as results, a non-zero exit is still a call that *ran*, `max_turns` and the deadline stop the run, and the exact event sequence a client renders. Plus the **routed model call** over a real `ModelRouter` and a real `ProviderRegistry`, with only the adapter faked: the route decides the model, the key follows the credential the pool granted, a refused credential is benched and its *sibling* is tried before another provider, a missing key and a 502 both give the reservation back (asserted with `concurrent: 1`, since a leaked lease looks exactly like a rate limit), and a day's budget that covers one pessimistic reservation still allows three calls |
| `hx-store` | 38 | 2051 | Migrations applied once and never re-run, **a database from a newer build refused with both versions named** (and left untouched), `STRICT` rejecting a type mistake at insert, the transcript written by `seq` the caller does not track, a batch written whole or not at all, a cascade that only happens because `Store` sets `foreign_keys`, every part type round-tripping while an unknown one is reported rather than dropped, events and usage surviving a reopen — plus 4 in `tests/resume.rs` that drop the store and open a **new connection** to the same file, which is the closest a test gets to killing the daemon |
| `hx-tools` | 70 | 2576 | Requirements per tool, bounded output, the two-phase registry, and **a misnamed argument refused rather than ignored** — `cwd` instead of `workdir` used to drop silently and run the command in the daemon's own directory |
| `hx-server` | 28 | 1730 | Route dispatch via `oneshot`, `HxError`→HTTP status mapping, and twelve tests that run the **real loop over the real HTTP surface** with only the model scripted: an answer comes back with its session, its cost and its events; a tool call runs and its result reaches the model; a write outside the workspace is denied and never happens; a shell command that needs a human is refused **with the reason**, and the same command runs under `yolo`; a second request on a session continues the transcript; unknown autonomy and unknown roles are 400s that name what is accepted; and a request that cannot run leaves no session behind |
| `hx` | 20 | 570 | Renderers for pools/hosts/sandbox-spec/sessions/runs, CLI parsing, and the daemon client's URL rules (an explicit `--daemon` wins, a bare `host:port` from the config gets a scheme, a URL that already has one is left alone) |

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
| **Egress filtering** | Not implemented: no proxy, no firewall rule. Now *refused* rather than ignored (`SpecError::EgressNotEnforced`), so it cannot silently mean "open internet" | Medium — a networked sandbox is unrestricted |
| DuckDuckGo keyless scraping — the *success* path | Every attempt from a plain HTTP client is answered with an `anomaly` challenge: a TLS-fingerprint wall, not a markup change. The failure path is verified live; the success path needs a browser-fingerprint client (M6) | Medium — search silently loses a source, but `SearchReport` names it |
| Vault written to disk and reopened in a **new process** | Untested | Medium — in-process round-trip only |
| `hxd` reaper loop, `axum::serve` under load | Manual only | Low |

### Tier D — absent

Three crates are one line each — placeholder `lib.rs` with a doc comment and nothing else:

`hx-browser` · `hx-gateway` · `hx-mcp`

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

A third, smaller lesson came out of running the live suite on a real machine: **a failing test
littered**. Cleanup lived at the end of each test body, so the run that found the `seccomp=default`
defect left a container running, and it was still up 36 minutes later. A `Drop` guard now destroys
the sandbox however the test ends — including a panic. A test that fails should not also leak.

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
`cargo test --workspace` reports `18 ignored` instead of implying full coverage, and
`.github/workflows/integration.yml` runs them where CI can host them. The remaining tier C paths —
L3, the egress proxy, real search backends — should get the same treatment as they gain tests; the
suite's real weakness was never low coverage but that **nothing distinguished "verified" from
"compiles"**, so a green run read as more assurance than it was.

**5 — Live search canary. ✅ Done.** `crates/hx-search/tests/search_live.rs`, four tests, run nightly
by `.github/workflows/canary.yml` — which starts a SearXNG of its own, because that is the one
backend a non-browser client can rely on. It asserts the promises the design makes rather than
wishing the web were friendlier: *never a silent empty* (no results implies a named reason), every
failure is accounted for, results that do come back are usable and not redirect wrappers, and with
`HX_SEARCH_EXPECT_RESULTS=searxng` the configured backend must actually answer. The first live run
found DuckDuckGo serving an `anomaly` challenge on every request — reported correctly, and now
recorded in README as the reason a browser-fingerprint client is M6 work rather than a parsing bug.

**6 — End-to-end agent test.** ◐ Unblocked, not done. The loop exists now (`crates/hx-agent`), and
its 21 tests exercise the gate end to end — but against a *scripted* model and an in-memory host,
which is still only our own assumptions. The test that counts drives a real model through the loop
with a real tool against a real host or sandbox, and it cannot be written before the loop is wired
into something that owns a credential and a host (`hx-store` and `hxd`, next in M1).

**7 — L3, and a non-Linux remote.**

✅ **L3 done.** gVisor's `runsc` is installed by the integration job, registered as a daemon runtime,
and the L3 test asserts the claim rather than the mapping: the sandbox reports `4.19.0-gvisor` where
the host reports `7.0.0-30-generic`, keeps a read-only root, runs non-root, and writes through the
bind mount. `HX_DOCKER_REQUIRE_L3=1` makes a missing gVisor a failure, so the capability cannot
quietly stop being tested.

◐ **A Windows remote is still unverified** — its shell wrapping and the POSIX-only file-transfer
guards have never met a real server. It needs a Windows box with an SSH server and a key, which is
environment work rather than code work.

## Tier C — a real model through the daemon (manual, recorded)

The suites above fake the model. This is the row that proves the harness drives one, and it is run by
hand because it needs a key and someone else's rate limits:

```console
$ export HX_LITELLM_KEY=...                      # a LiteLLM proxy key, never in the config
$ ./target/release/hxd --config ~/.hx/litellm.yaml --bind 127.0.0.1:8899
$ curl -s :8899/v1/chat -d '{"prompt":"...","role":"swe2high","workspace":"/tmp/ws"}'
```

Measured against `litellm.phantomic.live` (2026-09-16, hx-harness at `9de1227`):

| Model | Task | Result |
|---|---|---|
| `glm-prox/swe-2-high` | read 6 files, one call each | 6 tool calls, 0 refusals, correct; 22 s |
| `glm-prox/swe-2-high` | read 13 `Cargo.toml`s, name the `hx-provider` dependants | 3 calls, correct (batched) |
| `glm-prox/swe-2-high` | create a file and read it back | 2 calls, file on disk byte-for-byte |
| `minimax/MiniMax-M3` | read `Cargo.toml`, count members | 1 call, correct ("15") |
| `opencode-go/deepseek-v4.1-flash` | same | 1 call, correct |
| `glm-prox/glm-5-2` | same | 1 call, correct |
| `openrouter/nvidia/nemotron-3-super-120b-a12b:free` | same | 1 call, correct |
| `openrouter/cohere/north-mini-code:free` | same | 1 call, correct |

Three did **not** work, and none of it was the harness: `openrouter/google/gemma-4-31b-it:free` and
`openrouter/z-ai/glm-5.2:free` are upstream-limited or do not route tool use at all (verified with a
direct `curl` to the proxy), and `opencode-zen/nemotron-3.5-lightning-free` is restricted by the
provider to OpenCode's own client. A model that cannot call tools cannot drive this harness, and the
error says which of those it was.

**A kill, and what it leaves behind.** `kill -9` on the daemon 6 s into a run, once the first tool
result was on disk (`~/.hx/kill-test.sh` polls the database and kills at that moment rather than
guessing):

```console
$ ./kill-test.sh
session ses_7c8f29c6… has 3 messages on disk — killing -9 now
1 | user      | "Read every Cargo.toml under crates/ …"
2 | assistant | "I'll first find all the Cargo.toml files …"      (with a tool call)
3 | tool      | tool_result for shell_0#f8cdea97…
messages=3 events=6 usage=1
```

Then restart and resume the same session: `created=false repaired=0`, 13 tool calls, 0 refusals, 20
messages, and the answer correct. That is M1's second exit criterion — a killed run resumes because
its transcript was never only in memory, and a kill that lands *between* a call and its result is
repaired on the next request rather than sent to a provider that rejects it.

The first run of this tier found two bugs no scripted test could: an OpenAI-compatible proxy that hands
over *unmerged streaming fragments* as a `tool_calls` array (seven entries, six nameless, one call),
and relative paths from the model being checked against an absolute workspace grant — 35 refusals and
no progress. Both are fixed, and both now have tests that reproduce the real wire bodies.

**A deletion, and what the question said.** `docs/approvals.md` §3 asks a destructive prompt to name
what will be gone. That is a claim about the filesystem rather than about the arguments, so the test
that settles it is one where a model chooses the path and a person reads the measurement
(`~/.hx/delete-demo.sh`, which builds a tree with a nested file, runs the daemon, and answers the
question through the CLI rather than with a raw `curl`):

```console
$ ./delete-demo.sh
--- the target, before ---
610000  /home/yoav/.hx/ws/delete-demo/build        # one.o, two.o, and sub/three.o
--- the question a person sees (after 3s) ---
delete /home/yoav/.hx/ws/delete-demo/build
risk: destructive
why:  deletes /home/yoav/.hx/ws/delete-demo/build
target:
  /home/yoav/.hx/ws/delete-demo/build — directory, 4 entries, 595.7 KB
after: moves to the trash at /home/yoav/.local/share/Trash/files, where it can be moved back — nothing is destroyed until the trash is emptied
answer: allow once | allow for this chat | deny
id: apr_400a59742a374405b475551db9369089   ->  hx approve apr_400a59… --option once
```

`glm-prox/swe-2-high` called `delete {"path":"build","recursive":true}` — a **relative** path, measured
against the workspace — and the count is the tree, not the top level: 4 entries for two object files,
the `sub` directory, and the object file inside it. The run waited, the CLI answered, and afterwards
the workspace held only `keep.txt` while the trash held the tree byte-for-byte (610 000 bytes) with an
XDG `build.trashinfo` naming the original absolute path. Read back from SQLite once the run finished:

```json
{"event":"approval_requested","approval":"apr_400a59…",
 "reason":"deletes /home/yoav/.hx/ws/delete-demo/build",
 "targets":[{"path":"/home/yoav/.hx/ws/delete-demo/build","kind":"directory",
             "entries":4,"bytes":610000,"partial":false}]}
{"event":"approval_resolved","approval":"apr_400a59…","approved":true,"by":"terminal"}
```

The second line is the reason for the first: the trail records *who* answered **and** what they were
shown, so an approval can never be audited as a bare yes.

## Running the suite

```bash
cargo test --workspace          # 663 tests, 0 failed, 22 ignored live tests
cargo test -p hx-store          # 42 — migrations, the transcript, and 4 that reopen the file
cargo test -p hx-agent          # 42 — the loop's gate, the routed model call, the transcript sink
cargo test -p hx-tools          # 91 — requirements, bounded output, the two-phase registry, workspace resolution, the trash
cargo test -p hx-server         # 30 — routes, and the loop end to end over HTTP
cargo test -p hx-sandbox        # 62 — includes the ladder and the rollback invariants
cargo test -p hx-remote         # 90 — includes known_hosts parsing and the host key policy
cargo build --workspace         # clean: 0 warnings, 0 deprecations
cargo clippy --workspace        # clean

# the ones that need a real service (this is the shape CI runs them in)
cargo test -p hx-sandbox --test docker_live -- --ignored --test-threads=1
HX_SSH_TEST_HOST=<host> HX_SSH_TEST_USER=<user> HX_SSH_TEST_KEY=~/.ssh/id_ed25519 \
  cargo test -p hx-remote --test ssh_live -- --ignored --test-threads=1
```

## Summary

- **11 crates with logic**: unit-tested at the level of pure functions and in-process lifecycles.
- **3 crates**: empty. The green suite does not cover them.
- **The store's resume path is tested across a real process boundary, in the only way a test can**:
  four tests in `crates/hx-store/tests/resume.rs` drop the `Store` and open a *new connection* to
  the same file, then continue the conversation. One of them is the case M1's exit criterion turns
  on — a run that died between a tool call and its result — where the transcript is repaired with a
  result that says the call did not run, rather than being sent to a provider that would reject it
  with an error that does not mention the cause.
- **The agent loop's gate is tested where it can be**: 21 integration tests with no network and no
  model — a capability denial that an approval cannot widen, an approval denial that never reaches the
  host, a refusal that does not stop the next call, and the event sequence a client will render. What
  none of them reaches is a real model: a scripted one is a model we wrote.
- **22 live tests**, all `#[ignore]`d by default: a real Docker daemon with gVisor installed, a real
  `sshd` and a real SearXNG are run in CI; the four against a real model are run deliberately, since
  they need a key and CI has none.
- **The SSH transport and the sandbox lifecycle are tier A, and regress loudly**: host key refusals
  observed against a real server, and a container whose egress, pid ceiling, read-only root, bind
  mount and reaper were each verified against the daemon rather than against our own bookkeeping.
- **Running them found four defects** the unit suite could not see: two security options the engine
  rejects (so every L2/L3 sandbox failed to start), an egress allowlist that was accepted and
  ignored, and a hardcoded sandbox uid that made the workspace unwritable on any host whose user is
  not uid 1000. All four are fixed and pinned by tests.
- **The ladder is now verified end to end**, L3 included: the sandbox on a VM-backed runtime sees a
  guest kernel, not the host's.
- **What is still tier C**: egress filtering (not implemented, and refused rather than pretended),
  keyless scraping that survives a TLS-fingerprint bot wall (browser-pool work), the vault opened in
  a new process, and provider calls to a real model API.
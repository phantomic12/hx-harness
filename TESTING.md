# Testing roadmap — what is verified, and what only looks verified

Status: 2026-09-16. Companion to `ROADMAP.md` (which tracks features); this file tracks **evidence**.

```console
$ cargo test --workspace
904 tests, 0 failed                       # includes 20 chat API tests and 4 database reopen tests
47 ignored                               # live: Docker, SSH, search, a real model

# The 24 that need a real server, run by `.github/workflows/integration.yml`
# and `.github/workflows/canary.yml`:
$ cargo test -p hx-sandbox --test docker_live -- --ignored --test-threads=1
9 passed; 0 failed                       # a real Docker daemon, with gVisor installed
$ HX_OPENAI_TEST_BASE_URL=… HX_OPENAI_TEST_MODEL=… HX_OPENAI_TEST_KEY=… \
  cargo test -p hx-provider --test openai_live -- --ignored --test-threads=1
4 passed; 0 failed                       # a real model, through a real gateway
$ cargo test -p hx-remote --test ssh_live -- --ignored --test-threads=1
5 passed; 0 failed                       # a real sshd, real key auth
$ cargo test -p hx-server --test chat_live -- --ignored --test-threads=1
2 passed; 0 failed                       # a real container, through POST /v1/chat
$ HX_SEARXNG_URL=http://127.0.0.1:8888 HX_SEARCH_EXPECT_RESULTS=searxng \
  cargo test -p hx-search --test search_live -- --ignored --test-threads=1
4 passed; 0 failed                       # a real SearXNG, real internet
```

The counts matter in both directions. A green `cargo test` alone still means **the logic is right**;
those 24 ignored tests are the ones that have reached another process, and the only ones here that
could catch a protocol mistake. They now run in CI, which is the difference between "verified once"
and "stays verified".

## The audit chain (hermetic + verified on a real database)

`crates/hx-store/src/audit.rs` gives every event row a digest over (its sequence, timestamp, kind,
payload, session id) and the previous row's digest. **The first version of the verifier only compared
each stored digest to the previous stored digest — a property true of any list of strings, so it
detected nothing.** Three tests failed and caught it: a verifier that cannot fail certifies an edited
log as intact. `verify_events` now recomputes each row's digest from the row's own content, and takes
content + digest rather than digests alone.

Verified on a real database (a copy of a V1 store with 348 events): opening it with this build
migrated the schema to V2, added the `digest` column, kept all 348 rows (all reported as *unchained*
rather than as tampered with), and a subsequent run chained its 4 new events. That is the upgrade path
an existing deployment takes.

What it does not prove: it is hash chaining, not a signature. An attacker who rewrites the whole chain
from a chosen point forward produces one that verifies, because the only secret involved is the
construction. Detecting *that* needs a key held outside the database — `hx-secrets`' business and an
open step.

## Chat sandbox wiring verification

`cargo fmt --all --check`, strict workspace clippy, and `cargo test --workspace --locked` pass.
Four added HTTP tests cover unknown profile (400), absent engine (503), failed startup (502), and
successful shell dispatch through the real manager with a recording runtime. They assert no model
call or session on startup rejection, exact command source without a host-side `cd`, translated
`/workspace`, and no host marker. A shell test covers an explicit relative workdir separately from
command source. CLI help exposes `--sandbox-profile`.

This is hermetic evidence, not a live container run. Docker is not installed on this development host;
the new chat path has not yet been exercised against a real engine. The historical live results below
remain evidence for their named suites, not for this new wiring.

## Remote sandbox wiring (M4)

The `Host`→`RemoteCommandRunner` adapter and the per-host manager routing are unit-tested in-process:

- `hx-server` lib `remote_sandbox` tests drive `HostCommandRunner` with `hx_tools::testing::FakeHost`
  (a real in-memory `Host`), asserting the field-for-field copy across the seam including that a non-zero
  and an unknown (`None`) exit pass through **unchanged** — a non-zero is a successful *transport*
  result, and only the remote runtime decides what it means.
- `hx-server` `api` tests build the full `AppState`: `a_profile_naming_an_unknown_host_is_refused_by_name`
  (a profile whose `host:` names no configured machine is refused with the name, not silently local), and
  `a_profile_with_no_host_resolves_to_the_local_manager` (the control: a profile without a `host` key
  returns the exact local daemon's `SandboxManager` `Arc`).

Not yet exercised against a live remote daemon; that is the remaining M4 step.

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

**The chat path, against a real container engine** (`crates/hx-server/tests/chat_live.rs`)

Two tests that drive `POST /v1/chat` with a scripted model and a real Docker daemon. `tests/api.rs`
proves the wiring with a *recording* runtime — the manager is real, the command is asserted exactly —
but a recording runtime cannot see whether that command can actually run where it is sent. That gap is
not hypothetical: the first version of this wiring built the command line with `cd '/host/checkout' &&
…` embedded in the shell source, so the container received a path that does not exist inside it while
the adapter was dutifully translating the separate workdir argument into `/workspace`. Every hermetic
test passed.

| What ran | Observed |
|---|---|
| A request that names a profile, with a shell call | The command ran inside a real container: `printf … > proof.txt && pwd && id -u` produced a file that appears on the **host** through the bind mount, with the container's own contents |
| What the model was told | `/workspace` — not the host checkout path — plus `ran in sandbox …`, so the model is not handed a path that only exists outside the box |
| Which user it ran as | Non-root: the adopted workspace owner, which is what makes the bind writable on a host whose uid is not 1000 |
| A second request in the same checkout | Reused the same container id rather than starting a second one — the cache is keyed on profile + host workspace path, so a boundary is paid for once per checkout |
| A request naming an unknown profile | `400`, naming the profile, with **no** container started and **no** session created — a misspelt boundary is never a quiet unconfined run |

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

**A terminal on another machine, end to end** (`crates/hx-remote/tests/pty_live.rs`,
`crates/hx-server/tests/terminal_remote_live.rs`)

Against a throwaway OpenSSH 10.5 `sshd` on port 2222. The server-side suite is the one that matters:
a client POSTs a terminal with `"host": "buildbox"`, attaches over the WebSocket, and types — every
layer in between is real (config, secret store, SSH transport, the pump, the broadcast, the socket).

| What ran | Observed |
|---|---|
| **A command typed after the shell starts executes remotely** | `echo PTY_MARKER_$((6*7))` came back `PTY_MARKER_42`. The arithmetic is evaluated by the *remote* shell, so the marker cannot appear unless the bytes reached a shell on the far side |
| A resize reaches the kernel | `stty size` after a resize reported `40 120` — the winsize the pty actually has, not the request going out |
| Closing is idempotent and ends the stream | Second `close()` is not an error; `read()` returns `None`. Buffered output already in flight may arrive first, and dropping it would lose the last thing the terminal said |
| A client attaching late is sent the scrollback | The second client received what the first one had seen after the first detached |
| **Without an allow rule** | `403 host "buildbox" requires approval (external) but no approver is attached to this route` — and nothing was registered, so a client cannot then attach to a terminal that never existed |
| An unknown host | Refused, naming the host asked for, with nothing registered |

Three findings are recorded here because each looks like a broken transport and is not:

- **`fish` waits for the terminal to answer.** The default login shell here performs a DA1/DSR
  handshake on start and blocks until the emulator replies. A test process is not an emulator, so the
  shell parks at the handshake and the typed command arrives as literal text interleaved with the
  queries. The tests pass an explicit `sh`; against a real client the queries are answered.
- **`ssh-keyscan` never authenticates, so OpenSSH ≥9.8 bans it.** After a few scans every later
  connection is reset (`kex_exchange_identification: read: Connection reset by peer`) while sshd
  looks healthy and keeps listening. A test sshd needs `PerSourcePenalties no`.
- **The daemon pins host keys against its own file**, not `~/.ssh/known_hosts`, so reaching a real
  sshd requires seeding `<data_dir>/known_hosts` — `ssh-keyscan` into it, as an operator would.

**A terminal inside a sandbox, end to end** (`crates/hx-sandbox/tests/docker_live.rs`,
`crates/hx-server/tests/terminal_sandbox_live.rs`)

Against a real Docker daemon, with the image provided by `HX_DOCKER_TEST_IMAGE` (the tests never pull:
a missing image fails rather than hanging on a network). The engine-level suite drives the session API
directly; the server suite is the one that matters, because it goes through every layer — the HTTP
route, the adapter, the engine attach, the pty inside the container, the pump, the broadcast and the
WebSocket:

| What ran | Observed |
|---|---|
| **A shell inside a container is typed into** | `echo hx-pty-echo-9f3c` came back with the marker **twice** — the pty's echo and the shell's own output. Asserting on one occurrence would pass against a session that echoes and executes nothing |
| Resizing reaches the pty | `stty size` reported `33 101` at open and `47 137` after a resize: the client's frame, the manager, the engine's `exec resize` and the pty itself, not a field on this side |
| An interactive session is not a way out | L2: `id -u` is `1000`, the read-only root refuses a `touch /`, and `/workspace` stays writable. A shell is the same unprivileged user with a prompt |
| Closing ends it | The engine's attach stream **cannot be half-closed** (`tokio::io::split` shares the socket, so dropping the write half closes nothing — measured: the session stayed alive and `read()` never returned), so `close()` sends EOT, which the pty's line discipline turns into end-of-input and the shell exits on |
| **Through the daemon** | `POST /v1/terminals {"sandbox": …}` → WebSocket → typed `echo hx-inbox-4b71` arrives twice, `pwd` is `/workspace`. Driven in a real browser too: the pane read `in sbx_…`, `hostname` printed the container's id, and the terminal label turned amber |
| **A box that goes away takes its shells with it** | `DELETE /v1/sandboxes/{id}` on an attached session sends the client `exited` and deregisters the terminal. Found by running it, not by reasoning: the first version left the pane attached over a container that no longer existed, because the engine does not end the exec's stream when the container is removed |
| A backend with no way to attach | `409` naming the limit, from a runtime that creates and execs but cannot carry a byte stream — never a client waiting on a terminal that will never speak |
| `host` and `sandbox` together | `400`, before the host capability gate: refusing one of two targets on behalf of a caller who has not said which they meant is not an answer |

One defect was found by running the live suite rather than the unit tests, and it is the reason that
suite exists: `Terminal::write` is synchronous and ran the remote session's future with
`block_in_place` + `block_on`, which **deadlocks** from inside the WebSocket task — the SSH write
needs the connection's own task to progress. It failed 6 of 8 runs. Fixed with async twins
(`write_async`/`resize_async`) that await instead.

**A live screen** (`crates/hx-browser/tests/screen_live.rs`, `crates/hx-server/tests/screen_api.rs`)

The screen is a browser the daemon runs and streams: JPEG frames down a WebSocket, mouse, wheel and
keys back up. Every claim in this section was measured against a real Chrome on the host, and the
input half is measured *by the page it drives* — a click that the browser ignored produces no request,
and the tests wait for one:

| What ran | Observed |
|---|---|
| `POST /v1/screens` | Launches and lists: `{"created":true,"screen":{"id":"probe","pid":46528,"url":"http://127.0.0.1:7721/","width":1024,"height":768}}` |
| Frames | The bytes are a JPEG passed through untouched (SOI `ff d8 ff`, EOI `ff d9`, ~100 KB of a real page), with the frame's **own** dimensions — `800x600` for a request of `800x600`, which only holds because the driver overrides the viewport metrics rather than trusting `--window-size` (`--window-size=800,600` under `--headless=new` renders `782x504`) |
| A click a watcher dispatches | The page's own `onclick` ran: the test's stub records the `GET /clicked` that only the page could have issued. Clicking in the **browser pane** end to end (the daemon's web client, a `data:` page that turns red on click): corner pixel `[255,255,255]` before, `[250,3,0]` after |
| Typing | `keyDown` with `text` inserts a character and `Input.insertText` appends at the caret (`?q=h` then `?q=hi`); `Ctrl+A` arrives with `ctrlKey` true (`/key?ctrl=true`) rather than as a plain letter, which is what the modifier mask is for |
| A navigation | `Page.frameNavigated` reaches the client as `{"type":"navigated","url":…}` and the address bar and the pane's caption follow it |
| No browser on the host | `503` naming every path searched and the config key that would fix it: `no Chromium-class browser was found (looked for ["/usr/lib/chromium/chromium", …]); name one with the screen.browser config key`. 503 rather than 502 because that is a fact about the host, not a failure of the request |
| An id that would escape the profile root | `400` for `../../escape`, `..`, `.`, `a/b` and `""`: the id names the browser profile directory, so it cannot be a path. Nothing is registered |
| A screen that does not exist | `404` **before** the upgrade, and `DELETE` on one is `404` too — a socket to a screen that was never there must not look connected |
| Closing | `DELETE` returns 200, `GET /v1/screens` is `[]`, and **zero** `chrome.exe` processes remain (checked by command line, not by image name) |
| `scripts/check_web_client.py` against a live daemon | All seven of the pane's own checks pass: `POST /v1/screens`, the listing, a JPEG frame at the requested `800x600`, a click and a key that leave the screen live, `DELETE`, and `GET /v1/screens` back to `[]`. The script reads `HX_WEB_CHECK_HOST`/`HX_WEB_CHECK_PORT` because the address it defaults to is a *convention* — a machine where `8899` is already taken (a colleague's daemon, another walk of this harness on `7721`) made it unrunnable, and a check that cannot be pointed at the daemon you are running is a check nobody runs |
| The daemon's own log | Two lines per screen, and neither is decoration: `launched a browser to watch screen=… url=… viewport=… profile=…`, where the profile is printed as an **absolute** path resolved the same way the browser resolves it (a relative `profile_root` is resolved against the daemon's working directory, which no one reading a log can see), and `closed the screen and took its browser with it`, emitted *after* the wait for the browser so the line is true when it appears |

**Three defects were found by running this rather than by reading it**, and each one is now a
test:

1. **A relative `screen.profile_root` made every screen refuse to start**, with a message that named
the one thing that was not wrong (`did not write DevToolsActivePort within 20.0s`). Chrome treats a
*relative* `--user-data-dir` as the default profile and refuses remote debugging outright
(`DevTools remote debugging requires a non-default data directory`), and the driver was nulling the
browser's stderr, so the only sentence that explained it was thrown away. The path is now resolved to
absolute before the browser sees it (`a_relative_profile_directory_still_starts_a_browser`), and the
browser's stderr is kept — bounded to 2 KiB and drained continuously so a long-lived browser cannot
fill a pipe — and quoted in the failure: `… within 20.0s; the browser said: …`.
2. **Keyboard input was dropped whenever the browser did not hold the operating system's focus.**
Found as an intermittent test failure under load (1 of 9, then 3 of 6 runs), not as an obvious bug:
a target created over CDP is attached but never *activated*, and Chromium routes keyboard input to the
active frame — so a watcher's typing reached the page only by luck. Clicks were unaffected because
they are dispatched at coordinates, which is exactly the asymmetry the failures showed. Fixed with
`Target.activateTarget` + `Page.bringToFront` after the navigation and `Emulation.setFocusEmulationEnabled`,
after which 10 consecutive full runs were green at ~1.2s each.
3. **A refused setup call was silently swallowed.** Every setup request was `let _ = …`, so a screen
that lost a capability (a rejected emulation call, say) looked exactly like a page with nothing to say.
A setup step that does not work is a screen that failed; the calls are propagated now.

The tests also gained a precondition rather than a sleep: the page announces itself (`fetch('/ready')`)
before any test clicks at a coordinate, because "a frame arrived" only says the browser painted
*something*, and an empty document paints too.

**Not covered by any run**, and stated so it is not mistaken for covered: a screen is **not** behind
the ladder's admission (a page can navigate and fetch anywhere the daemon's machine can reach — see
`crates/hx-browser/src/screen.rs`), the browser is **not** confined to a sandbox (it runs on the daemon
host; a box's own pixels need a browser inside the box and a way to reach its port, neither of which
exists yet), and no run watches a screen for longer than a test's lifetime, so the frame throttle
(`SCREEN_FRAME_BUFFER`, 2) is asserted by construction rather than by a soak.

**A person at the last rung** (`crates/hx-server/src/pane.rs`, `crates/hx-server/tests/challenge_api.rs`)

`hx-browser`'s ladder ends with a person: the plain rung is refused, the browser rung is refused, and the
wall is handed to a `HumanPane`. Until now the only implementation of that trait was `NoPane` — the pane
that is not there — so the contract was real and the loop was open. It is closed here, and it is driven
end to end over HTTP against a stub that refuses and a **real browser**:

| What ran | Observed |
|---|---|
| A stub answering `403` to everything, through a pool built with `with_pane` | `769ms over 3 attempts: http -> chromium -> interactive-cdp`, measured rung by rung: `1ms http -> the http rung was refused: the site answered HTTP 403`; `523ms chromium -> the interactive rung was refused: the site answered HTTP 403` (a real browser launched and read the stub's refusal); `244ms interactive-cdp -> the interactive rung stopped: screen-pane cleared the challenge; the session's profile is now unblocked, so re-run the ladder in this session`. The same run on a host with no browser at the rung's old hardcoded path instead read `1ms chromium -> the interactive rung is unavailable: /usr/lib/chromium/chromium is not installed` — a capability gap rather than a wall, which is what the shared search below removes |
| The person's view | `GET /v1/challenges` lists it while the fetch waits: `{id, screen, session, url, reason, seconds_left}` — the site in **redacted** form, the session that is blocked, why the automated rungs gave up, and the budget the rung enforces counting down |
| Answering | `POST /v1/challenges/{id} {"outcome":"solved"}` → `200 {"answered":true}`, and the fetch is told what happened |
| A second click | `409` — *the challenge is over*, which is a different fact from `404` *no such challenge*, and a person who clicked a second too late is owed the first |
| The browser | Gone before the rung is told anything: `GET /v1/screens` is `[]` after the answer, because the pane waits for the process rather than reporting an outcome over a renderer that is still exiting |
| No pane at all | The same ladder without `with_pane` still carries the rung and fails closed: `stop_reason` names it, `no human pane is attached, so the interactive rung fails closed rather than waiting for a person who will never arrive`, and no browser is launched |
| The web client, in a real browser | The banner over the screen pane read `browser_final is blocked on http://example.test/verify` · `90s left` · the reason, with the rail and drawer `screen` tabs marked. `it is cleared` posted `{"outcome":"solved"}` and hid it; `give up` with an empty note showed the daemon's own refusal verbatim and **kept the banner up** (so the person can supply the reason the daemon asked for); `give up` with a note posted it |
| `scripts/check_web_client.py` against a live daemon | Six checks pass on any host, no browser needed: the listing is a listing, an unknown id is a `404`, a reasonless decline is a `400` (not the `404` that would hide the real mistake), and the served page carries the banner's markup |

**Cancellation is the property the contract names as the one a pane gets wrong**, so it is measured
rather than argued, at both levels:

- `pane::tests::a_dropped_wait_withdraws_the_challenge_and_hands_the_screen_back` drops `present`'s
future — which is exactly what the rung's budget does — and asserts the challenge is gone and the screen
was handed back **synchronously**.
- `a_challenge_nobody_answers_leaves_no_browser_and_no_question_behind` drives it for real: a 1.2s budget
through the daemon's own pane, and afterwards the fetch reports `nobody answered within 1.2s, so the
challenge was abandoned`, `GET /v1/screens` is `[]`, `GET /v1/challenges` is `[]`, and **zero `chrome.exe`
processes remain** (checked by process, after the run). A person arriving late to the id they were shown
gets `409`, not `404`.

That synchronous path is the design, not a shortcut. `Drop` cannot await, and the obvious alternative —
taking a runtime handle and spawning the close — panics on a runtime that is shutting down, which is
precisely when a daemon tears a fetch down. The browser dies instead because dropping the last handle to a
screen kills its child, so `Screens::forget` — the sync half of `remove` — is the whole job.

**Four defects were found by running this rather than by reading it**, and each one is now a test:

1. **A second click on an answered challenge reported "no such challenge"** — a lie, and one that sends
a person looking for a mistake they did not make. The registry now remembers finished challenges (bounded
at 64) so *too late* and *never existed* are different answers, which is what makes the route's `409`
reachable at all rather than a race nobody can hit.
2. **The pane reconnected forever to a screen the daemon did not have.** A closed screen is not a failed
attachment — that is what reconnecting is for — but the browser's `WebSocket` API does not expose the
`404`, so the pane retried with a backoff for as long as the tab was open. It now asks the daemon, and
distinguishes carefully: a *successful* listing without the id ends the attempt with `screen closed: the daemon
no longer has it`, while a listing that **fails** keeps retrying, because an unreachable daemon is the case
recovery exists for. Measured both ways: one socket opened against a missing screen, ten in four seconds
against a daemon that was down.
3. **The caption kept a stale claim while reconnecting.** With the fix above, the pane could be quietly
retrying to `hx-screen` while the caption still said the previous screen was gone. It now says
`reconnecting to hx-screen…`, because a caption is a statement about now.
4. **The contract's own refusal message had gone stale.** A `Solved` outcome ended the rung saying
`no CDP driver is wired yet`, which stopped being true when the screen landed — the pane it just used *is*
the driver. The reason and the module docs now say what the rung actually did: it presents the wall and
takes an answer, and reading the cleared page is the ladder's job on a re-run.

**The browser the ladder drives is the browser the screen finds** (`crates/hx-browser/src/browser.rs`)

Until this change the run above reached the person through the Chromium rung's **capability gap**:
`hx-search`'s `browser_available()` and `ChromiumRung` each spelled `/usr/lib/chromium/chromium`, while the
screen searched the platform's real places. On a host whose browser is elsewhere — this one, where it is
Chrome under `Program Files` — the daemon could open a screen on a real page and still never *select* a
browser rung, so the chromium attempt above was `1ms … /usr/lib/chromium/chromium is not installed` rather
than a browser reading a wall. One search now lives in one place and answers for all three askers —
`ChromiumRung`, `hx_browser::screen`, `hx_search::browser_available` — so a fetch and a screen on one host
cannot disagree. Measured after the change, on the same host:

| What ran | Observed |
|---|---|
| The same refusing stub, rung by rung | `523ms chromium -> the interactive rung was refused: the site answered HTTP 403`: a real browser launched, read the stub's `403` and refused it, and the person was asked *because of the wall* rather than because nothing was installed |
| `POST /v1/research`, `fetch_mode: browser` | `200 {"fetcher":"browser","fetch_note":"browser: explicit opt-in, driving Chromium for every page"}` — this was the `503` naming `/usr/lib/chromium/chromium` |
| `POST /v1/research`, `fetch_mode: auto` | `200 {"fetcher":"browser","fetch_note":"auto: browser available, escalating plain-HTTP-then-Chromium"}` — this was `"auto: no browser on this host, degraded to plain fetch (honest default)"` |
| `POST /v1/research`, `fetch_mode: http` | Unchanged: `200 {"fetcher":"http"}` — a host finding its browser must not make a plain fetch launch one |
| `crates/hx-search/tests/browser_rung_canary.rs` (ignored), now running on this host | `browser_rung_canary: driving C:\Program Files\Google\Chrome\Application\chrome.exe`, `selection: auto=Browser, browser=Browser`, and the browser path's citation contains the token the page's own script inserts (`JS_RENDERED_CANARY_…`) while the plain path's does not. It used to skip here, keyed on the Linux path |
| `hx.example.yaml` / `examples/dogfood.yaml` comments | The `screen.browser` key and the usual-places search are now described as one search, since that is what they are |

Two things are deliberately *not* the same as before, and both are honest rather than merely narrower.
The rung resolves the binary **when the fetch runs**, not when it is built, because whether a host has a
browser is a fact about the host and a ladder has to be buildable anywhere — so `BrowserFetcher::new`
succeeds on a machine with no browser and only the *fetch* refuses, naming every path searched. And the
`Browser`-mode refusal is the search's own message rather than a second, thinner one about a binary this
crate never went looking for.

**A wall *through* the research route, with the fetch path configured** (`crates/hx-core/src/config.rs`'s
`fetch:` section, `hx_search::FetchPolicy`, `crates/hx-server/tests/research_api.rs`)

The join above was the one thing that could not be driven, and two config keys were what it was missing:
`fetch.admission` says who a target may be and `fetch.browser` names the binary to drive. Both become one
`FetchPolicy` in one place — `FetchPolicy::from_config`, the single mapping between `hx-core`'s vocabulary
and `hx-browser`'s, because the config model cannot depend on the fetcher crate (the dependency runs the
other way) and a second mapping anywhere else would be a second answer to *"may this fetch reach
loopback"*.

| What ran | Observed |
|---|---|
| `POST /v1/research {"fetch_mode":"auto"}` at a loopback stub that answers `403` to everything, with `fetch.admission: allow_local` and `fetch.browser` naming this host's Chrome | The climb is http → chromium → interactive-cdp, a challenge appears at `GET /v1/challenges` carrying the stub's URL, the blocked session (`browser_…`) and the reason, and the stub was reached **twice** (plain rung, then browser) — the person is asked because the *site* refused both rungs, not because one could not run |
| The person's answer, `POST /v1/challenges/{id} {"outcome":"solved"}` | `200 {"answered":true}`, and the research POST then returns `200 {"fetcher":"browser"}` with the source cited and an **empty** snippet — the run ended at the person, so the page itself was never read. Afterwards `GET /v1/challenges` and `GET /v1/screens` are both `[]` |
| The same route at a wall that refuses anything whose user agent is not Chrome's | The citation's snippet carries the page's sentinel — text only a real browser is served — and the wall was *asked* twice. This is the assertion that the config key reached the rung: a policy that stopped at the selector would leave one request and an empty snippet |
| The **default** policy, same stub, `fetch_mode: browser` | Unchanged and still a refusal: the loopback page is refused before any socket (`0` connections at the stub), the citation is empty, and **no challenge is opened** — a person is never asked to solve hx's own policy |
| A policy naming a binary that is not there | The gate becomes the path itself rather than the host's search, so a named-but-missing browser is refused with that path in the message, and the rung built from the policy is the one that tries *that* binary (`hx-search`'s own tests, no host needed) |
| The same walk against a **real daemon** (`hxd` with a `fetch:` section, a SearXNG-shaped stub, plain `curl` over real HTTP) | A challenge appeared **1s** into the run — `chal-0`, session `browser_f8232989ba863d69`, url `http://127.0.0.1:8873/wall`, `seconds_left: 29` — with **11 `chrome.exe` processes** alive while it waited (the browser rung's child plus the pane's screen); `POST /v1/challenges/chal-0 {"outcome":"solved"}` → `200 {"answered":true}`; the research POST returned `200`, `"fetcher":"browser", "fetch_note":"auto: browser available, escalating plain-HTTP-then-Chromium"`, the source cited with an empty snippet; afterwards `GET /v1/challenges` and `GET /v1/screens` are both `[]` and **zero** `chrome.exe` remain. The stub's own log is the climb by user agent: `/search … Chrome/131` (the backend), `/wall ua=hx-browser/0.0.1` (the plain rung), `/wall ua=… HeadlessChrome/153…` (the browser rung — the binary `fetch.browser` named), then the same pair again for the pane's screen |
| The same daemon with `fetch.admission: public_internet`, same stub, same request | The stub was asked for `/search` and **never for `/wall`**: the refusal is hx's own policy rather than the site's, the citation is empty, and `GET /v1/challenges` is `[]` — nobody is asked to clear a target admission refused |

One defect came out of running this, and it was not in the new keys. **A waiting person lost to the
fetcher's own clock:** `BrowserFetcher::fetch` bounds the whole climb with `DEFAULT_FETCH_TIMEOUT` (10s),
which is *shorter* than any sane `challenge_budget_secs` — so the promise the screen section makes ("a
refused page opens a screen on this machine and waits" that long) was broken by a timeout ten seconds in,
and the report blamed the fetch instead of saying a person was still deciding. `with_pane` now widens the
bound to clear the budget plus `PANE_TIMEOUT_GRACE` (30s, the rungs' own work either side of the wait);
the arithmetic is asserted in `hx-search` and the behaviour is exercised by the route test above.

One more defect came out of driving a real daemon, and it was one layer down from the first timeout:
**the ladder's own per-rung deadline cut the person off at 20s.** `with_pane` widened the fetcher's outer
bound (above), but the ladder *inside* the pool still ended every rung at `hx-browser`'s
`DEFAULT_RUNG_TIMEOUT` (20s) — so a person with a 90s budget was withdrawn at 20s and the report blamed
the rung. Measured before/after on a live daemon: a challenge handed at 03:07:36 was withdrawn at
03:07:56 (20s, the ladder's clock); after the fix, handed 03:08:39, withdrawn 03:10:09 (89.8s — the
budget). `build_pool` now widens the ladder's deadline to clear the budget by the same grace, only when a
person is attached; the machine rungs keep the machine deadline. Asserted as arithmetic in `hx-search`
(`the_ladders_own_deadline_clears_a_persons_budget_but_not_the_machine_rungs`) — and the unit test
`a_token_against_an_id_that_is_not_waiting_is_answered_not_hung_on` pins a **deadlock** an integration
test found on the way: the token check must not hold the registry lock while calling into the registry,
which is exactly what a request naming an id *with* a token reached.

**Addressed to a person, and they are told** (`crates/hx-server/src/challenge_notice.rs`,
`crates/hx-server/tests/challenge_api.rs`)

A challenge is a question for one person, so it is now *delivered* rather than put on a noticeboard. The
daemon names the operator (`screen.operator`, falling back to `api.admin_username`), pushes a
notification to `approval.push_url` — the same webhook approvals and completions use, with its own
`kind` (`challenge` / `challenge_resolved`) — and the listing carries who it is for and whether anyone
was told. The notification carries a **one-time token** (a `NoticeToken`, redacted in logs exactly as
the phone's respond token is): `POST /v1/challenges/{id}?token=…` answers that one challenge without the
daemon's bearer token, and a wrong token is a `403` that leaves the question open.

| What ran | Observed |
|---|---|
| A stub answering `403`, through a daemon with `api.token`, `screen.operator: yoav` and `approval.push_url` pointed at a loopback relay | The relay received `{"kind":"challenge","id":"chal-0",…,"operator":"yoav","page_url":"http://127.0.0.1:8901/#screen=chal-0","respond_url":"…/v1/challenges/chal-0?token=…"}` within a second of the wall being reached |
| The listing | `"operator":"yoav","notified":true` — who it is for, and that a push really went out |
| The answer, exactly as a relay would send it | `POST {respond_url} {"outcome":"solved"}` with **no** `Authorization` header → `200 {"answered":true}`; the relay then received `{"kind":"challenge_resolved",…,"outcome":"solved"}` |
| No credential at all | The listing is a `401`, and so is an answer — the token is the way in, not an open door beside the bearer |
| A token that is not this challenge's | `403` naming the mistake, and the challenge **still waiting** for the person who was asked |
| The banner, in a real browser | `browser_f823… is blocked on http://127.0.0.1:8873/wall · 31s left · for yoav — told on their own channel`, with the reason and the action row |
| The notification's `page_url` deep link | `#screen=chal-6` opened the screen pane, attached to the live challenge screen and drew the wall's frames; the banner showed over it |
| The resolution, when nobody answers | The relay received `challenge_resolved … withdrawn` — a person told to hurry is told when they can stop, on every path including the `Drop` one |

`an_addressed_challenge_is_announced_to_the_operator_and_its_token_answers_it` drives the whole loop in
`challenge_api.rs` — real browser, real relay, token-only answer, wrong-token refusal, bearer-gated
everything else. `scripts/check_web_client.py` gained checks for the `challenge-for` line and the deep
link handler in the served page.

**Several operators, each on their own channel** (`screen.operators`,
`crates/hx-server/tests/challenge_api.rs`)

One shared webhook is the noticeboard the addressing work was meant to end, and it is also unusable
once a second person is responsible for a daemon: every question reaches every operator, and the name
on it says nothing about whose run is blocked. `screen.operators` is a list of `{name, push_url}`, and
the daemon **rotates** through it — each challenge goes to the next name in order, wrapping at the end
— pushed to *only* that person's webhook, with the resolution taking the same route back.

The interesting assertion is the one that is not made: what the **other** relay received. A test that
stood up a single relay could not tell a routed push from a broadcast one, because both arrive. So this
test stands up two, points the config at both, points `approval.push_url` at a third address that must
never be used, and then checks that the second relay received nothing at all.

| What ran | Observed |
|---|---|
| A daemon configured with `screen.operators: [yoav, dana]`, each on its own loopback relay, `approval.push_url` set to a third, unroutable address; a stub answering `403`; a live browser | yoav's relay received `{"kind":"challenge",…,"operator":"yoav",…}`; **dana's relay received nothing** — the push is routed, not broadcast, and the roster did not merge with the single-operator keys |
| The listing | `"operator":"yoav","notified":true` — the same name the notification carried, and `notified` is about *that person* rather than about the daemon |
| The answer, from the notification's own one-time URL | `POST {respond_url} {"outcome":"solved"}` with no `Authorization` → `200`; the fetch reports `screen-pane cleared the challenge` |
| The resolution | Back to **yoav's** relay (`{"kind":"challenge_resolved",…,"operator":"yoav","outcome":"solved"}`) and to nobody else — the person told to hurry is the person who learns they can stop, and the other operator's phone is not woken about a run they were never asked about |
| Both relays' total contents at the end | yoav `[challenge, challenge_resolved]`, dana `[]`. Exactly the two pushes about this run, and no third to the address `approval.push_url` names |

The rotation itself is pinned as arithmetic in the pane, where it can be observed without a browser
(`crates/hx-server/src/pane.rs`):

| What ran | Observed |
|---|---|
| Three challenges against a roster of `[yoav, dana, sam]` | `yoav`, `dana`, `sam` — the config's order, one question each |
| Five challenges against a roster of two | `yoav, dana, yoav, dana, yoav` — it wraps rather than running out of people to ask, which is the failure the rotation exists to prevent |
| Two challenges against a default daemon | `admin`, `admin` — a daemon that names one operator gets no rotation it did not ask for, and the roster is still never empty |
| A roster of `[yoav (with a webhook), dana (without one)]` | `notified: true` then `notified: false` from the same daemon and the same notifier. A daemon-level flag would have told dana her run was ringing somebody else |
| A roster with a repeated name, a blank name, and a blank `push_url` | The repeated name keeps the first channel and the table holds two people; a blank name is dropped; nobody-with-a-channel reports as unreachable rather than as reachable |

**Still not covered by any run:** the pane itself — *watching* a screen — stays first-come, so a
second operator who opens the daemon's page can clear a wall addressed to the first; the routing is for
the notification, not for the keystrokes. There is also no chat-connector path for the notice — the
Telegram mirror answers *approvals*, not challenges — and nothing weights the rotation by who asked or
which session the run came from, because the daemon has no fact to weight it by. And `allow_local` is exercised here against a loopback stub, not against the deployment it
is written for: a private host or a metadata endpoint on a real network. The policy is the same code
either way, but no run in this repository configures it against one.

**A box that boots something** (`crates/hx-sandbox/tests/docker_live.rs`, `crates/hx-server/src/runtime.rs`)

`sandbox_profiles.<name>.command` turns a box from a place to run commands into an environment with a
process of its own. Against a real daemon (127.0.0.1:7721, `examples/dogfood.yaml`, `debian:latest`):

| What ran | Observed |
|---|---|
| A profile with a command, through `POST /v1/sandboxes` | The engine's own view from the host: `/sbin/docker-init -- sh -c printf … ; exec sleep 3600` and `sleep 3600`, and from inside, `/proc/1/cmdline` is the profile's argv. A runtime that accepted the key and started `sleep infinity` anyway would look identical from every other angle |
| The command really ran, before anything connected | The marker it wrote was in the **host** workspace (`target/hx-boot-ws/booted.txt`) — the box is not waiting for a probe to do something |
| It is still a box | `id -u` is `1000`, `/workspace` is the only writable place, and an attached shell works *beside* the boot command rather than replacing it |
| A command that exits at once | **Refused**, naming it: `sandbox profile 'one-shot' boots \`sh -c echo this box is already over\`, which exited within the 500ms it is given to prove it stays up … It has been removed.` `GET /v1/sandboxes` is empty afterwards and the slot is free |
| The firecracker backend | Refuses a profile with `command` before any work: its guest boots its own init, so there is no place for the argv to go. Booting anyway would be a silent lie |
| A NUL byte in a command | `command contains a NUL byte, which cannot be passed to a process; send the command without it` — before, it reached `execve` and the engine answered `exec /usr/bin/sh: invalid argument`, naming neither the request nor the byte |

The first of those two defects is the one worth recording: a box whose command dies is reported by the
engine exactly like a box that is quietly running a server (`create` succeeded, `start` succeeded, the
container exists), and the only thing that could tell them apart is asking the engine about the
container's own state. Hence `SandboxRuntime::alive`, whose default answers "cannot tell" — the
CLI-speaking remote runtime and the microVM backend have no such call, and a backend that cannot
observe its sandbox must not invent an answer. The grace period before the question is settled is
`BOOT_GRACE` (500ms), paid only by a spec that boots something: a program that dies 50ms in is
reported `running` by the first look, so one look is not a check.

Also changed by this work: the remote runtime's command line now shell-quotes the default argv
(`'sleep' 'infinity'`) exactly as it already quoted an operator's, because the far side is a shell and
an argv element may contain a space — the two paths must not need different trust.

Not covered by any run: a *long*-lived command that dies after the grace period (a server that crashes
an hour in) is invisible to the check and the box stays tracked until its TTL; a remote sandbox with a
`command` has no `alive` at all, so it keeps the old behaviour deliberately.

Those runs are also why the suite's `Cleanup` guard was rewritten. It existed to remove a test's
container when the test panics — its own doc comment says so, after a failing run left one up for 36
minutes — but it did its work with `runtime.spawn` on the test's runtime, and `#[tokio::test]` drops
that runtime the moment the body returns: the removal was scheduled and never polled, so **the guard
worked only on the paths that never needed it**. Nine orphans from earlier runs were still up. It is
a thread with its own current-thread runtime now, joined before the drop returns, and the claim is
measured in both directions: a test that panics after a successful spawn leaves the container count
unchanged (9 before, 9 after), and the full 15-of-18 run above now leaves **no** containers behind —
where the same run left three.

Running that suite on this host (Windows) gives **15 of 18 `docker_live` tests green, 3 red for
reasons that have nothing to do with this work**: the two egress tests cannot bind-mount
`hx-egress-proxy.exe` into a container (`mount denied … too many colons` — Docker Desktop will not
accept a `\\?\C:\…` path), and the L2 settings test asserts `adopt_workspace_owner` produced a
`uid:gid`, which is a documented no-op off Unix. `the_concurrency_cap_refuses_the_n_plus_first_container`
is also red when the file's tests run in parallel — it counts **every** `hx-` container on the daemon,
including ones other tests are creating — and passes with `--test-threads=1`.

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
| write → read of a binary file | 8 bytes including `0x00 0xff 0xfe 0x80`, byte-identical (a `cat`-based transfer would mangle this); over the SFTP subsystem when the server offers one | 
| list a directory | The file listed with the right size and absolute path; a missing directory is an error, not an empty list |
| **SFTP subsystem measured + rename** | The probe opens `sftp` and completes the handshake, reporting `has_sftp == Some(true)`; a 200 KB binary file is `write_file` → `rename` → `read_file` over the subsystem, byte-identical |
| **Unknown host under `Strict`** | Refused **before authentication**, nothing written: `refused to connect to … — no known_hosts entry for …; refusing under strict host key checking (add the key with ssh-keyscan, or use HostKeyPolicy::Tofu)` |
| **A changed key (the MITM case)** | Refused, planted entry untouched: `the host key for … does not match the one recorded at /tmp/…/known_hosts:1 (recorded …IJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ, offered ssh-ed25519); a changed host key is what a man-in-the-middle looks like, and a rebuilt server looks identical — remove that entry if the change is expected` |

Still not covered by any run: a Windows SSH server, a jump host, and `ssh-agent` auth (which returns
an explicit "not implemented" error rather than a wrong answer).

**The WinRM transport, against a real Windows host** (`crates/hx-remote/tests/winrm_live.rs`)

**9 passed, 0 self-skipped** against the `hx-wintest` guest on rainbowone (Windows 10, `dockur/windows`).
What that covers: connect and self-report, a command's output coming back through the SOAP framing, a
failing command reporting its exit code and stderr separately, a file round-tripping byte-for-byte, a
directory listing with real entries, `rename` refusing to overwrite, several commands reusing one
shell, an unreachable host failing cleanly, and bad credentials being refused with a message that
names the account **and never echoes the password**.

**The transport is HTTPS + Basic. NTLM-over-HTTP cannot work and never will** — WinRM seals every
post-handshake request with the negotiated session key (`multipart/encrypted`, MS-NLMP SEAL) and this
client does not implement that layer, so a plaintext envelope is refused whatever the password is. The
NTLM crypto is correct; the transport is the problem. Do not spend time on it again.

The guest has **no HTTPS listener**, so the run puts a TLS-terminating proxy in front of the plain
5985 listener. The proxy must NOT sit on **5986**: the suite computes `https = port == 5986`, so a
proxy there silently switches the client to TLS against a plain listener. Use a spare port (**5999**):

```console
# on the host that can reach the Windows guest (rainbowone here):
cp /tmp/tls_proxy.py /tmp/tls_proxy_5999.py
sed -i 's/^LISTEN = ("127.0.0.1", 5986)/LISTEN = ("127.0.0.1", 5999)/' /tmp/tls_proxy_5999.py
setsid nohup python3 /tmp/tls_proxy_5999.py < /dev/null > /tmp/tls5999.log 2>&1 &

# from the machine running the tests, forward that port:
ssh -N -L 5999:127.0.0.1:5999 yoav@100.99.145.19

# the guest account's password is read from its own container env, never typed into a transcript:
PW=$(ssh yoav@100.99.145.19 "docker inspect hx-wintest --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^PASSWORD=' | cut -d= -f2-")
HX_WINRM_HOST=127.0.0.1 HX_WINRM_PORT=5999 HX_WINRM_USER=hxtest HX_WINRM_PASSWORD="$PW" \
HX_WINRM_AUTH=basic HX_WINRM_HTTPS=1 HX_WINRM_INSECURE=1 \
  cargo test -p hx-remote --test winrm_live -- --ignored --test-threads=1
```

`HX_WINRM_INSECURE=1` accepts the self-signed cert; `HX_WINRM_HTTPS=1` is what makes the client accept
Basic at all (the crate refuses Basic over plain HTTP, for exactly the confidentiality reason above).

**One test was wrong and is now fixed.** `wrong_credentials_…` hard-coded `WinRmAuth::Ntlm` and derived
`https` from `port == 5986` instead of honouring the configured auth — which made it the one test that
could not pass on the transport that actually works, and it failed with a misleading `error sending
request for url (http://127.0.0.1:5999/wsman)`. It now follows the same `auth()` helper as every other
test in the file. Worth remembering as a shape: **a test that pins its own transport while the rest of
the suite is configured for another will always be the odd one out, and its failure looks like a
product bug.**

**This cannot run in CI** — it needs a reachable Windows box, and CI runners can reach neither the
tailnet guest nor a Windows machine, so there is deliberately no job that would only skip.

**The remote sandbox runtime, against a real remote Docker daemon** (`crates/hx-sandbox/tests/remote_live.rs`)

`RemoteSandboxRuntime` renders the same settings the local runtime maps to as docker CLI command
lines and hands them to a transport; the unit tests assert those lines token-for-token against a
recording fake. That proves the words we send are the words we reviewed, not that a far `docker`
accepts them or that the far daemon enforces the flags. This suite connects a **real `SshHost`** to
a host with Docker and drives the runtime for real, inspecting the container on the far host to verify
the security properties independently of the command string.

Run it exactly like `ssh_live.rs`, naming a machine that has Docker reachable without sudo:

```console
$ HX_SSH_TEST_HOST=100.99.145.19 \
  HX_SSH_TEST_USER=yoav \
  HX_SSH_TEST_KEY=~/.ssh/yoav \
  cargo test -p hx-sandbox --test remote_live -- --ignored --nocapture --test-threads=1
```

The host's user must be able to `docker` without sudo (be in the `docker` group), and the test
image (`ubuntu:24.04`, override with `HX_DOCKER_TEST_IMAGE`) must be pullable by that daemon.

| What ran (rainbowone, `100.99.145.19`, Docker 29.3.1) | Observed |
|---|---|
| **Full lifecycle over SSH: create → start → exec → stop → remove** | The container existed on the far host after create and after stop; `exec` ran `REMOTE_ALIVE; id -u` → `1000`; gone after remove; a second remove left it removed (idempotent, no leak) |
| **Security flags as the far daemon stored them** (`docker inspect` parsed from the far host, not re-read from the command) | `ReadonlyRootfs==true`, `Privileged==false`, `CapDrop` contains `ALL`, `NetworkMode=="none"`, `PidsLimit==128`, workspace bind-mounted; a real `touch /definitely-not-allowed` was denied while `/workspace` stayed writable and the write reached the remote host's directory |
| **Remote egress is enforced on the far host, not refused** | `network: true` + `example.com` created a `-egress` internal network and a `hx-egress-proxy` sidecar **on the far daemon**. The sidecar was confirmed *running* by name first — a dead sidecar must not read as a routing or DNS symptom — then probed **through** it from inside the sandbox with a hand-written `CONNECT` line: `example.com` → `200`, `malware.test` → the allowlist's own refusal (`403`), and a *direct* connect to `93.184.216.34:443` → `NO_ROUTE`. The allowed/denied **pair** is what distinguishes enforcement from a blanket block, and the direct attempt is what a sandbox merely *told* about a proxy would violate. After `remove`, the sandbox, the sidecar and the network were all gone |
| **A real finding: `--userns=private`** | L2/L3 sends `--userns=private`, which a daemon **without** `userns-remap` in `daemon.json` refuses at create with `--userns: invalid USER mode`. The module claimed the CLI flag was a no-op on such a daemon — it is not (see the ROADMAP entry). The finding is pinned by `the_far_daemon_rejects_l2_userns_remapping_when_it_is_not_configured` and leaves nothing behind |

**This suite cannot run in CI.** It needs a machine on the private tailnet (`100.99.x.x`) that CI
runners cannot reach, so there is deliberately **no** integration.yml job for it — a job that only
skips would add noise without evidence. An operator runs it by hand against a reachable host, as above.
No container, network, sidecar or workspace is left on the host when it finishes: the egress test
asserts each one's absence after `remove`, and the `Cleanup` guard sweeps them on the panic path as a
**blocking `ssh` child process** — deliberately not a spawned task, since the runtime is torn down while
a panic unwinds and a never-run spawn is exactly how a live sidecar once leaked off this suite.

**The same SSH transport against Darwin** (`macos-ssh` job in `integration.yml`)

The table above is a Linux sshd. A GitHub-hosted `macos-latest` runner is a real Apple-signed macOS
VM, so the same `ssh_live` suite points at it — a real `sshd` started on the runner's loopback
with `systemsetup -setremotelogin on`, the runner's own key authorized, `HX_SSH_TEST_OS=macos`
so the capability probe must report `Darwin` → `RemoteOs::MacOs` (see `expected_os` in `ssh_live.rs`).
Since macOS ships an SFTP server, `has_sftp` is measured `Some(true)` and the file round-trips and
rename go through the subsystem, not the shelled-out fallback. The run records `sw_vers` and `uname -a`
in the job summary and uploads the live log as the `ssh-live-darwin` artifact, so the evidence is
readable without re-running.

**The key invariant: no private key reaches the model, the trail, or a sandbox** (hermetic, five tests)

M4's exit criteria ends with a security claim — *"no private key ever enters the model context or a
sandbox"* — that was asserted in prose and never tested. These tests make it a tripwire:

| Where the leak would surface | Test | Result |
|---|---|---|
| `SshAuth`'s `Debug` line | `a_remote_key_that_is_genuinely_present_never_renders_into_any_debug_line` | **passes** |
| A connected host's rendered surface | `a_connected_host_surface_never_renders_the_key_that_opened_it` | **passes** |
| The vault → `SshAuth` seam | `a_vault_key_that_is_genuinely_resolved_never_renders_in_its_ssh_auth` | **passes** |
| The sandbox spec | `a_sandbox_spec_from_a_profile_never_mounts_the_vault_or_any_secret` | **passes** |

**The invariant holds.** Key material cannot reach a tool result, an audit event, an error line or a
sandbox spec on any path inspected.

**These are tripwires, not restatements, and that was checked rather than assumed.** Each test uses a
distinctive generated sentinel and asserts that the sentinel *is* genuinely present on the path
before asserting it never renders — so a future refactor that stops passing the key turns the test
into an explicit failure rather than a silent no-op. The negative control was then run for real:
making `SshAuth::Key`'s `Debug` print the key (instead of `"<redacted>"`) made the first test **fail**
at `ssh.rs:1154`, and reverting it made the test pass again. A test that cannot fail is not evidence.

**What this does NOT prove**, and the doc comments say so: a sandbox with real network access could
exfiltrate a secret by other means; that is scoped out. The live connect-error path (a *failed*
connection is the likeliest place a key would render into an error the model reads) is gated as a live
test in `ssh_live.rs` rather than faked, so it runs when a real host is named.

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

**Read the `Tests` column with care: it has drifted, and this is the measurement rather than a
correction.** The numbers below were carried forward by hand as crates grew, so several are far too
low, and a table that looks precise while being stale is worse than one that admits it. Re-measured
on this machine (Windows, `cargo test --locked --no-fail-fast`):

| Crate | This table says | Measured now (passed / ignored) |
|---|---|---|
| `hx-core` | 108 | 218 / 0 |
| `hx-search` | 45 | 193 / 6 |
| `hx-sandbox` | 90 | 148 / 21 |
| `hx-server` | 46 | 283 / 3 |

`scripts/measure-test-counts.sh` is what produced the right-hand column — one `cargo test` per named
member, summing every target's `test result:` line and keeping the raw output beside the number so
the parse can be checked. Re-running it for the whole workspace is the way to refresh this table; the
column is left as-is rather than half-corrected, because two current rows beside eight stale ones
would read as "the others are current too".

| Crate | Tests | LOC | What the tests actually prove |
|---|---|---|---|
| `hx-core` | 108 | 5385 | ID monotonicity, error taxonomy (**a rejected credential is an auth failure, and a 500 is not**, so a pool retries one and benches the other), **capability path grants** (incl. the empty-grant-means-root regression), approval policy incl. unattended budgets and **the shipped catastrophe set in both directions** (the unrecoverable paths refused, `/tmp` and `/home` left answerable) and the refusal of a delete whose target is a pattern, message/event round-trips, target descriptions a person can price, and config parsing incl. rejection of unknown keys and **`hx.example.yaml` itself parsing** |
| `hx-provider` | 111 | 4091 | Token-bucket timing, **budget fail-closed on a zero estimate**, credential pool round-robin, shared-limiter identity across pools, routing and fallthrough, a granted ticket carrying the credential's `secret_ref`, a role's reservation estimated from the **dearest** route, the provider factory refusing a kind it has no adapter for, and **streaming**: SSE events reassembled across split chunks before being parsed, text deltas emitted in order, and the batch of unmerged tool-call fragments a proxy hands over merged by `index` into one call. The **Anthropic** stream as well: named events reassembled across split reads and CRLF terminators, text deltas in order, `input_json_delta` fragments accumulated and parsed only at `content_block_stop` (a per-fragment parse fails on nearly every real call), an empty-argument call treated as `{}` while genuinely truncated JSON is an error naming the call, two tool calls in one turn kept apart by index, usage taken from the last cumulative `message_delta` rather than summed, `ping` and unknown event types ignored rather than fatal, and a mid-stream `error` event raised rather than returned as a short answer — plus two tests over real HTTP asserting `stream: true` is the only difference from the non-streaming body |
| `hx-remote` | 130 | 7162 | Platform caps parsing (`uname`/`ver`), path translation, shell quoting incl. injection attempts, risky-command classification, mid-truncation, approval round-trip against the local host, **`known_hosts`**: hashed host fields (HMAC-SHA1), globs, negation, `@revoked` beating trust regardless of line order, a different key type reading as first use rather than substitution, plus the policy's fail-closed behaviour and the wording of every refusal — and the **SFTP v3 client** (`src/sftp.rs`): packet framing, a byte buffer that reassembles a packet split across channel chunks, STATUS/NAME/VERSION reply parsing, a directory NAME packet's entries with their sizes and dir-bit, and the three-way availability collapsing to the capability field |
| `hx-sandbox` | 90 | 2066 | Isolation ladder ordering and monotonicity, spec↔YAML round-trip, `SandboxSpec`→`HostConfig` mapping field by field, **no engine-rejected security option** (`userns=`, `seccomp=default`), the entries of an egress allowlist the proxy cannot match, registry/TTL bookkeeping, the concurrency cap, and rollback on a failed start — plus the **remote runtime**: its docker CLI command lines carry every security setting as a flag (`--read-only`, `--cap-drop=ALL`, user-namespace remap, `--runtime=runsc` for L3), spec values are shell-quoted so they cannot become far-host commands, **remote egress is enforced on the far host**: an enforceable allowlist renders the internal network, the `hx-egress-proxy` sidecar created with **no** `--network` (Docker refuses a second network once the mode is fixed) and the `HTTP_PROXY`/`HTTPS_PROXY` that make the sidecar the only route — a sidecar nothing talks to would enforce nothing, invisibly — asserted token-for-token through setup → create → start → remove → teardown against a recording transport that fails loudly when it runs out of script, while a CIDR/raw-IP entry, and a spec with no far-host proxy binary configured, are still refused with a reason naming the way out |
| `hx-search` | 45 | 1740 | RRF rank fusion, HTML extraction, entity decoding, per-backend failure isolation (with **fake** backends) |
| `hx-secrets` | 36 | 1302 | Argon2id+XChaCha20 round-trip, tamper detection, redaction patterns, and **credential resolution**: a `store:name` reference resolved through `vault:`/`env:`/a fixed map, an empty environment variable refused like an absent one, an unknown store listing the stores that *are* configured, and every error message asserted **not** to contain a value |
| `hx-agent` | 45 | 1407 | The loop's gate, in one file of integration tests: the target of a destructive call is **measured after the capability check and before the prompt** (and the event that reaches the store carries it, so the trail proves what the approver was shown), a **capability denial is a result the model reads and cannot be approved away** (an approver willing to say yes is never asked), an approval denial is reported and the command never reaches the host, `allow for chat` stops the second prompt while a remembered denial is not re-asked, a tool declaring no external effect is never prompted about, a refused call does not stop its sibling, unknown tools and unusable arguments return as results, a non-zero exit is still a call that *ran*, `max_turns` and the deadline stop the run, and the exact event sequence a client renders. Plus the **routed model call** over a real `ModelRouter` and a real `ProviderRegistry`, with only the adapter faked: the route decides the model, the key follows the credential the pool granted, a refused credential is benched and its *sibling* is tried before another provider, a missing key and a 502 both give the reservation back (asserted with `concurrent: 1`, since a leaked lease looks exactly like a rate limit), and a day's budget that covers one pessimistic reservation still allows three calls |
| `hx-store` | 42 | 2059 | Migrations applied once and never re-run, **a database from a newer build refused with both versions named** (and left untouched), `STRICT` rejecting a type mistake at insert, the transcript written by `seq` the caller does not track, a batch written whole or not at all, a cascade that only happens because `Store` sets `foreign_keys`, every part type round-tripping while an unknown one is reported rather than dropped, events and usage surviving a reopen — plus 4 in `tests/resume.rs` that drop the store and open a **new connection** to the same file, which is the closest a test gets to killing the daemon |
| `hx-tools` | 94 | 3826 | Requirements per tool, bounded output, the two-phase registry, **confinement** (a run with a boundary runs the command there and touches no host; a boundary that cannot be entered is reported as a failure instead of falling back to the machine — the failure mode that would silently unconfine every run whose engine hiccuped), and **a misnamed argument refused rather than ignored** — `cwd` instead of `workdir` used to drop silently and run the command in the daemon's own directory. `delete` is the largest entry: the XDG trash round-trip on a real in-memory host, a directory walked rather than counted at the top level, the filesystem root refused, an unreadable path refused **before** anything is touched, an existing trash name never overwritten, a *pattern* read as one literal filename and told so, a transport failure that says nothing was deleted, and a `delete` that still requires the `Delete` capability on the resolved path |
| `hx-server` | 46 | 2545 | Route dispatch via `oneshot`, `HxError`→HTTP status mapping, and twelve tests that run the **real loop over the real HTTP surface** with only the model scripted: an answer comes back with its session, its cost and its events; a tool call runs and its result reaches the model; a write outside the workspace is denied and never happens; a shell command that needs a human is refused **with the reason**, and the same command runs under `yolo`; a second request on a session continues the transcript; unknown autonomy and unknown roles are 400s that name what is accepted; and a request that cannot run leaves no session behind. Two of them are the floor a `yolo` run cannot lift: `rm -rf /etc` is **refused** (with the shipped rule's reason, so the model can read why) while `rm -rf /tmp/…` still runs, which is the pair that shows the refusal is a list of named paths and not a blanket stop. Plus the sandbox adapter: a command runs in the boundary with its workdir translated host→mount, a path outside the mount is refused **without running anything**, a sandbox path is left alone (the model may have copied one), one container per checkout and none shared across checkouts, a reaped sandbox is replaced rather than returned, a command that outlives its deadline is reported as still-running rather than as success, and dropping the boundary destroys it. Plus **SSE**: three tests that POST `/v1/chat/stream` through the real router and parse the response the way a spec-compliant client would — a run streams its events and ends with a named `done` carrying the reply, a run that cannot start arrives as a named `error` event rather than a status (the response is already `text/event-stream` by then, so there is no status left to change), and two runs on one shared bus do not see each other's events |
| `hx` | 39 | 1884 | Renderers for pools/hosts/sandbox-spec/**policy**/sessions/runs/approvals, CLI parsing, and the daemon client's URL rules (an explicit `--daemon` wins, a bare `host:port` from the config gets a scheme, a URL that already has one is left alone). The policy renderer is asserted on the *order* of the rules rather than their presence — printing them in the struct's order would describe a policy the session does not have — and the approvals renderer is asserted to show a target list, the way back, and the command that answers the question, because a terminal that showed less than the daemon asked would be a weaker interface to one decision. Plus the **SSE reader** for `hx chat --stream`: a frame needs a blank line to complete, a CRLF stream still terminates frames (a proxy that sent those would otherwise buffer every event forever with no error), a run event carries its session, `done` and `error` frames are told apart, a keepalive comment is not a frame, a multi-line payload needs several `data:` lines and joins with newlines, a long argument is truncated to one line, and the `done` frame is asserted to unwrap to the same shape `/v1/chat` returns — the mistake that printed `session ?` and `0 turn(s)` for a run that had done real work |

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

## An environmental flake in two `hx-server` exec route tests (Windows)

`exec_runs_a_command_on_the_local_host` and
`exec_reports_a_failing_command_rather_than_making_it_a_transport_error` (in
`crates/hx-server/src/routes.rs`) intermittently fail on `windows-latest` with:

```
remote host error: command timed out after 30.0s
```

as a **502** instead of the expected **200**. This is environmental, confirmed two ways: the failure
appeared on a commit that did not touch `routes.rs` at all, and `gh run rerun --failed` on that
same commit went green. On a loaded CI runner the local `exec` can exceed the request's 30s default
even when the route is healthy.

**The two-step diagnosis.** (1) Diff the commit that went red. If it did not touch the failing crate
(`hx-server`/`routes.rs`), the failure is not caused by that commit. (2) `gh run rerun --failed`
on the same commit. If it goes green, the run was a loaded-runner flake, not a regression.

**Do NOT bump the production exec timeout to make CI green.** The 30s default is a real product
property — a route pointable at any machine should not hold a request open indefinitely. Instead the two
tests pass `timeout_secs: 120` on their own request (a field the route already supports, clamped
1..600), giving the *test* headroom without touching the product default and without weakening the
assertion: they still assert `status == OK`, exact stdout, and exit code, so exec failing genuinely
still fails the test. If the flake ever returns, re-check runner health before suspecting the route.

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

✅ **WinRM against a real Windows host.** `hx-remote` carries a hand-rolled NTLMv2 implementation
(`src/ntlm.rs`) and a WinRM transport (`src/winrm.rs`), and `tests/winrm_live.rs` exercises both
against a Windows 10 guest: **9 of 9 pass.** The suite is `#[ignore]`d, so the default gate does not
run it — it needs a host.

    HX_WINRM_HOST  HX_WINRM_USER  HX_WINRM_PASSWORD   the host to talk to
    HX_WINRM_PORT                                     5985 HTTP, 5986 HTTPS
    HX_WINRM_AUTH=basic                               use Basic auth instead of NTLM
    HX_WINRM_HTTPS=1                                  https, required with Basic
    HX_WINRM_INSECURE=1                               accept a self-signed certificate

**NTLM is not the transport to use over plain HTTP WinRM.** WinRM over NTLM seals every request after
the handshake with the session key (`multipart/encrypted`, MS-NLMP SEAL), which this client does not
implement, so an NTLM request carrying the envelope in the clear is rejected. **Use HTTPS with Basic
auth** — TLS supplies the confidentiality that makes Basic acceptable, and the client refuses Basic
over HTTP for exactly that reason. The `HX_WINRM_*` matrix above is what the live suite is verified
with. One consequence worth knowing before deploying: the live tests pass through a TLS-terminating
proxy in front of a plain listener, because configuring an HTTPS listener on the guest was more
moving parts than the code under test.

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

### Streaming, end to end (2026-09-17)

`hx chat --stream` against `litellm.phantomic.live`, real model, real tools:

```
$ hx --config ~/.hx/litellm.yaml --daemon 127.0.0.1:8899 chat --stream --autonomy yolo \
    --workspace ~/.hx/ws/sse-e2e2 --max-turns 8 \
    "Read a.txt and b.txt, then create combined.txt with both lines in order, then run 'wc -l combined.txt'. Report the count."

turn 1
turn 2
turn 3
turn 4
`combined.txt` contains:
...
session ses_17e49a344b0841a0bba1cf9f692e9bc9  (new)
stop completed after 4 turn(s): 4 tool call(s), 0 refusal(s)
tokens 5694 in / 300 out   cost no rate card configured
```

Progress went to stderr and the reply to stdout, so the piped stdout stayed parseable. The run's work
was checked independently rather than taken on its word: `combined.txt` held both lines in order and a
separate `wc -l` said 2.

The first attempt at this printed `session ?` / `stop ?` / `0 turn(s)` for a run that had done four
turns and four tool calls — the `done` frame wraps its reply where `/v1/chat` returns it flat, and the
client was reading the envelope. Fixed in the client (the envelope is the server's contract), with a
test asserting both paths hand `render_chat` the same shape.

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

**`hx policy`, against the real config.** The renderer is unit-tested, but the thing it is for is
reading a *deployment's* ladder, and that is a fact about a file nobody tests:

```console
$ hx policy --config ~/.hx/litellm.yaml
approval policy from /home/yoav/.hx/litellm.yaml
  level    balanced — asks before anything leaving the machine, or worse
  read         runs free
  mutate       runs free
  external     asks
  destructive  asks
  privileged   asks
  ceiling  none — a `yolo` chat can auto-approve anything, including a deleted database
  deletes  a pattern or a variable in a delete is refused outright (`rm -rf build*`, `rm -rf $DIR`), …
rules, in the order they are checked:
  deny — refused before anything else is considered, and no approval can buy it back
     1. tool shell, matching rm -rf /  # recursive delete of the root directory
     …
    32. tool shell, matching *DROP DATABASE*  # dropping a database
      (all 32 shipped catastrophe rules, from `default_denials()`)
```

That output is what makes the two defects in §7 of `docs/approvals.md` *visible*: rule 4 used to be a
single `*rm -rf /*` that also matched `/tmp`, and a config with no `agent:` section printed no rules at
all until `AgentConfig::default()` was fixed.

### Laya terminal driving (2026-10-06)

`hx drive` — the consumer rung on top of `hx decision`: each tick it senses a tmux pane's tail as
text, asks the Laya sidecar typed questions, and sends the winning action's keystrokes. Verified
against real programs, CPU-only sidecar (~0.5–1.5 s per tick; the GPU path is ~20 ms).

**Ops runbook with a destructive step** (`examples/laya-drive/ops_console.py` — five steps, the third
asks to "drop and recreate the staging database"). Task spec asks one binary question per tick
(`step_pending` → `confirm`/`wait`) plus a veto question (`mentions_delete` → `decline`):

```console
$ hx drive examples/laya-drive/ops-console.task.json
  #0   confirm  p=0.915  626ms  act
  #1   confirm  p=0.878  842ms  act
  #2   decline  p=0.900  770ms  guard
  #3   decline  p=0.850  837ms  guard
  #4   -        p=0.894  796ms  act
drive …: done after 5 steps — 5 steps, 4.1s
```

The pane afterwards showed `[1/5] … y`, `[2/5] … y`, `[3/5] drop and recreate the staging database … n`
→ `DECLINED — runbook stopped by operator`: the routine steps confirmed, the destructive step was
vetoed by the guard rather than left to the action question. (The second `decline` at #3 raced the
program's exit — the stray `n` hit a shell prompt, `n: command not found`. Harmless here; on a real
target, bind veto actions to keys that are no-ops outside the prompt.)

**`git add -p` with a secret hunk** (`git-add-p.task.json` — one hunk adds `import logging`, the
other `SECRET_KEY=hunter2`). Action question `letter_menu` ("the last line lists single letters in
square brackets and ends with a question mark"), guard `adds_secret`, done `shell_done`:

```console
  #0   stage    p=1.000   597ms  act
  #1   skip     p=0.644  1279ms  guard
  #2   skip     p=0.661  1528ms  guard
  #3   -        p=0.762  1685ms  act
drive …: done after 4 steps — 5.3s
```

`git status` afterwards: `M  app.py` (staged), ` M config.env` (the secret hunk left unstaged).
Two bindings this needed: keystrokes for interactive programs are `y Enter`, not `y` — git's hunk
prompt line-buffers in a pty — and the veto threshold has to sit under scrollback dilution
(`adds_secret` reads 0.805 on a clean frame but 0.633 with the previous hunk still on screen;
`guard_threshold` is 0.6 here while the ops runbook's reads 0.87 at 0.8).

**moon-buggy, the frame-per-frame case** (`moon-buggy.task.json`): `obstacle_ahead` → jump/coast at
300 ms ticks. It crashed on the first crater twice, `game_over` caught the crash screen (0.872), and
`obstacle_ahead` sat at ~0.12 every frame — the question sees text, and a crater in moon-buggy's
ASCII art is a gap in a row of `###`, not words. Real-time games need both the GPU latency and a
state encoding that says "obstacle ahead" in prose; as shipped, this rung is honest about where it
stops: prompt-driven and turn-based programs drive correctly, scrolling ASCII action does not.

What the probing runs established, in numbers: a choice whose options compete on overlapping prose
("press y to confirm" vs "wait — screen unclear") flattens to ~0.64/0.36 and never clears a gate;
the same decision as one noul reads 0.91/0.09. Judgment nouls ("this step permanently destroys
data") score ~0.22 where mention nouls ("the step's text asks to drop, delete, destroy, wipe, or
recreate a database") score 0.87 — the guard veto exists because that gap is real.

### Laya desktop driving — real mouse and keyboard (2026-10-06)

`hx drive` with a `gui` spec senses the app's AT-SPI accessibility tree each tick (a pyatspi
helper under `apps/hx/src/atspi_sense.py`), lets the model answer typed questions about it, and
actuates with xdotool — mousemove+click on a widget's centre, `type`, or a bare keyspec. Target
apps launch with `QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1`; the spec's `coord_scale` maps a11y logical
pixels to the real 3200×2400 display (2.0 here); the window is raised at start because
click-to-focus raises whatever is topmost at the point.

**Type into a document** (`kwrite-type.task.json` — doc must gain the line `Devin was here`;
noul `has_greeting` doubles as action question (on_false → `seq:click:gui-demo.txt|text:Devin
was here`) and done question):

```console
  #0   type_greeting  p=0.962   978ms  act
  #1   -              p=0.559   839ms  act
drive …: done after 2 steps — 2 steps, 3.6s
```

The a11y tree afterwards reads `shows 'line one Devin was here'` — the click hit the text area's
centre and the typed text landed.

**Handle a modal save dialog** (`kwrite-close-save.task.json` — close the doc keeping the text;
`save_dialog` detects "a dialog offers 'Save', 'Discard' and 'Cancel'" → on_true `click:Save`,
on_false `ctrl+w`; `document_gone` ends it):

```console
  #0   click_save  p=0.850  1660ms  act
  #1   -           p=0.631  1418ms  act
drive …: done after 2 steps — 2 steps, 3.2s
```

`cat /tmp/gui-demo.txt` afterwards: `line one` + `Devin was herex` — the click hit the *dialog's*
Save, not the toolbar's same-named button (name lookup takes the last match — dialogs append
late in the a11y tree), the buffer went to disk, and the editor was back to `Untitled`.

**Open a menu and pick an item** (`kwrite-menu.task.json` — `menu_open` noul → on_true
`click:Save As...` : on_false `click:File`): the drive reached done in 3 steps (4.8 s) with the
Save File chooser open — tick 0 answered `menu_open` true at 0.629 (a borderline false positive)
and clicked `Save As...`, which resolved to the *toolbar* button — the outcome the spec wanted
via a shortcut the environment offered. Menu-state nouls hover near the gate; a cleaner signal is
a signature unique to the open menu.

**Calculator sequencing — the honest ceiling** (`kcalc.task.json` — "press 7, ×, 8, =" with the
pick filtered to those four buttons): escalated at p=0.447/conf=0.104 every tick — probed
standalone, the pick shows a persistent `AC`-then-`=` prior (~0.4–0.5) no matter what the
"pressed so far" history says; 322M doesn't sequence button presses from an element list. The
drive's gate held: it escalated rather than clicking the wrong button — the calc display stayed
`0`. Same conclusion moon-buggy reached for real-time: the loop is a reactive controller, not a
planner — shape tasks as state-detection → bound action, and leave sequences to the spec's
bindings.

**Multi-phase task — type, save as, name it** (`kwrite-save-as.task.json`): a `stages` spec
composing three reactive drives — stage 1 types `Devin was here` until `has_greeting` clears;
stage 2 senses with `window: "Save File"` (falls back to the whole app while the dialog is
absent) and clicks the toolbar `Save As...` until `chooser` (`'Parent Directory'` showing)
clears; stage 3 fires `fill_and_save` (`seq:click:File name:|ctrl+a|text:devin-note.txt|
click:Save`) once `chooser` holds, and ends when `named_doc` sees the title flip:

```console
-- stage 1: has_greeting
  #0   type_greeting  p=0.923  1404ms  act
  #1   -              p=0.628  1427ms  act
   stage done after 2 steps
-- stage 2: chooser
  #0   open_saveas    p=0.632  1868ms  act
  #1   -              p=0.725   913ms  act
   stage done after 2 steps
-- stage 3: chooser
  #0   fill_and_save  p=0.725   851ms  act
  #1   -              p=0.843  1545ms  act
   stage done after 2 steps
drive …: done — 6 steps, 12.4s
```

`~/devin-note.txt` landed on disk (15 bytes) and the KWrite title flipped. The same noul
(`chooser`) drove both dialog stages with opposite bindings — open it when absent, fill it
when present. Two sense-side additions made this tractable: `gui.window` restricts a stage's
element table to a dialog subtree (the save chooser's ~70 elements → 11) while falling back
to the whole app when no matching frame exists, and `gui.skip_roles` drops grid roles
(`table cell`, `list item`) so file rows can't crowd the cap — unfiltered, the state
overflows the 512-token window and questions get `truncated_questions`. Phrasing probes
that stayed mushy (~0.6–0.7 both states on "menu open", filename-in-field strings like
`devin-note.txt`) were dropped for signals naming widgets unique to one state —
`'Parent Directory'`, the post-save title — a lexical-presence rule that also explains why
menu-open nouls can't separate (drop-down item names collide with toolbar ones).

**OSWorld-adapted queue — 10/10 verified** (`examples/laya-drive/queue/`): ten tasks
shaped like OSWorld's harness — `setup.sh` fixture, `hx drive` phase, `verify.sh`
execution check on the filesystem. `run_queue.py` runs them and writes the scorecard:

| task | domain | what it drives | drive | verify |
|---|---|---|---|---|
| kwrite-save-as | editor dialog | type → Save As → name it → Save | done 13.0s | PASS |
| os-append-br | editor | `End`+type `<br/>` on 3 lines → `ctrl+s` | done 8.1s | PASS |
| os-chmod-644 | terminal | `find -type f -exec chmod 644` | done 10.7s | PASS |
| os-compress-old | terminal | `find -mtime +30` to file | done 11.2s | PASS |
| os-failed-ipynb | terminal | `cp --parents` failed.ipynb tree | done 10.8s | PASS |
| os-jpg-collect | terminal | recursive `*.jpg` → one dir | done 10.3s | PASS |
| os-nano-edit | TUI (4 stages) | nano open → type → `ctrl+o` save → `ctrl+x` exit | done 12.7s | PASS |
| os-organize-logs | terminal | `mkdir` + `mv *.log` | done 9.5s | PASS |
| os-php-lines | terminal | `find -name '*.php' -exec wc -l` | stopped* 16.5s | PASS |
| os-rename-dir | terminal | `mv` rename | done 8.0s | PASS |

*php-lines verified but ended `stopped` — the done read stayed conservative on a real
result; the filesystem check is the arbiter, same as OSWorld's execution-based scoring.

Failures burned down along the way (each changed the sensor or the spec, not the model):
`terminal shows` truncating at 80 chars hid every output line — now head+tail; markers
inside their own `echo` command confabulated — output-only `==BENCH-DO""NE==` idiom plus
prompt-below-output phrasing; `warmup: 1` ended tick-0 "done" reads (0.82 on a blank
prompt); goal-state claims ("the edit is applied") confabulated where current-state
claims ("last line is plain `gamma`") split; window titles/tab labels (`br-doc.txt *`,
`bench : nano`) turned out to be the most readable state signals of all.

## Running the suite

```bash
cargo test --workspace          # 695 tests, 0 failed, 24 ignored live tests
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
- **What is still tier C**: egress filtering by CIDR or raw IP — a hostname allowlist is now enforced
  on both the near and the far host, but the proxy matches hostnames, so those entries are refused
  rather than pretended — plus keyless scraping that survives a TLS-fingerprint bot wall (browser-pool
  work), the vault opened in a new process, and provider calls to a real model API.
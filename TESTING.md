# Testing roadmap — what is verified, and what only looks verified

Status: 2026-09-20. Companion to `ROADMAP.md` (which tracks features); this file tracks **evidence**.

```console
$ cargo test --workspace
998 tests, 0 failed                      # includes 24 chat API tests and 4 database reopen tests
56 ignored                               # live: Docker, SSH, pty, WinRM, search, a real model, a real bot

# The five live suites below — 29 tests — are `#[ignore]`d by default.
# `.github/workflows/integration.yml` runs docker_live, chat_live, ssh_live, pty_live and
# terminal_remote_live; `canary.yml` runs search_live — 32 of the 56. The model suites need a key,
# which CI has none of, so they are run by hand.
$ cargo test -p hx-sandbox --test docker_live -- --ignored --test-threads=1
12 passed; 0 failed                      # a real Docker daemon, with gVisor installed
$ HX_OPENAI_TEST_BASE_URL=… HX_OPENAI_TEST_MODEL=… HX_OPENAI_TEST_KEY=… \
  cargo test -p hx-provider --test openai_live -- --ignored --test-threads=1
4 passed; 0 failed                       # a real model, through a real gateway — manual, not CI
$ cargo test -p hx-remote --test ssh_live -- --ignored --test-threads=1
7 passed; 0 failed                       # a real sshd, real key auth
$ cargo test -p hx-server --test chat_live -- --ignored --test-threads=1
2 passed; 0 failed                       # a real container, through POST /v1/chat
$ HX_SEARXNG_URL=http://127.0.0.1:8888 HX_SEARCH_EXPECT_RESULTS=searxng \
  cargo test -p hx-search --test search_live -- --ignored --test-threads=1
4 passed; 0 failed                       # a real SearXNG, real internet
```

The counts matter in both directions. A green `cargo test` alone still means **the logic is right**;
The counts matter in both directions. A green `cargo test` alone still means **the logic is right**;
the 52 `#[ignore]`d tests are the ones that have reached another process, and the only ones here that
could catch a protocol mistake. The ones CI can host run there, which is the difference between
"verified once" and "stays verified".

**A caveat on the live numbers above, stated rather than glossed.** Those pass counts are *recorded
observations* from an earlier revision on a host that had Docker, an sshd and a SearXNG. This
environment has none of them, so the `cargo test --workspace` line is the only figure in this block
that one machine can reproduce. `openai_live` is run by no workflow, despite the sentence that used to
sit in this spot saying all of them ran in CI. Re-running those suites is what would make them
trustworthy again; until then they are the weakest claims in this file.

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

The tests above are hermetic in-process evidence for this wiring. The live half of the same path is
`crates/hx-server/tests/chat_live.rs` — two tests against a real Docker daemon, recorded in tier A
below — and a container engine *is* installed on this development host (Docker 29.8.1), so the path is
not blocked on one. The historical live results further down remain evidence for their named suites
rather than for this wiring.

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

That is the in-process half. The live half has since run: `crates/hx-sandbox/tests/remote_live.rs`
(three tests, `#[ignore]`d) drives a real `SshHost` against a real remote Docker daemon and reads the
security properties back from `docker inspect` **on the far host** — see *The remote sandbox runtime,
against a real remote Docker daemon* below.

## A button tap names its question, and a token never reaches an error

Two things had to be true before an answer from a phone could be *joined* to the run that asked, and
neither was:

1. **The button carried only the label.** `callback_data` was `"allow once"`, and the connector handed
   the tap up as an `Inbound::ApprovalAnswer` with `approval_id: ""`. An answer that names no question
   can only be matched by guessing — "whatever is pending in this chat now" — which is how a tap that
   arrives after a run moved on answers a different question. `callback_data` is now
   `apr_<id>:<label>` and `split_callback_data` is the inverse; a payload that does not split (an
   older build's button, a hand-sent string) arrives with an empty id, which no pending request can
   match, and is refused rather than guessed at. Asserted by
   `a_button_carries_the_question_it_answers_and_the_answer_round_trips`,
   `a_payload_that_names_no_question_is_not_an_answer_to_one`, and over the wire in
   `an_approval_is_posted_with_one_button_per_option`, which now asserts the exact `callback_data`
   Telegram is sent.
2. **A transport failure put the bot token in the error message.** Telegram authenticates with
   `/bot<token>/` in the *path*, and `reqwest::Error`'s `Display` includes the URL it failed on, so
   `could not reach Telegram: {err}` was a token in an error message — about to become a token in the
   transcript and the audit trail, because a failed `ask` denies a run with its reason attached. The
   test was written first and run against the unfixed code:

   ```console
   $ cargo test -p hx-gateway --test telegram_http a_token_never
   thread '...' panicked at crates/hx-gateway/tests/telegram_http.rs:470:
   the bot token must never appear in an error: connector main-tg failed: could not reach Telegram:
   error sending request for url (http://127.0.0.1:1/bot0123456789:TESTBOT-…/sendMessage)
   ```

   `TelegramConnector::unreachable` now formats the error through `reqwest`'s own `without_url()`, and
   `a_token_never_reaches_an_error_message_not_even_the_url` asserts the message carries neither the
   token nor the URL. Not even the URL, because the URL is where the token lives.

   **One caveat, measured rather than assumed.** The *send* path is the one that leaked, and it is the
   one the test above exercises. The three sites that report a response whose **body** could not be read
   are now formatted through `without_url()` too, and
   `a_body_that_cannot_be_read_is_reported_without_the_url_either` pins them — but that test **cannot
   fail against the pinned `reqwest`**: reverting the call and re-running still passes, because the
   error it produces is `error decoding response body` and carries no URL. It is a guard on a
   dependency contract (`reqwest` upgrades are routine here), not evidence of a fixed leak. The honest
   summary is: the send path leaked and is fixed; the body path was never broken.

## The approval loop-back (M5)

The gap the milestone was actually missing: a tap was parsed and judged and then dropped, so pressing
"Approve" on a phone did nothing. `crates/hx-gateway/src/bridge.rs` is the join, and
`crates/hx-gateway/tests/approval_loopback.rs` is the evidence. **Everything in that file is the real
object**: a real `AgentLoop` gated by the real `ApprovalQueue`, the real `TelegramConnector` over a real
TCP socket, the real bridge. The only scripted piece is the model, which has nothing to do with the
question being asked.

| Test | The property |
|---|---|
| `a_tap_on_the_posted_button_resumes_the_run_and_is_attributed_to_its_channel` | The prompt goes out with one button per option, each carrying the request id; the tap comes back through `receive`; the run resumes with the decision a terminal would have produced, `by: telegram:4242 via main-tg` |
| `the_running_agents_audit_trail_names_the_channel_the_answer_came_from` | The same, through a real run: `AgentEvent::ApprovalResolved { by: "telegram:4242 via main-tg", approved: false }`, and the refusal the model is told about names the channel too |
| `a_destructive_tap_is_refused_on_the_running_path` | A `Destructive` question answered "allow once" from a `Mutate` channel is refused at the moment of the answer; the run keeps waiting and ends in the timeout denial, not in the phone's yes |
| `a_stale_or_replayed_tap_does_not_answer_a_different_question` | Two questions pending in one chat: the replay is refused, a forged id is refused, an unoffered answer is refused, a tap from another chat is refused, and the other question is untouched throughout |
| `a_permanent_grant_is_not_made_from_a_phone` | `always allow this` is refused from a channel; `allow for this chat` is honoured |
| `a_channel_that_cannot_be_reached_denies_the_run_instead_of_leaving_it_waiting` | The run is denied immediately with the reason, nothing is parked in the queue, and the bot token appears in no decision |

The stub is what makes the tap honest, and it is worth being explicit about: it does not hand the
connector a callback the test invented. It **reads the button the connector actually posted** and presses
that, so what is exercised is the wire round trip (`callback_data` out, `callback_query` back). A tap
whose id did not survive that trip could not answer anything, and the test would fail.

Unit tests in `bridge.rs` cover the parts that touch no platform: the attribution string (including the
thread, because one chat with two threads is two conversations), that a chat message is not an answer,
that an answer through an unconfigured channel is refused, that a question above the channel's ceiling is
never *posted* (the connector panics if asked, so reaching the platform would be a failure rather than a
silent pass), and that a question cannot be asked through a channel that does not exist.

**Design decision, and its cost.** `hx-gateway` now depends on `hx-agent`. The bridge applies an answer
to the queue a run is parked on, and the queue is the loop's; the dependency never runs the other way,
and the alternatives (a newtype in `hxd`, a new crate for one `impl`) would move the channel-policy check
away from `AnswerAuthority`, where it is tested. The cost is that building `hx-gateway` alone now builds
the tool and remote stack with it. Recorded in `ARCHITECTURE.md` §1 next to the crate graph.

**What this does not cover**, so the claim stays the size of the evidence: no live Telegram server (there
is still no `#[ignore]`d live suite, so the connector's contract is asserted against a stub rather than
against Telegram itself), no daemon-side receive loop (nothing in `hxd` drives `Connector::receive` yet),
and no `approval.ask_via` config key — a channel's ceiling and conversation are constructed in code
today. None of those is a property of the loop-back; they are the plumbing that will call it.

## The ceiling, on the path an answer is actually applied through

The loop-back above shipped with a ceiling that a reviewer could read as satisfied and that was not.
`AnswerAuthority::judge` had **no caller outside its own unit tests on `main`**, and
`Inbound::ApprovalAnswer` had none at all: the rule "a chat bridge can never authorise a `Destructive`
action" was true of a pure function nothing on the running system called. The one live answer path —
`POST /v1/approvals/{id}` → `ApprovalQueue::answer(id, option, by)` — had **no risk check and no ceiling
of any kind**, and its `by` field is documented as the place a phone tap's attribution lands. The bridge
enforced the ceiling; nothing that existed on `main` did.

The fix puts the ceiling where every transport meets: `ApprovalQueue::answer` now takes the answering
surface's ceiling as a **required** argument and judges it against the risk of the request the queue is
*holding*, at the moment the answer arrives. The comparison is `RiskClass::covers` — one implementation,
shared with `AnswerAuthority::may_answer` — and `RiskClass` has no `Default`, so there is no constructor,
no deserializer and no omitted argument that yields a permissive ceiling. An answer above the ceiling
leaves the question **open**, so the run still ends in its own timeout denial: a refusal is never
converted into a yes.

| Test | The property |
|---|---|
| `an_answer_above_the_ceiling_is_refused_and_the_question_stays_open` (`hx-agent`, unit) | A `Destructive` request answered with a `Mutate` ceiling is `AboveCeiling { risk, ceiling }`; the question is still in the queue; the run ends with `nobody answered`, and the phone's attribution is in no decision |
| `an_answer_at_the_ceiling_is_accepted` (`hx-agent`, unit) | The other half, so the check cannot pass by refusing everything: a `Mutate` question from a `Mutate` ceiling is answered |
| `a_destructive_answer_from_a_chat_channel_is_refused_over_http` (`hx-server/tests/api.rs`) | A **real run**, parked on a real question, answered over the real route with a chat channel's ceiling: **403**, the question is still listed, and the run records a refusal rather than running the `rm -rf` |
| `an_answer_that_declares_no_ceiling_is_refused_rather_than_granted_everything` (`hx-server/tests/api.rs`) | A body with no `ceiling` is a client error and answers nothing — omission is a rejection, not an unbounded grant |
| `a_ceiling_covers_everything_at_or_below_it_and_nothing_above` (`hx-core`, unit) | The ladder itself (`Read < Mutate < External < Destructive < Privileged`), so a reordering of the enum is a failing test rather than a silent widening of what a phone may authorise |

**Every check below was run against the broken code first.** With the ceiling check disabled in
`ApprovalQueue::answer`, the queue test fails `Answered` vs `AboveCeiling { Destructive, Mutate }` and the
HTTP test fails `200` vs `403` — the route's own body in the failure output is
`{"answered":"apr_…","by":"telegram:4242 via main-tg"}`, which is the defect stated as a passing response.
With the ceiling field made optional (`#[serde(default = …)]` returning `Privileged`) the no-ceiling test
fails on `200 OK`. Both breaks were reverted; the restored tree is the one the counts above describe.

**The design decision, and it is written down rather than picked silently.** The route requires the
*client* to declare its ceiling. That is deliberate and its limits are real: this API has **no
authentication**, so the daemon cannot tell one local client from another, and per-channel ceilings are
not configured yet (`approval.ask_via` is still a roadmap line). Given "declare it" or "have no check",
declaring it is what makes the check present, explicit and testable. The two clients that use this route
are the owner's own machine-local ones — the `hx` CLI (`by: "terminal"`) and the daemon's embedded web
page (`by: "web"`) — and both declare the terminal's full ladder, which is the authority a keypress at
the prompt has always had. A **channel** does not answer through this route at all: it answers through
`ApprovalBridge`, whose ceiling comes from the deployment rather than from the channel. The residual hole
is honest and named: with `--bind 0.0.0.0` and no auth on the API, a declared ceiling is not a defence
against a remote caller, because the API's own authentication is the missing control, not the ceiling.

## The browser pool (M6)

The escalation ladder, the pool and the two cheap rungs are built. **No browser is driven anywhere
below**: `camoufox`, Chromium and CDP are not exercised in this environment, and nothing here claims
otherwise. The stealth rung launches a configured tool, and no such tool is present here.

**Per-session profile isolation** (`crates/hx-browser/src/profile.rs`, 10 tests). The property is
that two sessions never share a directory, a cookie jar or a storage area, and it is asserted on a
real filesystem rather than derived: a cookie written for one session is read back by that session
and is *absent* for another (its file is never even created), a session id of `../other`, `a/b`,
`/absolute`, `..` or `` is refused by a whitelist rather than a `..` blacklist, an **uppercase** id
is refused because `Session_A` and `session_a` are one directory on macOS and Windows, and a
Windows device name (`con`, `nul`, `com1`) is refused by name. Eight sessions are created from
eight threads at once and every path is distinct, and every directory canonicalises inside the pool
root.

**The escalation ladder** (`src/ladder.rs`, `src/rung.rs`, `src/error.rs`, 18 tests). The decision
is the design, and it is asserted against scripted rungs that **panic when called with no script
left** — so "a success does not escalate" fails the test rather than passing because a double
answered anyway. A refusal escalates and the page comes from the dearer rung; a success ends the
climb with the stealth and interactive rungs *never called*; a transport error and a rung timeout
both stop it, with no browser launched and no person asked; a 404 stops it; a `Blocked` error from a
rung stops it; an unavailable rung (no camoufox installed) is reported and the climb continues; every
attempt is recorded in order with its own reason; and the attempt ceiling stops the climb even when
the site keeps refusing. Reports are asserted never to carry a token from the query string, and a
fetched body is asserted never to render in `Debug`.

**The rungs** (`src/rungs/http.rs`, `src/rungs/stealth.rs`, 88 lib tests + 10 integration tests). The
two rungs are real implementations rather than scripted doubles, and the interesting one is the
redirect guard.

`HttpRung` is a real `reqwest` client built with `Policy::none()` — deliberately *not* following
redirects itself, because a client that does has already opened the socket by the time any check could
run. The rung follows redirects itself and admits **every hop before anything connects to it**. The
test is built so it can fail: the redirect target is a *real listener*, so a guard that ran after
connecting would move its connection counter. It is `0`. A redirect to `169.254.169.254` is refused
with a report naming the page that sent us there — `BlockReason::Redirected`, not a bare "private
host", because only one of those means the page's author chose the destination — a relative `Location`
resolves against the hop that sent it, a redirect loop is bounded at 5 hops, a body over 4 MiB is
refused rather than buffered, a non-text body is refused on the site's own declared type, and a failed
fetch carries no URL (so no token) in its error.

`StealthRung` launches a configured subprocess and speaks a documented protocol: the URL, the session's
profile directory, the cookie jar and the budget on **stdin** (never in argv, which every process on the
machine can read), and the exit code as the verdict — `0` a body, `3` a wall, any other non-zero a
transport failure. The tool's stderr is deliberately not quoted into an error: it is unbounded, written
by something this crate does not control, and can contain the URL it was handed.

**What is not exercised: the tool itself.** No stealth browser exists here, so the protocol is verified
against `/bin/sh` scripts that speak it — real processes over a real pipe, but our reading of the
protocol at both ends. The browser rung is defined by the `Fetcher` trait and deliberately not wired;
the interactive rung is a pane a person drives, not a subprocess.

**Target admission** (`src/target.rs`, 13 tests). `file://`, `data:`, `gopher://` and `chrome://` are
refused by scheme; loopback, RFC 1918, link-local (`169.254.169.254`, the metadata service), CGNAT,
multicast, IPv6 unique-local and link-local, and IPv4-mapped spellings of the same are refused by
address; `localhost`, `localhost.` (the trailing dot is a one-character bypass), `.local`,
`.internal`, `.home.arpa`, the metadata hostnames and any single-label name are refused by name; and
public addresses and hostnames are the control that proves the rule is a list of ranges and not
"refuse IP literals". `Admission::AllowLocal` — the named escape hatch the hermetic suite uses — is
asserted **not** to lift the scheme rule. A three-failure run of this suite is what caught IPv6
literals being judged as *hostnames*: `Url::host_str` keeps the brackets, so `"[::1]"` never parsed
as an address and fell through to the name rules, where it was refused for the wrong reason. The
check now uses `url.host()`, which cannot be fooled by spelling.

**The human-in-the-loop contract** (`src/interactive.rs`, 10 tests). The pane's interface is real and
its absence fails closed. With no pane attached the rung returns an unavailable error that the ladder
reports and moves past — it does not wait, retry, or invent a result. A pane that never answers is
abandoned on the rung's own budget, asserted by wrapping the call in a *longer* outer timeout and
requiring the rung's error to come back first, so a hang fails the test. The challenge a pane is
handed is asserted to carry the session's **own** profile directory (a pane that picked its own would
break the isolation the pool is built on), a URL with the query string stripped (a challenge URL
routinely carries a return-to token), the budget the rung will actually enforce, and a distinct id
per challenge. A person who clears the wall ends the rung with a reason saying what to do next —
re-run the ladder in that session — because reading the page needs a CDP driver this crate does not
have yet, and saying so is better than returning an empty page.

**The pool** (`src/pool.rs`, 11 tests). The two things the pool adds over the ladder, both asserted
rather than described. *Identity*: the same session id returns the same handle (`Arc::ptr_eq`, not a
path comparison — the handle is what the rungs are handed) and eight concurrent callers get that one
handle, while distinct ids get distinct directories. *Admission before anything exists*: for
`file://`, the metadata address, loopback and `localhost` the report carries **no attempts** and the
pool holds **no session**, asserted under a rung that panics if it is called at all. The first
version of that test built its pool with `Admission::AllowLocal` and therefore asserted nothing —
`AllowLocal` admits the metadata address by design, the rung ran, and the rung's own panic is what
failed the gate. The refusal test now uses the default policy, and a helper exists for each. A
session id that escapes the root is reported as a stopped fetch rather than a panic, and a token in
the query never renders in a report's summary or its `Debug`.

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

Twelve tests against Docker 29 on Ubuntu 24.04 with cgroup v2 and gVisor registered. This suite exists because the ladder
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
back. The third is now *enforced* rather than accepted and ignored: an allowlist puts the sandbox on
an internal Docker network with no gateway, and the only route out is a proxy sidecar that admits a
`CONNECT` target only when the allowlist matches — so a profile that names four hostnames reaches
those four and nothing else (`crates/hx-sandbox/src/egress.rs`, and the live pair in tier A). What is
still *refused* — `SpecError::EgressNotEnforced`, which says what to do instead — is an entry the
proxy cannot decide, a CIDR or a raw IP, rather than accepted and ignored. The example config no
longer claims a constraint it cannot keep. The first failing run also happened to demonstrate the
rollback invariant against a real engine: seven spawns failed at *start* after a successful create,
and every one reported `it has been removed`.

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

One defect was found by running the live suite rather than the unit tests, and it is the reason that
suite exists: `Terminal::write` is synchronous and ran the remote session's future with
`block_in_place` + `block_on`, which **deadlocks** from inside the WebSocket task — the SSH write
needs the connection's own task to progress. It failed 6 of 8 runs. Fixed with async twins
(`write_async`/`resize_async`) that await instead.

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
| **A real finding, still open: the far host's own bridge address is reachable from inside the sandbox** | `NO_ROUTE` on `93.184.216.34:443` is *internet* unreachability, not total unreachability. The `-egress` network's IPAM gateway (`10.200.7.1`) is the far host's own bridge interface on the **same on-link subnet**, and on-link delivery needs no route: `gateway:22` from inside the sandbox answered with the host's own sshd (also `4330`, `9191`, `20140`, `44321-44323`). Container-*published* ports are dropped by Docker's isolation; **host-native services are not.** `egress.rs` claimed "literally no route" off the network and `remote.rs` claimed the sidecar was the only way out — both were wrong and are corrected. Pinned by `a_sandbox_reaches_the_far_hosts_own_bridge_address_and_that_is_a_known_hole`, which asserts the hole **is still there** (so it cannot be assumed away) *and* that `/proc/net/route` still carries no `00000000` default. Filed as an open security item in `ROADMAP.md` |

**This suite cannot run in CI, and the consequence is worth naming.** It needs a machine on the private
tailnet (`100.99.x.x`) that CI runners cannot reach, so there is deliberately **no** integration.yml job
for it — a job that only skips would add noise without evidence. The cost is that **every remote-side
security property has zero CI coverage**: the egress ordering that keeps a refused spec from leaving a
live sidecar behind, the `inet_aton` refusal on the far path, the far-host docker flags, and the
bridge-address hole above are all proven *only* by a hand-run suite. A regression there would be caught
by a person, not by a red check. The local halves of the same properties (the validator, the proxy's own
dial guard, the ordering assertions against the recording transport) *are* in CI, which is what keeps
this from being an unguarded surface — but the far-host half is not, and no test-only trick changes that.
An operator runs the suite by hand against a reachable host, as above.
No container, network, sidecar or workspace is left on the host when it finishes: the egress tests
assert each one's absence after `remove`, and the `Cleanup` guard sweeps them on the panic path as a
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

**The key invariant: no private key reaches the model, the trail, or a sandbox** (four hermetic tests, plus a live fifth)

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

| Crate | Tests (all targets) | LOC (`src/`) | What the tests actually prove |
|---|---|---|---|
| `hx-core` | 119 | 6065 | ID monotonicity, error taxonomy (**a rejected credential is an auth failure, and a 500 is not**, so a pool retries one and benches the other), **capability path grants** (incl. the empty-grant-means-root regression), approval policy incl. unattended budgets and **the shipped catastrophe set in both directions** (the unrecoverable paths refused, `/tmp` and `/home` left answerable) and the refusal of a delete whose target is a pattern, message/event round-trips, target descriptions a person can price, and config parsing incl. rejection of unknown keys and **`hx.example.yaml` itself parsing** |
| `hx-provider` | 149 | 6200 | Token-bucket timing, **budget fail-closed on a zero estimate**, credential pool round-robin, shared-limiter identity across pools, routing and fallthrough, a granted ticket carrying the credential's `secret_ref`, a role's reservation estimated from the **dearest** route, the provider factory refusing a kind it has no adapter for, and **streaming**: SSE events reassembled across split chunks before being parsed, text deltas emitted in order, and the batch of unmerged tool-call fragments a proxy hands over merged by `index` into one call. The **Anthropic** stream as well: named events reassembled across split reads and CRLF terminators, text deltas in order, `input_json_delta` fragments accumulated and parsed only at `content_block_stop` (a per-fragment parse fails on nearly every real call), an empty-argument call treated as `{}` while genuinely truncated JSON is an error naming the call, two tool calls in one turn kept apart by index, usage taken from the last cumulative `message_delta` rather than summed, `ping` and unknown event types ignored rather than fatal, and a mid-stream `error` event raised rather than returned as a short answer — plus two tests over real HTTP asserting `stream: true` is the only difference from the non-streaming body |
| `hx-remote` | 132 | 7276 | Platform caps parsing (`uname`/`ver`), path translation, shell quoting incl. injection attempts, risky-command classification, mid-truncation, approval round-trip against the local host, **`known_hosts`**: hashed host fields (HMAC-SHA1), globs, negation, `@revoked` beating trust regardless of line order, a different key type reading as first use rather than substitution, plus the policy's fail-closed behaviour and the wording of every refusal — and the **SFTP v3 client** (`src/sftp.rs`): packet framing, a byte buffer that reassembles a packet split across channel chunks, STATUS/NAME/VERSION reply parsing, a directory NAME packet's entries with their sizes and dir-bit, and the three-way availability collapsing to the capability field |
| `hx-sandbox` | 90 | 2066 | Isolation ladder ordering and monotonicity, spec↔YAML round-trip, `SandboxSpec`→`HostConfig` mapping field by field, **no engine-rejected security option** (`userns=`, `seccomp=default`), the entries of an egress allowlist the proxy cannot match — **including the whole `inet_aton` address family** (`0x01010101`, `0x7f000001`, `127.1`, `2130706433`, `0177.0.0.1`, `0x7f.0.0.1`, …), which passes a hostname-shape check, is *really dialed as an address* (`0x01010101` → 1.1.1.1, `127.1` → 127.0.0.1), and was accepted as a "hostname" until the `IpAddr`-only guard was replaced by an `inet_aton` grammar — with the names an operator actually writes (`example.com`, `123.example.com`, `*.example.com`) kept accepted as the positive control, and the proxy holding its **own copy** of the predicate with the **same test table** on both sides, asserted end to end over real loopback sockets: a `CONNECT localhost:<port>` is dialed and answered `200`, a `CONNECT 0x01010101:443` is refused `403` *before* dialing — registry/TTL bookkeeping, the concurrency cap, and rollback on a failed start — plus the **remote runtime**: its docker CLI command lines carry every security setting as a flag (`--read-only`, `--cap-drop=ALL`, user-namespace remap, `--runtime=runsc` for L3), spec values are shell-quoted so they cannot become far-host commands, **remote egress is enforced on the far host**: an enforceable allowlist renders the internal network, the `hx-egress-proxy` sidecar created with **no** `--network` (Docker refuses a second network once the mode is fixed) and the `HTTP_PROXY`/`HTTPS_PROXY` that make the sidecar the only *internet* route — a sidecar nothing talks to would enforce nothing, invisibly — asserted token-for-token through setup → create → start → remove → teardown against a recording transport that fails loudly when it runs out of script, while a CIDR/raw-IP entry, an address-shaped entry, and a spec with no far-host proxy binary configured, are still refused with a reason naming the way out — and **every refusal happens before the first far-host resource exists**: `create` validates the spec, checks the proxy binary and builds the command *before* creating anything, and one teardown helper covers a failed egress setup, a failed sandbox create and `remove`. The assertion for that is not the error message but that a recording runner which **panics on any unscripted command was never asked to run one** — the old order created, joined and **started** the sidecar before `create_command` refused an unenforceable entry, and left a live proxy and its network running on the far host; the same order silently ignored an allowlist set with `network: false` |
| `hx-search` | 117 | 4790 | RRF rank fusion, HTML extraction, entity decoding, per-backend failure isolation (with **fake** backends). Plus **four more keyless backends**, each parsed from a captured response rather than from a shape the parser and the test agree on: Wikipedia against a **real live JSON capture** (the `searchmatch` spans stripped, `formatversion=1` pinned, a `site:` filter applied to the returned URLs because MediaWiki has no such operator), Marginalia against a **real HTML capture** (25 title anchors / 25 snippets, `<wbr>` removed as the word-break *opportunity* it is, no `&count=` because it was tried live and empties the result set), **Hacker News against two real live Algolia captures** (`_highlightResult` deliberately ignored because its `<em>` markup would otherwise reach the model, `null` *and* `""` url both falling back to the item page, a text post's body used as the snippet while a link post gets score/comments/author, and a long body cut on a character boundary) — and Mojeek against a **transcription of its markup**, because its live path is bot-walled from this environment (`curl` UA → 403, browser UA → 200 with `<title>Captcha</title>`) and has **not been exercised**, which the module doc and this row both say. Recency is deliberately not forwarded by Mojeek (its advanced form exposes no date-range parameter, only a `date` *display* toggle) or by Hacker News (no filter parameter was verified here, and a cutoff read from the clock would make the builder impure); a test pins Mojeek's exact query key set. The Wikipedia article URL escapes `&` as `%26` while leaving `+` alone, pinned on the final URL string — an earlier comment justified the escape with a false claim (a bare `&` does not start a query string; `Url::parse("…/AT&T").query()` is `None`), so the reasoning in the code is now the measured one. `every_keyless_backend_is_counted` compares the crate's own `KEYLESS_BACKENDS` list against what the registry builds and asserts the count is **6**, so the milestone's number cannot drift away from the code. Plus the **two keyed backends**: `the_default_registry_contains_no_keyed_backend` asserts no default names one, `a_keyed_backend_reports_that_it_needs_a_key` covers `requires_key`/`BackendKind::Keyed`, and a credential that will not resolve produces an error naming the **reference** and never a value. Both keyed parsers are tested against the **documented** response shape rather than a capture — this build has no paid key, and the row says so. `a_transport_error_never_carries_the_key_that_was_in_the_url` builds a **real** `reqwest::Error` whose message genuinely contains a sentinel key (asserted first, so the test cannot pass vacuously) and then asserts the converted error does not |
| `hx-gateway` | 57 | 2097 | The `Connector` trait, the deterministic session router and the Telegram connector, over a real TCP Bot API stub: the same thread always maps to one `SessionKey` and two threads on one platform do not collide, a chat bridge's answer ceiling never authorises `Destructive`, background output with no home channel is refused rather than dropped, and the connector's real `getUpdates`/`sendMessage` URLs, in-path token, advancing offset and fail-closed error paths are exercised over a socket. **The bot token never reaches an error**: the transport-failure path is asserted over a real refused connection not to contain the fixture token. That path had no test at all — the one assertion guarding the property ran against a *stub-answered* 401, whose message is built from the status and the body and never from a URL, so the leak `reqwest`'s `Display` was printing the token-bearing URL into was outside everything the suite looked at. **The message id is read out of the Message object the API actually returns** (`result.message_id`, with a bare integer tolerated and a refusal yielding `None` rather than an invented id): reading `result` as a number is never true of a real `sendMessage`, so the id was silently absent and any edit of that message was skipped. **The streaming driver** (`src/telegram_stream.rs`) is the third thing here, and the properties it exists to hold are asserted as *numbers*, never as durations: the write count is bounded by **characters, not tokens** — 400 one-character chunks at a unit of 40 cost at most 11 API calls, and that bound is tight rather than loose (the first chunk writes immediately, each later write needs 40 new characters, so the maximum is 1 + 9 + the closing write, and a skipped flush can only lower it); the first call creates the message and **every later one edits it by the id the send returned**, never re-sends; and the visible text only ever grows, ending at the whole answer. **The write is provably non-blocking**: with a capacity-1 channel and a stub holding the first response open, all 50 chunks still go through, the flushes arriving during that write are *skipped* rather than queued, and the stub sees exactly two requests — one held write plus the final edit. That test was checked to fail for the right reason rather than assumed to be able to: awaiting the write inline, the rejected alternative, makes it panic on `chunk 13 blocked: the driver is waiting for its own write` (and takes three other streaming tests red with it). `429`/`retry_after` is honoured and not hammered — one refused call, one retry, the gap asserted as a *lower* bound so a loaded machine flakes safe rather than into a false pass, and the retry carrying the whole answer rather than a truncation; a repeated identical edit is a benign no-op that neither fails nor is retried, with its control — the same `400` meaning "message to edit not found" is a real failure that falls back to a fresh message; every edit being refused still consumes the stream in full and delivers the partial text as a new message; a stream that ends mid-answer delivers what arrived; a stream that produced no text writes nothing at all; and the streaming failure path carries no token. The retry *policy* itself (`classify`, `next_step`, `retry_after_of`, the throttle cap, the refusal-detail cap, a `2xx` without `ok: true` reading as a failure) is unit-tested pure, with no network and no sleep. **The honest limit**, documented in the module rather than papered over: coalescing bounds the *number* of writes, not their *rate*, which follows generation speed — a very fast model can outrun Telegram's per-chat edit rate (community-observed at roughly one per second; the Bot API documents no number), and when it does the `429` path keeps the run correct and the display lags while generation does not. `tests/telegram_live.rs` adds 4 `#[ignore]`d tests against a **real** bot: that a real `sendMessage` reports the message id at all (without which the edit path is unreachable and every answer is one post), that the real API really does answer an identical edit with `message is not modified` — which is also the only thing that proves what a message *holds*, an accepted edit being evidence the text differed — that a stream cut short still leaves the partial answer on the screen, and that a real transport failure and a real refusal carry no token |
| `hx-mcp` | 58 | 2433 | **The supervisor's promise, held against a real child process on a real pipe**: `tests/support/fake_mcp_server.rs` is a hand-rolled MCP server speaking real newline-delimited JSON-RPC 2.0, and it *fails loudly* — any input it was not scripted for is recorded as an `UNEXPECTED` line and exits non-zero, which every test asserts is absent, so a client bug that sent the wrong method or a malformed frame fails a test instead of being answered politely. Each misbehaviour mode has a test: **silent** (accepts and never writes — cut off by the handshake timeout, not waited on), **garbage** (non-JSON on stdout), **exit-after-init** (the handshake half-done), **die-on-tool** (detected mid-call, marked down, restarted), **hang-on-tool** (cut off by `call_timeout_secs` while the connection is deliberately left up — a slow server and a dead one look the same from here), **noisy-stderr** (40 lines written, counted, and present in no result, no health report and no description). **Restarts are bounded**: the pid file counts spawns, so a server that cannot start stops being respawned and the `RestartBudget` is pure and takes `now` — the window tests assert counts and never sleep. **A child is reaped**: after shutdown the pid is gone from `/proc`, with the zombie case named separately. **The server's own spelling of a tool name is what goes back on the wire** (`a b` arrives as `ns__a_b` and is called as `a b`). Namespacing: `__` splitting that survives a tool named `a__b`, folding to the provider charset, a 64-char cap with a stable FNV-1a suffix (a `DefaultHasher` would rename a tool between builds and silently invalidate every approval rule written against it), and the lossy-fold collision the host *refuses* rather than trusting. The client declares **no capabilities** — asserted on the wire, because a capability that let a server reach back into `hx` is the one an untrusted server would use. HTTP: the happy path runs **`rmcp`'s own server on `axum` over a real loopback socket** (a client bug in the handshake, the session header or the `Accept` negotiation shows up against an implementation this crate does not own), plus raw-TCP endpoints that accept and say nothing or answer 500. **The credential rule is a pair**: a sentinel token is resolved through `hx-secrets` and the endpoint *records the `Authorization` header it received*, so the assertion that the value appears in no error and no log is made about a run that genuinely carried it; and a reference that cannot resolve fails **without dialling the endpoint**, asserted by zero recorded requests — a leak test against a path that never had the secret is a no-op that passes forever |
| `hx-secrets` | 36 | 1302 | Argon2id+XChaCha20 round-trip, tamper detection, redaction patterns, and **credential resolution**: a `store:name` reference resolved through `vault:`/`env:`/a fixed map, an empty environment variable refused like an absent one, an unknown store listing the stores that *are* configured, and every error message asserted **not** to contain a value |
| `hx-agent` | 58 | 2047 | The loop's gate, in one file of integration tests: the target of a destructive call is **measured after the capability check and before the prompt** (and the event that reaches the store carries it, so the trail proves what the approver was shown), a **capability denial is a result the model reads and cannot be approved away** (an approver willing to say yes is never asked), an approval denial is reported and the command never reaches the host, `allow for chat` stops the second prompt while a remembered denial is not re-asked, a tool declaring no external effect is never prompted about, a refused call does not stop its sibling, unknown tools and unusable arguments return as results, a non-zero exit is still a call that *ran*, `max_turns` and the deadline stop the run, and the exact event sequence a client renders. Plus the **routed model call** over a real `ModelRouter` and a real `ProviderRegistry`, with only the adapter faked: the route decides the model, the key follows the credential the pool granted, a refused credential is benched and its *sibling* is tried before another provider, a missing key and a 502 both give the reservation back (asserted with `concurrent: 1`, since a leaked lease looks exactly like a rate limit), and a day's budget that covers one pessimistic reservation still allows three calls |
| `hx-store` | 58 | 2920 | Migrations applied once and never re-run, **a database from a newer build refused with both versions named** (and left untouched), `STRICT` rejecting a type mistake at insert, the transcript written by `seq` the caller does not track, a batch written whole or not at all, a cascade that only happens because `Store` sets `foreign_keys`, every part type round-tripping while an unknown one is reported rather than dropped, events and usage surviving a reopen — plus 4 in `tests/resume.rs` that drop the store and open a **new connection** to the same file, which is the closest a test gets to killing the daemon |
| `hx-tools` | 102 | 4125 | Requirements per tool, bounded output, the two-phase registry, **confinement** (a run with a boundary runs the command there and touches no host; a boundary that cannot be entered is reported as a failure instead of falling back to the machine — the failure mode that would silently unconfine every run whose engine hiccuped), and **a misnamed argument refused rather than ignored** — `cwd` instead of `workdir` used to drop silently and run the command in the daemon's own directory. `delete` is the largest entry: the XDG trash round-trip on a real in-memory host, a directory walked rather than counted at the top level, the filesystem root refused, an unreadable path refused **before** anything is touched, an existing trash name never overwritten, a *pattern* read as one literal filename and told so, a transport failure that says nothing was deleted, and a `delete` that still requires the `Delete` capability on the resolved path |
| `hx-server` | 112 | 6242 | Route dispatch via `oneshot`, `HxError`→HTTP status mapping, and twenty-one of the twenty-two tests in `tests/api.rs` driving the **real loop over the real HTTP surface** with only the model scripted: an answer comes back with its session, its cost and its events; a tool call runs and its result reaches the model; a write outside the workspace is denied and never happens; a shell command that needs a human is refused **with the reason**, and the same command runs under `yolo`; a second request on a session continues the transcript; unknown autonomy and unknown roles are 400s that name what is accepted; and a request that cannot run leaves no session behind. Two of them are the floor a `yolo` run cannot lift: `rm -rf /etc` is **refused** (with the shipped rule's reason, so the model can read why) while `rm -rf /tmp/…` still runs, which is the pair that shows the refusal is a list of named paths and not a blanket stop. Plus the sandbox adapter: a command runs in the boundary with its workdir translated host→mount, a path outside the mount is refused **without running anything**, a sandbox path is left alone (the model may have copied one), one container per checkout and none shared across checkouts, a reaped sandbox is replaced rather than returned, a command that outlives its deadline is reported as still-running rather than as success, and dropping the boundary destroys it. Plus **SSE**: three tests that POST `/v1/chat/stream` through the real router and parse the response the way a spec-compliant client would — a run streams its events and ends with a named `done` carrying the reply, a run that cannot start arrives as a named `error` event rather than a status (the response is already `text/event-stream` by then, so there is no status left to change), and two runs on one shared bus do not see each other's events — plus the **daemon-side remote sandbox wiring**: a profile naming an unknown host is refused by name (not silently local), a profile with no `host` returns the exact local manager `Arc`, and a host's configured `egress_proxy_bin` reaches the `RemoteSandboxRuntime` the daemon builds for it — with a host that names none staying unset, because the path must exist on the *far* machine and a guessed one would be wrong at runtime. Without that last one the daemon refused every remote egress allowlist with "no proxy binary path was configured", so "remote egress is enforced" was true of the library and false of the daemon |
| `hx` | 43 | 2619 | Renderers for pools/hosts/sandbox-spec/**policy**/sessions/runs/approvals, CLI parsing, and the daemon client's URL rules (an explicit `--daemon` wins, a bare `host:port` from the config gets a scheme, a URL that already has one is left alone). The policy renderer is asserted on the *order* of the rules rather than their presence — printing them in the struct's order would describe a policy the session does not have — and the approvals renderer is asserted to show a target list, the way back, and the command that answers the question, because a terminal that showed less than the daemon asked would be a weaker interface to one decision. Plus the **SSE reader** for `hx chat --stream`: a frame needs a blank line to complete, a CRLF stream still terminates frames (a proxy that sent those would otherwise buffer every event forever with no error), a run event carries its session, `done` and `error` frames are told apart, a keepalive comment is not a frame, a multi-line payload needs several `data:` lines and joins with newlines, a long argument is truncated to one line, and the `done` frame is asserted to unwrap to the same shape `/v1/chat` returns — the mistake that printed `session ?` and `0 turn(s)` for a run that had done real work |

**Tests** is every target of `cargo test -p <crate> --locked` (unit, integration and bin targets);
the `#[ignore]`d live suites are excluded here and counted in tier A. **LOC** is
`find crates/<crate>/src -name '*.rs' | xargs wc -l` — the crate's own source, not its tests. Both
columns are reproducible with those two commands.

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
| **Egress filtering by CIDR or raw IP** | A hostname / `*.domain` allowlist **is** enforced, on both the near and the far host (internal network with no *default* route + `hx-egress-proxy` sidecar). What has no implementation is *matching* a CIDR or a raw IP against an unresolved `CONNECT` target, so such an entry — and anything address-shaped in the `inet_aton` grammar — is *refused* rather than pretended (`SpecError::EgressNotEnforced`) | Medium — a `network: true` profile with no allowlist at all is still unrestricted |
| DuckDuckGo keyless scraping — the *success* path | Every attempt from a plain HTTP client is answered with an `anomaly` challenge: a TLS-fingerprint wall, not a markup change. The failure path is verified live; the success path needs a browser-fingerprint client (M6) | Medium — search silently loses a source, but `SearchReport` names it |
| Vault written to disk and reopened in a **new process** | Untested | Medium — in-process round-trip only |
| `hxd` reaper loop, `axum::serve` under load | Manual only | Low |
| **`hx-mcp` against a real third-party MCP server** | No real server can be assumed on a build machine, so the live canary (`tests/mcp_live.rs`) is `#[ignore]`d and reads its target from `HX_MCP_LIVE_COMMAND`/`HX_MCP_LIVE_URL`. It has **never been run**. Everything the suite verifies about the wire is verified against a double this crate also wrote — real JSON-RPC over a real pipe, but our reading of the protocol at both ends. The one test in that file that needs no environment (`a_live_target_that_is_not_there_is_a_readable_failure_and_not_a_hang`) *does* run, and covers the commonest real state: a misconfigured server | Medium — a `rmcp` behaviour we have misread would pass every test here and fail on first contact. `rmcp` is the mitigation, and it is not under test |
| **`hx-mcp` children inherit the daemon's environment** | Deliberate, and therefore never exercised as a failure. `env:` in a server's config *adds* variables; it does not replace the inherited set, because `npx` resolves Node through `PATH` and servers read `HOME` for caches. A secret exported into the daemon's shell therefore reaches every child it spawns. See `src/stdio.rs`'s module doc | Medium — the exposure is real but bounded: `hx`'s own credentials come from the vault, resolved per call, and are never placed in an environment |
| **A stdio MCP call is auto-allowed at the default autonomy level** | Not a bug in `hx-mcp`: `requirement_for` reports `Resource::Process` + `Action::Execute` for a stdio server, which is what a child process *is*, and `hx-agent`'s risk table maps `Process` to `RiskClass::Mutate`, which the default `balanced` level allows without asking. Changing it in `hx-mcp` would mean reporting a resource that means something else | Medium — an operator who expects a prompt for a stdio server's tools does not get one. The workaround is an `ask` rule on the tool name, which the approval engine already supports (see ROADMAP) |

### Tier D — absent

Two crates are one line each — placeholder `lib.rs` with a doc comment and nothing else:

**No typed stubs remain.** `hx-browser`, `hx-gateway` and `hx-mcp` were each declared as a workspace
member with only a typed interface, so `cargo test` reported nothing for them and the build stayed
green — **a green suite says nothing about a stub.** All three have now been replaced by real
implementations. Also absent: the Tauri desktop/mobile apps, host certificates, `ssh-agent` auth, and
SSH file transfer to a Windows host (the POSIX-only paths refuse via a capability check).

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

**2 — A real Docker integration test. ✅ Done.** `crates/hx-sandbox/tests/docker_live.rs`, twelve
tests, run in CI on `ubuntu-latest`. The ladder is no longer a mapping function: the daemon's own
view of the container is asserted, `network=none` is probed from inside, the pid ceiling is read from
the cgroup and then attacked, and the reaper is checked against `docker inspect` rather than against
its own bookkeeping.

**3 — A real SSH integration test. ✅ Done, and scheduled.** Seven tests against a throwaway `sshd` in
CI, on a non-default port so the bracketed `known_hosts` form is exercised. It is not a second
machine and not a Windows host — that is item 7.

**4 — Mark the untested paths so the suite cannot lie. ✅ Done for both live surfaces.**
`cargo test --workspace` reports `52 ignored` instead of implying full coverage, and
`.github/workflows/integration.yml` runs them where CI can host them. The remaining tier C paths —
real search backends, the vault opened in a new process — should get the same treatment as they gain
tests; the suite's real weakness was never low coverage but that **nothing distinguished "verified"
from "compiles"**, so a green run read as more assurance than it was.

**5 — Live search canary. ✅ Done.** `crates/hx-search/tests/search_live.rs`, four tests, run nightly
by `.github/workflows/canary.yml` — which starts a SearXNG of its own, because that is the one
backend a non-browser client can rely on. It asserts the promises the design makes rather than
wishing the web were friendlier: *never a silent empty* (no results implies a named reason), every
failure is accounted for, results that do come back are usable and not redirect wrappers, and with
`HX_SEARCH_EXPECT_RESULTS=searxng` the configured backend must actually answer. The first live run
found DuckDuckGo serving an `anomaly` challenge on every request — reported correctly, and now
recorded in README as the reason a browser-fingerprint client is M6 work rather than a parsing bug.

**6 — End-to-end agent test.** ◐ Unblocked, not done. The loop exists now (`crates/hx-agent`), and
its 31 tests exercise the gate end to end — but against a *scripted* model and an in-memory host,
which is still only our own assumptions. The loop is wired into something that owns a credential and
a host (`hx-store` and `hxd`), and a real model has been driven through it by hand (see *Tier C — a
real model through the daemon* below), but that run is still manual: what is missing is a **test**
that drives a real model through the loop with a real tool against a real host or sandbox, which
needs a key CI does not have.

**7 — L3, and a non-Linux remote.**

✅ **L3 done.** gVisor's `runsc` is installed by the integration job, registered as a daemon runtime,
and the L3 test asserts the claim rather than the mapping: the sandbox reports `4.19.0-gvisor` where
the host reports `7.0.0-30-generic`, keeps a read-only root, runs non-root, and writes through the
bind mount. `HX_DOCKER_REQUIRE_L3=1` makes a missing gVisor a failure, so the capability cannot
quietly stop being tested.

✅ **A Windows remote is verified — over WinRM.** What that does *not* cover is a Windows **SSH**
server: the POSIX-only file-transfer guards and the shell wrapping have never met one. That needs a
Windows box running `sshd`, which is environment work rather than code work.

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

## Running the suite

```bash
cargo test --workspace --locked   # 978 tests, 0 failed, 52 ignored live tests
cargo test -p hx-store          # 58 — migrations, the transcript, and 4 that reopen the file
cargo test -p hx-agent          # 60 — the loop's gate, the routed model call, the transcript sink
cargo test -p hx-tools          # 102 — requirements, bounded output, the two-phase registry, workspace resolution, the trash
cargo test -p hx-server         # 114 — routes, and the loop end to end over HTTP
cargo test -p hx-sandbox        # 94 — includes the ladder and the rollback invariants
cargo test -p hx-remote         # 132 — includes known_hosts parsing and the host key policy
cargo test -p hx-gateway        # 44 — the connector trait, the Telegram wire, and the approval loop-back
cargo test -p hx-core           # 120 — classification, the policy ladder, and the ceiling comparison
cargo build --workspace         # clean: 0 warnings, 0 deprecations
cargo clippy --workspace --all-targets --locked -- -D warnings   # clean (this is what CI runs)

# the ones that need a real service (this is the shape CI runs them in)
cargo test -p hx-sandbox --test docker_live -- --ignored --test-threads=1
HX_SSH_TEST_HOST=<host> HX_SSH_TEST_USER=<user> HX_SSH_TEST_KEY=~/.ssh/id_ed25519 \
  cargo test -p hx-remote --test ssh_live -- --ignored --test-threads=1
```

## Summary

- **`hx-gateway` is no longer a placeholder.** It carries the `Connector` trait, the deterministic
  session router, the Telegram connector and the streaming driver that wires a model's token stream to
  coalesced `editMessageText`, proven by **57 tests** (36 unit + 21 over a hermetic HTTP stub) plus 4
  `#[ignore]`d against a real bot: the same thread always maps to one `SessionKey` and two threads on one
  platform do not collide; a chat bridge's answer ceiling never authorises `Destructive`; background
  output with no home channel is refused not dropped; the Telegram connector's real
  `getUpdates`/`sendMessage` URLs, in-path token, advancing offset, message/button parsing and fail-closed
  error paths are exercised over a real TCP stub; and the streaming driver's write count is asserted as a
  *number* (bounded by characters, not tokens, and the bound is tight) with its one-write-in-flight rule
  proven against a held-open response and a capacity-1 channel. No bot token (a generated fixture), no
  network. What is *not* covered here: a real bot answering a real stream has not been run from this
  checkout — `tests/telegram_live.rs` exists and is `#[ignore]`d, and running it is deliberate, since it
  needs a token and a chat.
- **13 crates with logic**: unit-tested at the level of pure functions and in-process lifecycles. There
  are no empty crates left — `hx-browser` and `hx-mcp` were the last two, and both now carry tests.
- **The store's resume path is tested across a real process boundary, in the only way a test can**:
  four tests in `crates/hx-store/tests/resume.rs` drop the `Store` and open a *new connection* to
  the same file, then continue the conversation. One of them is the case M1's exit criterion turns
  on — a run that died between a tool call and its result — where the transcript is repaired with a
  result that says the call did not run, rather than being sent to a provider that would reject it
  with an error that does not mention the cause.
- **The agent loop's gate is tested where it can be**: 31 integration tests with no network and no
  model — a capability denial that an approval cannot widen, an approval denial that never reaches the
  host, a refusal that does not stop the next call, and the event sequence a client will render. What
  none of them reaches is a real model: a scripted one is a model we wrote.
- **56 live tests**, all `#[ignore]`d by default: a real Docker daemon with gVisor installed, a real
  `sshd`, a real SearXNG and a real bot are run in CI or deliberately; the ones against a real model
  and a real bot are run deliberately, since they need a key and CI has none. The rest — WinRM against
  a Windows guest, the remote-sandbox runtime, the remote PTY — need hosts on a private network, so
  they are run by hand too.
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
  work), the vault opened in a new process, and the `hxd` reaper loop and `axum::serve` under load.
# hx — an agent harness in Rust

[![CI](https://github.com/phantomic12/hx-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/phantomic12/hx-harness/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/phantomic12/hx-harness)](https://github.com/phantomic12/hx-harness/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A harness for driving AI agents against real machines: remote hosts, isolated sandboxes, model
pools with enforced ceilings, and one HTTP API that every front end talks to.

This repository is the working foundation — thirteen crates of tested logic, a runnable daemon, and a
CLI. It is **not** a finished harness; `ROADMAP.md` says exactly what is missing.

---

## What works today

```console
$ hx doctor
  ok   provider credentials   3 across 2 provider(s)
  ok   routing table          3 pool(s), 4 role binding(s)
  ok   roles                  builder, reviewer, scout, summarize
  ok   search backends        searxng, duckduckgo
  ok   sandbox profiles       2 valid profile(s)
  FAIL container engine       the Docker socket exists but the daemon is not responding
```

```console
$ hx sandbox spec untrusted
profile untrusted  (isolation L2)
  image             ubuntu:24.04
  cpus              2
  memory            4096 MiB
  pids              1024
  ttl               3600s
  network           none
  privileged        no
  readonly rootfs   yes
  user              1000:1000
  capabilities      (none granted)  [dropped: ALL]
  security opts     no-new-privileges:true
  userns mode       private (requested)
  runtime           (engine default)
  tmpfs             /tmp rw,noexec,nosuid,size=1g
  workspace         /home/you/proj -> /workspace
```

```console
$ hxd &           # the daemon
$ curl -s localhost:7717/healthz
ok
$ curl -s localhost:7717/v1/status | jq .pools
[ { "name": "interactive", "routes": [ … ], "healthy_credentials": 2, … } ]
```

| Area | State |
|---|---|
| Capability tokens, approval policy, command classification | **Done**, tested |
| Encrypted secret vault (Argon2id + XChaCha20), outbound redaction | **Done**, tested |
| Model pools, per-credential rate/token/budget limits, role routing | **Done**, tested — and now *reachable*: a call reserves at both levels, resolves the key the reservation was granted, sends, and settles against real usage (`crates/hx-agent/tests/router_model.rs`) |
| Provider adapters: OpenAI-compatible `/v1/chat/completions` | **Built** — wire mapping unit-tested, real HTTP against a stub, and a real model: text, usage, tool calls and a tool-result round trip (`crates/hx-provider/tests/openai_live.rs`) |
| Provider adapter: Anthropic Messages API (`/v1/messages`) | **Built** — top-level `system`, `x-api-key` + `anthropic-version` auth, `tool_use`/`tool_result` blocks, `stop_reason`; hermetic HTTP over a stub + a `#[ignore]`d live suite (`crates/hx-provider/tests/anthropic_live.rs`) |
| Web search: self-hosted SearXNG + keyless DuckDuckGo, RRF fusion, per-backend failure reporting | **Built** — SearXNG verified end to end against a live instance; DuckDuckGo is bot-walled for a non-browser client and *says so* rather than returning nothing |
| Remote hosts: local + SSH (real `russh`), host key verification, Windows/macOS/Linux capability detection | **Built** — connect, auth, exec and file transfer run against a real host (`crates/hx-remote/tests/ssh_live.rs`) |
| Sandboxes: L1/L2/L3 isolation ladder, Docker lifecycle, TTL reaper | **Built** — created, confined and reaped against a real daemon (`crates/hx-sandbox/tests/docker_live.rs`), running as the workspace's owner so the bind mount is writable; L3 verified inside gVisor, where the sandbox sees `4.19.0-gvisor` and not the host kernel |
| Daemon (`hxd`) + HTTP API + CLI (`hx`) | **Done**, runnable |
| Tools (`hx-tools`) + the agent loop (`hx-agent`) | **Built** — seven tools, and a loop that classifies every call against the capability token and then the approval policy; 26 tests pin the gate down against a scripted model (`crates/hx-agent/tests/loop.rs`). `delete` moves a named path to the XDG trash rather than unlinking it, and a destructive prompt carries what will be gone — the resolved path, its entry count, its bytes — because the tool measures the target before anyone is asked |
| Sessions (`hx-store`) | **Built** — SQLite: create, resume, list, rename, delete, export (JSON/Markdown), events, usage totals. A transcript that ended mid-call is *repaired*, not sent to a provider that would reject it |
| Web UI, Tauri desktop/mobile, chat connectors | **Not started** |
| MCP client, browser-automation pool | **Not started** |
| The loop wired into `hxd` and `hx`: `POST /v1/chat`, `hx chat`, session routes over `hx-store` | **Built** — one request runs the loop against a session: the prompt is stored before the model is called, the role decides the model, credentials come from a `store:name` reference, events are written as they happen, and a transcript that ended mid-call is repaired before it is sent. Twenty tests drive the **real loop over the real HTTP surface**; model replies are scripted and sandbox engine calls use a recording runtime. `hx chat --sandbox-profile dev` selects a configured shell boundary; missing or failed boundaries never fall back to host execution |

---

## The one thing to understand first

**The daemon owns all state; every front end is a client of it.**

That single decision is what makes the web-UI requirement achievable rather than a promise that
decays. CLI, browser, Tauri desktop, Tauri mobile and chat connectors all render the same
`AgentEvent` stream and call the same HTTP API, so a feature cannot exist on one surface only.
It is why `hx status` and the daemon cannot disagree about what is running.

## The four design decisions worth reviewing

**1. No ambient authority.** An agent is not trusted because it is "our agent". It holds a
capability token listing resources, actions and constraints, and every tool call is checked
against it. Path grants are subtree-matched component-wise, so a grant on `/workspace/a` does not
leak into `/workspace/ab`, and an empty grant path denies rather than silently meaning root.
There is a regression test for exactly that.

**2. Rate limits belong to the credential, not the pool.** Credential pools are keyed by
*provider* and shared between named pools. Two pools that both use `anthropic-main` contend for
the same 50 RPM, because that is how the provider sees it. Getting this backwards — per-pool
copies of a credential limiter — lets N pools each spend one key's full quota. There is a test
that fails if you reintroduce it.

**3. Limits are reserved, not counted.** Output tokens are unknown before a request is sent, so
the limiter reserves the whole prompt plus the full output allowance and refunds the surplus on
reconcile. Spending is enforced fail-closed: once a daily budget is reached, everything is
denied — including requests that estimate `$0`.

**4. Platform is a runtime property, not a compile-time one.** A Linux daemon driving a Windows
box is the interesting case, and `cfg!(windows)` cannot express it. Every host is probed on
connect and reports capabilities; commands are built for the shell that is actually there.

## Layout

```
crates/
  hx-core        ids, errors, messages, events, capability tokens, approval, config
  hx-secrets     Argon2id + XChaCha20-Poly1305 vault, credential resolution, redaction engine
  hx-provider    token buckets, credential pools, role router, provider trait
  hx-search      SearXNG + DuckDuckGo backends, RRF fusion, graceful degradation
  hx-remote      Host trait, capability detection, local + SSH transports, command runner
  hx-sandbox     isolation ladder, sandbox specs, container lifecycle + reaper
  hx-tools       the tools an agent calls, each declaring the resource it needs
  hx-agent       the loop, and the two gates — capability, then approval — every call passes
  hx-store       SQLite: sessions, transcripts, events, usage
  hx-server      the HTTP API and shared daemon state
apps/
  hxd            the daemon
  hx             the CLI
```

Empty placeholder crates (`hx-browser`, `hx-gateway`, `hx-mcp`) are reserved for the milestones that
need them.

## Installing

Prebuilt static binaries. No toolchain, no Docker, no sudo:

```console
$ curl -fsSL https://raw.githubusercontent.com/phantomic12/hx-harness/main/install.sh | sh
```

Windows PowerShell: `iwr -useb https://raw.githubusercontent.com/phantomic12/hx-harness/main/install.ps1 | iex`

Container: `docker pull ghcr.io/phantomic12/hx-harness:latest`

**[DEPLOY.md](DEPLOY.md)** covers all four paths, version pinning, checksum and attestation
verification, and the two things that bite people — the Docker socket, and the fact that `hxd`
has no authentication of its own.

## Running it

```console
$ cp hx.example.yaml hx.yaml     # then edit
$ hx doctor                      # validate the config
$ hx policy                      # what runs free, what is asked about, what is refused
$ hxd --config hx.yaml --bind 127.0.0.1:7717
```

`hx policy` prints the ladder the daemon will actually apply, in the order it is checked: the level
spelled out per risk class, the ceiling, the rules as a numbered list with `deny` first, and which of
them are the shipped catastrophe set. It is the answer to "what did I allow?" without reading
`hx-core/src/approval.rs`:

```console
$ hx policy
approval policy from hx.yaml
  level    balanced — asks before anything leaving the machine, or worse
  read         runs free
  mutate       runs free
  external     asks
  destructive  asks
  privileged   asks
  ceiling  none — a `yolo` chat can auto-approve anything, including a deleted database
  deletes  a pattern or a variable in a delete is refused outright (`rm -rf build*`, `rm -rf $DIR`), …
```

A call that needs a human does not fail, it waits — and any client can answer it. From a second
terminal, while the run is blocked:

```console
$ hx chat "delete the ./build directory" --role glm52 --workspace ~/projects/thing &
$ hx approvals
delete /home/yoav/projects/thing/build
risk: destructive
why:  deletes /home/yoav/projects/thing/build
target:
  /home/yoav/projects/thing/build — directory, 1342 entries, 480.0 MB
after: moves to the trash at /home/yoav/.local/share/Trash/files, where it can be moved back — nothing is destroyed until the trash is emptied
answer: allow once | allow for this chat | deny
id: apr_7f3a…   ->  hx approve apr_7f3a… --option once

$ hx approve apr_7f3a… --option once --by terminal
```

From a clone:

```console
$ cargo build --release --locked
$ ./target/release/hx doctor
$ ./target/release/hxd --bind 127.0.0.1:7717
```

```console
$ cargo test --workspace         # 695 tests, 0 failed, 24 ignored live tests
$ cargo test -p hx-sandbox --test docker_live -- --ignored   # needs a container engine
$ cargo test -p hx-remote --test ssh_live -- --ignored       # needs an SSH server
$ HX_SEARXNG_URL=... HX_SEARCH_EXPECT_RESULTS=searxng \
  cargo test -p hx-search --test search_live -- --ignored   # needs the internet
$ HX_OPENAI_TEST_BASE_URL=... HX_OPENAI_TEST_MODEL=... HX_OPENAI_TEST_KEY=... \
  cargo test -p hx-provider --test openai_live -- --ignored # needs a real model
```

The last two are what reach a real service; `.github/workflows/integration.yml` runs both, against a
real Docker daemon and a throwaway `sshd`. **[TESTING.md](TESTING.md)** keeps the honest ledger of
what has been executed, what is only unit-tested, and what merely compiles.

Rust 1.89+ (edition 2021). Verified on 1.98.1.

## What is deliberately not done yet

- **Approval is a queue a client polls.** A run that needs a human waits, and any client can read the
  question and answer it over HTTP (`GET /v1/approvals`, `POST /v1/approvals/{id}`; `hx approvals` and
  `hx approve` are the terminal one). Silence is a denial on a timer, the answer is recorded as an
  event with its `by`, and the question itself — including what a deletion measures — is in the
  stored trail. What is *not* there yet: nothing pushes a question to a client, so a web UI polls.
  `hx policy` prints the ladder in force, so "why did it ask?" and "what did I allow?" are answered by
  the same output rather than by reading the source.
- **Project-scoped allowlists are not persisted.** "Always allow this" is remembered in memory for the
  rest of the run, and `docs/approvals.md` §5's reviewable `.hx/allow.toml` — the file in the
  repository a team can diff — is not written yet. Until it is, a remembered approval outlives
  nothing. The `confined` axis (§4), chat profile selection, and `hx policy` (§6) are built.
  Shell confinement does not confine file tools or make the writable workspace mount disposable.
- **Streaming.** **Built** for the OpenAI-compatible provider: a turn is sent with `stream: true`
  and deltas are emitted as they arrive, with tool-call fragments merged by the same rule the
  non-streaming parser uses. The daemon publishes every `AgentEvent` at `POST /v1/chat/stream` as
  SSE, tagged with its session, ending in a named `done` (or `error`) event carrying the reply; and
  `hx chat --stream` renders a run as it happens — turns, tool calls and text deltas live on stderr,
  the reply on stdout. The Anthropic adapter still completes whole and replays its deltas through the
  default `Provider::stream`, and **Anthropic streams for real too**: `stream: true`, named SSE
  events reassembled across reads, `input_json_delta` fragments accumulated and parsed only when the
  block stops, cumulative usage taken from the last `message_delta`, and a mid-stream `error` event
  raised rather than returned as a short answer. Context
  compaction is **built** too: a long session is elided at the `compact_at_tokens` threshold (head +
  an explicit marker + tail, never splitting a tool call from its result) for the model while the
  stored audit trail is untouched.
- **Nothing in `ci.yml` reaches another machine.** That file is in-process unit tests; the tests
  that open a socket — a real Docker daemon, a real `sshd` — live in
  `.github/workflows/integration.yml` and are `#[ignore]`d by default, so a local `cargo test` stays
  green on a laptop without Docker while still reporting `18 ignored` rather than implying coverage.
  L3 is verified where gVisor is installed — the CI job installs it, and `HX_DOCKER_REQUIRE_L3`
  turns a skip into a failure so the strongest claim in the ladder cannot quietly stop being
  tested.
- **Egress filtering.** A sandbox has a network or it does not. There is no proxy and no firewall
  rule behind `egress`, so an allowlist is *refused* (`SpecError::EgressNotEnforced`) rather than
  silently ignored — a profile that says four hostnames must not mean the whole internet.
- **Keyless scraping that survives a bot wall.** DuckDuckGo, Mojeek and public SearXNG instances
  now serve a challenge to a plain HTTP client — a TLS-fingerprint problem, not a markup one, and
  one no amount of parsing fixes. The harness reports it per backend rather than returning an empty
  list, self-hosted SearXNG works because you host it, and a browser-fingerprint client is the M6
  browser pool's job.
- **Host certificates.** A server presenting one is *refused*, not accepted: `@cert-authority`
  lines are parsed so they cannot be mistaken for a host key, but no certificate chain is
  verified, and accepting an unverified chain would claim a check that did not happen. The same
  applies to `ssh-agent` auth, which returns an explicit error rather than pretending.
- **Host key policy from config.** The policy is an argument to `SshHost::connect`
  (`Strict` / `Tofu` / `Insecure`) with `~/.ssh/known_hosts` as the default store. Reading it out
  of `hx.yaml` belongs to the host registry in M4, along with `WinRMHost` and a Windows remote,
  where the shell wrapping and the POSIX-only file-transfer guards have never met a real server.
- **Web UI, desktop/mobile apps, chat connectors, MCP, browser pool.** Designed in
  `ARCHITECTURE.md`, not built.
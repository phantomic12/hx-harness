# hx — Roadmap

Each milestone ends with something **demonstrably working**, not a layer of scaffolding.
Ordering is by dependency and by how much it de-risks.

---

## M0 — Skeleton + the parts that are pure logic ✅ (landed)

The pieces that are hard to get right *and* can be proven correct without a network, so they
exist before anything can hide behind an integration test.

- Cargo workspace, 15 crates, layered (arrows only point down)
- `hx-core` — ids, messages, events, capability tokens, config model, **approval engine +
  command risk classifier** (§3.11)
- `hx-secrets` — Argon2id → XChaCha20-Poly1305 vault, redaction engine
- `hx-provider` — token-bucket limits (rpm/tpm/rpd/daily-USD/concurrency), reserve-then-reconcile
  accounting, credential pools with 4 routing strategies and health benching, `ModelRouter`
- `hx-search` — backend trait, parallel fan-out, RRF fusion, URL-normalized dedupe
- `hx-remote` — `Host` trait and per-host capability probing (local transport only; see M4)
- `hx-sandbox` — spec → container translation across the L1/L2/L3 isolation levels, lifecycle,
  TTL reaping, rollback on a failed start
- `hx-server` + `hxd` — axum route surface and the daemon binary

**Status: 690 tests green, clippy clean (0 warnings).** M0 closed at 324 of them: core 83, provider
61, sandbox 53, search 45, remote 33, secrets 27, server 11, cli 11 — `hx-tools`, `hx-agent` and
`hx-store` came after M0 and are covered in the M1/M2 sections.

What the tests actually pin down: the vault round-trips and rejects both a wrong passphrase and a
tampered ciphertext; redaction masks known secrets and provider-shaped tokens; the risk classifier
escalates command chains, nested substitutions and `curl | sh`; approval policy honours level,
ceiling, unattended budget and expiry; buckets refuse when exhausted and recover on refill; pools
fail over and bench unhealthy credentials; RRF dedupes `?utm_source=` variants of one URL; a
failed sandbox create rolls back rather than leaking a container.

**Not landed yet** (typed stubs only): `hx-browser`, `hx-mcp`, `hx-gateway`.

**Deliberately unverified at M0:** the concrete HTTP adapters (`OpenAiCompatible`,
`AnthropicMessages`) and the fetch/parse halves of the search backends. Their *pure* halves —
request construction, URL building, response shape — are tested; the socket round-trip is not,
because without recorded fixtures a "passing" test just asserts our own assumptions back at us.
Those get real tests in M1 against a live endpoint.

---

## M1 — One binary, it actually works

**Goal:** `hx "refactor this repo and run the tests"` completes a real task against a real model.

- ✅ `Provider` impl for OpenAI-compatible endpoints (covers ~80% of providers) — landed with a
  hermetic HTTP suite and a live suite (text, usage, tool calls, transcript)
- ✅ Provider adapter for Anthropic Messages API — landed with a hermetic HTTP suite (top-level `system`,
  `x-api-key` + `anthropic-version`, `tool_use`/`tool_result` blocks) and a live suite
- ✅ Streaming over SSE, token deltas into the TUI — provider-level deltas (OpenAI-compatible;
  Anthropic too: named events, `input_json_delta` fragments parsed only at the block stop),
  `POST /v1/chat/stream`, and `hx chat --stream` rendering
  turns, tool calls and text live
- ✅ Tool dispatch: `shell`, `read_file`, `write_file`, `patch`, `delete`, `search`, `todo` — each
  declares the resource and action it needs; none decides whether it is allowed
- ✅ **Approval wired into dispatch** — every tool call is classified against the capability token and
  then the approval policy, in that order, and every refusal comes back to the model as a tool result
  (`crates/hx-agent/tests/loop.rs`). `docs/approvals.md` §7's steps 1–4 have landed with it: `ask`
  rules and the `deny → ask → allow` precedence, the shipped catastrophe deny set, remember-scoping by
  tier, and the `delete` tool — a destructive request now names its targets, measured after the
  capability check and before the prompt, and the question reaches a client over HTTP
  (`hx approvals` / `hx approve`), and `hx policy` prints the ladder in force, in the order it is
  checked (§6), and **`confined` as a second axis (§4)**: a rule can require that a call run inside a
  boundary, `shell` runs it there when its context has one, and a boundary that cannot be entered is a
  failed call rather than a quiet fallback to the machine. Requests select a profile with
  `sandbox_profile` (`hx chat --sandbox-profile`); invalid or unavailable boundaries fail before the
  model runs. `docs/approvals.md` §5's project-scoped allowlist has landed: `.hx/allow.toml` is a
  reviewable file in the checkout, loaded per run and scoped to that workspace alone
- ✅ **Compaction at a token threshold** — `compact_at_tokens` is honoured: when a transcript's
  estimated tokens pass the threshold, the middle is elided for the model (head + an explicit marker +
  tail, never splitting a tool call from its result) while the stored audit trail is untouched. The
  The general context builder has landed too: `hx_agent::context::ContextBuilder` owns what a turn
  sends — which transcript (the audit trail, or a compacted view of it), whether tools are offered,
  whether a system prompt exists — so the loop is control flow and the request's *shape* has one
  home. Both halves of this item are done.
- ✅ `hxd` runs, `hx` connects to it: `hx chat` sends the prompt to the daemon over the configured
  HTTP address and prints the run's report (over HTTP rather than the unix socket, which the config
  also names and nothing uses yet); `hx sessions` / `hx session <id> [--export md]` read back what the
  daemon stored. A run that did not complete exits non-zero, so a script can tell
- ✅ Session persistence (`hx-store`): resume, list, export — and the case that actually matters, a
  transcript that ended mid-call being repaired rather than sent to a provider, which rejects it
- ✅ **The loop reachable over HTTP** — `POST /v1/chat` runs the loop against a session, `hx-server`
  resolves the role's model through the routing table (reserving capacity and resolving the key), the
  prompt is stored before the model is called, events are written as they happen, and `/v1/sessions*`
  reads sessions, transcripts, events and exports back. Messages and events are written as the run
  produces them, so a killed daemon leaves a session that says what happened — the difference between
  "restartable" and "resumable". The approval channel is built, and so is the WebSocket event stream
  that used to be named here as open: `GET /v1/sessions/{id}/ws` frames `{"seq", "session", "event"}`
  and a reconnecting client sends `since_seq` to be sent only what it missed.

**Exit criteria:** a multi-step task (5+ tool calls) completes end-to-end; killing the TUI and
reconnecting resumes the session mid-flight. **Both met against a real model** (2026-09-17): a task
(“read the sources, add `divide()`, add its test, run pytest”) completed in 12 turns and 14 tool calls
— 9 shell, 3 read_file, 2 patch — with 0 refusals, and the `pytest` output it reported was re-run
independently (`2 passed`). For the second half, the daemon was `kill -9`d the moment a tool result
reached disk: 3 messages and 5 events survived, the client saw `RemoteDisconnected`, and restarting
the daemon resumed that same session id — 3 → 19 messages, unchanged `created_at` — to a correct
answer. The evidence is `~/.hx/kill-test.sh`, whose session-picker was fixed to consider only
sessions created *after* the run starts (it previously latched onto the previous run's session and
killed an idle daemon while looking like a pass).

---

## M2 — Web UI, and TUI/web parity

**Goal:** everything the TUI does, in a browser, at the same time, on the same session.

- ✅ **Per-session WebSocket event stream** — `GET /v1/sessions/{id}/ws` upgrades to a stream that
  sends the session's stored events first, then its live ones, as `{"seq","session","event"}` JSON
  frames sharing one filtered broadcast bus (a client gets only its own session's events). A reconnecting
  client sends `{"since_seq": N}` as its first message and the server replays exactly `seq > N` from the
  store — no duplicates, no gaps — because every live event carries the store sequence `chat::write_events`
  assigned it. Tested end to end in `crates/hx-server/tests/ws_api.rs` against a real socket: two
  clients on one session both receive the same events, and a reconnecting client proves no-dup/no-gap.
- ✅ **A server-side terminal** — `POST /v1/terminals`, `GET /v1/terminals/{id}/ws`, `DELETE
  /v1/terminals/{id}`. The PTY lives in `hxd` and outlives every client, so an attach is a *join*: a
  browser and a TUI reach one shell and see the same bytes, and closing either leaves it running.
  Output arrives as scrollback-then-live as separate frames, base64 because a terminal is
  byte-oriented; scrollback is capped on write so a runaway producer cannot exhaust memory; the
  shell exiting is its own frame, because a stream that simply stops is indistinguishable from a
  hung shell. Per the roadmap's own preference for a self-contained service this uses `nix` (already
  in the lock, and a PTY is four libc calls) rather than `portable-pty`, which is not vendored.
- `hx-server`: axum, REST + `/v1/sessions/{id}/ws` + `/v1/terminals/{id}/ws`
- ✅ **A web client** — one self-contained page served by the daemon at `/` (`include_str!`, so the
  binary is the whole daemon and a deploy cannot half-succeed), xterm.js on a CDN, no build step.
  It is a client in the strict sense: the terminal is created once under a fixed id and reattached,
  so a refresh rejoins the running shell; the session socket resumes with `since_seq` so a reconnect
  renders the gap rather than the whole history.
- Frontend, still to come: a workspace file tree, a diff/review pane, and the approval queue
- **Two clients on one session simultaneously** (TUI + browser) — this is the real test that
  the daemon/client split is honest and not cosmetic

**Exit criteria:** open a browser terminal to a shell, run a command, watch the same bytes in
the TUI; then send an agent prompt from the browser and see it stream in both. **Both halves are
proven at the protocol level.** The events half: two WebSocket clients on one session, and a browser
SSE run plus a WebSocket client, seeing the same stream (`tests/ws_api.rs`). The terminal half: two
clients on one shell receiving the same bytes, a late client sent the scrollback, and a detached
client leaving the shell running (`tests/terminal_api.rs` for the socket, `tests/terminal.rs` for the
PTY, and `scripts/check_web_client.py` against a live daemon, which drives the exact frames the page
sends). What is *not* yet exercised is a real TUI and a real browser against one session at the same
moment: the browser stack was unavailable, so the page's protocol was driven directly rather than
through a rendered page.

---

## M3 — Sandboxes + the capability model

- `bollard` sandbox lifecycle: create/exec/stop/destroy, cgroup v2 limits, volume quotas
- Isolation tiers: rootless podman (L1) → gVisor `runsc` (L2) → Firecracker (L3)
- Default-deny egress with an allowlist; per-sandbox TTL and deterministic teardown
- Capability tokens wired into the policy engine. Approval and capability are two independent
  checks on one path: the level decides whether to *ask*, the token decides whether "yes" is
  even legal. A denied capability is an auditable event, not a prompt the user can approve away.
- ✅ Hash-chained audit log — every event row carries a digest over its content and its
  predecessor, so an edited or deleted row is detectable (`hx-store/src/audit.rs`). Verified against a
  real V1 database: 348 pre-chain events kept and reported as unchained, new events chained. It is not
  a signature — see that module's doc block for exactly what it does not prove.
- ✅ The check is reachable: `hx audit <session>` and `GET /v1/sessions/{id}/audit`, exiting 2 on a
  break. Three answers kept distinct — `intact`, `broken` (naming the row and both digests), and the
  count of rows written before the chain existed, which is never folded into `intact`. Verified live
  against a daemon: 8 chained events report intact, one row rewritten with raw SQL reports TRAIL
  ALTERED at that row.
- Web UI: container pane, and an approval queue showing the risk class, the reason, and the
  remaining unattended budget

**Exit criteria:** an agent asked to "build this untrusted code and run it" does so in L2 with
no network, is killed at TTL, and its workspace survives while the sandbox doesn't. An
attempted capability escalation shows up as a denial event, not a hang.

---

## M4 — Multi-machine

- ✅ **`SshHost` on `russh`** — exec, PTY, SFTP, port-forward, keepalive/reconnect. Live-tested in
  CI against a real sshd (`ssh transport` job).
- ✅ **`WinRMHost`** for the boxes that cannot do SSH — NTLM and Basic-over-TLS, with the credential
  path unit-tested and live tests `#[ignore]`d behind `HX_WINRM_*`.
- ✅ **Host registry in config + vault-backed auth** — `hosts:` in the config, credentials resolved
  from the vault at connect time. `AppState::resolve_host` is the one way anything obtains a remote
  handle (`crates/hx-server/src/hosts.rs`), so a configured machine is reachable by *every* client,
  not only the agent.
- ✅ **`HostCaps` adaptation** so tools do not need Windows/Linux branches — `RemoteOs`/`ShellKind`
  drive per-shell quoting and command chaining.
- ✅ **Reachable over HTTP and in the browser** — `GET /v1/hosts/{id}` (describe),
  `/files` (list), `/file` (read/write), `/exec` (run). The web client opens any host into a
  directory browser with a file viewer/editor and a command runner. Reads and writes are gated by
  the same approval policy an agent run uses, and a command is classified by the real classifier, so
  `hostname` runs and `curl … | sh` does not.
- ✅ **File transfer over SFTP** — `SshHost::read_file`/`write_file`/`list_dir`/`rename` open the
  `sftp` subsystem on a dedicated channel and speak SFTP v3 directly (see `crates/hx-remote/src/sftp.rs`),
  so a file is a byte stream on that channel rather than a command's stdout. For a server without SFTP
  (`Some(false)`) the methods fall back to the old shelled-out `base64` path, which is why the capsule
  probe now *measures* the subsystem instead of guessing: `HostCaps::has_sftp` was a `bool` hard-coded
  to `true` by both capability parsers and handed to clients as a measured fact, but a `uname` string says
  nothing about which SSH subsystems a server offers. It is an `Option<bool>`; `SshHost` opens the
  subsystem and completes the version handshake so `Some(true)` is now a measured fact, `Some(false)` a
  measured absence, and `None` is reserved for a probe the transport itself cut short. `WinRmHost` reports
  `Some(false)`, which it genuinely knows, since WinRM is not an SSH transport at all.
- ❌ **Remote sandboxes** — run the sandbox on a *remote* Docker/Podman host. Nothing in
  `hx-sandbox` reaches a remote daemon today.
- ✅ **Remote terminal (a PTY straight to a remote host)** — `POST /v1/terminals` takes an optional
  `host`, and the daemon adopts the session as a terminal like any other, so the terminal pane and
  the WebSocket contract are unchanged: a client attaches to a remote shell the same way it attaches
  to a local one. `Host::open_pty` returns a `PtySession` (a stream, not a request); `SshHost`
  implements it over a real pty channel, `LocalHost` and `WinRmHost` refuse with reasons rather than
  handing back a session that never speaks. An interactive shell has no command line to classify, so
  it is gated as `Execute` (`RiskClass::External`) *before* the connect — a denial that still dialled
  the machine would leak its reachability.

**Exit criteria:** drive a Linux box, a Mac, and a Windows host from the browser; no private
key ever enters the model context or a sandbox.

*Status: four of the seven items are done, and with the remote terminal in place the browser drives a
remote box for real — browse, run, and an interactive shell — rather than only the first two. The exit
criteria is still not met: remote sandboxes are absent, and Unix-only CI means the Windows transport
is exercised by unit tests rather than against a live host.*

---

## M5 — Connectors

- `Connector` trait + session router (`platform/chat/thread` → `SessionKey`)
- **Telegram** (long-poll + webhook), streaming via coalesced `editMessageText`
- **Discord** (twilight gateway, slash commands, threads, Message Content Intent)
- Delivery targets, home-channel pinning, so cron output doesn't interleave with chat
- Then: Slack (Socket Mode) → Matrix → Email → WhatsApp Cloud → Signal → SMS

- **Approvals out of band, as a configurable option** — a request can be answered from anywhere the
  user already is, not only from the surface that started the run: `approval.ask_via` naming one or
  more channels (Telegram, Discord, Slack, email, a webhook), each with the policy for what it may
  answer. The prompt is the same `ApprovalRequest` that renders in the TUI (§3.11), so the buttons on
  a phone and the dialog in the terminal are the same decision — but the *answer authority* is
  configured per channel, because a phone tap is a weaker signal than a terminal. Rules worth
  pinning: only a channel that can display the full request (targets, sizes, what is irreversible)
  may answer; per-channel ceilings, so a chat bridge can approve a `Mutate` but never a
  `Destructive`; a channel that is down must fail closed rather than leave the run waiting; and the
  answer is attributed in the audit log to the channel it came from. `/yolo` and `/approval` over a
  DM follow the same rule: scoped to one chat, expiring, and never above the deployment's ceiling

**Exit criteria:** DM the bot from your phone, get a streaming answer, approve a dangerous
command with a button, receive a cron digest in a separate pinned thread.

---

## M6 — MCP + browser pool + full search

- `rmcp` host: consume stdio and streamable-HTTP MCP servers, per-server tool namespacing,
  health checks and restarts
- `rmcp` server: expose `hx`'s tools to other agents/IDEs
- Browser pool: crw (Rust, Firecrawl-compat) → camoufox (stealth) → Chromium (interactive CDP),
  per-container profile isolation, challenge escalation to a human-in-the-loop browser pane
- Search: SearXNG, DDG, Mojeek, Marginalia, Brave, Google PSE, Wikipedia, plus the
  extraction ladder and URL/ETag caching

**Exit criteria:** a research task runs 6 free backends in parallel, dedupes, RRF-ranks,
extracts the top 8, and cites them — with zero paid API calls.

---

## M7 — Native apps

- Tauri 2 shell reusing the exact web UI bundle; local or remote `hxd`
- Desktop: system tray, global hotkey, OS notifications, native file pickers
- Mobile (iOS + Android): chat, session browse, log view, approval queue, push notifications
  via APNs/FCM; device token in Keychain/Keystore
- Auto-update, code signing, CI matrix for all five targets

**Exit criteria:** an approval requested by a running agent pings your phone; you approve it
from the lock screen and the agent continues.

---

## Deliberately deferred

Full-text search across session history (FTS5 is fine until it isn't) · skill marketplace
with signing · multi-tenant auth · a graph memory backend · RL/replay tooling · voice
(STT/TTS) — voice lands once the connector layer exists, since it's the same inbound pipeline.
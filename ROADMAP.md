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

**Status: 667 tests green, clippy clean (0 warnings).** M0 closed at 324 of them: core 83, provider
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
- Provider adapter for Anthropic Messages API
- Streaming over SSE, token deltas into the TUI
- ✅ Tool dispatch: `shell`, `read_file`, `write_file`, `patch`, `delete`, `search`, `todo` — each
  declares the resource and action it needs; none decides whether it is allowed
- ✅ **Approval wired into dispatch** — every tool call is classified against the capability token and
  then the approval policy, in that order, and every refusal comes back to the model as a tool result
  (`crates/hx-agent/tests/loop.rs`). `docs/approvals.md` §7's steps 1–4 have landed with it: `ask`
  rules and the `deny → ask → allow` precedence, the shipped catastrophe deny set, remember-scoping by
  tier, and the `delete` tool — a destructive request now names its targets, measured after the
  capability check and before the prompt, and the question reaches a client over HTTP
  (`hx approvals` / `hx approve`), and `hx policy` prints the ladder in force, in the order it is
  checked (§6). Still open in that document: `confined` as a second axis (§4) and a persisted
  project-scoped allowlist (§5)
- Context builder + compaction at a token threshold
- ✅ `hxd` runs, `hx` connects to it: `hx chat` sends the prompt to the daemon over the configured
  HTTP address and prints the run's report (over HTTP rather than the unix socket, which the config
  also names and nothing uses yet); `hx sessions` / `hx session <id> [--export md]` read back what the
  daemon stored. A run that did not complete exits non-zero, so a script can tell
- ✅ Session persistence (`hx-store`): resume, list, export — and the case that actually matters, a
  transcript that ended mid-call being repaired rather than sent to a provider, which rejects it
- ◐ **The loop reachable over HTTP** — `POST /v1/chat` runs the loop against a session, `hx-server`
  resolves the role's model through the routing table (reserving capacity and resolving the key), the
  prompt is stored before the model is called, events are written as they happen, and `/v1/sessions*`
  reads sessions, transcripts, events and exports back. Messages and events are written as the run
  produces them, so a killed daemon leaves a session that says what happened — the difference between
  "restartable" and "resumable". Still to come: an approval channel (so a client can answer a prompt
  instead of the daemon refusing it) and a WebSocket event stream

**Exit criteria:** a multi-step task (5+ tool calls) completes end-to-end; killing the TUI and
reconnecting resumes the session mid-flight.

---

## M2 — Web UI, and TUI/web parity

**Goal:** everything the TUI does, in a browser, at the same time, on the same session.

- `hx-server`: axum, REST + `/ws/agent/:session` + `/ws/term/:id` + `/ws/events`
- Server-side PTY via `portable-pty`, attach/detach, scrollback retained in `hxd`
- Frontend: xterm.js terminal, chat/stream pane, workspace file tree, diff/review pane
- **Two clients on one session simultaneously** (TUI + browser) — this is the real test that
  the daemon/client split is honest and not cosmetic

**Exit criteria:** open a browser terminal to a shell, run a command, watch the same bytes in
the TUI; then send an agent prompt from the browser and see it stream in both.

---

## M3 — Sandboxes + the capability model

- `bollard` sandbox lifecycle: create/exec/stop/destroy, cgroup v2 limits, volume quotas
- Isolation tiers: rootless podman (L1) → gVisor `runsc` (L2) → Firecracker (L3)
- Default-deny egress with an allowlist; per-sandbox TTL and deterministic teardown
- Capability tokens wired into the policy engine. Approval and capability are two independent
  checks on one path: the level decides whether to *ask*, the token decides whether "yes" is
  even legal. A denied capability is an auditable event, not a prompt the user can approve away.
- Hash-chained audit log — every ask, answer, auto-allow and denial, with the risk class and
  reason string that produced it
- Web UI: container pane, and an approval queue showing the risk class, the reason, and the
  remaining unattended budget

**Exit criteria:** an agent asked to "build this untrusted code and run it" does so in L2 with
no network, is killed at TTL, and its workspace survives while the sandbox doesn't. An
attempted capability escalation shows up as a denial event, not a hang.

---

## M4 — Multi-machine

- `SshHost` on `russh`: exec, PTY, SFTP, port-forward, keepalive/reconnect
- `WinRMHost` for the Hyper-V boxes that can't do SSH (NTLM via jump host)
- Host registry in config + vault-backed keys/agent/hardware-key auth
- `HostCaps` adaptation so tools don't need Windows/Linux branches
- Web UI: host pane, file browser over SFTP, terminal straight to a remote host
- Remote sandboxes: run the sandbox on a *remote* Docker/Podman host

**Exit criteria:** drive a Linux box, a Mac, and a Windows host from the browser; no private
key ever enters the model context or a sandbox.

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
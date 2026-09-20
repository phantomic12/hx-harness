# hx — a Rust agent harness

**Status:** design + M0 skeleton
**Working name:** `hx` (trivially renamable — one `sed` across the workspace)

---

## 0. Thesis

Most harnesses (Hermes, Codex, Claude Code, OpenClaw) are **Python/Node programs that own your
terminal**. They scale to one user on one machine, and every new surface (web UI, mobile app,
chat platform) becomes a second, slightly-wrong implementation of the same features.

`hx` inverts that. There is **one daemon, `hxd`, that owns all state and all capabilities**.
Every other thing — TUI, web UI, Tauri desktop app, iOS/Android app, Discord bot, Telegram bot,
cron, webhooks — is a **protocol client of `hxd`**. Nothing reimplements anything.

That single decision is what makes "do everything in the browser that I can do in a terminal"
achievable rather than a forever-buggy duplicate. It's also what makes native mobile possible
at all: a phone can't run a 90-turn agent loop, but it can drive one.

```
                    ┌──────────── clients (thin) ────────────┐
   hx (TUI)   web UI (browser)   Tauri desktop   iOS/Android   Discord   Telegram   HTTP API
      │              │                 │              │            │          │          │
      └──────────────┴────────┬────────┴──────────────┴────────────┴──────────┴──────────┘
                             │
                    ┌────────▼────────┐
                    │   hxd  (daemon) │   ← the only thing with authority
                    │  sessions ·     │
                    │  agents ·       │
                    │  providers ·    │
                    │  sandboxes ·    │
                    │  secrets ·      │
                    │  policy         │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┬──────────────────┐
   model pools          SSH hosts            sandbox pool        browser pool
   (rate-limited)     (linux/mac/win)      (podman→gVisor→FC)   (camoufox/CDP)
```

**Second decision — no ambient authority.** Agents never get the Docker socket, never get a
private key, never get an unrouted network. They get short-lived, scoped, revocable
capabilities brokered by `hxd`, and every use is audited. The sandbox is the security boundary;
`hxd` is the authority boundary.

---

## 1. Crate graph

Deliberately layered so the core has **zero IO** and is testable without a network.

```
hx-core          ids, message/event types, errors, config model, capability tokens   [no IO]
  ├─ hx-secrets    vault (argon2id→xchacha20poly1305), credential resolution, redaction engine
  ├─ hx-store      sqlite: sessions, events, usage counters, audit log
  ├─ hx-provider   Provider trait, pools, rate limits, reservation accounting
  ├─ hx-search     SearchBackend trait + free backends + RRF aggregation
  ├─ hx-remote     Host trait: Local / SSH (russh) / WinRM / container-exec
  ├─ hx-sandbox    SandboxSpec + lifecycle: podman(rootless) → gVisor → Firecracker
  ├─ hx-browser    browser session driver (CDP + Firecrawl-compatible HTTP)
  ├─ hx-tools      built-in tool implementations
  ├─ hx-agent      the loop: context, compaction, tool dispatch, approvals, subagents
  ├─ hx-mcp        rmcp host (consume MCP servers) + rmcp server (be one)
  ├─ hx-gateway    Connector trait + platform adapters + the approval loop-back
  └─ hx-server     axum: REST + WebSocket protocol + static web UI
       ├─ hxd      the daemon binary
       └─ hx       the TUI/CLI binary (a protocol client, not a special case)
```

Rule: **arrows only point down.** `hx-agent` never imports `hx-server`. If it did, the
daemon-and-clients split would rot immediately.

One arrow points sideways, and it is deliberate: `hx-gateway` depends on `hx-agent`, because a channel's
answer has to be applied to the queue a run is parked on, and the queue is the loop's. The dependency
never runs the other way — a `Connector` that knew about approval queues would be a connector that is not
a connector — and the alternatives (a newtype in `hxd`, a crate for one `impl`) would each move the
channel-policy check further from `AnswerAuthority`, where it is tested. The cost is stated where it is
paid: building `hx-gateway` alone now builds the tool and remote stack with it. See
`crates/hx-gateway/src/bridge.rs`.

---

## 2. Stack decisions

| Need | Choice | Why |
|---|---|---|
| async runtime | `tokio` | only real option |
| HTTP / WS | `axum` + `tower-http` | same as axum's own examples; hyper 1.x |
| SSH | `russh` 0.63 + `russh-sftp` + `russh-config` | pure Rust, client **and** server, PTY/exec/SFTP/tunnels. No libssh2 C dep |
| Containers | `bollard` | Docker **and** Podman API, rootless podman socket autodiscovery |
| PTY | `portable-pty` | cross-platform, feeds xterm.js over WS |
| MCP | `rmcp` 3.3 (official Rust SDK) | stdio + streamable-HTTP, both roles |
| Model APIs | `reqwest` + hand-rolled provider traits | avoid the framework lock-in that makes Hermes hard to extend |
| Persistence | `sqlx` (SQLite) | async, compile-time-checked queries |
| Secrets | `argon2` + `chacha20poly1305` + `zeroize` + `keyring` | don't invent crypto; OS keystore holds the root key |
| Desktop/mobile | **Tauri 2** | one frontend → Win/mac/Linux **+ iOS + Android**; ~3 MB shells, native webview |
| TUI | `ratatui` + `crossterm` | |
| Telegram | `teloxide` | mature |
| Discord | `twilight` | gateway + slash + threads |
| Browser | drive **camoufox/CDP**, don't rewrite | see §3.9 — this is the honest call |
| Logging | `tracing` + `tracing-subscriber` | |

---

## 3. The ten requirements, designed

### 3.1 Multi-machine connectivity (Linux / macOS / Windows, secure key storage)

`Host` is the abstraction — not "SSH". It exposes exec, PTY, file transfer, and port-forward,
because containers and local processes need exactly the same interface.

```rust
#[async_trait]
pub trait Host: Send + Sync {
    async fn exec(&self, cmd: &Command) -> Result<ExecOutput>;
    async fn open_pty(&self, spec: PtySpec) -> Result<Box<dyn PtySession>>;
    async fn stat(&self, path: &str) -> Result<FileStat>;
    async fn read_file(&self, path: &str) -> Result<Vec<u8>>;
    async fn write_file(&self, path: &str, data: &[u8]) -> Result<()>;
    async fn forward(&self, local: u16, remote: (&str, u16)) -> Result<Box<dyn Forward>>;
    fn capabilities(&self) -> HostCaps;   // has_pty, has_sftp, is_windows, shell_flavor
}
```

Backends: `LocalHost`, `SshHost` (russh — covers Linux, macOS, and Windows 10+ via the
built-in OpenSSH server), `WinRMHost` (only for hosts where SSH is genuinely unavailable —
your Hyper-V boxes today), `ContainerHost` (exec into a sandbox).

**Windows reality check.** OpenSSH-on-Windows is the recommended path and covers PowerShell,
`cmd`, and Win32 binaries. WinRM stays as a fallback because your existing Hyper-V/PowerShell
Remoting setup (DNS-less NTLM through eynat-01) can't be reached by SSH without re-plumbing.
`HostCaps` lets tools adapt — e.g. paths get `\\` treatment, `sudo` becomes
`Start-Process -Verb RunAs`, line endings get normalized at the boundary, not in every tool.

**Key storage — the part most harnesses get wrong.** Three tiers, in order of preference:

1. **OS keystore** (`keyring`): macOS Keychain, Windows Credential Manager/DPAPI, Linux Secret
   Service or kernel keyring. The master key lives here and never touches disk in plaintext.
2. **Encrypted vault file**: keys sealed with XChaCha20-Poly1305, key derived from the
   passphrase via Argon2id (m=64MiB, t=3, p=4). For headless servers with no keystore.
3. **External agent / hardware key**: ssh-agent over the socket, or FIDO2 `sk-ssh-ed25519`.

The important rule: **`hxd` holds the keys and does the signing.** An agent asks "run this
command on host X"; `hxd` authenticates. The private key is never written into a sandbox, never
enters the model context, and never appears in a tool result. `hx-secrets` also runs an
outbound redaction pass (entropy + known-secret matching) on every tool result before it
reaches a model, so a key that leaks into stdout gets masked rather than exfiltrated.

### 3.2 Isolated dev containers

Three isolation tiers, chosen per-task, because "safe" and "fast" are a dial not a switch:

| Tier | Runtime | Startup | Boundary | Use for |
|---|---|---|---|---|
| **L1** | rootless podman, userns, readonly rootfs, all caps dropped, no-net default | ~100 ms | kernel namespaces + cgroups v2 + seccomp | trusted-ish code: your repos, builds, tests |
| **L2** | gVisor (`--runtime=runsc`) | ~150 ms | userspace syscall interception | LLM-written code you don't trust |
| **L3** | Firecracker / Kata microVM | ~125 ms + KVM | hardware virt | arbitrary untrusted code, multi-tenant |

Default is **L2** for agent-authored code, **L1** for your own. L3 requires KVM and is opt-in.

Every sandbox gets: cgroup v2 limits (cpu.max, memory.max, pids.max, io.max), an ephemeral
overlay workspace, a **size quota** on its volume, a *default-deny* egress policy with an
explicit allowlist, a wall-clock TTL, and deterministic teardown that does not depend on the
agent's cooperation. Workspace survives the sandbox (it's a named volume); everything else
is discarded.

"Allocate space" is answered concretely: a per-sandbox volume from a thin pool (btrfs subvol
with `qgroup` quota, or ZFS dataset with `quota=`, or plain `project quota` on ext4/XFS), with
`size_bytes` in the spec and enforcement at the filesystem layer — not merely a polite number
the agent is asked to respect.

### 3.3 Feature-packed web UI

`hx-server` (axum) exposes three things over one WebSocket multiplex, plus REST for CRUD. **Built as
REST so far**: `/v1/chat` (one request, one session, one run), `/v1/sessions*` (list, read, rename,
export, events, delete), and the routing, search, sandbox and host routes. The WebSocket multiplex is
**not built** — a client polls a session's events rather than subscribing, which is why the routes
below are still the design and not the description:

- **`/ws/term/:id`** — full PTY, server-side (`portable-pty`), attach/detach like tmux. This is
  what makes the browser a real terminal: it's not an emulation of a terminal, it *is* one.
  The same endpoint carries local shells, SSH sessions, and `exec` into sandboxes.
- **`/ws/agent/:session`** — streaming events (token deltas, tool calls, approvals, diffs).
- **`/ws/events`** — the audit/capability firehose for dashboards.

Frontend: `xterm.js` + Monaco + the chat pane, served as a static bundle from the same binary.
The browser gets a **terminal pane** (local shells, SSH hosts, and `exec` into sandboxes all
through the one endpoint above), a **workspace pane** (file tree over SFTP/exec),
a **container pane**, a **diff/review pane**, and an **approval queue**.

Because every surface is a client of `hxd`, feature parity is structural. Adding a feature to
the daemon lights it up in the TUI, web, desktop, and mobile simultaneously. That is the whole
point.

### 3.4 Model pools with rate/token limits

Pools are **policy objects**, not just lists. This is the design your `litellm` setup wants
but can't express, because litellm's limits live on credentials, not on logical work classes.

```yaml
providers:
  anthropic-main:
    kind: anthropic
    credentials:
      - { id: a1, secret: vault:anthropic/key1, limits: { rpm: 50, tpm: 40000, rpd: 1000, daily_usd: 25 } }
      - { id: a2, secret: vault:anthropic/key2, limits: { rpm: 50, tpm: 40000 } }
    routing: least_loaded        # weighted | round_robin | least_loaded | priority

pools:
  interactive:                   # you, right now
    members: [anthropic-main/claude-*, openai-main/gpt-*]
    strategy: priority
    limits: { tpm: 80000, concurrent: 4 }
  background:                    # cron, cron jobs, bulk subagents
    members: [local/qwen3-32b, openrouter/cheap-*]
    strategy: cheapest_capable
    limits: { daily_usd: 5 }
  scout:      { inherits: background, limits: { daily_usd: 2 } }

roles:                           # what each agent role draws from
  builder: interactive
  scout: scout
  reviewer: interactive
```

Mechanics:

- **Token bucket per (credential × dimension)**, persisted in SQLite so restarts don't reset
  your quota. Dimensions: rpm, tpm, rpd, daily_usd, concurrent.
- **Reserve-then-reconcile.** You can't know completion tokens up front. On send, reserve
  `estimated_input + max_tokens`; on completion, refund the difference. Without this, a burst
  of parallel subagents all pass the check and then collectively blow through TPM.
- **Failover, not failure.** On 429: honour `Retry-After`, mark the credential cooling, retry
  on the next member. On 401: quarantine the credential and alert. On
  `thought_signature`-class provider bugs (the `cap/coding` failure you hit): mark the *route*
  unhealthy and fall through immediately rather than burning the loop.
- **Role-scoped pools** so a cron job cannot eat your interactive quota — the failure mode
  you've already been bitten by.
- **Per-session and per-subagent caps** so a runaway agent loop self-terminates on budget, not
  on your credit card.

### 3.5 What to steal, and from whom

| Source | The idea worth taking | Where it lands |
|---|---|---|
| **Hermes** | skills as progressive-disclosure markdown; persistent memory; delegation w/ roles; cron; multi-agent kanban queue; profiles; the gateway concept | `hx-agent` (skills, memory), `hx-gateway`, scheduling in `hxd` |
| **Codex** | sandbox-first execution; approval modes (`suggest` / `auto-edit` / `full-auto`); unified-diff patch application; git worktree isolation | `hx-sandbox` + `hx-agent` policy, `hx-tools` |
| **Claude Code** | plan mode; hooks; checkpoint/rewind; compaction; MCP as the extension seam | `hx-agent`, `hx-mcp`, `hx-store` (checkpoints as content-addressed snapshots) |
| **Aider** | repo map for cheap context; explicit edit-format reliability | `hx-agent` context builder |
| **OpenHands** | the container-as-the-workspace model | `hx-sandbox` |
| **jcode / Grok Build** | swarm coordination; memory graph; a TUI worth using | `hx-agent` (subagents), `hx` |

The deliberate omissions: no Python plugin runtime (that's how you get back to a 600 MB
process tree), no provider-specific framework, no "one giant agent loop with 40 `if` branches".

### 3.6 Native mobile and desktop

**Tauri 2.** One frontend bundle → Windows, macOS, Linux, iOS, Android. Native webviews, ~3 MB
shells, ~50% the RAM of an Electron equivalent.

- **Desktop** is a first-class client: it can run a *local* `hxd` (so a laptop works offline)
  or connect to a remote one. Rust core is shared, so tools behave identically either way.
- **Mobile** is a thin, always-remote client. This is a deliberate constraint, not a
  compromise: iOS will suspend your app mid-agent-loop no matter what you build. So mobile
  gets push notifications on approvals/completions, a chat surface, session browsing, a
  read-mostly log view, and the approval queue. Long work runs in `hxd` on your own hardware,
  where it belongs. Native bits: Keychain/Keystore for the device token, push via APNs/FCM.

### 3.7 Chat connectors

```rust
#[async_trait]
pub trait Connector: Send + Sync {
    fn id(&self) -> &'static str;
    async fn run(&self, tx: Sender<Inbound>, ctl: CancellationToken) -> Result<()>;
    async fn send(&self, target: &ThreadRef, msg: Outbound) -> Result<MessageRef>;
    async fn edit(&self, m: &MessageRef, text: &str) -> Result<()>;   // streaming
    async fn upload(&self, target: &ThreadRef, file: &FileBlob) -> Result<()>;
    fn capabilities(&self) -> ConnectorCaps;                          // threads? edits? buttons?
}
```

Inbound normalizes to `(ConnectorId, ChatId, ThreadId) → SessionKey`. Outbound streaming is
per-platform: Telegram gets throttled `editMessageText` (it rate-limits aggressively — batch
at ~1.5 s or you get `429 retry_after`), Discord gets message edits and real threads, Slack
(Socket Mode, later) gets `chat.update`.

Order: **Telegram → Discord → Slack → Matrix → Email (IMAP/SMTP) → WhatsApp Cloud API →
Signal (signal-cli bridge) → SMS.** Same adapter shape every time, so each is a bounded piece
of work rather than a project.

Session routing detail worth stealing from Hermes: **thread → session mapping with a pinned
"home" channel**, and per-job delivery targets, so cron output doesn't interleave with your
conversation.

### 3.8 Web search backends — all the free ones

```rust
#[async_trait]
pub trait SearchBackend: Send + Sync {
    fn id(&self) -> &'static str;
    fn cost(&self) -> Cost;                    // Free | Keyed | Metered
    async fn search(&self, q: &Query, n: usize) -> Result<Vec<Hit>>;
}
```

| Backend | Cost | Notes |
|---|---|---|
| **SearXNG** (self-hosted) | free | aggregates Google/Bing/Brave/DDG; the workhorse. One `docker run` |
| DuckDuckGo | free | HTML/lite scrape + Instant Answer API for entity queries |
| Mojeek | free/no key | independent index, genuinely different results |
| Marginalia | free | great for technical/long-tail, bad for shopping |
| Brave Search API | free tier | 2k/month, real index, needs key |
| Google Programmable Search | free tier | 100/day |
| Wikipedia / Wikidata | free | not general search but high-value for entities |
| Jina Reader (`r.jina.ai`) | free tier | markdown extraction, not search |
| **crw** (Rust, Firecrawl-compatible) | self-host | crawl + map + structured extract, single binary |
| Tavily / Exa / Firecrawl | paid | only when quality demands it, behind the same trait |

Aggregation strategy — this is where you beat paid search for free:
**fan out → normalize → dedupe by canonical URL + content simhash → RRF-rank → extract top-k
→ rerank.** Reciprocal Rank Fusion over 4–6 independent free backends reliably beats any single
one, because the failure modes aren't correlated.

Extraction ladder per URL: `readability`+`html2md` → `crw` → Jina Reader → headless browser.
Escalate only on failure. Caching by URL hash + ETag, so re-research is nearly free.

### 3.9 Browser automation

**Do not rewrite a browser in Rust.** Two distinct needs, two backends, one trait:

1. **Stealth/research** → **camoufox** (patched Firefox, C++/Rust) driven over CDP, or **crw**
   (Rust, Firecrawl-compatible REST) for crawl/structured-extract.
2. **Interactive agent automation** → headless Chromium pool (kernel-images style) with CDP +
   screenshot → vision.

`hx-browser` is a **driver and pool manager**, not a browser: session pooling, cookie/profile
persistence per identity, proxy rotation, challenge detection with escalation from
crw → camoufox → human-in-the-loop handoff (the browser pane in the web UI is exactly where
you solve a CAPTCHA the agent can't). Containers are used because that's the only way to keep
browser state from leaking between tasks — one profile per container, destroyed on task end.

### 3.10 All in Rust — the honest version

The core is Rust and ships as **one static binary** (`hxd`, guestimating 25–40 MB, ~50–100 MB
RSS idle) versus a Python process tree. That's the real win, and it's large.

What will *not* be Rust, and why pretending otherwise is a trap:

- **Web UI / native app frontend** — TypeScript/HTML. Unavoidable, and it's *served by* `hxd`,
  so the deployment is still one binary + a static bundle (Tauri embeds it). Rust-native GUI
  (Dioxus/egui) would cost you the shared codebase across desktop+mobile for no runtime gain.
- **The browser itself** — Firefox/Chromium. You drive it over CDP/BiDi. Nothing to gain here.
- **Existing MCP servers and CLIs** — Python/Node/Go. Run them *inside* the sandbox. Rewriting
  `npx` servers in Rust is pure cost.
- **whisper/STT, some model tooling** — C++/CUDA. Sidecar with a Rust supervisor.

So the rule is: **Rust owns the core, the daemon, the CLI/TUI, and the protocol. Everything
else is a client or a sandboxed subprocess.** "All in Rust" achieved where it matters —
resource usage — without a rewrite-everything tax.

### 3.11 Approval autonomy — how often it stops and asks

The requirement: *"a permission level, from ask before anything is done to yolo per-chat, to
dictate how often the user is prompted to ask for commands."*

A single "yolo" boolean is the wrong shape, because it conflates two independent questions:
**what is dangerous**, and **how much you want to be interrupted**. Someone may want zero
prompts for file edits and a prompt for every `sudo`; someone else may want the reverse. The
design separates the two and then recombines them with one dial.

#### Step 1 — classify the action

Every proposed tool call is assigned a `RiskClass`. The shell classifier is the interesting
part, and four details are what make it trustworthy rather than decorative:

- **A chain is classified by its worst segment.** `ls && rm -rf /srv` must classify as
  destruction. An implementation that looks only at the first word sees `ls` and reports a read.
  Segments are split on `&&`, `||`, `;`, `|` and newline, each is classified, and the maximum
  wins. This is the whole safety argument, and it is the first thing you should test.
- **Substitutions are classified recursively.** `echo $(rm -rf /srv)` and `` `rm -rf /srv` ``
  hide a command inside an argument. `$(...)` and backticks are extracted and classified too,
  depth-bounded so a hostile string cannot blow the stack.
- **Unknown means middle, not low.** An unrecognised command is `Mutate`, never `Read`. Guessing
  low is exactly how a classifier becomes a security hole.
- **Piping is context-sensitive.** `curl … | sh` is not "a network fetch", it is remote code
  execution, and it is classified `Destructive`. That is a property of two adjacent segments,
  not of either one alone.

| Class | Severity | Examples |
|---|---|---|
| `Read` | 0 | `ls`, `cat`, `git status`, web search, `docker ps` |
| `Mutate` | 1 | `cp`, `mkdir`, `git commit`, `npm install`, `sed -i` |
| `External` | 2 | `curl`, `git push`, `ssh`, `scp` — anything leaving the machine |
| `Destructive` | 3 | `rm -rf`, `git reset --hard`, `git push --force`, `DROP TABLE` |
| `Privileged` | 4 | `sudo …` (escalates whatever it wraps), `mount`, `chmod -R 777`, `gpg`/`op`/`bw` |

`sudo` is handled by re-classifying its inner command and flooring the result at `Privileged`,
so `sudo ls` still registers as privilege escalation rather than as a read.

#### Step 2 — one dial sets the interruption threshold

The comparison is `severity >= threshold`, so raising the level lowers the prompt rate:

| Level | Auto-allows | Asks about |
|---|---|---|
| `paranoid` | nothing | everything, reads included |
| `cautious` | reads | mutations and up |
| `balanced` *(default)* | reads, mutations | external, destructive, privileged |
| `trusting` | reads, mutations, external | destruction and privilege |
| `yolo` | everything the capability token permits | nothing |

#### Step 3 — per-chat, revocable, and bounded

"Yolo" is scoped to one chat, not to the daemon. `/yolo 30m` sets `level = yolo` and
`expires_at = now + 30m` on that session only; expiry is re-checked on every decision, so the
grant degrades back to `balanced` mid-run with no user action. Two guards sit *above* the dial
and therefore hold even at `yolo`:

- **Ceiling** — the maximum severity that may ever be auto-allowed. `ceiling: destructive` means
  privilege escalation always asks, at every level. This is what lets a shared or hosted
  deployment keep `yolo` available for everything else without handing over `sudo`.
- **Unattended budget** — a rate limit *on autonomy*. After N consecutive auto-approvals the
  harness checks in regardless of level. This targets the failure mode where an agent
  confidently grinds through several hundred approved-by-default actions before anyone notices
  the direction it went. Any explicit human answer resets the counter to zero.

#### Step 4 — what "remember this" means is scoped to the risk

- `Read`/`Mutate` decisions are remembered by command **signature** (first two words), so
  approving `git status` covers `git status --short` but not `git push`.
- `External` and above are remembered by the **exact** command line: `git push origin main` is
  not `git push origin main --tags`.
- The more dangerous the class, the narrower the approval. Over-asking is recoverable;
  over-approving is not.

#### Step 5 — fail closed when nobody answers

Every request carries a default for the timeout case. For unattended runs that default is
`deny` — silence is not consent.

#### Why this is testable

Approval requests are ordinary `AgentEvent`s, so the same prompt renders in the TUI, the web UI,
the native app, and as Telegram/Discord buttons; a tap on a phone is a first-class answer. The
decision function is pure and lives in `hx-core`, so the policy can be verified without a model,
a network, or a UI. `hx-core/src/approval.rs` carries 37 tests covering chain escalation, quote
handling, descriptor redirects, nesting depth, expiry, ceiling, budget, and remember-scoping.

---

## 4. Security model

**Trust boundaries:**

```
model context          ← secrets redacted outbound, never sees keys or full env
  ↓ tool call
hxd policy engine      ← capability token check, allowlist, budget check
  ↓ scoped capability
sandbox / host         ← the enforcement point
```

1. **No ambient authority.** Every tool call carries a capability token: `(subject, resource,
   action, constraints, expiry, budget)`. The agent cannot escalate by asking nicely; a denied
   capability produces an auditable event, not a prompt injection surface.
2. **Sandbox is the boundary, not the prompt.** "Don't touch /etc" is not a security control.
   A read-only rootfs is.
3. **Default-deny egress** with an explicit per-sandbox allowlist.
4. **Approval autonomy is policy, not a chat message.** Never a boolean "yolo": a risk
   classification plus a threshold, scoped per chat, revocable, expiring, and bounded by a
   ceiling and an unattended budget that hold even at `yolo`. See §3.11.
5. **Everything audited** to SQLite: capability grants, denials, tool calls, credential use,
   sandbox lifecycle. Tamper-evident (hash-chained).
6. **Redaction on the way out** — both to the model and to any connector.

---

## 5. Known hard parts (so they don't surprise you later)

| Risk | Reality | Mitigation in design |
|---|---|---|
| TPM accounting under concurrency | you can't pre-count completion tokens | reserve-then-reconcile, per-sandbox budget |
| Windows without SSH | your Hyper-V boxes need NTLM WinRM via a jump host | `WinRMHost` fallback + `HostCaps` adaptation; don't force SSH |
| gVisor + GPU | `runsc` has poor GPU passthrough | GPU work runs L1 (trusted) or on the host, never L2/L3 |
| PTY over WS reconnect | terminals die on flaky links | server-side PTY + attach/detach (tmux semantics), scrollback on `hxd` |
| iOS background limits | agents can't run on-device | mobile is a remote client; push for approvals |
| Telegram edit rate limits | streaming edits get 429'd | server-side coalescing window per connector |
| Provider API churn | 20+ providers, all drifting | one `Provider` trait, OpenAI-compat covers ~80%, quirks isolated per adapter |
| Rust compile times | workspace-wide rebuilds are slow | `mold`/`lld`, split into many small crates, `cargo-nextest` for tests |

---

## 6. Why this is better than a fork

Forking Hermes gets you Python's process tree, plugin fragility, and a gateway that *is* the
agent. Forking Codex gets you a single-machine, single-user tool with no pool/daemon
architecture. Building on `hxd` gets you: one binary, real isolation, pool-level policy,
all surfaces as clients, and native mobile — none of which are retrofittable onto a
terminal-first design.

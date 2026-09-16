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
| Model pools, per-credential rate/token/budget limits, role routing | **Done**, tested |
| Web search: SearXNG + keyless DuckDuckGo, RRF fusion, failure reporting | **Done**, tested |
| Remote hosts: local + SSH (real `russh`), host key verification, Windows/macOS/Linux capability detection | **Built** — connect, auth, exec and file transfer run against a real host (`crates/hx-remote/tests/ssh_live.rs`) |
| Sandboxes: L1/L2 isolation ladder, Docker lifecycle, TTL reaper | **Built** — created, confined and reaped against a real daemon (`crates/hx-sandbox/tests/docker_live.rs`), running as the workspace's owner so the bind mount is writable; L3 (`runsc`) unexecuted |
| Daemon (`hxd`) + HTTP API + CLI (`hx`) | **Done**, runnable |
| Web UI, Tauri desktop/mobile, chat connectors | **Not started** |
| MCP client, browser-automation pool | **Not started** |
| The agent loop itself | **Not started** — see below |

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
  hx-secrets     Argon2id + XChaCha20-Poly1305 vault, secret redaction engine
  hx-provider    token buckets, credential pools, role router, provider trait
  hx-search      SearXNG + DuckDuckGo backends, RRF fusion, graceful degradation
  hx-remote      Host trait, capability detection, local + SSH transports, command runner
  hx-sandbox     isolation ladder, sandbox specs, container lifecycle + reaper
  hx-server      the HTTP API and shared daemon state
apps/
  hxd            the daemon
  hx             the CLI
```

Empty placeholder crates (`hx-agent`, `hx-tools`, `hx-store`, `hx-gateway`, `hx-mcp`,
`hx-browser`) are reserved for the milestones that need them.

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
$ hxd --config hx.yaml --bind 127.0.0.1:7717
```

From a clone:

```console
$ cargo build --release --locked
$ ./target/release/hx doctor
$ ./target/release/hxd --bind 127.0.0.1:7717
```

```console
$ cargo test --workspace         # 390 unit tests + 13 ignored integration tests
$ cargo test -p hx-sandbox --test docker_live -- --ignored   # needs a container engine
$ cargo test -p hx-remote --test ssh_live -- --ignored       # needs an SSH server
```

The last two are what reach a real service; `.github/workflows/integration.yml` runs both, against a
real Docker daemon and a throwaway `sshd`. **[TESTING.md](TESTING.md)** keeps the honest ledger of
what has been executed, what is only unit-tested, and what merely compiles.

Rust 1.89+ (edition 2021). Verified on 1.98.1.

## What is deliberately not done yet

- **The agent loop.** The provider router, tool plumbing, search, sandboxes, approvals and hosts
  all build and are unit-tested, but nothing yet ties them into a model-calling loop. `/v1/chat`
  returns `501` and says so rather than pretending.
- **Nothing in `ci.yml` reaches another machine.** That file is in-process unit tests; the tests
  that open a socket — a real Docker daemon, a real `sshd` — live in
  `.github/workflows/integration.yml` and are `#[ignore]`d by default, so a local `cargo test` stays
  green on a laptop without Docker while still reporting `13 ignored` rather than implying coverage.
  Even so, **L3 has never run**: `runtime: runsc` is passed to the engine and asserted, but nothing
  installs gVisor, so the strongest claim in the ladder is unexecuted.
- **Egress filtering.** A sandbox has a network or it does not. There is no proxy and no firewall
  rule behind `egress`, so an allowlist is *refused* (`SpecError::EgressNotEnforced`) rather than
  silently ignored — a profile that says four hostnames must not mean the whole internet.
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
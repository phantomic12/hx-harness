# hx — Setup and build guide

This guide is for a developer who has just cloned the `hx-harness` repository and wants to
build it, run it, and run its test suites. It covers the offline build, the daemon/CLI, and
the live (integration) test suites that need a real service.

The two authoritative documents in the repo are **`ROADMAP.md`** (milestones and what is
demonstrably working) and **`TESTING.md`** (the honest ledger of what is verified versus what
merely compiles). Read both before trusting a green test run. `ARCHITECTURE.md` and
`DEPLOY.md` cover design and deployment respectively.

## What this is

`hx` is an agent harness: a long-running daemon (`hxd`) that owns an HTTP API, model pools,
sandbox manager, search backends and session store, plus a CLI/terminal client (`hx`) that
talks to it. Every front end (CLI, web UI, future desktop/mobile apps) is a client of the
daemon. **The daemon owns all state; every front end is a client of it.**

## Prerequisites

- **A Rust toolchain, >= 1.89** (the workspace MSRV, declared in `Cargo.toml`:
  `rust-version = "1.89"`, edition 2021). CI verifies the declared MSRV with a dedicated job.
  The repo has been verified on 1.98.1.
- **Rust only.** There is no Python/pip toolchain requirement anywhere in the build or test
  path. The one Python script in the repo (`scripts/check_web_client.py`) is a manual web-UI
  check, not part of the build or the test suite.
- **No network access is needed.** All dependencies are vendored in the Cargo registry and the
  lockfile is committed. Build and test commands use `--offline`.

Install via your toolchain manager (e.g. `rustup update`), then confirm:

```console
$ rustc --version
rustc 1.98.1 (48a229cea 2026-09-01)
$ cargo --version
cargo 1.98.1 (797e8a9bc 2026-08-05)
```

> Only some Unix platforms can run the full unit suite. Anything that drives a real PTY/terminal
> (e.g. `crates/hx-server/tests/terminal_api.rs` and the terminal module in `hx-server`) is
> `#[cfg(unix)]` — **on Windows those compile to zero tests rather than being silently skipped
> with a passing result.** See *Cross-platform notes* below.

## Workspace layout

The workspace has **15 crates** (13 under `crates/`, 2 apps under `apps/`), edition 2021:
`hx-core`, `hx-secrets`, `hx-store`, `hx-provider`, `hx-search`, `hx-remote`, `hx-sandbox`,
`hx-browser`, `hx-mcp`, `hx-tools`, `hx-agent`, `hx-gateway`, `hx-server`,
`apps/hxd`, `apps/hx`.

Three crates (`hx-browser`, `hx-gateway`, `hx-mcp`) are **empty placeholders** — one-line
`lib.rs` files reserved for future milestones. A green build says nothing about them; see
`TESTING.md` "Tier D".

Two **binaries** are built, plus one internal sidecar helper:

| Binary | Package | Purpose |
|---|---|---|
| `hxd` | `apps/hxd` | The daemon: HTTP API, router, search, sandbox manager, session store |
| `hx` | `apps/hx` | The CLI/terminal client |
| `hx-egress-proxy` | `crates/hx-sandbox` | Internal sandbox egress sidecar — not run by hand |

## Build

Debug build of the whole workspace, offline:

```console
$ cargo build --workspace --offline
...
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 3.56s
```

Release build (what `README.md` recommends for running, and what CI/Docker use):

```console
$ cargo build --release --offline
$ ./target/release/hx --version
```

Both binaries land next to each other in `target/<profile>/`. You can also build/run a single
package:

```console
$ cargo build -p hx -p hxd --offline
```

Use `--locked` (as CI does) to fail loudly if `Cargo.lock` is out of date with the manifests:

```console
$ cargo build --workspace --locked
```

Other CI-quality checks, all offline and matching what `.github/workflows/ci.yml` runs:

```console
$ cargo fmt --all --check
$ cargo clippy --workspace --all-targets --locked -- -D warnings
$ cargo check --workspace --all-targets --locked   # MSRV job's check
```

## Test

The full unit suite, offline:

```console
$ cargo test --workspace --offline
```

On this checkout it reports, per target, `N passed; 0 failed` with the live/integration tests
reported as **ignored** (they are `#[ignore]`d and need a real service; see below). To run one
crate:

```console
$ cargo test -p hx-store --offline
$ cargo test -p hx-agent --offline
$ cargo test -p hx-server --offline
```

> **`cargo test --workspace` on its own is green and meaningful, but it is Tier B evidence only.**
> Read `TESTING.md` for the four-tier ledger (A executed / B unit-tested / C compiles /
> D absent). A green local run does **not** mean the live suites passed — the live suites are
> `#[ignore]`d and do not run unless you ask for them.

## Run the daemon and the client

Start from a copy of the example config:

```console
$ cp hx.example.yaml hx.yaml     # then edit
```

Validate the config without serving:

```console
$ hxd --check
2026-..Z  INFO hxd: configuration loaded providers=2 pools=3 roles=4 hosts=1
{ "version": "0.0.1", ... "pools": [ ... ] }
```

Start the daemon (default bind `127.0.0.1:7717`):

```console
$ ./target/debug/hxd --config hx.yaml --bind 127.0.0.1:7717
```

In a second terminal, the client. Most `hx` subcommands read the config directly and work with or
without the daemon:

```console
$ ./target/debug/hx --config hx.yaml doctor        # validate config + environment
$ ./target/debug/hx --config hx.yaml policy       # the approval ladder in force
$ ./target/debug/hx --config hx.yaml sandbox spec untrusted
$ ./target/debug/hx --config hx.yaml pools
```

Send a prompt to the running daemon:

```console
$ ./target/debug/hx --config hx.yaml chat "list the workspace" --workspace /path/to/work
$ ./target/debug/hx --config hx.yaml chat --stream "..." --autonomy yolo --sandbox-profile dev
```

`--stream` renders the run as it happens (turns/tool calls on stderr, reply on stdout);
`--sandbox-profile` confines shell calls to a daemon sandbox profile; `--autonomy` sets
`paranoid|cautious|balanced|trusting|yolo`. Calls above the approval threshold wait and any
client can answer them:

```console
$ ./target/debug/hx approvals          # list questions a run is waiting on
$ ./target/debug/hx approve apr_XXXX --option once --by terminal
```

List/export sessions and verify the audit trail:

```console
$ ./target/debug/hx sessions
$ ./target/debug/hx session <id> --export md
$ ./target/debug/hx audit <session>    # exits 2 on a broken chain
```

You can also build and run directly with `cargo run`:

```console
$ cargo run -p hxd -- --config hx.yaml --bind 127.0.0.1:7717
$ cargo run -p hx -- chat "..." 
```

See `./target/debug/hx --help` and `./target/debug/hxd --help` for full options.

## Live / ignored test suites

These are `#[ignore]`d by default and verify the code against a **real service**. They are the
only tests that reach another process, and are run by `.github/workflows/integration.yml` (and
`canary.yml` for search). Each needs infrastructure you must provide. The counts below are what
this checkout reports.

### WinRM (real Windows host) — `crates/hx-remote/tests/winrm_live.rs`

Tests the hand-rolled NTLMv2 auth + WinRM transport (`crates/hx-remote/src/winrm.rs`) against
a live Windows host. **9 ignored tests.** Needs these env vars:

```
HX_WINRM_HOST        the host to talk to
HX_WINRM_USER        username
HX_WINRM_PASSWORD    password
HX_WINRM_PORT        5985 HTTP, 5986 HTTPS
HX_WINRM_AUTH=basic  use Basic auth instead of NTLM
HX_WINRM_HTTPS=1     https, required with Basic
HX_WINRM_INSECURE=1  accept a self-signed certificate
```

```console
$ HX_WINRM_HOST=<host> HX_WINRM_USER=<user> HX_WINRM_PASSWORD=<pw> \
  cargo test -p hx-remote --test winrm_live --offline -- --ignored --test-threads=1
```

> **NTLM is not the transport to use over plain-HTTP WinRM** — WinRM over NTLM seals requests
> with the session key (which this client does not implement), so an NTLM request over plain HTTP
> is rejected. **Use HTTPS with Basic auth** (`HX_WINRM_AUTH=basic HX_WINRM_HTTPS=1`), which
> is the matrix the suite is verified against; the client refuses Basic over plain HTTP.
> When `HX_WINRM_HOST` is unset the tests bail out (report as passing) rather than failing.

### Docker / sandbox lifecycle — `crates/hx-sandbox/tests/docker_live.rs`

Tests the L1/L2/L3 isolation ladder, egress allowlist, TTL reaper, concurrency cap against a
**real Docker daemon** (gVisor `runsc` registered for the L3 test). **12 ignored tests.**

```console
$ cargo test -p hx-sandbox --test docker_live --offline -- --ignored --test-threads=1
```

`HX_DOCKER_REQUIRE_L3=1` turns a missing-gVisor skip into a hard failure so the L3 claim cannot
quietly stop being tested. The sandbox runs as the workspace's owner (not uid 1000) — see
`TESTING.md` for the hardcoded-uid defect this class of test caught.

### SSH transport — `crates/hx-remote/tests/ssh_live.rs`

Against a real `sshd` (in CI, a throwaway one on a non-default port). **7 ignored tests.**
Uses each test's own trust store in a temp dir, so nothing touches `~/.ssh/known_hosts`:

```console
$ HX_SSH_TEST_HOST=<host> HX_SSH_TEST_USER=<user> HX_SSH_TEST_KEY=~/.ssh/id_ed25519 \
  cargo test -p hx-remote --test ssh_live --offline -- --ignored --test-threads=1
```

### Chat end to end — `crates/hx-server/tests/chat_live.rs`

Drives `POST /v1/chat` with a scripted model against a **real container engine**. **2 ignored
tests.** Needs a running Docker daemon and the sandbox profile configured.

### Search live — `crates/hx-search/tests/search_live.rs`

**4 ignored tests** — a real SearXNG (JSON output enabled) and the real internet. Needs a SearXNG
instance; the canary starts its own:

```console
$ HX_SEARXNG_URL=http://127.0.0.1:8888 HX_SEARCH_EXPECT_RESULTS=searxng \
  cargo test -p hx-search --test search_live --offline -- --ignored --test-threads=1
```

### Remote PTY, remote terminal, remote sandbox

Three more suites that reach another machine, all `#[ignore]`d:

- `crates/hx-remote/tests/pty_live.rs` — **4 ignored tests** against a throwaway `sshd` (run by
  `integration.yml`).
- `crates/hx-server/tests/terminal_remote_live.rs` — **3 ignored tests**: a client POSTs a terminal
  with a `host`, attaches over the WebSocket and types, with every layer real (run by
  `integration.yml`).
- `crates/hx-sandbox/tests/remote_live.rs` — **3 ignored tests**: a real `SshHost` drives
  create → start → exec → stop → remove against a remote Docker daemon. Needs
  `HX_SSH_TEST_HOST`/`HX_SSH_TEST_USER`/`HX_SSH_TEST_KEY` and a host on the private tailnet, so
  **CI cannot run it** — an operator runs it by hand.

### Provider live — `crates/hx-provider/tests/openai_live.rs` and `anthropic_live.rs`

Real model through a real gateway. **4 ignored each.** Needs a key (never echoed):

```console
$ HX_OPENAI_TEST_BASE_URL=... HX_OPENAI_TEST_MODEL=... HX_OPENAI_TEST_KEY=... \
  cargo test -p hx-provider --test openai_live --offline -- --ignored --test-threads=1
```

## Cross-platform notes

- **Unix-only PTY/terminal tests.** `crates/hx-server/tests/terminal_api.rs` opens with
  `#![cfg(unix)]`, so the whole file and the `hx-server` terminal module compile **only on
  Unix**; on Windows they produce **zero tests**, not silently-passing ones. Expect the local
  unit-test count to differ on Windows for this reason.
- **PowerShell 5.1 does not accept `&&`.** The shell tool joins sequential commands per-shell via
  `ShellKind::chain` in `crates/hx-remote/src/host.rs` (POSIX `sh` and `cmd.exe` both use
  `&&`, but `powershell` 5.1 rejects it). Command construction is therefore shell-aware.
- **PTY ioctl constants differ per platform.** In `crates/hx-server/src/terminal.rs`,
  `TIOCSCTTY` and `TIOCSWINSZ` are defined separately for Linux/macOS/other BSD because the
  request numbers are not the same on every Unix.
- **Windows paths are first-class in the capability engine.** `crates/hx-core/src/capability.rs`
  accepts drive-letter (`C:\work`, `C:/work`) and UNC (`\\server\share`) paths as "absolute"
  and normalizes/unifies separators (drive letter uppercased).
- **Host os is a runtime property, not a compile-time one.** `cfg!(windows)` cannot express a
  Linux daemon driving a Windows box; every host is probed on connect. `WinRMHost` is written
  but only exercised by the `#[ignore]`d live suite.

## CI overview

- **`ci.yml`** (on every push/PR): `fmt` (rustfmt check), `clippy` (`--workspace
  --all-targets --locked -D warnings`), `test` (on **ubuntu / macos / windows** with `cargo
  test --workspace --locked`), `msrv` (checks the declared `rust-version` with `cargo check
  --workspace --all-targets --locked`), `deny` (cargo-deny: advisories, licenses, provenance).
- **`integration.yml`**: `docker` (sandbox lifecycle against a real Docker daemon with gVisor —
  pulls `ubuntu:24.04`, installs gVisor) and `ssh` (SSH transport against a throwaway real
  `sshd` on a non-default port). These are the Tier-A suites.
- **`docker.yml`**: builds and pushes the container image (`Dockerfile`).
- **`canary.yml`**: nightly live search canary (starts its own SearXNG).

## Troubleshooting — real failure modes

These are failures documented in the code, `TESTING.md`, or CI config — not speculation.

- **`cargo build` fails to resolve / "no matching package".** The workspace is meant to build
  offline with the vendored registry. If it tries to hit the network, the environment is missing
  the offline/vendored setup. CI always uses `--locked`, which fails loudly if `Cargo.lock` is
  stale relative to the manifests — update the lock rather than building the drift away.
- **MSRV mismatch.** CI's `msrv` job exists because the manifest once claimed an older version
  than a dependency required. If MSRV fails, `ros-version` in `Cargo.toml` is dishonest —
  raise it; do not delete the job. Current MSRV: 1.89.
- **Every L2/L3 sandbox fails to start.** Historically two settings the engine rejects were the
  cause: `security_opt: userns=keep-id` (a podman spelling Docker rejects) and
  `security_opt: seccomp=default` (the daemon expects a profile path or `unconfined`). Both are
  now refused/pinned by tests; if a sandbox refuses to start, check the engine's security_opt
  strings against the test that guards them.
- **Sandbox writes fail with `Permission denied` despite a successful start.** A hardcoded
  sandbox uid of `1000:1000` cannot write a bind-mounted workspace owned by anyone else (e.g. CI
  runs as uid 1001). `SandboxSpec::user` is overridable and `adopt_workspace_owner()` is the
  supported way to set it, so the sandbox runs as whoever owns the mount.
- **An egress allowlist that is (silently) not enforced.** A `network: true` profile plus
  hostnames used to produce a full bridge network. It is now *enforced*: the sandbox rides an
  internal Docker network with no gateway, and the only route out is an `hx-egress-proxy` sidecar
  that matches the `CONNECT` target by name (`crates/hx-sandbox/src/egress.rs`). Only actual
  hostnames / `*.domain` entries can be matched that way, so a CIDR or raw IP is *refused*
  (`SpecError::EgressNotEnforced`) rather than half-enforced.
- **WinRM over plain HTTP with NTLM fails.** See the WinRM note above: NTLM seals are not
  implemented; use HTTPS + Basic.
- **`hx doctor` reports the container engine as `FAIL`.** This is expected behaviour (the daemon
  reports a dead/unreachable engine rather than crashing) — it means Docker isn't reachable on
  this host, which is only needed for the sandbox live tests and for `chat --sandbox-profile`.
- **A known/unknown SSH host is refused.** Host key policy is `Strict`/`Tofu`/`Insecure`
  (default `~/.ssh/known_hosts`), and a changed key is refused with the recorded key and line
  number — a rebuilt server looks like a MITM; remove the offending entry if the change is
  expected. A certificate (`@cert-authority`) is refused, not accepted.
- **`hx chat` prints `session ?` / `0 turn(s)`.** A historical bug where the client read the
  SSE `done`-frame envelope instead of the reply the way `/v1/chat` returns it. Fixed and pinned
  by tests — if you see this again it's a regression in the SSE reader.
- **Tests report an empty placeholder crate as green.** `hx-browser`, `hx-gateway`, `hx-mcp`
  are one-line placeholders; a green suite says nothing about them (`TESTING.md` Tier D). Also,
  a genuinely untested path is marked `#[ignore]` rather than implied as covered — a gap is
  reported as ignored, not as passing.
- **Windows: fewer tests than on Linux.** Expected — the PTY/terminal suites are `#[cfg(unix)]`
  and compile to zero tests on Windows, not silently-passing ones.

For anything deployment-shaped (the Docker socket, the fact that `hxd` has no authentication of
its own, version pinning, checksums), see **`DEPLOY.md`**.

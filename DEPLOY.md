# Deploying hx

Four ways to get it running, in the order most people should consider them.

| | Use when | Needs a toolchain? |
|---|---|---|
| [Install script](#1-install-script-recommended) | You just want the binaries | No |
| [Prebuilt binary](#2-prebuilt-binaries-manual) | You pin versions, or script installs | No |
| [Container](#3-container) | You already run Docker and want it supervised | No — Docker only |
| [From source](#4-from-source) | You're developing or auditing | Rust 1.89+ |

---

## What you actually get

Two binaries:

- **`hxd`** — the daemon. Owns the model router, search backends, sandbox manager and HTTP API. Every front end (CLI, web UI, desktop app, chat connectors) is a client of this process.
- **`hx`** — the CLI. Inspects and validates a running configuration (`hx doctor`, `hx pools`, `hx sandbox profiles`), and drives the daemon (`hx chat "…"`, `hx sessions`, `hx session <id> --export md`).

> **Read this before you deploy.** The harness is a work in progress. `hxd` starts, validates
> your configuration, exposes the HTTP API and reports status — but there is no agent loop yet,
> so `/v1/chat` returns `501` and says so. Credential references (`vault:anthropic/main`) are
> parsed and validated but **not resolved to real secret values**. Nothing today requires
> credentials to run. Full list in [What is deliberately not done yet](README.md#what-is-deliberately-not-done-yet).

---

## 1. Install script (recommended)

```console
$ curl -fsSL https://raw.githubusercontent.com/phantomic12/hx-harness/main/install.sh | sh
```

That detects your platform, downloads the matching build, **verifies its SHA-256 against the
released `SHA256SUMS`**, and installs `hx` and `hxd` to `~/.local/bin`. It never calls `sudo`,
and the only things it writes are the two binaries and a temporary download directory it
cleans up on exit.

Options, via environment:

```console
$ HX_VERSION=0.0.1 sh install.sh                 # pin a version instead of latest
$ HX_INSTALL_DIR=/usr/local/bin sh install.sh    # install elsewhere (may need sudo)
```

If `~/.local/bin` isn't on your `PATH`, the script tells you the line to add.

To uninstall, delete the two files:

```console
$ rm ~/.local/bin/hx ~/.local/bin/hxd
```

**Windows:**

```powershell
> iwr -useb https://raw.githubusercontent.com/phantomic12/hx-harness/main/install.ps1 | iex
```

Installs to `%LOCALAPPDATA%\hx\bin` and adds it to your user `PATH` (no admin rights).
Parameters: `-Version`, `-InstallDir`.

---

## 2. Prebuilt binaries (manual)

Every release publishes static binaries for five targets. Grab what you need from the
[releases page](https://github.com/phantomic12/hx-harness/releases).

| Platform | Target triple | Archive |
|---|---|---|
| Linux x86-64 | `x86_64-unknown-linux-musl` | `.tar.gz` |
| Linux arm64 | `aarch64-unknown-linux-musl` | `.tar.gz` |
| macOS Intel | `x86_64-apple-darwin` | `.tar.gz` |
| macOS Apple Silicon | `aarch64-apple-darwin` | `.tar.gz` |
| Windows x64 | `x86_64-pc-windows-msvc` | `.zip` |

```console
$ curl -fsSLO https://github.com/phantomic12/hx-harness/releases/download/v0.0.1/hx-0.0.1-x86_64-unknown-linux-musl.tar.gz
$ curl -fsSLO https://github.com/phantomic12/hx-harness/releases/download/v0.0.1/SHA256SUMS
$ sha256sum -c --ignore-missing SHA256SUMS
$ tar xzf hx-0.0.1-x86_64-unknown-linux-musl.tar.gz
$ install -m755 hx hxd ~/.local/bin/
```

### Why the Linux builds are musl, not glibc

The Linux binaries are statically linked against musl. A glibc build only runs on a machine
whose glibc is at least as new as the build machine's — which is how you end up with
`GLIBC_2.38 not found` on a slightly older distro, or a binary that won't run in a
`scratch`/`distroless` container at all. A static musl binary has no dynamic loader and no
libc version to satisfy. It runs on Alpine, on distroless, on a ten-year-old CentOS, on
whatever you have.

There are **no runtime dependencies** on any platform. `reqwest` is built with `rustls`
rather than OpenSSL, and SQLite is compiled in (`rusqlite`'s `bundled` feature), so there is
nothing to `apt install` first.

### Verifying a download

`SHA256SUMS` covers every archive in the release. Because it's fetched from the same origin
as the binary, it proves the download wasn't corrupted or truncated — it does **not** prove
provenance. For that, check the build attestation:

```console
$ gh attestation verify hx-0.0.1-x86_64-unknown-linux-musl.tar.gz --repo phantomic12/hx-harness
```

---

## 3. Container

```console
$ docker pull ghcr.io/phantomic12/hx-harness:latest
```

Or with Compose, from a clone — this is the more useful path, because it mounts your config
and the Docker socket:

```console
$ cp hx.example.yaml hx.yaml     # then edit
$ docker compose up -d
$ curl -s localhost:7717/healthz
```

There's a working [`docker-compose.yml`](docker-compose.yml) in the repo root.

### Two things that bite people

**Sandboxes need the Docker socket.** `hxd` drives the Docker API to create sandboxes, so
mount `/var/run/docker.sock`. Without it the daemon still starts and serves the HTTP API —
it just reports the sandbox backend as unavailable. Compose already has the mount.

**Authentication is a bearer token, and it is required off loopback.** The API can read files, run
commands on every configured host, and answer the approval questions an agent run is waiting on, so
`hxd` refuses to start when `--bind` is not a loopback address and no token is configured — a
warning would be a line in a log nobody reads while the port is open. Set `api.token` in the config
(a literal, or a `store:name` reference resolved through `hx-secrets` such as
`"env:HX_API_TOKEN"`), or set `HX_API_TOKEN` in the environment, which is the form a container uses.
On a loopback bind a token is optional but honoured if set. The Compose file binds to `127.0.0.1` on
purpose; for anything else, give it a token:

```console
$ export HX_API_TOKEN=$(head -c 32 /dev/urandom | base64)
$ hxd --config hx.yaml --bind 0.0.0.0:7717        # starts, because a token is configured
$ hxd --config hx.yaml --bind 0.0.0.0:7717        # without HX_API_TOKEN and without api.token:
                                                  # refuses to start, naming both settings
```

`hx` and the embedded web page send the token automatically when it is configured, so nothing else
changes for a client. A tunnel is still the better answer where you have the choice, because the
transport is plain HTTP and the token is a bearer credential with no rotation or expiry:

```console
$ ssh -N -L 7717:127.0.0.1:7717 user@your-host
```

### The socket is the privilege boundary

Mounting the Docker socket grants root-equivalent power over the host. Running the process as
a non-root user *inside* the container while mounting that socket adds friction without
adding security — the socket bypasses the uid entirely. So the image defaults to root, which
is also what makes the socket work without a `--group-add` dance. If you only use the HTTP
API and skip the socket, harden it:

```console
$ docker run --user 65534:65534 -p 127.0.0.1:7717:7717 \
    -v "$PWD/hx.yaml:/etc/hx/hx.yaml:ro" ghcr.io/phantomic12/hx-harness:latest
```

### Building the image yourself

```console
$ docker build -t hx .
```

Self-contained and `--locked`, so it builds the same dependency versions CI tested. The
build takes a few minutes the first time; BuildKit cache mounts make rebuilds much faster.

The image is `linux/amd64` only. On arm64 hosts, prefer the native static binary from the
release workflow over emulation.

---

## 4. From source

Requires Rust 1.89 or newer (the workspace declares `edition = "2021"`, `rust-version = "1.89"`).
The floor is set by `russh`, not by hx itself — see the MSRV job in `.github/workflows/ci.yml`,
which reads the value out of `Cargo.toml` and checks against it so the two cannot disagree.

```console
$ git clone https://github.com/phantomic12/hx-harness
$ cd hx-harness
$ cargo build --release --locked
$ install -m755 target/release/{hx,hxd} ~/.local/bin/
```

Straight from git without cloning, if you have a toolchain:

```console
$ cargo install --git https://github.com/phantomic12/hx-harness --locked hxd
$ cargo install --git https://github.com/phantomic12/hx-harness --locked hx
```

These are **not** on crates.io, so plain `cargo install hxd` will not find them.

One build dependency worth knowing about: `aws-lc-sys` (via rustls) generates and compiles C,
so you need `cmake` and a C compiler. Everything else is pure Rust. On Debian/Ubuntu that's
`apt install build-essential cmake`.

---

## Configuration

`hxd` reads its config from `--config`, or `HX_CONFIG`, defaulting to `./hx.yaml`.

```console
$ cp hx.example.yaml hx.yaml
$ hx doctor                     # validate and report, without serving
$ hxd --config hx.yaml --bind 127.0.0.1:7717
```

| Flag | Env | Default |
|---|---|---|
| `--config` | `HX_CONFIG` | `hx.yaml` |
| `--bind` | `HX_BIND` | `127.0.0.1:7717` |
| `--check` | — | validate config, print a JSON status report, exit |

`--bind` is not only an address. A value that is not loopback (`127.0.0.1`, `localhost`, `::1`)
requires an API token, and the daemon **refuses to start** without one — `--check` included, so a
config that would not be allowed to run says so before anything binds. See
[Authentication](#authentication-is-a-bearer-token-and-it-is-required-off-loopback).

Unknown config keys are rejected, so a typo fails loudly at startup instead of being
silently ignored.

`hx.yaml` holds deployment-specific settings and is gitignored; `hx.example.yaml` is the
tracked template. Keep it that way — don't commit an edited config.

### Credential handling

Config refers to secrets indirectly, by reference:

```yaml
providers:
  anthropic-main:
    kind: anthropic
    base_url: https://api.anthropic.com
    credentials:
      - { id: primary, secret: "vault:anthropic/main", limits: { concurrent: 4 } }
```

Agents ask for a *role*, never a key or a model — that indirection is what lets you rotate a
key or reweight a pool without touching agent definitions. `SecretRef` is parsed and
validated at startup.

**These references are not yet resolved to real values.** The encrypted vault exists in
`hx-secrets` and is unit-tested, but nothing in the daemon holds a provider credential, and there
is no env var that supplies one. Treat credential plumbing as unbuilt rather than as
misconfigured. **The one secret the daemon does hold is the API's own bearer token**
(`api.token`, or `HX_API_TOKEN` — the same resolution path, so `api.token: "env:HX_API_TOKEN"` and
`HX_API_TOKEN` are the same thing by two routes). It is the exception that proves the rule: the
daemon needs it to admit a caller at all, so it cannot be fetched on demand.

---

## Health and status

```console
$ curl -s localhost:7717/healthz                        # exempt from the token, by design
$ curl -s localhost:7717/v1/status | jq .pools          # 401 without the token
$ curl -s -H "Authorization: Bearer $HX_API_TOKEN" localhost:7717/v1/status | jq .pools
```

`/healthz` and `GET /` (the embedded page) are the only two routes that answer without a token.
`/healthz` is exempt because a supervisor — Docker's `HEALTHCHECK`, systemd, a load balancer —
has to be able to ask whether the process is alive without being handed the credential, and it
answers nothing about the daemon's state or data. `/` is exempt because a browser navigation
cannot attach a header, so the page would be unreachable otherwise; it serves a static file, and
every call the page then makes goes to a token-protected route.

The container image has a `HEALTHCHECK` against `/healthz`. `hxd --check` is the
validate-and-exit equivalent for CI, and prints a JSON status report.

`RUST_LOG` controls verbosity (`error`/`warn`/`info`/`debug`/`trace`). Set `log_json: true`
in the config for structured logs.

---

## Upgrading

The install script always fetches the latest release and overwrites in place — re-run it:

```console
$ curl -fsSL https://raw.githubusercontent.com/phantomic12/hx-harness/main/install.sh | sh
```

For containers, `docker compose pull && docker compose up -d`. To pin a version, use the
install script's `HX_VERSION` or a specific image tag (`:0.0`, `:0.0.1`).

## Portability summary

- **No runtime dependencies, with one caveat.** Static musl on Linux, so no libc or shared
  objects to install; nothing extra on macOS or Windows. The exception is TLS trust: as of
  reqwest 0.13 the binaries verify certificates against the **platform trust store** instead
  of roots compiled into the binary, so HTTPS needs a CA bundle on the host
  (`ca-certificates` on Linux). Every mainstream distro ships one — a scratch or distroless
  container does not, which is why the Dockerfile installs it explicitly and this is worth
  remembering if you copy the binaries into a minimal image.
- **No root required** for the client or the daemon. The install script writes to `~/.local/bin` and never escalates.
- **No Docker required** unless you want sandboxes.
- **No credentials required** to run it today.
- **Reproducible.** Every artifact is built with `--locked` against the committed `Cargo.lock`, and the container image builds from the same lockfile.
# syntax=docker/dockerfile:1
#
# hxd in a container.
#
# This image is self-contained: `docker build .` works on a clone with no prebuilt
# artifacts. That's a deliberate choice over downloading a release binary, because a
# Dockerfile that only works inside this project's CI is not much use to anyone else.
#
# Two things worth knowing before you run it:
#
#   1. SANDBOXES NEED THE DOCKER SOCKET. hxd drives the Docker API to create sandboxes.
#      Mount /var/run/docker.sock for that to work. Without it the daemon still starts and
#      serves the HTTP API — it just reports the sandbox backend as unavailable.
#
#   2. THE SOCKET IS THE PRIVILEGE BOUNDARY, NOT THE CONTAINER USER. Mounting the Docker
#      socket grants root-equivalent power over the host. Running the process as an
#      unprivileged user inside the container while mounting that socket adds friction
#      without adding security — the socket bypasses the uid entirely. So this image
#      defaults to root, which is also what makes the socket work without a `--group-add`
#      dance. If you only use the HTTP API (no sandboxes), harden it:
#
#          docker run --user 65534:65534 ...
#
# Base image note: rust:1-bookworm tracks the latest 1.x Rust on Debian 12, matching the
# glibc in the runtime stage below.

# ---------------------------------------------------------------------------
# Stage 1 — build
# ---------------------------------------------------------------------------
FROM rust:1-bookworm AS builder

# aws-lc-sys (pulled in by rustls) generates and compiles C, so it needs cmake and a
# compiler. This is the one dependency that stops a plain `cargo build` from working in
# a bare Rust image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake clang \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Manifests first, then sources. The cache mounts below survive source changes, so
# rebuilding after a code edit reuses every compiled dependency instead of starting over.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps ./apps
COPY hx.example.yaml ./

# --locked keeps the build pinned to the committed Cargo.lock: the image can never
# silently pick up a different dependency version than CI tested.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked --bin hx --bin hxd \
 && mkdir -p /out \
 && cp target/release/hx target/release/hxd /out/

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="hx" \
      org.opencontainers.image.description="hx agent harness daemon — model router, search, sandboxes, approvals" \
      org.opencontainers.image.source="https://github.com/phantomic12/hx-harness" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.documentation="https://github.com/phantomic12/hx-harness/blob/main/DEPLOY.md"

# ca-certificates: the daemon makes TLS calls to model providers.
# curl: only so the HEALTHCHECK below can run — orchestrators need a working one.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/hx  /usr/local/bin/hx
COPY --from=builder /out/hxd /usr/local/bin/hxd

# Ship the example config as a starting point. It contains no credentials — every secret
# is a `vault:` reference — so it is safe to bake in.
COPY hx.example.yaml /etc/hx/hx.yaml

# Defaults that make the container reachable and self-describing. Override HX_BIND if you
# put something in front of it; 0.0.0.0 is required for the port to be visible outside.
#
# 0.0.0.0 also means the API's bearer token is **required**: `hxd` refuses to start when the bind
# address is not loopback and no token is configured, rather than serving an unauthenticated API to
# the network with a warning in the log. Set HX_API_TOKEN (or `api.token` in the config) or this
# image will exit at startup — with a message naming both settings. There is deliberately no
# default token here: a token baked into an image is a token every deployment shares.
ENV HX_CONFIG=/etc/hx/hx.yaml \
    HX_BIND=0.0.0.0:7717 \
    RUST_LOG=info

EXPOSE 7717

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:7717/healthz || exit 1

ENTRYPOINT ["hxd"]

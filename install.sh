#!/bin/sh
#
# hx installer — downloads a prebuilt binary, verifies it, and puts it on your PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/phantomic12/hx-harness/main/install.sh | sh
#
# Environment:
#   HX_VERSION      version to install, without the leading v (default: latest release)
#   HX_INSTALL_DIR  where to put the binaries (default: ~/.local/bin)
#
# Deliberately POSIX sh, not bash: this runs via `sh`, and on Debian and Alpine that is
# dash and busybox ash respectively. Bash-only syntax would break on exactly the systems
# these static binaries are built for.

set -eu

REPO="phantomic12/hx-harness"
BINARIES="hx hxd"

# ---------------------------------------------------------------- output helpers

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$(printf '\033[1m')
    DIM=$(printf '\033[2m')
    RED=$(printf '\033[31m')
    GREEN=$(printf '\033[32m')
    YELLOW=$(printf '\033[33m')
    RESET=$(printf '\033[0m')
else
    BOLD='' DIM='' RED='' GREEN='' YELLOW='' RESET=''
fi

info() { printf '%s\n' "$*"; }
step() { printf '%s==>%s %s\n' "$BOLD" "$RESET" "$*"; }
warn() { printf '%swarning:%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
fail() {
    printf '%serror:%s %s\n' "$RED" "$RESET" "$*" >&2
    exit 1
}

usage() {
    cat <<EOF
hx installer

Usage: install.sh [--help]

Environment:
  HX_VERSION      version to install, without the leading v (default: latest)
  HX_INSTALL_DIR  install destination (default: ~/.local/bin)

Examples:
  sh install.sh                        # latest release, into ~/.local/bin
  HX_VERSION=0.0.1 sh install.sh       # a specific version
  HX_INSTALL_DIR=/usr/local/bin sh install.sh   # system-wide (needs write access)
EOF
}

for arg in "$@"; do
    case "$arg" in
        -h | --help)
            usage
            exit 0
            ;;
        *) fail "unrecognised argument: $arg (try --help)" ;;
    esac
done

# ---------------------------------------------------------------- preflight

command -v uname >/dev/null 2>&1 || fail "uname is required but was not found"

if command -v curl >/dev/null 2>&1; then
    download() { curl -fsSL --retry 3 --retry-delay 1 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
    download() { wget -q -O "$2" "$1"; }
else
    fail "need curl or wget to download the release"
fi

command -v tar >/dev/null 2>&1 || fail "tar is required but was not found"

# sha256sum is coreutils (Linux); shasum is macOS; openssl is the last resort.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    else
        fail "no SHA-256 tool found (need sha256sum, shasum, or openssl)"
    fi
}

# ---------------------------------------------------------------- platform

os=$(uname -s)
arch=$(uname -m)

case "$os" in
    Linux) os_part="unknown-linux-musl" ;;
    Darwin) os_part="apple-darwin" ;;
    *)
        fail "unsupported operating system: $os
This installer covers Linux and macOS. On Windows, use install.ps1:
  irm https://raw.githubusercontent.com/$REPO/main/install.ps1 | iex
Or build from source: cargo build --release"
        ;;
esac

case "$arch" in
    x86_64 | amd64) arch_part="x86_64" ;;
    aarch64 | arm64) arch_part="aarch64" ;;
    *)
        fail "unsupported architecture: $arch
No prebuilt binary for this target. Build from source: cargo build --release"
        ;;
esac

target="${arch_part}-${os_part}"

# ---------------------------------------------------------------- resolve version

if [ -n "${HX_VERSION:-}" ]; then
    version="${HX_VERSION#v}"
    step "Using requested version $version"
else
    step "Looking up the latest release"
    latest_json=$(download "https://api.github.com/repos/$REPO/releases/latest" -) || true
    version=$(printf '%s' "$latest_json" |
        sed -n 's/.*"tag_name":[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)

    if [ -z "$version" ]; then
        fail "could not determine the latest release of $REPO.
There may be no release published yet. Pin one explicitly:
  HX_VERSION=0.0.1 sh install.sh
Or build from source: cargo build --release"
    fi
    step "Latest release is $version"
fi

# ---------------------------------------------------------------- destination

install_dir="${HX_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$install_dir" || fail "could not create $install_dir"
[ -w "$install_dir" ] || fail "$install_dir is not writable
Re-run with a writable directory:
  HX_INSTALL_DIR=\$HOME/.local/bin sh install.sh"

# ---------------------------------------------------------------- download

archive="hx-${version}-${target}.tar.gz"
base_url="https://github.com/$REPO/releases/download/v${version}"

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t hx)
# shellcheck disable=SC2064
trap "rm -rf '$tmp'" EXIT INT TERM

step "Downloading $archive"
download "$base_url/$archive" "$tmp/$archive" ||
    fail "download failed: $base_url/$archive
Check that release v$version has an asset for $target:
  https://github.com/$REPO/releases/tag/v$version"

download "$base_url/SHA256SUMS" "$tmp/SHA256SUMS" ||
    fail "download failed: $base_url/SHA256SUMS"

# ---------------------------------------------------------------- verify
#
# Verify before unpacking, not after. An archive is attacker-controlled input until the
# hash says otherwise, and extraction is where a malicious archive does its work.

step "Verifying checksum"
expected=$(awk -v want="$archive" '
    { f = $2; sub(/^\.\//, "", f); if (f == want) print $1 }
' "$tmp/SHA256SUMS" | head -1)

[ -n "$expected" ] || fail "$archive is not listed in SHA256SUMS of v$version
The release is either incomplete or has been tampered with. Nothing was installed."

actual=$(sha256_of "$tmp/$archive")

if [ "$expected" != "$actual" ]; then
    fail "checksum mismatch for $archive
  expected: $expected
  actual:   $actual
Nothing was installed. Do not run this download."
fi
info "    ${GREEN}ok${RESET} ${DIM}${actual}${RESET}"

# ---------------------------------------------------------------- install

step "Unpacking"
mkdir -p "$tmp/extract"
tar -xzf "$tmp/$archive" -C "$tmp/extract"

# Install each binary to a temp name first, then move into place. A move within the same
# filesystem is atomic, so an interrupted upgrade cannot leave a half-written binary at a
# path a running service might exec.
step "Installing into $install_dir"
for bin in $BINARIES; do
    src="$tmp/extract/$bin"
    [ -f "$src" ] || fail "$bin is missing from $archive (the release is malformed)"

    if [ -w "$install_dir/$bin" ] 2>/dev/null || [ ! -e "$install_dir/$bin" ]; then
        cp "$src" "$install_dir/$bin.new"
        chmod 755 "$install_dir/$bin.new"
        mv -f "$install_dir/$bin.new" "$install_dir/$bin"
    else
        fail "cannot replace $install_dir/$bin (not writable)
Re-run with a writable HX_INSTALL_DIR, or remove the existing file first."
    fi
    info "    ${GREEN}ok${RESET} $install_dir/$bin"
done

# ---------------------------------------------------------------- report

installed_version=$("$install_dir/hx" --version 2>/dev/null || echo "v$version")

printf '\n%s%s installed%s (%s)\n' "$BOLD" "$installed_version" "$RESET" "$target"

case ":${PATH}:" in
    *":${install_dir}:"*)
        printf '\nNext:\n  hx doctor        %s# check your environment%s\n  hxd --help       %s# the daemon%s\n' \
            "$DIM" "$RESET" "$DIM" "$RESET"
        ;;
    *)
        printf '\n%s%s is not on your PATH.%s Add it:\n\n' "$YELLOW" "$install_dir" "$RESET"
        shell_name=$(basename "${SHELL:-sh}")
        case "$shell_name" in
            zsh) printf '  echo '"'"'export PATH="%s:$PATH"'"'" >> ~/.zshrc\n' "$install_dir" ;;
            bash) printf '  echo '"'"'export PATH="%s:$PATH"'"'" >> ~/.bashrc\n' "$install_dir" ;;
            *) printf '  export PATH="%s:$PATH"\n' "$install_dir" ;;
        esac
        printf '\nThen start a new shell, or run the binaries by absolute path:\n'
        printf '  %s/hx doctor\n' "$install_dir"
        ;;
esac

printf '\nDocs: https://github.com/%s/blob/main/DEPLOY.md\n' "$REPO"

#!/bin/sh
#
# scripts/verify-release.sh — end-to-end proof that install.sh can consume a
# release dist/ directory.
#
#   scripts/verify-release.sh <dist-dir> <version>
#
# <dist-dir> is a directory holding the packaged release (archives plus
# SHA256SUMS, plus the .sig blobs when the release was signed). <version> is
# the version to install, without the leading v (e.g. 0.0.1).
#
# No network is involved beyond what the runner already has: the "release" is
# the local directory, served to install.sh as a file:// URL via
# HX_RELEASE_BASE_URL, and install.sh installs into a throwaway --prefix.
#
# What it asserts:
#   1. the good dist/ installs: both binaries land and hx --version prints the
#      expected version;
#   2. one changed byte in a copy of the archive is REJECTED —
#      install.sh exits non-zero;
#   3. with COSIGN_SKIP=1 the checksum path alone still rejects the tampered
#      archive (so skipping the signature layer never skips verification).
#
# Signature-path honesty: when cosign and SHA256SUMS.sig are both present the
# good install must show the signature verification running, and the script
# fails otherwise. When either is missing the script says so explicitly on
# stdout (NOTE, not silence) and verifies the checksum path with COSIGN_SKIP=1.
#
# Deliberately POSIX sh, like install.sh.
#
# Exit status: 0 when every assertion holds, 1 otherwise.

set -eu

fail() {
    printf 'verify-release: error: %s\n' "$*" >&2
    exit 1
}

note() {
    printf 'verify-release: NOTE: %s\n' "$*"
}

pass() {
    printf 'verify-release: ok: %s\n' "$*"
}

usage() {
    cat <<EOF
Usage: verify-release.sh <dist-dir> <version>

  <dist-dir>  local release directory (archives + SHA256SUMS [+ .sig blobs])
  <version>   version to install, without the leading v (e.g. 0.0.1)
EOF
}

[ $# -eq 2 ] || { usage >&2; fail "expected 2 arguments, got $#"; }
dist_dir="$1"
version="${2#v}"
[ -n "$version" ] || fail "version must not be empty"

script_dir=$(cd "$(dirname "$0")" && pwd)
installer="$script_dir/../install.sh"
[ -f "$installer" ] || fail "installer not found at $installer"

[ -d "$dist_dir" ] || fail "dist directory not found: $dist_dir"
dist_abs=$(cd "$dist_dir" && pwd)

# ---------------------------------------------------------------- platform
#
# Same mapping as install.sh: the archive under test is the one for THIS host.

os=$(uname -s)
arch=$(uname -m)

case "$os" in
    Linux) os_part="unknown-linux-musl" ;;
    Darwin) os_part="apple-darwin" ;;
    *) fail "unsupported operating system for verify: $os" ;;
esac

case "$arch" in
    x86_64 | amd64) arch_part="x86_64" ;;
    aarch64 | arm64) arch_part="aarch64" ;;
    *) fail "unsupported architecture for verify: $arch" ;;
esac

target="${arch_part}-${os_part}"
archive="hx-${version}-${target}.tar.gz"

[ -f "$dist_abs/$archive" ] || fail "$archive not found in $dist_abs (have: $(ls "$dist_abs"))"
[ -f "$dist_abs/SHA256SUMS" ] || fail "SHA256SUMS not found in $dist_abs"

# ---------------------------------------------------------------- signature inventory, stated out loud

sig_present=0
cosign_present=0
[ -f "$dist_abs/SHA256SUMS.sig" ] && sig_present=1
command -v cosign >/dev/null 2>&1 && cosign_present=1

if [ "$sig_present" -eq 1 ]; then
    note "SHA256SUMS.sig is present in $dist_abs"
else
    note "no SHA256SUMS.sig in $dist_abs — the signature path is NOT exercised by this run (checksum path only, COSIGN_SKIP=1)"
fi
if [ "$cosign_present" -eq 1 ]; then
    note "cosign is installed — the signature path will be exercised"
else
    note "cosign is NOT installed — the signature path is NOT exercised by this run (checksum path only)"
fi

work=$(mktemp -d 2>/dev/null || mktemp -d -t hx-verify)
# shellcheck disable=SC2064
trap "rm -rf '$work'" EXIT INT TERM

# ---------------------------------------------------------------- 1. the good dist/ installs

good_prefix="$work/good-prefix"
good_log="$work/good.log"
mkdir -p "$good_prefix"

# A missing signature (or a missing cosign) means install.sh would fail-closed
# (cosign present, .sig absent) or warn (cosign absent); neither state proves
# anything about the installer, so verify the checksum path explicitly instead.
good_cosign_skip=0
if [ "$sig_present" -eq 0 ] || [ "$cosign_present" -eq 0 ]; then
    good_cosign_skip=1
fi

printf 'verify-release: installing %s from %s into %s\n' "$archive" "$dist_abs" "$good_prefix"
if [ "$good_cosign_skip" -eq 1 ]; then
    COSIGN_SKIP=1 \
    HX_VERSION="$version" \
    HX_RELEASE_BASE_URL="file://$dist_abs" \
    sh "$installer" --prefix "$good_prefix" >"$good_log" 2>&1 \
        || fail "good dist/ failed to install (log below):\n$(cat "$good_log")"
else
    HX_VERSION="$version" \
    HX_RELEASE_BASE_URL="file://$dist_abs" \
    sh "$installer" --prefix "$good_prefix" >"$good_log" 2>&1 \
        || fail "good dist/ failed to install (log below):\n$(cat "$good_log")"
fi

[ -x "$good_prefix/hx" ] || fail "hx did not land in $good_prefix (log below):\n$(cat "$good_log")"
[ -x "$good_prefix/hxd" ] || fail "hxd did not land in $good_prefix (log below):\n$(cat "$good_log")"
pass "both binaries landed in the prefix"

reported=$("$good_prefix/hx" --version 2>/dev/null) \
    || fail "installed hx --version exited non-zero"
case "$reported" in
    *"$version"*) pass "hx --version prints the expected version ($reported)" ;;
    *) fail "hx --version printed '$reported', expected it to contain '$version'" ;;
esac

# When the signature layer could have run, prove that it did — otherwise this
# check would pass the same way with verification silently skipped. And when
# the good install ran checksum-only, prove the skip was explicit, not silent.
if [ "$good_cosign_skip" -eq 0 ]; then
    grep -F "signature matches the release workflow" "$good_log" >/dev/null \
        || fail "cosign and SHA256SUMS.sig were both present but the install log shows no signature verification (log below):\n$(cat "$good_log")"
    pass "signature verification ran (SHA256SUMS.sig verified via cosign)"
else
    grep -F "signature verification skipped (COSIGN_SKIP=1)" "$good_log" >/dev/null \
        || fail "good install ran checksum-only but never said the signature was skipped (log below):\n$(cat "$good_log")"
    pass "good install says explicitly it ran checksum-only (COSIGN_SKIP=1)"
fi

# ---------------------------------------------------------------- 2. a tampered archive is REJECTED

tamper_dir="$work/tampered"
mkdir -p "$tamper_dir"
cp "$dist_abs/$archive" "$dist_abs/SHA256SUMS" "$tamper_dir/"
if [ "$sig_present" -eq 1 ]; then
    cp "$dist_abs/SHA256SUMS.sig" "$tamper_dir/" 2>/dev/null || true
fi
# Change one byte in the copy, and prove the change landed. The archive now no
# longer matches its line in SHA256SUMS, which install.sh checks before
# unpacking anything.
#
# Appending is used rather than overwriting a byte at a fixed offset:
# `dd if=/dev/zero ... seek=N` is a no-op whenever the byte at N is already
# zero (about 1 in 256 for a gzip stream), which would leave an intact archive
# in the "tampered" directory and turn this assertion into one that cannot
# fail. Appending uses no such fixed offset, so the failure can only mean the
# installer accepted an archive whose checksum does not match.
size_before=$(wc -c < "$tamper_dir/$archive")
printf 'x' >> "$tamper_dir/$archive" || fail "could not tamper the archive copy"
size_after=$(wc -c < "$tamper_dir/$archive")
[ "$size_after" -eq "$((size_before + 1))" ] ||
    fail "the tamper did not change the archive copy ($size_before -> $size_after bytes)"

tamper_prefix="$work/tamper-prefix"
tamper_log="$work/tamper.log"
mkdir -p "$tamper_prefix"

# Same COSIGN mode as the good install: this run must reject the tampered
# archive under the exact conditions the good one was accepted in.
if [ "$good_cosign_skip" -eq 1 ]; then
    COSIGN_SKIP=1 \
    HX_VERSION="$version" \
    HX_RELEASE_BASE_URL="file://$tamper_dir" \
    sh "$installer" --prefix "$tamper_prefix" >"$tamper_log" 2>&1 \
        && fail "tampered archive was ACCEPTED (COSIGN_SKIP=1, log below):\n$(cat "$tamper_log")"
else
    HX_VERSION="$version" \
    HX_RELEASE_BASE_URL="file://$tamper_dir" \
    sh "$installer" --prefix "$tamper_prefix" >"$tamper_log" 2>&1 \
        && fail "tampered archive was ACCEPTED (log below):\n$(cat "$tamper_log")"
fi
grep -Fi "checksum mismatch" "$tamper_log" >/dev/null \
    || grep -Fi "signature" "$tamper_log" >/dev/null \
    || fail "tampered install failed but not for a verification reason (log below):\n$(cat "$tamper_log")"
pass "tampered archive rejected (install.sh exited non-zero on checksum/signature)"

# ---------------------------------------------------------------- 3. COSIGN_SKIP=1 still rejects via the checksum alone

skip_prefix="$work/skip-prefix"
skip_log="$work/skip.log"
mkdir -p "$skip_prefix"

# Plain local path (not a file:// URL) here, so both HX_RELEASE_BASE_URL
# spellings get exercised across the three install runs.
COSIGN_SKIP=1 \
HX_VERSION="$version" \
HX_RELEASE_BASE_URL="$tamper_dir" \
sh "$installer" --prefix "$skip_prefix" >"$skip_log" 2>&1 \
    && fail "tampered archive was ACCEPTED with COSIGN_SKIP=1 (log below):\n$(cat "$skip_log")"
grep -Fi "checksum mismatch" "$skip_log" >/dev/null \
    || fail "COSIGN_SKIP=1 run failed but not on the checksum (log below):\n$(cat "$skip_log")"
pass "COSIGN_SKIP=1 still rejects the tampered archive on the checksum alone"

printf 'verify-release: ALL CHECKS PASSED (version %s, target %s)\n' "$version" "$target"

#!/usr/bin/env bash
# Measure every workspace member's test count mechanically, from cargo's own output.
#
# Why this exists: TESTING.md's per-crate table is the file's evidence, and it drifted because
# the numbers were carried forward by hand instead of re-run. This script re-measures every
# member from the tool, keeps each crate's raw output next to the number so the parse can be
# checked, and prints the workspace total as the sum it actually is.
#
# Usage
#   scripts/measure-test-counts.sh                    # every workspace member, one cargo run each
#   scripts/measure-test-counts.sh hx-server hx-core  # named crates only
#   LOGDIR=/tmp/counts CARGO_TEST_ARGS='--locked' scripts/measure-test-counts.sh
#   PARSE_ONLY=1 LOGDIR=/tmp/counts scripts/measure-test-counts.sh   # re-sum logs already on disk
#
# What is counted
#   `cargo test -p <crate>` runs unit tests, every `tests/*.rs` integration binary, bin targets
#   and doc-tests. Each of those prints one
#       test result: ok. N passed; M failed; K ignored; ...
#   line; the script sums N, M and K across all of them, so `passed` is every test that ran
#   green in any target, `failed` every red one, and `ignored` the `#[ignore]`d live suites
#   (libtest excludes those from `passed`). Nothing is inferred from filenames or from reading
#   TESTING.md. PARSE_ONLY=1 re-derives the table from the logs of an earlier run, so the parse
#   can be corrected without re-running the suite.
#
# The raw log for each crate is $LOGDIR/<crate>.log. Host and toolchain matter — see TESTING.md
# on the chromium-gated hx-browser suite — so record which host produced the numbers.
set -uo pipefail

cd "$(dirname "$0")/.."

LOGDIR="${LOGDIR:-/tmp/hx-test-counts}"
ARGS="${CARGO_TEST_ARGS:---locked --no-fail-fast}"
mkdir -p "$LOGDIR"

# Sum the libtest summary lines of one log. Loops to NF rather than a fixed field count, because
# the summary is `test result: ok. N passed; M failed; K ignored; L measured; ...` and a bound
# that stops short of the `ignored;` field silently reports zero ignored tests.
count_log() {
  awk '
    /^test result: / {
      for (n = 2; n <= NF; n++) {
        if ($n == "passed;")  p += $(n-1)
        if ($n == "failed;")  f += $(n-1)
        if ($n == "ignored;") i += $(n-1)
      }
    }
    END { printf "%d %d %d\n", p, f, i }
  ' "$1"
}

if [ "$#" -gt 0 ]; then
  crates=("$@")
else
  # `cargo metadata` prints one JSON line; python3 pulls the package names out of it.
  mapfile -t crates < <(cargo metadata --no-deps --format-version 1 \
    | python3 -c 'import json,sys; [print(p["name"]) for p in json.load(sys.stdin)["packages"]]')
fi

{
  printf '# host: %s\n' "$(hostname)"
  printf '# rustc: %s\n' "$(rustc --version)"
  printf '# cargo test args: %s\n' "$ARGS"
  printf '# chromium at /usr/lib/chromium/chromium: %s\n' "$([ -x /usr/lib/chromium/chromium ] && echo present || echo absent)"
  [ "${PARSE_ONLY:-0}" = 1 ] && printf '# parsed from existing logs in %s\n' "$LOGDIR"
  echo
  printf '%-14s %8s %8s %8s\n' crate passed failed ignored
} | tee "$LOGDIR/SUMMARY.txt"

sum_p=0 sum_f=0 sum_i=0
for c in "${crates[@]}"; do
  if [ "${PARSE_ONLY:-0}" != 1 ]; then
    # shellcheck disable=SC2086
    cargo test -p "$c" $ARGS > "$LOGDIR/$c.log" 2>&1
  fi
  read -r p f i < <(count_log "$LOGDIR/$c.log")
  sum_p=$((sum_p + p)); sum_f=$((sum_f + f)); sum_i=$((sum_i + i))
  printf '%-14s %8d %8d %8d\n' "$c" "$p" "$f" "$i" | tee -a "$LOGDIR/SUMMARY.txt"
done
printf '%-14s %8d %8d %8d\n' TOTAL "$sum_p" "$sum_f" "$sum_i" | tee -a "$LOGDIR/SUMMARY.txt"

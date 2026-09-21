#!/usr/bin/env bash
# Run a cargo gate for a local worktree on a remote build host.
#
# Why this exists: bigwhite is memory-tight, and garlic-clove is idle with a warm target cache.
# This script ships only the *source* (no .git/, no local target/) to a fresh remote directory
# and builds with CARGO_TARGET_DIR pointing at the host's warm target cache.
#
# It avoids `rsync --delete` (which trips approval gates as a destructive pattern) by using
# a fresh timestamped destination and `tar` over ssh.
#
#   scripts/remote-gate.sh <worktree-path> '<cargo args>' [host]
set -euo pipefail
WT="${1:?usage: remote-gate.sh <worktree> "<cargo args>" [host]}"
CARGO_ARGS="${2:?missing cargo args}"
HOST="${3:-yoav@garlic-clove}"
NAME="$(basename "$WT")"
# fresh directory on the remote, with a human-readable but conflict-free path
TS="$(date +%Y%m%d%H%M%S)"
DEST="hx-gate/${TS}-${NAME}-${$}"
WARM_TARGET="$HOME/projects/hx-harness/target"

echo "==> $NAME -> $HOST:$DEST (target cache: $WARM_TARGET)"

# Ship source. Excludes .git/ and target/ to keep the transfer small.
# Using tar over ssh is allowed where rsync --delete is often blocked as a destructive op.
(cd "$WT" && tar czf - --exclude='.git' --exclude='target' .) \
  | ssh -o BatchMode=yes -o StrictHostKeyChecking=no "$HOST" \
    "mkdir -p $DEST && cd $DEST && tar xzf - && echo source_extracted"

# Run cargo with the warm shared target dir. Cargo will lock the target dir; concurrent runs
# from other lanes serialize correctly, so a shared cache is safe.
ssh -o BatchMode=yes -o StrictHostKeyChecking=no "$HOST" \
  "export PATH=\$HOME/.cargo/bin:\$PATH; cd \\$HOME/$DEST && CARGO_TARGET_DIR=$WARM_TARGET cargo $CARGO_ARGS"

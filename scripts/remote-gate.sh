#!/usr/bin/env bash
# Run a cargo gate for a local worktree on a remote build host.
#
# Why this exists: bigwhite is at 28/31 GiB swap with 13 GiB available, and every worktree costs a
# cold 15-crate build. garlic-clove is idle (16 cores, 30 GiB free, load 0.10), so the heavy
# full-workspace runs go there instead of competing for bigwhite's RAM.
#
# The source is rsynced, not cloned: the worktree branches are local-only and never pushed, so a
# remote `git clone` could not see them. `target/` is excluded (the remote keeps its own, so repeat
# runs are incremental) and `.git/` is excluded because cargo does not need it and it is the bulk of
# the transfer.
#
#   scripts/remote-gate.sh <worktree-path> '<cargo args>' [host]
set -euo pipefail
WT="${1:?usage: remote-gate.sh <worktree> \"<cargo args>\" [host]}"
CARGO_ARGS="${2:?missing cargo args}"
HOST="${3:-yoav@100.67.232.8}"
NAME="$(basename "$WT")"
DEST="hx-gate/$NAME"

echo "==> $NAME -> $HOST:$DEST"
rsync -a --delete --exclude 'target/' --exclude '.git/' "$WT/" "$HOST:$DEST/"
ssh -o BatchMode=yes -o StrictHostKeyChecking=no "$HOST" \
  "export PATH=\$HOME/.cargo/bin:\$PATH; cd \$HOME/$DEST && echo \"host: \$(hostname), nproc \$(nproc), load \$(cut -d' ' -f1 /proc/loadavg)\" && cargo $CARGO_ARGS"

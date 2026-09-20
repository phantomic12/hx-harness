#!/usr/bin/env bash
# Independent verification of the two IDLE fix branches, from the parent.
#
# Only branches with no lane running in them: rsyncing a worktree a lane is still writing to would
# ship a moving target and the result would mean nothing.
#
# Children cannot run this at all - their ssh/rsync is denied by the approval policy
# (`delegation.subagent_auto_approve` is false and nobody is there to approve), which is why the
# lane briefs tell children to gate locally and this script exists on the parent side.
set -u
H="yoav@100.67.232.8"
for spec in "fix-cache-token:hx-search" "fix-browser-env:hx-browser"; do
  name="${spec%%:*}"; crate="${spec#*:}"
  echo "########## $name  ->  cargo test -p $crate"
  rsync -a --delete --exclude 'target/' --exclude '.git/' \
    "/home/yoav/projects/hx-wt/$name/" "$H:hx-gate/$name/" || { echo "  rsync FAILED"; continue; }
  ssh -o BatchMode=yes -o StrictHostKeyChecking=no "$H" \
    "export PATH=\$HOME/.cargo/bin:\$PATH; cd \$HOME/hx-gate/$name && \
     echo '  --- fmt:'; cargo fmt --all --check 2>&1 | head -5; \
     echo '  --- clippy:'; cargo clippy -p $crate --all-targets --offline -- -D warnings 2>&1 | grep -cE '^(error|warning)' | sed 's/^/    diagnostics: /'; \
     echo '  --- test:'; cargo test -p $crate --offline -j 8 2>&1 | grep -E 'test result:|^error|FAILED' | head -12"
done
echo "########## done"

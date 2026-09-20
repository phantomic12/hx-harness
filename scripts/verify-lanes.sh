#!/usr/bin/env bash
# Verify the three finished lanes on garlic-clove, from the parent.
#
# Children cannot run this: their ssh/rsync commands are denied by the approval policy
# (delegation.subagent_auto_approve is false and nobody is there to approve), which is why two
# lanes reported "rsync denied" and one halted to ask. The parent can, so the offload lives here
# and the lane briefs should NOT tell children to ssh anywhere.
set -u
H="yoav@100.67.232.8"
for spec in "research-task:hx-search:--offline" "mcp-http:hx-mcp:--offline" "m7-desktop:hx-desktop:"; do
  name="${spec%%:*}"; rest="${spec#*:}"; crate="${rest%%:*}"; off="${rest#*:}"
  echo "########## $name  ->  cargo test -p $crate $off"
  rsync -a --delete --exclude 'target/' --exclude '.git/' \
    "/home/yoav/projects/hx-wt/$name/" "$H:hx-gate/$name/" || { echo "  rsync FAILED"; continue; }
  ssh -o BatchMode=yes -o StrictHostKeyChecking=no "$H" \
    "export PATH=\$HOME/.cargo/bin:\$PATH; cd \$HOME/hx-gate/$name && cargo test -p $crate $off -j 8 2>&1 | grep -E 'test result:|^error|error\\[|^warning|Compiling hx' | tail -22"
  echo "  (exit $?)"
done
echo "########## done"

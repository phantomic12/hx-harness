#!/usr/bin/env bash
# Prune git worktrees whose branches are already merged into main.
#
# Why this exists: /home/yoav/projects/hx-wt/ accumulates one worktree per
# finished lane. Once the lane's branch is merged, the worktree is just disk.
# This script removes the merged ones and deletes their branches, while
# refusing to touch anything that still holds uncommitted or unmerged work.
#
# Safety rules (all enforced, no overrides):
#   - Default is --dry-run: print what WOULD be removed, change nothing.
#   - Never touches the main repo worktree or detached-HEAD worktrees.
#   - Skips dirty worktrees (git status --porcelain non-empty) — reports them.
#   - Skips branches that are not an ancestor of main — reports them as unmerged.
#   - Skips branches named via --keep (repeatable) — reports them.
#   - Deletes branches with -d only; if git refuses, the branch is left alone
#     and reported rather than forced with -D.
#
# Usage:
#   scripts/prune-merged-worktrees.sh [--dry-run] [--apply]
#       [--keep BRANCH]... [--skip-recent HOURS] [--main BRANCH]
#
#   --skip-recent HOURS  also skip worktrees whose directory was modified
#       within the last HOURS hours (an agent may be working there now).
set -euo pipefail

MODE="dry-run"
MAIN="main"
SKIP_RECENT_HOURS=""
KEEPS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) MODE="dry-run"; shift ;;
    --apply) MODE="apply"; shift ;;
    --keep) KEEPS+=("${2:?--keep needs a branch name}"); shift 2 ;;
    --keep=*) KEEPS+=("${1#--keep=}"); shift ;;
    --skip-recent) SKIP_RECENT_HOURS="${2:?--skip-recent needs hours}"; shift 2 ;;
    --skip-recent=*) SKIP_RECENT_HOURS="${1#--skip-recent=}"; shift ;;
    --main) MAIN="${2:?--main needs a branch name}"; shift 2 ;;
    --main=*) MAIN="${1#--main=}"; shift ;;
    -h|--help)
      sed -n '3,16p' "$0" | sed 's/^# \?//'
      echo "Usage: $(basename "$0") [--dry-run] [--apply] [--keep BRANCH]... [--skip-recent HOURS] [--main BRANCH]"
      exit 0 ;;
    *) echo "error: unknown flag: $1" >&2; exit 2 ;;
  esac
done

# Operate from the top level of this repo so `git worktree list` covers
# every worktree (they all share one git dir).
REPO_TOP="$(git rev-parse --show-toplevel)"
cd "$REPO_TOP"
# The main worktree is the one holding the common git dir. NOTE: in a linked
# worktree `git rev-parse --show-toplevel` returns the *linked* path, so it
# must NOT be used to find the main worktree.
MAIN_ABS="$(dirname "$(git rev-parse --git-common-dir)")"
MAIN_ABS="$(cd "$MAIN_ABS" && pwd -P)"

in_keep_list() {
  local b="$1" k
  for k in ${KEEPS[@]+"${KEEPS[@]}"}; do
    [[ "$k" == "$b" ]] && return 0
  done
  return 1
}

echo "==> mode: $MODE (main: $MAIN)"
echo "==> filesystem before:"
df -h "$MAIN_ABS" | cat

REMOVED=()
SKIPPED=()

# Parse `git worktree list --porcelain`: records are
#   worktree <path>\n[branch refs/heads/<name>|detached]\n...
WT_PATH=""
WT_BRANCH=""
flush_worktree() {
  [[ -z "$WT_PATH" ]] && return 0
  local path="$WT_PATH" branch="$WT_BRANCH"
  WT_PATH=""; WT_BRANCH=""

  # Never touch the main worktree.
  if [[ "$(cd "$path" 2>/dev/null && pwd -P)" == "$MAIN_ABS" ]]; then
    SKIPPED+=("$path [main worktree — never touched]")
    return 0
  fi
  # Never touch detached-HEAD worktrees.
  if [[ -z "$branch" ]]; then
    SKIPPED+=("$path [detached HEAD — never touched]")
    return 0
  fi
  # Never touch the --keep list.
  if in_keep_list "$branch"; then
    SKIPPED+=("$path [$branch — on --keep list]")
    return 0
  fi
  # Optionally skip recently-modified worktrees (someone may be working there).
  if [[ -n "$SKIP_RECENT_HOURS" ]]; then
    if find "$path" -maxdepth 0 -mmin "-$(( SKIP_RECENT_HOURS * 60 ))" -print -quit 2>/dev/null | grep -q .; then
      SKIPPED+=("$path [$branch — modified in the last ${SKIP_RECENT_HOURS}h]")
      return 0
    fi
  fi
  # Never discard uncommitted work.
  local dirty
  dirty="$(git -C "$path" status --porcelain 2>&1)" || {
    SKIPPED+=("$path [$branch — status check failed, left alone: $dirty]")
    return 0
  }
  if [[ -n "$dirty" ]]; then
    SKIPPED+=("$path [$branch — dirty, uncommitted changes]")
    return 0
  fi
  # Only branches fully merged into main are eligible.
  if ! git merge-base --is-ancestor "$branch" "$MAIN" 2>/dev/null; then
    SKIPPED+=("$path [$branch — NOT merged into $MAIN]")
    return 0
  fi

  if [[ "$MODE" == "dry-run" ]]; then
    REMOVED+=("$path [$branch — would remove worktree and delete branch]")
    return 0
  fi
  # Apply: remove the worktree, then delete the branch (safe -d only).
  if git worktree remove --force -- "$path"; then
    if git branch -d "$branch" 2>/dev/null; then
      REMOVED+=("$path [$branch — worktree removed, branch deleted]")
    else
      SKIPPED+=("$branch [worktree removed but branch -d refused — left alone, use -D manually if intended]")
      REMOVED+=("$path [$branch — worktree removed, branch KEPT (git refused -d)]")
    fi
  else
    SKIPPED+=("$path [$branch — worktree remove failed, left alone]")
  fi
}

while IFS= read -r line; do
  case "$line" in
    worktree\ *)
      # A new record starts: flush the previous one.
      flush_worktree
      WT_PATH="${line#worktree }"
      ;;
    branch\ refs/heads/*)
      WT_BRANCH="${line#branch refs/heads/}"
      ;;
    "") flush_worktree ;;
  esac
done < <(git worktree list --porcelain)
flush_worktree

echo
echo "==> REMOVED / WOULD-REMOVE (${#REMOVED[@]}):"
for r in ${REMOVED[@]+"${REMOVED[@]}"}; do echo "  - $r"; done
echo
echo "==> SKIPPED (${#SKIPPED[@]}):"
for s in ${SKIPPED[@]+"${SKIPPED[@]}"}; do echo "  - $s"; done
echo
if [[ "$MODE" == "apply" ]]; then
  git worktree prune
  echo "==> filesystem after:"
  df -h "$MAIN_ABS" | cat
else
  echo "==> dry-run: nothing changed. Re-run with --apply to perform removals."
fi

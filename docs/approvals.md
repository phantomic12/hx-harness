# Allowlists, from least to most risky

`ARCHITECTURE.md` §3.11 explains how an action is *classified*. This is the other half: given a
classification, what is allowed without asking, what always asks, what can never be answered, and what
a "yes, don't ask again" is allowed to mean. The question it exists to answer is the operator's, not
the engineer's: *what can this thing do to my machine while I am not looking?*

Prior art worth copying, and what each teaches:

| System | Its shape | What is worth taking |
|---|---|---|
| Claude Code (`/permissions`) | `allow` / `ask` / `deny` rule lists per tool, evaluated **deny → ask → allow**; four permission modes; a built-in read-only Bash set and preapproved documentation domains; `Bash(git diff:*)`, `WebFetch(domain:…)` specifiers | The three outcomes and their order; shipped defaults rather than "write your own"; a *tiered* answer to "don't ask again" — a Bash command is remembered permanently per repository, a file edit only until the session ends, a domain forever |
| OpenCode (`permission`) | `allow` / `ask` / `deny` per tool, with granular object syntax (`bash: { "git push": "ask", "*": "allow" }`), wildcards, `~` expansion | Per-command granularity in config, per-agent overrides, an explicit "what does *ask* do" definition |
| Codex CLI | `approval_policy` (untrusted / on-failure / on-request / never) × `sandbox_mode` (read-only / workspace-write / full access) | Risk and *confinement* are two axes, not one: the same command is a different proposition inside a sandbox |
| Claude Code sandbox, Codex sandbox | the confinement axis | An action may be auto-allowed *because* it is confined, and confirmed when it is not |

## 1. The ladder

`RiskClass` already orders these (`Read < Mutate < External < Destructive < Privileged`). Here is what
each tier should mean to an allowlist, least risky first:

| # | Tier | Examples | Default | May a "don't ask again" outlive the chat? |
|---|---|---|---|---|
| 0 | **Observe** — `Read` | `ls`, `cat`, `rg`, `git status/log/diff/show`, `wc`, `file`, `du`, `docker ps`, web search, reading any file the token covers | **allowed** at every level above `paranoid`, no prompt | N/A — nothing to remember |
| 1 | **Local, reversible** — `Mutate` | `write_file`/`patch` **inside the workspace**, `mkdir`, `touch`, `cp` within the workspace, `git add/commit`, formatters, `npm install` into the project | **allowed** at `balanced` and above | Yes, but by **command signature** — `git add` covers `git add -A`, `git commit` never covers `git commit --amend` on pushed history |
| 2 | **Leaves the machine** — `External` | `curl`, `ssh`, `scp`, `git push`, `npm publish`, any fetch whose destination is not local | **asks** at `balanced`; allowed at `trusting` | **No.** Chat-scoped at most: `git push origin main` is not `git push origin main --tags` |
| 3 | **Cannot be undone** — `Destructive` | `rm -rf`, `truncate`, `dd`, `git reset --hard`, `git clean -f`, `git branch -D`, force-push, `DROP TABLE`, `curl … \| sh` | **asks** at every level including `trusting`; allowed at `yolo` only as a *once* answer | **Never.** A once-answer, and the request must name its targets (see §3) |
| 4 | **Privilege or credentials** — `Privileged` | `sudo …` (escalates whatever it wraps), `mount`, `chmod -R` on system paths, `systemctl`, `gpg`/`op`/`bw`, reading a vault file | **asks** at every level; `ceiling: destructive` (recommended default) means even `yolo` asks | **Never**, under any policy |

Two absolutes fall out of the table, and they are the ones worth defending:

- **A deny rule and the ceiling sit above the dial.** A per-request `--autonomy yolo` can lower the
  level. It can never remove a `deny` rule or raise the `ceiling`. That is what makes a per-request
  grant worth offering at all.
- **`Destructive` and `Privileged` are never remembered.** Not per repository, not per chat. The cost
  of the extra prompt is a second; the cost of a remembered `rm -rf` is the thing you forgot about.

## 2. The three outcomes, in one order

`ApprovalPolicy` today has `allow` and `deny`; the level threshold supplies the implicit *ask*. That
loses one thing the prior art has: the ability to force a prompt for something that is *below* the
threshold — a project that wants to look at every `write_file` even at `trusting`, or an operator who
wants a prompt for `shell` regardless of its class because the classifier might be wrong about a
command it has never seen.

So: **`deny` → `ask` → `allow` → level threshold**, in that order, matching both Claude Code and
OpenCode. `ask` and `allow` are both subject to the ceiling: a rule cannot allow what the ceiling
forbids, and an `ask` rule cannot be answered by an allow rule that comes after it.

```yaml
agent:
  approval:
    level: balanced
    ceiling: destructive          # sudo always asks, even under --autonomy yolo
    unattended_budget: 25         # check in after 25 consecutive auto-approvals
    deny:
      - { tool: shell, command: "*rm -rf /*",   note: "recursive delete from the root" }
      - { tool: shell, command: "*curl * | sh", note: "remote code execution" }
      - { tool: shell, command: "*rm -rf $*",   note: "the target set cannot be enumerated" }
    ask:
      - { tool: write_file, note: "this project reviews every write" }
      - { tool: shell, risk: destructive, note: "explain the blast radius first" }
    allow:
      - { tool: shell, command: "git status*" }        # a signature-shaped allow
      - { tool: shell, command: "git log*" }
      - { tool: shell, command: "rg *" }
      - { tool: read_file, command: "/home/yoav/projects/hx-harness/*" }   # path-scoped
```

Rules match `tool` (glob) and, optionally, `command` — which for filesystem tools is the **resolved
absolute path**, now that `ToolContext::resolve` exists. That is what makes a path-scoped allow
meaningful rather than decorative: `read_file` under this workspace, never under `/etc`.

## 3. The delete rule: say what will be gone

The user-facing complaint this section exists for: *"always clarify what you delete."* An approval
prompt that says `<command> rm -rf build` is not a prompt — it does not say what is inside `build`, and
"the agent told me it was cleaning up" is how a directory nobody backed up disappears. A destructive
request must therefore carry:

1. **The resolved targets**, each one absolute: `/home/yoav/projects/x/build`, not `build`.
2. **What each target is and how big**: directory, 1 342 entries, 480 MB — with a **bounded** count, so
   a scan of `/home` cannot become the prompt.
3. **The plain sentence**: "This cannot be undone." Not an icon, not a colour.
4. **What is *not* covered**: if a glob or a variable is involved, the prompt says the target set is
   not enumerable — and the request is refused rather than guessed at (see below).

And the tooling should make the destructive case rare, in this order:

- **Prefer reversible.** Ship a `delete` tool that moves to the XDG trash (or `git rm` for tracked
  files) instead of a shell `rm`. `rm` remains available through `shell`, classified, promptable.
- **Refuse wildcards and variables on irreversible operations.** `rm -rf $DIR` and `rm -rf build*`
  cannot be answered honestly, because the person answering cannot know what they cover. The refusal
  says so and offers the enumerable form. A `deny` rule matching `*$*` and `*\**` on destructive
  classifications is a reasonable default to ship.
- **Prefer the dry run.** Where a command has one, ask for it first: `git clean -n` before `git clean
  -f`, `rsync --dry-run`, `terraform plan`. The classifier already knows `-n`/`--dry-run`; a request
  that contains one is `Read`, and that is a real convenience: exploring a destructive operation is
  free and performing it is not.
- **Refuse the specific catastrophe set outright**, as a shipped `deny` list rather than a config
  suggestion: `rm -rf /`, `rm -rf ~`, `rm -rf $HOME`, `rm -rf .` from a workspace root, `dd` to a
  block device, `mkfs`, `> /dev/sd*`, `chmod -R 777 /`, `curl … | sh`, `git push --force` to a shared
  branch, `DROP DATABASE`. These are not "ask" — the answer is no, and saying so in advance is what
  makes an unattended run safe by construction rather than by attention.

## 4. Confinement is a second axis

The same command is not the same action on the host and inside an L2 sandbox with only the workspace
mounted. The classifier runs before a sandbox is chosen, so `ActionRequest` should carry the
*confinement* of the call, and rules should be able to require it:

```yaml
allow:
  - { tool: shell, command: "npm test", confined: true }    # fine in the sandbox
ask:
  - { tool: shell, command: "npm test", confined: false }   # on the host, run it by me
```

That is Codex's insight applied to hx's existing isolation ladder: allow-by-confinement lets an agent
run untrusted build steps unattended, which is the main reason to have a sandbox at all.

**As built.** `ActionRequest` carries a `Confinement` (`host` | `sandbox`), `Rule` may require one
(`confined: bool`, absent means *either*), and the loop fills the field from the **tool** before the
decision — `Tool::confinement(args, ctx)` defaults to the host, so a tool that has not thought about it
cannot claim a boundary, and `shell` is the one tool that answers from the context it was given.

The boundary itself is `hx_tools::tool::SandboxExec`: a trait, so the tool layer never links a container
engine, returning the same `hx_remote::ExecOutput` a transport returns — a sandbox is a place with its own
shell and its own paths, so both paths share one output type and one reporter. `hx-server::sandbox`'s
`SandboxFor` implements it over a live `SandboxManager`, translating a host path into its mounted
equivalent and refusing a path outside the mount **rather than passing it through**, because a command
that resolved against the sandbox's own root would succeed and touch the wrong filesystem.

Two properties are the whole point, and both are asserted:

- **A boundary that cannot be entered does not become the host.** `ShellTool` reports a failed call and
  says so; nothing falls back. Otherwise the answer §4 gave before the command ran is false by the time
  it runs, and every rule written to require confinement quietly means nothing.
- **The prompt says which one it is.** A confined request renders `where: inside a sandbox, not on the
  host`, above the `after:` line — it qualifies what follows, because a promise about what a sandbox will
  do is not a promise about the machine.

Not built yet: a *request* that asks for confinement. `SandboxFor` is opened per checkout through
`SandboxCache` (keyed on profile + host workspace path, so two runs in one checkout share a container and
two checkouts never do), and the manager's TTL reaper plus a drop-guard own its lifetime — but nothing in
the chat request path reaches for it yet. The wiring is the next step, and it is deliberately small: the
mechanism above is what it needed.

## 5. Where "remember" lives, and for how long

`RememberedDecision` today is `Allow`/`Deny` with `AllowOnce`/`AllowForChat` decision variants. The tier
decides which of those a client may even offer — the prompt should not show a button the policy will
ignore:

| Tier | `once` | `for this chat` | `for this project` | `for this machine` |
|---|---|---|---|---|
| Observe | n/a | n/a | n/a | n/a |
| Local, reversible | yes | yes | **yes** (command signature, written to `.hx/allow.toml`) | no |
| Leaves the machine | yes | **yes** | no | no |
| Cannot be undone | **yes** | no | no | no |
| Privilege | yes | no | no | no |

Project-scoped grants are files in the repository (reviewable, diffable, and shareable) rather than
rows in a database — and they apply to one repository, matching what Claude Code learned the hard way
(an approval in a worktree must not become an approval everywhere).

## 6. Being able to see it

`hx policy` prints the effective ladder for the current configuration: for each risk class, whether it
runs free or asks; whether a run is capped by the ceiling or by a check-in budget; the rules as a
numbered list in the order they are checked (`deny` first, because that is the order the session uses);
how many of them are the shipped catastrophe set; and which options a prompt may offer at which tier.
Prior art has a `/permissions` panel for the same reason: a policy nobody can read is a policy nobody
will check, and the first question after "why did it do that?" is "what did I allow?".

It reads the *configuration*, and says so at the bottom of its own output: a chat's `--autonomy` level
and an `allow for this chat` answer are live state it cannot see, and `hx approvals` is the command for
what is waiting right now. It also cannot tell you what the classifier will call a given command, which
is why the tiers are shown by risk class rather than by example — a renderer that guessed would be
wrong in exactly the case a reader cares about.

It is what would have caught the two floor defects §7 records: the report prints the shipped rules
individually, so `rm -rf /tmp/build` being refused by a pattern meant for the root is visible in one
line rather than in a test nobody ran.

## 7. What is missing in the code, and in what order

| Step | Change | Where | Size | State |
|---|---|---|---|---|
| 1 | `ask: Vec<Rule>` and the `deny → ask → allow` precedence | `hx-core/src/approval.rs`, `ApprovalSession::decide` | small, ~20 tests | **done** |
| 2 | Shipped default `deny` set for the catastrophe list (§3) | `ApprovalPolicy::default`, `hx.example.yaml` | small | **done** |
| 3 | Remember-scoping by tier: which options a request may offer | `hx-core/src/approval.rs` + the event that renders the prompt | medium | **done** |
| 4 | `delete` tool that trashes, and the enumerable-target requirement for `Destructive` | `hx-tools`, `hx-core` prompt text | medium | **done** |
| 5 | `confined` on `ActionRequest` and in rules | `hx-core`, `hx-agent` (sandbox-aware dispatch) | medium | **done** |
| 6 | `hx policy` renderer | `apps/hx` | small | **done** |

Steps 1–2 are the upgrade that makes an *unattended* daemon useful: today the choice is prompt-for-
everything or `--autonomy yolo`, and an allowlist is what splits that into a real third option. Steps
3–4 are the safety half, and 4 is the one the user asked for by name.

### What step 4 turned out to be

Three pieces, because "say what will be gone" is a claim about the filesystem and none of the layers
above the filesystem can make it:

- **`Tool::targets` and `Tool::undo`** (`hx-tools/src/tool.rs`) — the tool answers for itself, since it
  is the only layer that knows what its arguments mean. Both default to the honest nothing: no targets
  (so no target section, rather than an invented one) and no undo sentence (so the prompt assumes the
  worst). `hx-tools/src/trash.rs` is the one tool that answers both today.
- **The measurement** (`hx-agent/src/agent.rs`, phase 3) — after the capability check and before the
  prompt, because a call this agent may not make is not worth a directory walk, and a number measured
  before the question is a number that describes the tree as it is when the question is asked. It is a
  lower bound: a partial walk says "at least N", and a failed walk degrades the prompt rather than
  failing the call.
- **`delete`** (`hx-tools/src/trash.rs`, `hx-remote`'s `Host::rename`) — move to the XDG trash, one
  named path at a time, refusing the filesystem root and any path it cannot read *before* it touches
  anything. The path is read literally: there is no shell here, so `build*` is a filename that happens
  to contain an asterisk, and the honest answer to a path-shaped query for it is "no file is called
  that, and this tool does not expand it". The refusal for a real pattern lives where expansion
  happens — `ApprovalPolicy::refuse_unenumerable_deletions` (shipped on by default in
  `deployment_default`) refuses `rm -rf build*` and `rm -rf $DIR` outright and prints the enumerable
  form instead.

Two consequences worth stating, because they were decisions rather than mechanics:

- **The question is in the audit trail, not just the answer.** `AgentEvent::ApprovalRequested` carries
  the targets as data, so a store that keeps the event can prove a year later what the approver was
  shown. A rendering is not storable for that purpose — a stored rendering can never be re-rendered
  against a better one.
- **`delete` is not `Action::Delete`-only.** It still requires the `Delete` action on the resolved path,
  so a token narrower than the workspace denies it outright and no approval can buy it back. What the
  *tool* adds is that the effect is recoverable: the prompt says where the file went instead of
  claiming it is gone.

### Two defects the shipped floor had

Writing the test for §3's catastrophe set turned up two ways the floor was not doing what this document
says, and both are the kind that only a test written from the document can find:

1. **The root pattern matched every absolute path.** `*rm -rf /*` was meant for `rm -rf /`; as a glob it
   also matches `rm -rf /tmp/build`, so a deployment refused ordinary cleanups. A floor that blocks
   ordinary work is a floor people delete — which costs the protection that mattered — so the list now
   names the directories whose loss nothing can restore (`/etc`, `/usr`, `/var`, `/boot`, … plus the
   exact root forms) and leaves `/tmp`, `/home`, `/Users` and `/opt` to the prompt that resolves the
   path and counts what is inside it. `rm -rf /*` — everything at the root — is a *pattern*, and the
   glob language cannot tell it apart from a path that merely starts with a slash; it is refused by
   `refuse_unenumerable_deletions` instead, which is the rule that exists for patterns.
2. **A config that never mentioned a policy got no floor at all.** `AgentConfig`'s field default was
   `deployment_default()`, but `Config`'s `agent` field is `#[serde(default)]` — so the *shortest*
   config, the one that omits `agent:` entirely, deserialised through `AgentConfig::default()` and got
   the blank policy: no catastrophe set, no refusal of unenumerable deletions, in the shape most people
   write. `AgentConfig::default()` now calls `deployment_approval()`, and
   `the_shipped_example_config_parses_and_carries_the_floor` pins it against the file people copy.

Known, and next: a config that writes its own `approval:` block still **replaces** the shipped deny set
rather than adding to it, so `agent: approval: {level: yolo}` quietly removes the floor. The fix is to
make the shipped rules additive with an explicit opt-out, which is a change to the policy model rather
than to the delete tool — `hx.example.yaml` states the trap plainly in the meantime.

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

`ApprovalPolicy` has `allow`, `ask` and `deny` rule lists; the level threshold supplies the implicit
*ask* for anything no rule matches. The explicit `ask` list is what adds the one thing the prior art
has and a threshold alone cannot: the ability to force a prompt for something that is *below* the
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

Chat requests now select a boundary with `sandbox_profile`; the CLI exposes it as
`hx chat "run tests" --sandbox-profile dev --workspace /absolute/checkout`.
The daemon resolves the configured profile before creating a session or calling the model, adopts the
workspace owner, and opens it through `SandboxCache`. Unknown profiles return 400; an absent engine
returns 503; a failed start returns 502. None falls back to the host. Selection is per request, including
resumed requests; omitting it keeps host execution. Only shell calls are confined: file tools still use
the host and declare that fact to the approval layer. The workspace remains a writable host bind mount.

The shell sends command source and workdir separately. Embedding `cd /host/checkout` in the command
would defeat mount translation even though the engine received `/workspace` as its working directory.
HTTP tests assert the exact engine command and translated directory, not merely that `exec` was called.
The live Docker verification of this chat path is `crates/hx-server/tests/chat_live.rs` — two tests
against a real daemon, recorded in `TESTING.md`'s tier A. The HTTP tests above use a recording runtime.

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
| 7 | Project-scoped `.hx/allow.toml` (§5), shown by `hx policy` | `hx-core/src/allowlist.rs`, `hx-server/src/chat.rs`, `apps/hx` | medium | **done** |

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

### The third defect, and the one that mattered most

**A config that wrote a policy replaced the floor.** A config deserialises *into* a policy, so any list it
wrote replaced the list the deployment started with — and `agent: {approval: {level: yolo}}`, the shortest
thing an operator writes to stop being prompted, silently removed all thirty-two catastrophe rules with it.
The looser the setting, the more the floor mattered, which is the worst possible shape for a safety default.

The floor is therefore **not a list that can be replaced by omission**. `inherit_denials` is a field on
`ApprovalPolicy` whose serde default is `true` and whose type default is `None`, because those are two
different questions: a policy that came from a *file* is a deployment and inherits the floor, while
`ApprovalPolicy::default()` is a library caller and must not acquire thirty-two rules it never wrote.
`with_floor()` folds the shipped rules in (the file's own rules first, so *its* note is the one that
explains a refusal), and `Config::from_yaml` — the boundary between a file and a policy — is where it runs.
Dropping the floor now takes the words `inherit_denials: false`, and `hx policy` reports that as
*"none of the shipped catastrophe set: this config's `deny` list replaced it"*.

Two bugs were found by the test that asserts a **run**, not a policy, refuses `rm -rf /etc` under `yolo`:

1. `with_floor()` was not idempotent. It rebuilt the deny list by keeping only the rules the floor did not
   already contain, so folding an already-floored policy produced an **empty** list — and since the daemon
   folds on every run, the catastrophe set was dropped silently before `set_level` was ever reached. The
   unit test that called the policy directly never saw it; the API test that ran a command did.
2. `deployment_default()` set the flag but did not resolve it, so the one constructor an embedder calls
   without a config file promised a floor it did not carry.

## 8. Answering from a phone

§1–§7 are about what may be *asked*. This is the other end: an answer arriving from somewhere the user
already is, rather than from the surface that started the run. `crates/hx-gateway/src/bridge.rs` is the
whole of it — the loop-back that was missing until it existed, because a button tap was parsed, judged
against the ceiling, and then dropped on the floor.

The question a run asks and the answer a phone gives are joined by **the id the button carries**. The
button's `callback_data` is `apr_<id>:<label>`, and an answer is looked up by that id *within the
conversation it was asked in* — never "whatever is pending in this chat now". Everything else follows
from that one rule:

- **A stale tap is not an answer.** A button from a question that has been answered, timed out, or asked
  by a different surface matches nothing and is refused.
- **A replayed tap is not a second decision.** The queue is the atomic authority: the first answer wins,
  and the second finds nothing to answer.
- **A tap in the wrong chat is not an answer.** A question asked through a channel is waited on under its
  conversation as the queue scope, so an answer arriving anywhere else has nothing to match — which is why
  the scope matters and why a channel-asked question must be waited on this way rather than under a
  session id.
- **An answer the question never offered is not an instruction.** The label has to be one this request
  rendered, checked against `ApprovalRequest::options` and not against the platform's word for it.

**The ceiling is judged when the answer arrives**, not only when the question was posted. A channel's
ceiling can be lowered while a question is up, and a queue can hold a question another surface asked, so
"may this channel authorise this risk" is a question about the moment of the answer. A `Destructive`
request answered "allow once" from a `Mutate` channel is refused, the run keeps waiting, and the wait ends
in the timeout denial — never in the yes the phone offered.

Two more rules belong to this layer rather than to the ceiling:

- **A channel may answer for this instance or for this chat, never permanently.** `allow once` and
  `allow for this chat` (chat-scoped, expiring) are honoured; `always allow this` is refused, because
  that option writes a grant into the deployment's configuration and a phone tap must not be the thing
  that writes it. The option list is the request's to offer — which surfaces may *exercise* a permanent
  promotion is this layer's decision.
- **A channel that is down fails closed, twice over.** A question that could not be posted is denied
  immediately, with the reason, rather than left for a timeout that would look to the model like a human
  who did not reply; and a question that was posted and never answered ends in the queue's timeout
  denial. A channel failure is never converted into an answer, and a transport error is reported without
  the URL it failed on — the URL is where the bot token lives.

**Attribution.** The decision reaches the loop as `ApprovalDecision { by }` and the loop records it in
`AgentEvent::ApprovalResolved.by`, so the trail says `telegram:4242 via main-tg` where a terminal
keypress says `user`. This is security-relevant rather than cosmetic: "who approved this" is the question
an incident review asks, and `user` does not answer it when the user was on a phone in another country.

**What is deliberately not here.** No receive loop (the bridge turns *one* inbound event into an outcome;
driving `Connector::receive` per channel is the daemon's job, one loop rather than one per waiting run),
no delivery of a "denied" acknowledgement back to the chat, and no configuration surface yet:
`approval.ask_via` is still a roadmap line rather than a key, so a channel's ceiling and conversation are
constructed in code. The properties above do not depend on that plumbing, which is why it can be added
without touching them.

## 9. The ceiling belongs where the answer is applied, not where it is parsed

§8 is the join. This is the part of it that was **wrong in a way that read as right**, and the reason the
ceiling now lives in `ApprovalQueue` rather than only in the gateway.

`AnswerAuthority::judge` is the rule — "a chat bridge may approve a `Mutate` and must never approve a
`Destructive`" — and for a while it was true of a pure function that **nothing on the running system
called**. The bridge called it. The only live answer path did not:
`POST /v1/approvals/{id}` → `ApprovalQueue::answer(id, option, by)` applied whatever option arrived,
against whatever question was waiting, with no risk and no ceiling anywhere in the call. A unit test of
`judge` passed the whole time. That is the shape of bug this file exists to catch: a rule that is
*correct* and *not wired*, where the test that proves it correct is the test that hides it.

So the ceiling moved to the choke point. Every transport applies an answer through
`ApprovalQueue::answer`, so that is where the check goes, and it takes the answering surface's ceiling as
a **required** argument:

- **Required, with no default, and `RiskClass` has no `Default`.** There is no constructor, no
  deserializer and no omitted argument that yields a permissive ceiling. A route body that does not say
  what it is gets a rejection, not everything — `an_answer_that_declares_no_ceiling_is_refused_rather_than_granted_everything`.
- **Judged at answer time, against the queue's own record.** The risk compared is the one on the request
  the queue is *holding*, not anything the caller supplied, and the comparison happens when the answer
  arrives — so a ceiling lowered while a question is up is the one that applies.
- **One implementation.** The comparison is `RiskClass::covers`; `AnswerAuthority::may_answer` delegates
  to it. A channel's ceiling and the local path's ceiling cannot come to mean different things.
- **A refusal is not a decision.** An answer above the ceiling leaves the question **open**. The run keeps
  waiting and its own timeout denies it, so the outcome is "nobody answered" — never the phone's yes, and
  never a silent no that looks like the operator said no.

**Why the route asks the caller to declare a ceiling, and what that is worth.** At the time the ceiling
moved to the choke point, this API had **no authentication**: the daemon could not tell one local client
from another, and per-channel ceilings are still not configured (`approval.ask_via` is still a roadmap
line). The honest choice was between "declare it" and "have no check", and declaring it is what makes the
check present, explicit and testable. The clients that use this route are the owner's own machine-local
ones — the `hx` CLI (`by: "terminal"`) and the daemon's embedded web page (`by: "web"`) — and both declare
the terminal's full ladder, which is the authority a keypress at the prompt has always had. A **channel**
does not answer through this route at all: it answers through `ApprovalBridge`, where the ceiling comes
from the deployment rather than from the channel, which is the distinction that makes the channel's
ceiling a control rather than a self-declaration.

**The API is authenticated now, and that is what the declared ceiling was missing.** The hole this section
used to end on — "with `--bind 0.0.0.0` and no auth, a declared ceiling is not a defence against a remote
caller" — is closed by a bearer token (`crates/hx-core/src/api_auth.rs`,
`crates/hx-server/src/auth.rs`): `api.token` in the config (a literal, or a `store:name` reference
resolved through `hx-secrets`) or `HX_API_TOKEN` in the environment, **required and refused at startup for
a bind that is not loopback**, optional on loopback, compared in constant time, and answered with `401`
and `WWW-Authenticate: Bearer` for a missing or wrong one. So a remote caller now has to present the token
before it can declare anything, and the ceiling is no longer the only thing standing between a routable
address and `POST /v1/approvals/{id}`.

Two limits are worth stating rather than leaving to be discovered:

- **A bearer token is not a session.** There is no rotation, no expiry, no per-client identity and no
  revocation short of changing the token for everyone, so a token that leaks stays useful for as long as
  it stands. `by:` is still a declaration by whoever holds the token, not a verified identity: the token
  says *a* client was allowed in, not *which* one. Per-channel ceilings (`approval.ask_via`) are what
  would make the answer's authority a property of the surface rather than of its declaration, and they
  are still a roadmap line.
- **The transport is plain HTTP.** Over a non-loopback interface the token travels in the clear unless
  something in front of the daemon terminates TLS. `WWW-Authenticate: Bearer` is the challenge a client
  should answer, not a claim that the channel is confidential.

What is now true: the API cannot be reached at all without the token, and a daemon asked to serve a
non-loopback address without one does not start. What is still not true: that the token tells the daemon
which client is answering.

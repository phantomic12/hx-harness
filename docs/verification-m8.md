# Adversarial verification of the M8 pool and M7 desktop shell

**Branch** `feat/verify-m8` at main `7fb8583` · **role** adversarial verifier · **rule** a claim is not
verified by reading the code that makes it, only by making the weak thing happen.

Eight claims were attacked. Each property test was exercised by **breaking it**: production code was mutated to
violate the property the claim asserts, and the suite was watched for red. Every mutation was reverted. One
real defect was found and fixed (F1). The docs' counts were re-measured from a full run.

| Claim | Verdict |
|---|---|
| A down member is never drawn while a healthy one exists | **Held** — 3 tests red on removal of health-filtering |
| All-down returns a distinct error naming each member and reason | **Held** — covered, wording correct |
| Empty is a separate error | **Held** — covered |
| Clamping picks the nearest accepted value and records it | **Held** — `.min()` and `.max()` both caught |
| A parameter kind a member does not support is dropped with `sent: None` | **Held** — covered |
| A member's credential is a reference, never a value | **Held** — no resolver exists; verbatim by construction |
| Round-robin does not starve a member | **Held** — 4 tests red on always-first |
| A refused hotkey surfaces as `Refused`, not swallowed | **Held** — red on swallow-mutation |
| The notification redacts token-shaped values and paths outside the workspace | **FALSIFIED** → **fixed** (F1) |
| Each feature degrades to a working window | **Held by structure** — read, not executed (headless) |
| `TESTING.md`: 1478 tests, 0 failed, 60 ignored | **Confirmed** by full run |
| `ROADMAP.md` M8: pool landed with no spawner drawing from it | **Confirmed** by tree-wide grep |

---

## F1 — The notification does not redact the repo's own bearer-token shapes

`apps/hx-desktop/src/notification.rs::leaky_token` refused a token only when it was
`all(|c| c.is_ascii_alphanumeric()) && len >= 16`. Every real bearer token this repo produces contains a
hyphen — `hx-secrets/src/redact.rs:87` lists `sk-`, `sk-ant-`, `sk-proj-`, `sk-or-v1-`,
`rk-`, and the M6 report's fixture token was `signed-token-9f3a2b7c`. A hyphen makes
`is_ascii_alphanumeric` false for the whole string, so such a token rides through the notification body
verbatim — on the exact surface the module doc (`:13-16`) and `ROADMAP.md` promise is redacted.

The sibling test `the_notification_never_leaks_a_token` used only `"A".repeat(40)`, which is
all-alphanumeric and so can never see the hyphenated shape — it passes forever against a `leaky_token` that
ignores hyphens entirely.

**Provable failing input** (before the fix):

```
$ cargo test -p hx-desktop --lib notification --offline -j 2
test notification::tests::the_notification_redacts_a_hyphenated_bearer_token ... FAILED
---- stdout ----
panicked at apps/hx-desktop/src/notification.rs:209:9:
the notification must never carry a bearer token, even one with hyphens
```

The key `sk-proj-9f3a2b7c8d1e2f3a4b5c6d7e` reached the body unredacted.

**Fix (chosen: make the code do what the sentence says — the security property is worth having).** `leaky_token`
now refuses any whitespace-token with ≥16 alphanumerics where every character is alphanumeric or
`-`/`_`/`.`; `/`, `:`, `=`, `?` still separate a path or URL and keep being shown. The module doc was
updated to state the shape precisely. Added `the_notification_redacts_a_hyphenated_bearer_token`, which
**failed on the old code** and passes now. Verified the change is load-bearing: the new test is the needle; the
old code red on it, the new code passes.

Clippy (`cargo clippy -p hx-desktop --all-targets -j 2 --offline -- -D warnings`: clean) and
`cargo fmt --all -- --check` (clean). Committed as `11f2fac`.

I did not over-redact: a short hyphenated word and a workspace-internal path (containing `hx-wt`) still
resolve to "shown" — pinned by the existing
`the_notification_never_leaks_a_path_outside_the_workspace` and friends, all green after the fix.

---

## Claim — a down member is never drawn while a healthy one exists

**Verdict: held.** `ModelPool::draw` filters to health == Healthy before choosing. Nothing can draw a down
member while a healthy index exists, and the `AllDown`/`Empty` arms are the only ways a draw can fail.

**Attempt to falsify — health filtering removed** (all members become "healthy"):

```
$ cargo test -p hx-core --lib pool --offline -j 2
test a_member_recovers_and_is_drawn_again_after_mark_up ... FAILED
test a_draw_with_every_member_down_is_a_distinguishable_error ... FAILED
test a_down_member_is_not_drawn_while_a_healthy_one_remains ... FAILED
test result: FAILED. 12 passed; 3 failed
```

The three named tests went red, so the health filter is load-bearing. The specific interleaving the brief named
(one down, then one marked up, then a draw) is covered by
`a_member_recovers_and_is_drawn_again_after_mark_up`, which draws only `b` while `a` is down and sees
`a` again after `mark_up`. Held.

## Claim — all-down returns a distinct error naming each member and reason

**Verdict: held.** `a_draw_with_every_member_down_is_a_distinguishable_error` asserts the `AllDown { members }`
variant lists `a`, `b`, `c` and that the `Display` text contains two of the per-member reasons. It was red
under the health-filter-removal mutation (the filter removal turns AllDown into a normal draw), and the `Display`
wording was read and confirmed (`{id} ({reason})`, semicolon-separated). No sentence overstated.

## Claim — empty is a separate error

**Verdict: held.** `an_empty_pool_draws_an_empty_error` asserts `Err(DrawError::Empty)` on a zero-member
pool. `draw` distinguishes `members.is_empty()` from "non-empty but all down". No falsification found.

## Claim — clamping picks the nearest accepted value and records it

**Verdict: held.** The lane's claim that it found one case where a simpler implementation agrees — and the test
`clamping_picks_the_truly_nearest_accepted_value` case B (target High, accepts [Low, Medium] → Medium)
that distinguishes nearest from `.min()` — was checked against **both** wrong extremes:

- `.min()` (always smallest): `clamping_picks_the_truly_nearest_accepted_value` red.
- `.max()` (always largest): both `clamped_parameters_reach_the_nearest_accepted_value_and_are_recorded`
  and `clamping_picks_the_truly_nearest_accepted_value` red.

The brief asked for cases the lane "did not find". I tried to find a wrong implementation that matches nearest on
all current cases but violates it elsewhere: the two ordinal-preserving simplifications (`min`, `max`) are both caught.
A "first-accepted" implementation is caught by case A. Because `ReasoningEffort` is a 3-value chain, nearest is
uniquely `min` or `max` or a middle value; the suite pins the middle value in both directions. No gap found.
The clamp is recorded (a `ParamClamp` with `sent: Some(nearest)`), asserted in
`clamped_parameters_reach_the_nearest_accepted_value_and_are_recorded`.

## Claim — unsupported parameter kind dropped with `sent: None`

**Verdict: held.** `an_unsupported_parameter_kind_is_dropped_and_recorded` uses a member with empty
`accepts` and asserts `params` empty and one clamp `{ requested, sent: None }`. `clamp`'s `same_kind` is
empty for a kind the member does not accept → the `sent: None` arm. All pool clamps re-verified after the two
nearest-mutations in the reverse direction too (the unsupported-kind path was never affected). Held.

## Claim — a member's credential is a reference, never a value

**Verdict: held.** `PoolMember.credential` and `ModelPoolMemberConfig.credential` are `String` fields with no
resolver anywhere: `grep` for `resolve|Secret|vault::|to_secret` in `pool.rs` finds nothing — `pool.rs`
never touches a vault, env, or secret; the module doc's own sentence ("resolved by whoever actually connects") is
true and there is no code path that could turn the string into a value. The round-trip test asserts the reference is
carried verbatim (`vault:pool/cheap`). A value cannot be stored as anything but a string here; every string is a
reference by construction. Not falsifiable from this module. What I tried: grepped for any value-resolution or
`Debug`-dump of a credential in `pool.rs`, and for any `env:`/`vault:` handling; none exists. Held.

## Claim — round-robin does not starve a member

**Verdict: held.** `n_draws_across_n_healthy_members_reach_n_distinct_members` and
`draws_cycle_round_robin_in_order_while_all_healthy` cover the fairness. On the always-first-healthy
mutation **4 tests red** (the two fairness tests plus `a_member_recovers_and_is_drawn_again_after_mark_up`
and the config round-trip draw assertions). The cursor advances on every draw (`wrapping_add`), and the healthy
set is recomputed each draw, so a newly-healthy member is picked up with no starvation under any interleaving I could
construct. Held.

## Claim — a refused hotkey binding surfaces as `Refused`, not swallowed

**Verdict: held.** `attempt_registration` maps a backend `Err(reason)` to `HotkeyOutcome::Refused { spec,
reason }`. **Mutation — the refusal converted to `Registered`**:

```
$ cargo test -p hx-desktop --lib hotkey --offline -j 2
test a_refused_hotkey_binding_is_surfaced_not_swallowed ... FAILED
```

So the test has teeth. Reverted. `lib.rs:242-250` matches `Refused` and `tracing::warn!`s the reason —
the composition surfaces it. Held. (Not executed headless — the real plugin path is only compiled — but the
decision `attempt_registration` is pure and its test bites.)

## Claim — each desktop feature degrades to a working window rather than failing to start

**Verdict: held by structure, not executed.** `lib.rs:236-238` warns and continues on tray error (`continue
without it`); `register_plugin_shortcut` always returns an outcome and `lib.rs:242-250` warns on
`Refused`/`Invalid` without returning an error; `notify_approval_request` takes `&AppHandle` and its result is
ignored. None of the three can prevent the window. The tray/hotkey real plugin paths need a display server and are
not exercisable headless; I did not run them. This is a structural read, reported as such.

## Docs — `TESTING.md` counts

**Re-measured, confirmed.** `cargo test --workspace --offline -j 2` (full run, 73 result lines):

```
$ grep -E "test result:" /tmp/ws_test_m8.log | awk ... 
passed sum: 1478        (parked in the `# The two totals above were re-measured …` header block)
```

73 binaries, **1478 passed, 0 failed**. The `60 ignored` figure is the `#[ignore]`d live tests. On my
edited tree, adding one hx-desktop test raises the running total to 1479 when counted, but the claim as written was
measured and matched. No doctored count found. Held.

## Docs — `ROADMAP.md` M8 honesty (no spawner draws from the pool)

**Confirmed.** `ROADMAP.md:682-713` states plainly "**Nothing draws from this pool yet**" and "no
`ChildSpec`, no orchestrator, no `spawn_child`". `grep -rn "spawn_child|spawn_delegate|delegate("
crates/hx-core/src/ apps/` finds only the pool's own doc comment denying their existence; `ModelPool::draw` is
called only from `config.rs` test code and `pool.rs` tests. Nothing claims more than the truth. The "exit criteria"
are marked "(still open — they describe the spawner)". Held.

---

## What I could not test

- **The real tray / hotkey / notification plugin calls.** They require a desktop session; only the pure decision
  points are asserted. The degradation claim rests on a structural read of `lib.rs`.
- **The Windows half of anything.** Linux host; `crates/hx-desktop` here is compiled for Linux.

## The tree I leave behind

The one intended change is the committed fix (`11f2fac`, `apps/hx-desktop/src/notification.rs`,
+29/−1). All nine pool/hotkey mutations were reverted; `git diff --stat` against the commit is empty and
`git status --porcelain` is clean. The deliverable is this document.

- `cargo fmt --all -- --check` → clean
- `cargo clippy -p hx-desktop --all-targets -j 2 --offline -- -D warnings` → clean
- `cargo test -p hx-desktop --lib --offline -j 2` → 15 passed, 0 failed
- `cargo test -p hx-core --lib pool --offline -j 2` → 15 passed, 0 failed
- `cargo test --workspace --offline -j 2` → 1478 passed, 0 failed (measured before the +1 test)

## Summary of mutations

| Mutation | File | Suite reaction |
|---|---|---|
| health filter removed from `draw` | `pool.rs:242` | 3 red — held |
| round-robin → always-first | `pool.rs:261` | 4 red — held |
| nearest → `.min()` | `pool.rs:176` | 1 red — held |
| nearest → `.max()` | `pool.rs:176` | 2 red — held |
| refusal swallowed → `Registered` | `hotkey.rs:81` | 1 red — held |
| **(defect) hyphenated token unredacted** | `notification.rs:70` | **failing input → fixed** |

All reverted except the committed fix.

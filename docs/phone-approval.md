# Phone / lock-screen approval (M7)

When an agent run needs a human answer, there are two ways to get one:

1. **Poll**: a terminal or the web UI calls `GET /v1/approvals` and answers with
   `POST /v1/approvals/{id}`. This is the default.
2. **Push** (this doc): the daemon `POST`s the question to a webhook you run, which turns it into a
   push notification on your phone. You answer from the **lock screen** — no terminal, no web client open.
   The tap comes back to `POST /v1/approvals/{id}/respond`.

## Enabling it

Set one field, the webhook URL:

```yaml
approval:
  push_url: https://push.my.service/hx-approval
```

When `push_url` is set, a run that would otherwise wait in the polling queue instead pushes its prompt
through this webhook. When it is absent (the default) nothing changes: a daemon that names no webhook
posts nothing and the poll path is untouched.

The responder URL each push carries is built from `daemon.http_addr` (`127.0.0.1:8787` becomes
`http://127.0.0.1:8787`). For a phone to reach it, that address must resolve from the phone's
network — on a loopback default, remote pushes won't resolve, so name a public origin when you use this
path.

## The wire protocol

`POST {push_url}` with a JSON body:

```json
{
  "id": "apr_…",
  "question": "git push origin main",
  "choices": ["allow", "deny"],
  "respond_url": "https://your-daemon/v1/approvals/apr_…/respond?token=…"
}
```

Your webhook relays this to the operator. When they tap:

```http
POST /v1/approvals/{id}/respond
Content-Type: application/json

{ "token": "…", "verdict": "allow" }
```

- `verdict` is `allow` or `deny`. Anything else is a `400`.
- The **one-time token** lives inside `respond_url` and is verified by the daemon before an answer is
  accepted. Replaying a tapped `respond_url` cannot answer twice.
- `allow` is a **one-shot** grant (`AllowOnce`) — never a chat-wide or permanent "always". A lock screen
  has no "always" button, so it is never offered one.
- An `allow` may only authorise at or below the **phone ceiling** (`external`). `destructive` and
  `privileged` taps are refused (the question stays open and the run's own timeout denies it).

## Security: a one-time token instead of a bearer token

The API is normally protected with a long-lived bearer secret. A push **must never** carry that secret — it
travels through your webhook relay and sits on a lock screen. So each pushed approval mints a fresh
one-time token, stored only in the daemon, and the `{id}/respond` route is the **one** route exempt
from the bearer check: it authenticates with that token instead. A caller without the token is refused; a
caller with it holds the proof the push itself issued. See `crates/hx-server/src/auth.rs`
(`is_phone_respond_route`) and `crates/hx-server/src/phone.rs` (`PhoneApprover`).

### The token never reaches a log line

The token travels inside `respond_url`. Everything that logs a URL strips its query string, and the token type
prints as `<redacted>` under `Debug`/`Display`, so a stray format string cannot leak it. Unit tests pin
this.

## What happens when the push fails

Fail-closed: if the POST fails (relay down, URL unreachable), the run still waits for its timeout and
expires into a **denial**. A push that did not arrive is never a silent yes.

## Testing without a push provider

`cargo test` never requires APNs/FCM or any real push relay. The path is a generic webhook: integration
tests drive the respond route over a real loopback HTTP stack against a `PhoneApprover` seeded with a
waiting approval, and unit tests pin the wire shape of the payload without a socket.

## Code map

- `crates/hx-core/src/config.rs` — `ApprovalConfig::push_url` (the on/off switch).
- `crates/hx-server/src/phone.rs` — `PhoneApprover` (the push), the one-time token, the payload shape.
- `crates/hx-server/src/routes.rs` — `POST /v1/approvals/{id}/respond`, which resolves the tap.
- `crates/hx-server/src/chat.rs` — selects the phone approver when `push_url` is set.
- `crates/hx-server/src/auth.rs` — why `{id}/respond` is the one bearer-exempt route.

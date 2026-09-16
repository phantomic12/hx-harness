//! SQLite: sessions, their transcripts, their events, and what they cost.
//!
//! ## What this crate owns
//!
//! The daemon holds state; a client that dies must not take it with it. That sentence is the whole
//! reason this crate exists, and it is why the store is the *only* place a session lives:
//! `hxd` loads a transcript from here, the loop appends to it, and every message is written as it
//! is produced. Kill the TUI, kill the daemon, reboot: the session is what the database says it is.
//!
//! ## The three shapes
//!
//! - **A session** is a row plus its transcript — [`Session`]. Resuming is `load`, and a session
//!   that ended mid-call says so ([`Session::interrupted_calls`]) so a caller can either repair it
//!   ([`Store::close_interrupted`]) or refuse to continue.
//! - **An event** is what a client renders ([`hx_core::event::AgentEvent`]), stored whole. The event
//!   stream is stored *beside* the transcript rather than derived from it, because a client
//!   reconnecting needs to redraw what happened, not re-infer it.
//! - **A usage row** is one provider call, as reported. Summed, it is what the session cost — in
//!   tokens the provider counts, and in dollars only when a price table was configured.
//!
//! ## Decisions worth arguing with
//!
//! **Parts are JSON, not columns.** `Message` belongs to `hx-core` and gains part types as the
//! harness grows (`Image` landed before this crate did). A schema that mirrored it would need a
//! migration per new part type and would still be unable to hold one it had never heard of. So the
//! role is a column — because *that* is what queries filter on — and the parts are a JSON blob the
//! crate round-trips without interpreting. A part type this build does not know therefore needs no
//! migration and is not silently dropped: it comes back as a message whose parts will not parse,
//! which is an error naming the row rather than a message missing the thing the model was told.
//!
//! **Sync API, one connection, behind a mutex.** `rusqlite` is synchronous and this store is not on
//! a hot path: one insert per message, one insert per event, a handful of reads per request. A
//! connection pool would add real complexity to hide a ~µs write. The honest caveat is that a
//! caller inside an async task must not hold the lock across an `await` — the guard is not `Send`.
//!
//! **No secrets, ever.** A credential lives in the vault and is referenced by name. Nothing in this
//! crate stores key material, and nothing it stores is redacted on the way in — redaction belongs
//! on the way *out* to a model or a chat platform, and a transcript that silently differs from what
//! happened is worse than one that contains a secret the vault already knows how to mask.

pub mod schema;
pub mod session;
pub mod store;

pub use session::{
    ExportFormat, NewSession, Session, SessionRecord, SessionSummary, Totals, UsageRecord,
};
pub use store::Store;

//! The store itself: one SQLite database, opened once and shared.

use crate::audit;
use crate::schema::{self, fail};
use crate::session::{
    parse_stamp, role_column, stamp, ExportFormat, NewSession, Session, SessionRecord,
    SessionSummary, Totals, UsageRecord,
};
use chrono::{DateTime, Utc};
use hx_core::config::Config;
use hx_core::error::{HxError, Result};
use hx_core::event::AgentEvent;
use hx_core::ids::SessionId;
use hx_core::message::{Message, Part, Role};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

/// How long a writer waits for another connection's lock before giving up.
///
/// The daemon is the only writer, a client may read, and `wal` mode lets those two proceed at the
/// same time. Five seconds is therefore not a tuning knob: it exists so that the transient case
/// resolves inside the store instead of surfacing as an error the caller would have to retry.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The file name inside a configured data directory.
pub const DATABASE_FILE: &str = "hx.db";

/// The durable state: sessions, transcripts, events, usage.
pub struct Store {
    conn: Mutex<Connection>,
    /// `None` for an in-memory store, which is how every test in this crate runs.
    path: Option<PathBuf>,
    /// The secret the audit chain is keyed with, or the fact that there is none.
    ///
    /// Held here rather than read per write, so a store's chain cannot change mode mid-life: a
    /// database whose earlier rows were written unkeyed and whose later rows were keyed would fail
    /// to verify at the seam, and the report would look like tampering rather than like a
    /// misconfiguration.
    chain_key: audit::ChainKey,
}

impl Store {
    /// Open (creating if needed) the database at `path`.
    ///
    /// Parent directories are created, because a data directory that does not exist yet is the
    /// first-run case rather than an error. A path that exists but is not a database is an error:
    /// SQLite will happily "open" a text file and only fail on the first query, so this asks the
    /// file for its schema version immediately, which is the cheapest real check.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|err| {
                    HxError::Store(format!("could not create {}: {err}", parent.display()))
                })?;
            }
        }

        let conn = Connection::open(&path)
            .map_err(|err| fail(&format!("could not open {}", path.display()), err))?;
        let store = Self::configure(conn, Some(path))?;
        Ok(store)
    }

    /// An in-memory database. Nothing survives the process, which is the point.
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|err| fail("could not open an in-memory database", err))?;
        Self::configure(conn, None)
    }

    /// The database a configuration points at: `<daemon.data_dir>/hx.db`.
    pub fn from_config(config: &Config) -> Result<Self> {
        let dir = expand_home(&config.daemon.data_dir);
        Self::open(dir.join(DATABASE_FILE))
    }

    /// Open the database with an explicit key for the audit chain.
    ///
    /// The daemon uses this so the key comes from its environment; `from_config` leaves the chain
    /// unkeyed, which is what the tests and a fresh checkout get.
    pub fn from_config_with_key(config: &Config, key: audit::ChainKey) -> Result<Self> {
        let dir = expand_home(&config.daemon.data_dir);
        let mut store = Self::open(dir.join(DATABASE_FILE))?;
        store.chain_key = key;
        Ok(store)
    }

    /// The secret an audit-write is keyed with, and whether there is one.
    pub fn chain_key(&self) -> &audit::ChainKey {
        &self.chain_key
    }

    fn configure(conn: Connection, path: Option<PathBuf>) -> Result<Self> {
        let mut conn = conn;
        conn.busy_timeout(BUSY_TIMEOUT)
            .map_err(|err| fail("could not set the busy timeout", err))?;
        // Without this pragma, `ON DELETE CASCADE` is decoration: SQLite defaults to ignoring
        // foreign keys entirely, so a deleted session would leave its transcript behind forever.
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|err| fail("could not enable foreign keys", err))?;

        if path.is_some() {
            // A reader and the daemon can then work at once. `journal_mode` answers with the mode
            // it settled on, so this is a query rather than an update.
            let mode: String = conn
                .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
                .map_err(|err| fail("could not switch the journal to WAL", err))?;
            if !mode.eq_ignore_ascii_case("wal") {
                return Err(HxError::Store(format!(
                    "the database refused WAL mode (got '{mode}'); a filesystem without shared \
                     memory — some network mounts — cannot host this store"
                )));
            }
            // `NORMAL` under WAL loses at most the last commits on a power cut, and `FULL` costs a
            // fsync per message. A transcript is not a ledger.
            conn.pragma_update(None, "synchronous", "NORMAL")
                .map_err(|err| fail("could not set synchronous=NORMAL", err))?;
        }

        schema::migrate(&mut conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            path,
            chain_key: audit::ChainKey::Unkeyed,
        })
    }

    /// Where this store lives, or `None` for an in-memory one.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// The schema version on disk.
    pub fn schema_version(&self) -> Result<i64> {
        let conn = self.lock();
        schema::version(&conn)
    }

    // -- sessions -------------------------------------------------------------------------------

    /// Start a session. The id is minted here, not by the caller: a client that could choose an id
    /// could collide with a session it has never seen.
    pub fn create(&self, new: NewSession, at: DateTime<Utc>) -> Result<SessionRecord> {
        let record = SessionRecord {
            id: SessionId::new(),
            title: new.title_or_default(),
            agent: new.agent,
            workspace: new.workspace,
            model: new.model,
            created_at: at,
            updated_at: at,
        };

        self.with_tx(|tx| {
            tx.execute(
                "INSERT INTO sessions (id, title, agent, workspace, model, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    record.id.as_str(),
                    record.title,
                    record.agent.as_ref().map(|agent| agent.as_str().to_string()),
                    record.workspace,
                    record.model,
                    stamp(record.created_at),
                    stamp(record.updated_at),
                ],
            )
            .map_err(|err| fail("could not create the session", err))?;
            Ok(())
        })?;

        Ok(record)
    }

    /// One session's row.
    pub fn record(&self, session: &SessionId) -> Result<SessionRecord> {
        let conn = self.lock();
        let record = conn
            .query_row(
                "SELECT id, title, agent, workspace, model, created_at, updated_at FROM sessions \
                 WHERE id = ?1",
                [session.as_str()],
                read_record,
            )
            .optional()
            .map_err(|err| fail("could not read the session", err))?;

        record.ok_or_else(|| Self::missing(session))
    }

    /// A session with its whole transcript — what a client calls when a user opens one.
    pub fn load(&self, session: &SessionId) -> Result<Session> {
        let record = self.record(session)?;
        Ok(Session {
            messages: self.messages(session)?,
            record,
        })
    }

    /// Sessions newest-first, with what a list view shows.
    pub fn list(&self, limit: usize) -> Result<Vec<SessionSummary>> {
        let conn = self.lock();
        let mut statement = conn
            .prepare(
                "SELECT s.id, s.title, s.agent, s.workspace, s.model, s.created_at, s.updated_at, \
                        (SELECT COUNT(*) FROM messages m WHERE m.session_id = s.id), \
                        (SELECT COUNT(*) FROM messages m WHERE m.session_id = s.id AND m.role = \
                         'assistant'), \
                        (SELECT COUNT(*) FROM usage u WHERE u.session_id = s.id), \
                        (SELECT COALESCE(SUM(u.input_tokens), 0) FROM usage u WHERE u.session_id = \
                         s.id), \
                        (SELECT COALESCE(SUM(u.output_tokens), 0) FROM usage u WHERE u.session_id = \
                         s.id), \
                        (SELECT COALESCE(SUM(u.cached_input_tokens), 0) FROM usage u WHERE \
                         u.session_id = s.id), \
                        (SELECT COALESCE(SUM(u.reasoning_tokens), 0) FROM usage u WHERE \
                         u.session_id = s.id), \
                        (SELECT COALESCE(SUM(u.cost_usd), 0.0) FROM usage u WHERE u.session_id = \
                         s.id) \
                 FROM sessions s ORDER BY s.updated_at DESC, s.id DESC LIMIT ?1",
            )
            .map_err(|err| fail("could not prepare the session list", err))?;

        let rows = statement
            .query_map([limit as i64], |row| {
                Ok(SessionSummary {
                    record: read_record(row)?,
                    messages: row.get::<_, i64>(7)? as u64,
                    turns: row.get::<_, i64>(8)? as u64,
                    totals: read_totals(row, 9)?,
                })
            })
            .map_err(|err| fail("could not list sessions", err))?;

        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|err| fail("could not read a session row", err))
    }

    /// How many sessions exist.
    pub fn count(&self) -> Result<u64> {
        let conn = self.lock();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
            .map_err(|err| fail("could not count sessions", err))?;
        Ok(count as u64)
    }

    /// Retitle a session.
    ///
    /// Bumps `updated_at`, because a rename is a thing a user did to the session and the list is
    /// ordered by the last thing that happened to it.
    pub fn rename(
        &self,
        session: &SessionId,
        title: impl Into<String>,
        at: DateTime<Utc>,
    ) -> Result<()> {
        let title = title.into();
        self.with_tx(|tx| {
            let touched = tx
                .execute(
                    "UPDATE sessions SET title = ?2, updated_at = ?3 WHERE id = ?1",
                    params![session.as_str(), title, stamp(at)],
                )
                .map_err(|err| fail("could not rename the session", err))?;
            if touched == 0 {
                return Err(Self::missing(session));
            }
            Ok(())
        })
    }

    /// Delete a session and everything hanging off it. `false` when there was nothing to delete.
    pub fn delete(&self, session: &SessionId) -> Result<bool> {
        self.with_tx(|tx| {
            let removed = tx
                .execute("DELETE FROM sessions WHERE id = ?1", [session.as_str()])
                .map_err(|err| fail("could not delete the session", err))?;
            Ok(removed > 0)
        })
    }

    // -- the transcript -------------------------------------------------------------------------

    /// Append one message, returning the `seq` it was stored at.
    ///
    /// `seq` is assigned inside the transaction rather than by the caller: a client that had to
    /// track the next sequence number would be a client that can compute it wrong, and two writers
    /// would race. The transcript is append-only, so a wrong `seq` is unrecoverable.
    pub fn append(&self, session: &SessionId, message: &Message, at: DateTime<Utc>) -> Result<u64> {
        let role = role_column(message.role);
        let parts = serde_json::to_string(&message.parts)
            .map_err(|err| HxError::Store(format!("could not serialise a message: {err}")))?;

        self.with_tx(|tx| {
            let seq = Self::next_seq(tx, "messages", session)?;
            Self::touch(tx, session, at)?;
            tx.execute(
                "INSERT INTO messages (session_id, seq, at, role, parts) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![session.as_str(), seq, stamp(at), role, parts],
            )
            .map_err(|err| fail("could not append the message", err))?;
            Ok(seq as u64)
        })
    }

    /// Append a batch in one transaction, returning the `seq` of the last message.
    ///
    /// One transaction rather than N: a transcript that is half-written because the process died
    /// between two messages is worse than one that is missing both, since the loop's next turn
    /// would see a conversation that never happened.
    pub fn append_all(
        &self,
        session: &SessionId,
        messages: &[Message],
        at: DateTime<Utc>,
    ) -> Result<u64> {
        if messages.is_empty() {
            return self
                .next_message_seq(session)
                .map(|seq| seq.saturating_sub(1));
        }

        let rows: Vec<(&'static str, String)> = messages
            .iter()
            .map(|message| {
                serde_json::to_string(&message.parts)
                    .map(|parts| (role_column(message.role), parts))
                    .map_err(|err| HxError::Store(format!("could not serialise a message: {err}")))
            })
            .collect::<Result<Vec<_>>>()?;

        self.with_tx(|tx| {
            let mut seq = Self::next_seq(tx, "messages", session)?;
            Self::touch(tx, session, at)?;
            for (role, parts) in &rows {
                tx.execute(
                    "INSERT INTO messages (session_id, seq, at, role, parts) VALUES (?1, ?2, ?3, \
                     ?4, ?5)",
                    params![session.as_str(), seq, stamp(at), role, parts],
                )
                .map_err(|err| fail("could not append a message", err))?;
                seq += 1;
            }
            Ok((seq - 1) as u64)
        })
    }

    /// The transcript, in order.
    pub fn messages(&self, session: &SessionId) -> Result<Vec<Message>> {
        let conn = self.lock();
        let mut statement = conn
            .prepare("SELECT role, parts FROM messages WHERE session_id = ?1 ORDER BY seq")
            .map_err(|err| fail("could not prepare the transcript query", err))?;

        let rows = statement
            .query_map([session.as_str()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|err| fail("could not read the transcript", err))?;

        let mut messages = Vec::new();
        for row in rows {
            let (role, parts) = row.map_err(|err| fail("could not read a message row", err))?;
            messages.push(read_message(&role, &parts)?);
        }
        Ok(messages)
    }

    /// How many messages a session holds.
    pub fn message_count(&self, session: &SessionId) -> Result<u64> {
        let conn = self.lock();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE session_id = ?1",
                [session.as_str()],
                |row| row.get(0),
            )
            .map_err(|err| fail("could not count messages", err))?;
        Ok(count as u64)
    }

    /// Repair a transcript that ended mid-call, returning the calls that were closed.
    ///
    /// Each unanswered call gets a result saying what happened, because the alternative — resuming
    /// with a dangling call — is a request most providers reject with an error that does not
    /// mention the real cause. The synthetic result is honest about being one: it reports that the
    /// call did not run, so the model re-asks rather than assuming the tool answered.
    ///
    /// Nothing is written when there is nothing to repair, so this is safe to call on every resume.
    pub fn close_interrupted(
        &self,
        session: &SessionId,
        reason: &str,
        at: DateTime<Utc>,
    ) -> Result<Vec<hx_core::ids::ToolCallId>> {
        let interrupted = {
            let loaded = self.load(session)?;
            loaded.interrupted_calls()
        };

        if interrupted.is_empty() {
            return Ok(interrupted);
        }

        let repairs: Vec<Message> = interrupted
            .iter()
            .map(|call| Message::tool_result(call.clone(), false, reason))
            .collect();
        self.append_all(session, &repairs, at)?;
        Ok(interrupted)
    }

    // -- events ---------------------------------------------------------------------------------

    /// Record one event from a run.
    pub fn append_event(
        &self,
        session: &SessionId,
        event: &AgentEvent,
        at: DateTime<Utc>,
    ) -> Result<u64> {
        let payload = serde_json::to_string(event)
            .map_err(|err| HxError::Store(format!("could not serialise an event: {err}")))?;
        // The tag is read back out of the payload rather than matched on, so a new variant cannot
        // be stored under a stale kind: whatever serde wrote is what the column says.
        let kind = serde_json::from_str::<serde_json::Value>(&payload)
            .ok()
            .and_then(|value| {
                value
                    .get("event")
                    .and_then(|kind| kind.as_str())
                    .map(str::to_string)
            })
            .ok_or_else(|| {
                HxError::Store(
                    "an AgentEvent serialised without its `event` tag; the stored kind would be \
                     wrong, so nothing was written"
                        .to_string(),
                )
            })?;

        self.with_tx(|tx| {
            let seq = Self::next_seq(tx, "events", session)?;
            Self::touch(tx, session, at)?;

            // The chain is extended inside the same transaction as the row, so a crash cannot leave
            // an event whose digest was never written — which would look like tampering on the next
            // verify. Read the predecessor in this transaction, not from a cached "last digest":
            // two writers would otherwise both chain from the same row and one of them would be
            // permanently unverifiable.
            //
            // `Option<Option<String>>` and not `Option<String>`: the outer one is "no previous row",
            // the inner one is "that row's digest is NULL". Both occur — the second for every row
            // written before the chain existed — and collapsing them into one `Option` makes
            // rusqlite fail the read with `Invalid column type Null`, which rejects *every write* on
            // an upgraded database. That bug shipped once; the test below is the shape that catches
            // it, and it must run against a migrated database rather than a fresh one.
            let previous: Option<String> = tx
                .query_row(
                    "SELECT digest FROM events WHERE session_id = ?1 ORDER BY seq DESC LIMIT 1",
                    [session.as_str()],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(|err| fail("could not read the previous event's digest", err))?
                .flatten();
            let previous = previous.unwrap_or_else(|| audit::GENESIS.to_string());

            let at_text = stamp(at);
            let digest = audit::digest_for(
                &self.chain_key,
                &previous,
                &audit::EventLink {
                    session_id: session.as_str(),
                    seq,
                    at: &at_text,
                    kind: &kind,
                    payload: &payload,
                },
            );

            tx.execute(
                "INSERT INTO events (session_id, seq, at, kind, payload, digest) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![session.as_str(), seq, at_text, kind, payload, digest],
            )
            .map_err(|err| fail("could not append the event", err))?;
            Ok(seq as u64)
        })
    }

    /// Walk this session's audit chain and report the first break, if any.
    ///
    /// Returns `Ok(None)` for a chain that holds *and* for a session whose events predate the chain
    /// — an upgraded database keeps its history rather than being refused, and its old rows carry no
    /// digest to check. The distinction is visible through [`Store::unchained_events`], which is what
    /// a caller reporting "verified" needs in order to say how much of the log was actually verified.
    pub fn verify_audit(&self, session: &SessionId) -> Result<Option<audit::Break>> {
        let conn = self.lock();
        // The row's content travels with its digest: a verifier handed only digests can compare
        // them to each other but cannot recompute anything, so it would certify an edited row.
        let mut stmt = conn
            .prepare(
                "SELECT seq, at, kind, payload, digest FROM events \
                 WHERE session_id = ?1 ORDER BY seq ASC",
            )
            .map_err(|err| fail("could not prepare the audit read", err))?;

        let rows = stmt
            .query_map([session.as_str()], |row| {
                Ok(audit::StoredEvent {
                    seq: row.get(0)?,
                    at: row.get(1)?,
                    kind: row.get(2)?,
                    payload: row.get(3)?,
                    digest: row.get(4)?,
                })
            })
            .map_err(|err| fail("could not read the audit chain", err))?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row.map_err(|err| fail("could not read an audit row", err))?);
        }
        audit::verify_events(&self.chain_key, session.as_str(), &events)
    }

    /// How many of this session's events carry no digest — rows written before the chain existed.
    pub fn unchained_events(&self, session: &SessionId) -> Result<usize> {
        let conn = self.lock();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE session_id = ?1 AND digest IS NULL",
                [session.as_str()],
                |row| row.get(0),
            )
            .map_err(|err| fail("could not count unchained events", err))?;
        Ok(count as usize)
    }

    /// The event stream, in order.
    pub fn events(&self, session: &SessionId) -> Result<Vec<AgentEvent>> {
        let conn = self.lock();
        let mut statement = conn
            .prepare("SELECT payload FROM events WHERE session_id = ?1 ORDER BY seq")
            .map_err(|err| fail("could not prepare the event query", err))?;

        let rows = statement
            .query_map([session.as_str()], |row| row.get::<_, String>(0))
            .map_err(|err| fail("could not read the events", err))?;

        let mut events = Vec::new();
        for row in rows {
            let payload = row.map_err(|err| fail("could not read an event row", err))?;
            events.push(serde_json::from_str::<AgentEvent>(&payload).map_err(|err| {
                HxError::Store(format!("a stored event no longer parses: {err}"))
            })?);
        }
        Ok(events)
    }

    /// The events with `seq` strictly greater than `after`, as `(seq, event)` pairs, in order.
    ///
    /// This is the replay half of a resumable stream. A WebSocket client reports the last sequence it
    /// has seen and the server returns everything after it, so a reconnection neither duplicates what the
    /// client already rendered nor skips the events emitted while it was away. The seq travels back so
    /// the caller can both send events *and* tell a live event that is already in the batch apart from
    /// a genuinely new one.
    ///
    /// `after = 0` replays the whole stream — the contract for a fresh client that has nothing yet.
    pub fn events_from(&self, session: &SessionId, after: u64) -> Result<Vec<(u64, AgentEvent)>> {
        let conn = self.lock();
        let mut statement = conn
            .prepare(
                "SELECT seq, payload FROM events WHERE session_id = ?1 AND seq > ?2 ORDER BY seq",
            )
            .map_err(|err| fail("could not prepare the event query", err))?;

        let rows = statement
            .query_map(rusqlite::params![session.as_str(), after as i64], |row| {
                Ok((row.get::<_, i64>(0)? as u64, row.get::<_, String>(1)?))
            })
            .map_err(|err| fail("could not read the events", err))?;

        let mut events = Vec::new();
        for row in rows {
            let (seq, payload) = row.map_err(|err| fail("could not read an event row", err))?;
            let event = serde_json::from_str::<AgentEvent>(&payload)
                .map_err(|err| HxError::Store(format!("a stored event no longer parses: {err}")))?;
            events.push((seq, event));
        }
        Ok(events)
    }

    /// How many events of one kind a session recorded — the audit-ish query, for now.
    /// How many events a session has, whatever their kind.
    ///
    /// Counted in SQL rather than by loading and parsing them: a row whose payload was edited does
    /// not parse, and the audit endpoint has to be able to report that row rather than fail on it.
    pub fn total_events(&self, session: &SessionId) -> Result<u64> {
        let conn = self.lock();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE session_id = ?1",
                params![session.as_str()],
                |row| row.get(0),
            )
            .map_err(|err| fail("could not count events", err))?;
        Ok(count as u64)
    }

    pub fn event_count(&self, session: &SessionId, kind: &str) -> Result<u64> {
        let conn = self.lock();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE session_id = ?1 AND kind = ?2",
                params![session.as_str(), kind],
                |row| row.get(0),
            )
            .map_err(|err| fail("could not count events", err))?;
        Ok(count as u64)
    }

    // -- usage ----------------------------------------------------------------------------------

    /// Record one provider call.
    pub fn record_usage(
        &self,
        session: &SessionId,
        usage: &UsageRecord,
        at: DateTime<Utc>,
    ) -> Result<()> {
        self.with_tx(|tx| {
            Self::touch(tx, session, at)?;
            tx.execute(
                "INSERT INTO usage (session_id, at, provider, credential, model, input_tokens, \
                 output_tokens, cached_input_tokens, reasoning_tokens, cost_usd) VALUES (?1, ?2, ?3, \
                 ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    session.as_str(),
                    stamp(at),
                    usage.provider,
                    usage.credential,
                    usage.model,
                    usage.input_tokens as i64,
                    usage.output_tokens as i64,
                    usage.cached_input_tokens as i64,
                    usage.reasoning_tokens as i64,
                    usage.cost_usd,
                ],
            )
            .map_err(|err| fail("could not record usage", err))?;
            Ok(())
        })
    }

    /// What a session has spent, summed from its rows.
    ///
    /// A session with no usage rows totals zero and is not an error: a chat that has not called a
    /// model yet has cost nothing.
    pub fn totals(&self, session: &SessionId) -> Result<Totals> {
        let conn = self.lock();
        let totals = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0), \
                        COALESCE(SUM(cached_input_tokens), 0), COALESCE(SUM(reasoning_tokens), 0), \
                        COALESCE(SUM(cost_usd), 0.0) FROM usage WHERE session_id = ?1",
                [session.as_str()],
                |row| {
                    Ok(Totals {
                        provider_calls: row.get::<_, i64>(0)? as u64,
                        input_tokens: row.get::<_, i64>(1)? as u64,
                        output_tokens: row.get::<_, i64>(2)? as u64,
                        cached_input_tokens: row.get::<_, i64>(3)? as u64,
                        reasoning_tokens: row.get::<_, i64>(4)? as u64,
                        cost_usd: row.get(5)?,
                    })
                },
            )
            .map_err(|err| fail("could not total the usage rows", err))?;
        Ok(totals)
    }

    // -- export ---------------------------------------------------------------------------------

    /// Write a session out as JSON or Markdown.
    pub fn export(&self, session: &SessionId, format: ExportFormat) -> Result<String> {
        let loaded = self.load(session)?;
        match format {
            ExportFormat::Json => {
                let totals = self.totals(session)?;
                crate::session::export_json(&loaded, totals)
            }
            ExportFormat::Markdown => Ok(crate::session::export_markdown(&loaded)),
        }
    }

    // -- internals ------------------------------------------------------------------------------

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A poisoned lock means a previous holder panicked inside a transaction, which rolls back —
        // so the database is consistent and the honest thing is to keep serving.
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn with_tx<T>(&self, work: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let mut conn = self.lock();
        let tx = conn
            .transaction()
            .map_err(|err| fail("could not begin a transaction", err))?;
        let value = work(&tx)?;
        tx.commit()
            .map_err(|err| fail("could not commit a transaction", err))?;
        Ok(value)
    }

    fn missing(session: &SessionId) -> HxError {
        HxError::NotFound(format!("session {}", session.as_str()))
    }

    /// The next sequence number for a session's transcript or event stream.
    fn next_seq(tx: &Transaction<'_>, table: &str, session: &SessionId) -> Result<i64> {
        // The table name is a literal from one of two call sites, never user input.
        let sql = match table {
            "messages" => "SELECT COALESCE(MAX(seq), 0) + 1 FROM messages WHERE session_id = ?1",
            "events" => "SELECT COALESCE(MAX(seq), 0) + 1 FROM events WHERE session_id = ?1",
            other => {
                return Err(HxError::Store(format!(
                    "'{other}' is not a table with a sequence column"
                )))
            }
        };
        tx.query_row(sql, [session.as_str()], |row| row.get(0))
            .map_err(|err| fail("could not read the next sequence number", err))
    }

    fn next_message_seq(&self, session: &SessionId) -> Result<u64> {
        let conn = self.lock();
        let seq: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM messages WHERE session_id = ?1",
                [session.as_str()],
                |row| row.get(0),
            )
            .map_err(|err| fail("could not read the next sequence number", err))?;
        Ok(seq as u64)
    }

    /// Bump `updated_at`, refusing to write into a session that does not exist.
    ///
    /// The check exists so that appending to a deleted or mistyped session id is a `NotFound` the
    /// caller can act on, rather than a foreign-key failure from inside SQLite.
    fn touch(tx: &Transaction<'_>, session: &SessionId, at: DateTime<Utc>) -> Result<()> {
        let touched = tx
            .execute(
                "UPDATE sessions SET updated_at = ?2 WHERE id = ?1",
                params![session.as_str(), stamp(at)],
            )
            .map_err(|err| fail("could not touch the session", err))?;
        if touched == 0 {
            return Err(Self::missing(session));
        }
        Ok(())
    }
}

fn read_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRecord> {
    let created_at: String = row.get(5)?;
    let updated_at: String = row.get(6)?;
    Ok(SessionRecord {
        id: SessionId::from_raw(row.get::<_, String>(0)?),
        title: row.get(1)?,
        agent: row
            .get::<_, Option<String>>(2)?
            .map(hx_core::ids::AgentId::from_raw),
        workspace: row.get(3)?,
        model: row.get(4)?,
        // A stored timestamp that will not parse is not a row that can be ordered or shown, so it
        // becomes an error with the text in it rather than a silent "now".
        created_at: parse_stamp(&created_at).unwrap_or(DateTime::<Utc>::MIN_UTC),
        updated_at: parse_stamp(&updated_at).unwrap_or(DateTime::<Utc>::MIN_UTC),
    })
}

fn read_totals(row: &rusqlite::Row<'_>, offset: usize) -> rusqlite::Result<Totals> {
    Ok(Totals {
        provider_calls: row.get::<_, i64>(offset)? as u64,
        input_tokens: row.get::<_, i64>(offset + 1)? as u64,
        output_tokens: row.get::<_, i64>(offset + 2)? as u64,
        cached_input_tokens: row.get::<_, i64>(offset + 3)? as u64,
        reasoning_tokens: row.get::<_, i64>(offset + 4)? as u64,
        cost_usd: row.get(offset + 5)?,
    })
}

/// Rebuild a message from its two columns.
///
/// The role is parsed from its column and the parts from their JSON, which means a part type this
/// build has never seen round-trips unchanged: the store does not interpret what it stores.
fn read_message(role: &str, parts: &str) -> Result<Message> {
    let role = match role {
        "system" => Role::System,
        "user" => Role::User,
        "assistant" => Role::Assistant,
        "tool" => Role::Tool,
        other => {
            return Err(HxError::Store(format!(
                "a stored message has role '{other}', which this build does not know"
            )))
        }
    };

    let parts: Vec<Part> = serde_json::from_str(parts)
        .map_err(|err| HxError::Store(format!("a stored message no longer parses: {err}")))?;

    Ok(Message { role, parts })
}

/// Expand a leading `~` in a configured path.
///
/// The config model's default data directory is the literal string `~/.hx`, and nothing else in the
/// workspace expands it — a shell would, but a daemon started by systemd has no shell.
pub(crate) fn expand_home(path: &str) -> PathBuf {
    let home = {
        #[cfg(windows)]
        {
            std::env::var_os("USERPROFILE")
        }
        #[cfg(not(windows))]
        {
            std::env::var_os("HOME")
        }
    };

    match path.strip_prefix("~/") {
        Some(rest) => match home {
            Some(home) => PathBuf::from(home).join(rest),
            // Left alone rather than guessed at: a relative `~/...` directory is visibly wrong in
            // an error message, where an invented one would look intentional.
            None => PathBuf::from(path),
        },
        None => PathBuf::from(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_core::event::{AgentEvent, StopReason};
    use hx_core::ids::{AgentId, ToolCallId};
    use serde_json::json;

    fn at(offset: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + offset, 0).unwrap()
    }

    fn store() -> Store {
        Store::in_memory().expect("in-memory store")
    }

    fn call(id: &str) -> Message {
        Message::new(
            Role::Assistant,
            vec![Part::ToolCall {
                id: ToolCallId::from(id),
                name: "shell".into(),
                arguments: json!({ "cmd": "cargo test" }),
            }],
        )
    }

    #[test]
    fn a_new_store_is_migrated_and_empty() {
        let store = store();
        assert!(store.path().is_none());
        assert_eq!(store.schema_version().unwrap(), schema::SCHEMA_VERSION);
        assert_eq!(store.count().unwrap(), 0);
        assert!(store.list(10).unwrap().is_empty());
    }

    #[test]
    fn a_session_round_trips_through_its_row() {
        let store = store();
        let created = store
            .create(
                NewSession::new()
                    .titled("fix the build")
                    .in_workspace("/w")
                    .with_model("qwen3-32b")
                    .run_by(AgentId::from("agt_1")),
                at(0),
            )
            .unwrap();

        let read = store.record(&created.id).unwrap();
        assert_eq!(read, created);
        assert_eq!(read.title, "fix the build");
        assert_eq!(read.agent.as_ref().unwrap().as_str(), "agt_1");
        assert_eq!(read.created_at, read.updated_at);
    }

    #[test]
    fn an_untitled_session_is_still_listable() {
        let store = store();
        let record = store.create(NewSession::new(), at(0)).unwrap();
        assert_eq!(record.title, "untitled");
        assert!(record.workspace.is_none() && record.model.is_none());
    }

    #[test]
    fn a_missing_session_is_not_found_rather_than_an_empty_one() {
        let store = store();
        let missing = SessionId::from_raw("ses_nope");
        assert!(matches!(store.record(&missing), Err(HxError::NotFound(_))));
        assert!(matches!(store.load(&missing), Err(HxError::NotFound(_))));
        assert!(matches!(
            store.append(&missing, &Message::user("hi"), at(0)),
            Err(HxError::NotFound(_))
        ));
        assert!(matches!(
            store.rename(&missing, "x", at(0)),
            Err(HxError::NotFound(_))
        ));
        assert!(!store.delete(&missing).unwrap(), "nothing to delete");
    }

    #[test]
    fn appending_assigns_sequence_numbers_the_caller_does_not_have_to_track() {
        let store = store();
        let session = store.create(NewSession::new(), at(0)).unwrap().id;

        assert_eq!(
            store
                .append(&session, &Message::user("one"), at(1))
                .unwrap(),
            1
        );
        assert_eq!(store.append(&session, &call("tc_1"), at(2)).unwrap(), 2);
        assert_eq!(
            store
                .append(
                    &session,
                    &Message::tool_result(ToolCallId::from("tc_1"), true, "ok"),
                    at(3)
                )
                .unwrap(),
            3
        );

        let messages = store.messages(&session).unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].text(), "one");
        assert_eq!(store.message_count(&session).unwrap(), 3);
    }

    #[test]
    fn a_batch_is_written_whole_or_not_at_all() {
        let store = store();
        let session = store.create(NewSession::new(), at(0)).unwrap().id;
        store
            .append(&session, &Message::user("one"), at(1))
            .unwrap();

        let last = store
            .append_all(
                &session,
                &[Message::assistant("two"), Message::user("three")],
                at(2),
            )
            .unwrap();
        assert_eq!(last, 3, "the seq of the last message written");

        // An empty batch writes nothing and reports the seq it would have taken — one past the
        // end — so a caller that loops over deltas does not have to special-case it.
        assert_eq!(store.append_all(&session, &[], at(3)).unwrap(), 3);
        assert_eq!(store.message_count(&session).unwrap(), 3);
    }

    #[test]
    fn appending_touches_updated_at_but_not_created_at() {
        let store = store();
        let created = store.create(NewSession::new(), at(0)).unwrap();
        store
            .append(&created.id, &Message::user("hi"), at(600))
            .unwrap();

        let read = store.record(&created.id).unwrap();
        assert_eq!(read.created_at, at(0), "when it started never changes");
        assert_eq!(read.updated_at, at(600), "the list orders on this");
    }

    #[test]
    fn an_unknown_part_type_is_reported_rather_than_dropped() {
        // A row written by a newer build: the parts are valid JSON with a part type this build
        // does not know. Reading the transcript must fail loudly, because the alternative is a
        // message silently missing the thing the model was told.
        let store = store();
        let session = store.create(NewSession::new(), at(0)).unwrap().id;
        {
            let conn = store.lock();
            conn.execute(
                "INSERT INTO messages (session_id, seq, at, role, parts) VALUES (?1, 1, ?2, 'user', \
                 ?3)",
                params![
                    session.as_str(),
                    crate::session::stamp(at(0)),
                    r#"[{"type":"hologram","payload":"future"}]"#
                ],
            )
            .unwrap();
        }

        let err = store.messages(&session).unwrap_err();
        assert!(err.to_string().contains("no longer parses"), "{err}");
    }

    #[test]
    fn every_part_type_this_build_knows_round_trips() {
        let store = store();
        let session = store.create(NewSession::new(), at(0)).unwrap().id;
        let message = Message::new(
            Role::Assistant,
            vec![
                Part::Text {
                    text: "here:".into(),
                },
                Part::Image {
                    mime: "image/png".into(),
                    data_b64: "aGk=".into(),
                },
                Part::ToolCall {
                    id: ToolCallId::from("tc_1"),
                    name: "read_file".into(),
                    arguments: json!({ "path": "/w/a.png" }),
                },
            ],
        );
        store.append(&session, &message, at(1)).unwrap();

        let read = store.messages(&session).unwrap();
        assert_eq!(read, vec![message]);
    }

    #[test]
    fn deleting_a_session_takes_its_transcript_with_it() {
        let store = store();
        let session = store.create(NewSession::new(), at(0)).unwrap().id;
        store.append(&session, &Message::user("hi"), at(1)).unwrap();
        store
            .record_usage(&session, &UsageRecord::new("p", "c", "m", 10, 1), at(1))
            .unwrap();

        assert!(store.delete(&session).unwrap());
        assert_eq!(store.count().unwrap(), 0);
        assert_eq!(store.message_count(&session).unwrap(), 0);
        assert_eq!(store.totals(&session).unwrap().provider_calls, 0);
    }

    #[test]
    fn list_puts_the_most_recently_touched_session_first() {
        let store = store();
        let first = store
            .create(NewSession::new().titled("first"), at(0))
            .unwrap()
            .id;
        let second = store
            .create(NewSession::new().titled("second"), at(1))
            .unwrap()
            .id;
        store.append(&second, &Message::user("hi"), at(2)).unwrap();
        // The older session is touched last, so it becomes the newest activity.
        store.append(&first, &Message::user("hi"), at(3)).unwrap();

        let listed = store.list(10).unwrap();
        assert_eq!(listed[0].record.id, first);
        assert_eq!(listed[1].record.id, second);
        assert_eq!(listed[0].messages, 1);
        assert_eq!(listed[0].turns, 0);

        // And the limit is honoured.
        assert_eq!(store.list(1).unwrap().len(), 1);
    }

    #[test]
    fn the_list_counts_turns_as_assistant_messages() {
        let store = store();
        let session = store.create(NewSession::new(), at(0)).unwrap().id;
        store
            .append_all(
                &session,
                &[
                    Message::user("go"),
                    call("tc_1"),
                    Message::tool_result(ToolCallId::from("tc_1"), true, "ok"),
                    Message::assistant("done"),
                ],
                at(1),
            )
            .unwrap();

        let listed = store.list(1).unwrap();
        assert_eq!(listed[0].messages, 4);
        assert_eq!(listed[0].turns, 2, "the tool-calling turn and the answer");
    }

    #[test]
    fn renaming_reorders_the_list_because_a_rename_is_activity() {
        let store = store();
        let first = store
            .create(NewSession::new().titled("first"), at(0))
            .unwrap()
            .id;
        let second = store
            .create(NewSession::new().titled("second"), at(1))
            .unwrap()
            .id;

        store.rename(&first, "first, renamed", at(2)).unwrap();

        let listed = store.list(10).unwrap();
        assert_eq!(listed[0].record.id, first);
        assert_eq!(listed[0].record.title, "first, renamed");
        assert_eq!(listed[1].record.id, second);
    }

    #[test]
    fn usage_rows_add_up_into_totals() {
        let store = store();
        let session = store.create(NewSession::new(), at(0)).unwrap().id;

        store
            .record_usage(
                &session,
                &UsageRecord::new("openrouter", "or-main", "qwen3-32b", 1_000, 200)
                    .cached(400)
                    .reasoning(50)
                    .costing(0.012),
                at(1),
            )
            .unwrap();
        store
            .record_usage(
                &session,
                &UsageRecord::new("openrouter", "or-main", "qwen3-32b", 500, 100).costing(0.004),
                at(2),
            )
            .unwrap();

        let totals = store.totals(&session).unwrap();
        assert_eq!(totals.provider_calls, 2);
        assert_eq!(totals.input_tokens, 1_500);
        assert_eq!(totals.output_tokens, 300);
        assert_eq!(totals.cached_input_tokens, 400);
        assert_eq!(totals.reasoning_tokens, 50);
        assert!(
            (totals.cost_usd - 0.016).abs() < 1e-9,
            "{}",
            totals.cost_usd
        );

        // The list carries the same totals, so a client does not need a second call per row.
        let listed = store.list(1).unwrap();
        assert_eq!(listed[0].totals, totals);
    }

    #[test]
    fn a_session_that_has_not_called_a_model_totals_zero() {
        let store = store();
        let session = store.create(NewSession::new(), at(0)).unwrap().id;
        let totals = store.totals(&session).unwrap();
        assert_eq!(totals, Totals::default());
    }

    #[test]
    fn a_real_write_chain_verifies_and_an_edited_row_does_not() {
        // The module tests prove the arithmetic; this proves the *store* builds the chain, and that
        // tampering is caught in the place an attacker would actually do it — a direct UPDATE against
        // the database, which no amount of in-process care can prevent.
        let store = store();
        let session = store.create(NewSession::new(), at(0)).unwrap().id;
        let agent = AgentId::from("agt_1");

        let mut events = Vec::new();
        for turn in 1..=4 {
            events.push(AgentEvent::TurnStarted {
                agent: agent.clone(),
                turn,
            });
            store
                .append_event(&session, events.last().unwrap(), at(turn as i64))
                .unwrap();
        }

        assert_eq!(
            store.unchained_events(&session).unwrap(),
            0,
            "every row is chained"
        );
        assert_eq!(
            store.verify_audit(&session).unwrap(),
            None,
            "an honest log verifies"
        );

        // Rewrite a row the way someone covering their tracks would: straight SQL, no store method.
        // The digest column belongs to the old content, so the chain must notice.
        let conn = store.lock();
        conn.execute(
            "UPDATE events SET payload = ?1 WHERE session_id = ?2 AND seq = 3",
            params![
                "{\"event\":\"TurnStarted\",\"agent\":\"agt_1\",\"turn\":99}",
                session.as_str()
            ],
        )
        .unwrap();
        drop(conn);

        let found = store
            .verify_audit(&session)
            .unwrap()
            .expect("the edited row is caught");
        assert_eq!(
            found.seq,
            3,
            "at the row that was edited: {}",
            found.explain()
        );
        assert!(
            found.explain().contains("edited after it was written"),
            "{}",
            found.explain()
        );
    }

    #[test]
    fn an_event_written_after_a_tampered_one_still_chains_from_it() {
        // A chain is append-only: the next row is built from whatever is stored, so tampering is
        // *detected* rather than prevented. This pins that behaviour deliberately — a store that
        // refused to append to a broken chain would be a denial of service on the audit log itself,
        // and an attacker could silence the record entirely by corrupting one row.
        let store = store();
        let session = store.create(NewSession::new(), at(0)).unwrap().id;
        let agent = AgentId::from("agt_1");
        let first = AgentEvent::TurnStarted {
            agent: agent.clone(),
            turn: 1,
        };
        store.append_event(&session, &first, at(0)).unwrap();

        {
            let conn = store.lock();
            conn.execute(
                "UPDATE events SET digest = 'deadbeef' WHERE session_id = ?1 AND seq = 1",
                [session.as_str()],
            )
            .unwrap();
        }

        // Appending still works, and the break is still reported at row 1 — the corruption is not
        // laundered into a chain that verifies.
        let second = AgentEvent::TurnFinished {
            agent,
            turn: 1,
            stop: StopReason::Completed,
        };
        store.append_event(&session, &second, at(1)).unwrap();
        let found = store.verify_audit(&session).unwrap().expect("still broken");
        assert_eq!(found.seq, 1);
    }

    #[test]
    fn a_row_from_before_the_chain_existed_is_reported_rather_than_silently_trusted() {
        // An upgraded database keeps its history. Those rows carry no digest, and the honest answer
        // is to say how many were not verified — a report that claims "verified" over rows it never
        // checked is the failure mode this counter exists to prevent.
        let store = store();
        let session = store.create(NewSession::new(), at(0)).unwrap().id;
        let agent = AgentId::from("agt_1");
        store
            .append_event(&session, &AgentEvent::TurnStarted { agent, turn: 1 }, at(0))
            .unwrap();

        {
            let conn = store.lock();
            conn.execute(
                "UPDATE events SET digest = NULL WHERE session_id = ?1",
                [session.as_str()],
            )
            .unwrap();
        }

        assert_eq!(store.unchained_events(&session).unwrap(), 1);
        assert_eq!(
            store.verify_audit(&session).unwrap(),
            None,
            "nothing contradicts nothing"
        );
    }

    #[test]
    fn events_round_trip_and_keep_the_kind_the_payload_claims() {
        let store = store();
        let session = store.create(NewSession::new(), at(0)).unwrap().id;
        let agent = AgentId::from("agt_1");

        let events = vec![
            AgentEvent::TurnStarted {
                agent: agent.clone(),
                turn: 1,
            },
            AgentEvent::ApprovalRequested {
                agent: agent.clone(),
                approval: hx_core::ids::ApprovalId::from_raw("apr_1"),
                call: ToolCallId::from("tc_1"),
                reason: "deletes /tmp/build".into(),
                // The measured target travels with the event, so the stored trail records what the
                // approver was shown — not just that somebody said yes to something.
                targets: vec![hx_core::approval::Target::directory(
                    "/tmp/build",
                    12,
                    2048,
                    false,
                )],
            },
            AgentEvent::TurnFinished {
                agent,
                turn: 1,
                stop: StopReason::Completed,
            },
        ];
        for (offset, event) in events.iter().enumerate() {
            store
                .append_event(&session, event, at(offset as i64))
                .unwrap();
        }

        assert_eq!(store.events(&session).unwrap(), events);
        assert_eq!(store.event_count(&session, "turn_started").unwrap(), 1);
        assert_eq!(
            store.event_count(&session, "approval_requested").unwrap(),
            1
        );
        assert_eq!(store.event_count(&session, "error").unwrap(), 0);
    }

    #[test]
    fn closing_interrupted_calls_is_idempotent() {
        let store = store();
        let session = store.create(NewSession::new(), at(0)).unwrap().id;
        store.append(&session, &Message::user("go"), at(1)).unwrap();
        store.append(&session, &call("tc_1"), at(2)).unwrap();

        let closed = store
            .close_interrupted(&session, "the daemon stopped before this call ran", at(3))
            .unwrap();
        assert_eq!(closed, vec![ToolCallId::from("tc_1")]);

        let loaded = store.load(&session).unwrap();
        assert!(!loaded.is_mid_flight());
        let result = loaded.messages.last().unwrap();
        assert_eq!(result.role, Role::Tool);
        assert!(
            matches!(&result.parts[0], Part::ToolResult { ok, content, .. }
                if !ok && content.contains("stopped before")),
            "{:?}",
            result.parts
        );

        // A second call has nothing to do — which is what makes it safe on every resume.
        assert!(store
            .close_interrupted(&session, "again", at(4))
            .unwrap()
            .is_empty());
        assert_eq!(store.message_count(&session).unwrap(), 3);
    }

    #[test]
    fn exporting_reaches_the_stored_content() {
        let store = store();
        let session = store
            .create(NewSession::new().titled("a run"), at(0))
            .unwrap()
            .id;
        store.append(&session, &Message::user("go"), at(1)).unwrap();
        store.append(&session, &call("tc_1"), at(2)).unwrap();
        store
            .append(
                &session,
                &Message::tool_result(ToolCallId::from("tc_1"), false, "boom"),
                at(3),
            )
            .unwrap();
        store
            .record_usage(&session, &UsageRecord::new("p", "c", "m", 7, 3), at(3))
            .unwrap();

        let json = store.export(&session, ExportFormat::Json).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["session"]["title"], "a run");
        assert_eq!(value["totals"]["input_tokens"], 7);
        assert_eq!(value["messages"].as_array().unwrap().len(), 3);

        let markdown = store.export(&session, ExportFormat::Markdown).unwrap();
        assert!(markdown.contains("# a run"), "{markdown}");
        assert!(
            markdown.contains("### tool result — `tc_1` (failed)"),
            "{markdown}"
        );
        assert!(markdown.contains("boom"), "{markdown}");
    }

    #[test]
    fn opening_a_file_creates_the_directory_it_needs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("data").join(DATABASE_FILE);
        let store = Store::open(&path).unwrap();

        assert_eq!(store.path(), Some(path.as_path()));
        let session = store.create(NewSession::new(), at(0)).unwrap().id;
        store.append(&session, &Message::user("hi"), at(1)).unwrap();
        drop(store);

        // Reopening is the interesting half: the file is a database, not a fresh one.
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.count().unwrap(), 1);
        assert_eq!(reopened.messages(&session).unwrap().len(), 1);
        assert_eq!(reopened.schema_version().unwrap(), schema::SCHEMA_VERSION);
    }

    #[test]
    fn a_second_connection_sees_a_committed_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DATABASE_FILE);
        let writer = Store::open(&path).unwrap();
        let reader = Store::open(&path).unwrap();

        let session = writer
            .create(NewSession::new().titled("shared"), at(0))
            .unwrap()
            .id;
        writer
            .append(&session, &Message::user("hi"), at(1))
            .unwrap();

        // Two connections to one file, which is the shape the daemon and a client have.
        assert_eq!(reader.count().unwrap(), 1);
        assert_eq!(reader.messages(&session).unwrap().len(), 1);
        assert_eq!(reader.record(&session).unwrap().title, "shared");
    }

    #[test]
    fn the_configured_data_directory_is_used_and_tilde_is_expanded() {
        let config = Config::default();
        assert_eq!(config.daemon.data_dir, "~/.hx");

        // Built without opening anything, so the path is what a daemon would use.
        let expanded = expand_home(&config.daemon.data_dir);
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from);
        match home {
            Some(home) => assert_eq!(expanded, home.join(".hx")),
            None => assert_eq!(expanded, PathBuf::from("~/.hx")),
        }

        // An absolute path is left alone, and so is a relative one that merely contains a `~`.
        assert_eq!(expand_home("/var/lib/hx"), PathBuf::from("/var/lib/hx"));
        assert_eq!(expand_home("./data"), PathBuf::from("./data"));
        assert_eq!(expand_home("~bad/data"), PathBuf::from("~bad/data"));
    }
}

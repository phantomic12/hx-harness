//! The database shape, and how it changes.
//!
//! ## Migrations are forward-only and versioned in the file
//!
//! `PRAGMA user_version` holds the schema version, and the version is written *inside* the same
//! transaction as the change it describes. A crash cannot leave a database that claims a version it
//! does not have, which is the failure mode that makes versioned schemas untrustworthy.
//!
//! ## A newer database is refused, not opened
//!
//! If the file's version is higher than this build understands, opening it read-write would let an
//! older build insert rows that violate constraints it cannot see, or fail a later migration's
//! `ALTER`. Neither is recoverable from the user's side, so the store refuses and says which
//! versions are involved. That refusal is the one place an operator needs a clear sentence rather
//! than a backtrace.
//!
//! ## Why `STRICT`
//!
//! SQLite will happily store the string `"nope"` in an INTEGER column and hand back whatever it
//! feels like later. `STRICT` turns that into an error at insert time — the cheapest possible place
//! to find a type mistake in code that builds SQL by hand.

use hx_core::error::{HxError, Result};
use rusqlite::Connection;

/// The schema this build writes and understands.
pub const SCHEMA_VERSION: i64 = 3;

/// `(version, sql)`, applied in order. Never edit an applied migration: add another.
pub(crate) const MIGRATIONS: &[(i64, &str)] = &[(1, V1), (2, V2), (3, V3)];

/// Adding a column is what makes the chain retrofittable: a database written before this migration
/// keeps its rows and gets a NULL digest for each, which `verify` reports as unchained rather than as
/// tampered with. Refusing to open an old database would be the other defensible choice and was
/// rejected: an audit log that disappears when the tool is upgraded is a worse audit log.
const V2: &str = r#"
ALTER TABLE events ADD COLUMN digest TEXT;
"#;

/// Eval runs: one job row owning many trial rows.
///
/// A trial carries its own outcome and cost, and the job row keeps running totals so `hx eval
/// results` lists jobs without summing trials per row. The totals are maintained by the insert
/// path in the same transaction, not recomputed — a job row is therefore a cache that trusts its
/// writer, which is the store itself.
const V3: &str = r#"
CREATE TABLE eval_jobs (
    id          TEXT PRIMARY KEY,
    dataset     TEXT NOT NULL,
    role        TEXT NOT NULL,
    task        TEXT NOT NULL,
    trials      INTEGER NOT NULL,
    passed      INTEGER NOT NULL,
    total_cost  REAL NOT NULL,
    created_at  TEXT NOT NULL
) STRICT;

CREATE TABLE eval_trials (
    id          TEXT PRIMARY KEY,
    job_id      TEXT NOT NULL REFERENCES eval_jobs (id),
    session_id  TEXT,
    task        TEXT NOT NULL,
    passed      INTEGER NOT NULL,
    reason      TEXT NOT NULL,
    duration_ms INTEGER NOT NULL,
    tokens_in   INTEGER NOT NULL,
    tokens_out  INTEGER NOT NULL,
    cost_usd    REAL NOT NULL,
    created_at  TEXT NOT NULL
) STRICT;

-- `trials_for_job` is the read path: every trial of one run, oldest first.
CREATE INDEX eval_trials_by_job ON eval_trials (job_id);
"#;

const V1: &str = r#"
CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    agent       TEXT,
    workspace   TEXT,
    model       TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;

-- `list` is newest-first and is what a client calls on connect.
CREATE INDEX sessions_by_updated ON sessions (updated_at DESC);

-- The transcript. `role` is a column because queries filter on it; `parts` is JSON because the
-- message shape belongs to `hx-core` and must be able to grow without a migration here.
CREATE TABLE messages (
    session_id  TEXT    NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    at          TEXT    NOT NULL,
    role        TEXT    NOT NULL,
    parts       TEXT    NOT NULL,
    PRIMARY KEY (session_id, seq)
) STRICT;

-- The event stream, stored beside the transcript rather than derived from it: a reconnecting
-- client redraws what happened instead of re-inferring it. `kind` is a queryable copy of the
-- payload's own tag, so "every approval request in this session" is an index lookup.
CREATE TABLE events (
    session_id  TEXT    NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    at          TEXT    NOT NULL,
    kind        TEXT    NOT NULL,
    payload     TEXT    NOT NULL,
    PRIMARY KEY (session_id, seq)
) STRICT;

CREATE INDEX events_by_kind ON events (session_id, kind);

-- One row per provider call. Money is `REAL` and therefore approximate, which is honest: it is
-- what the price table said, not what an invoice will say.
CREATE TABLE usage (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          TEXT    NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    at                  TEXT    NOT NULL,
    provider            TEXT    NOT NULL,
    credential          TEXT    NOT NULL,
    model               TEXT    NOT NULL,
    input_tokens        INTEGER NOT NULL,
    output_tokens       INTEGER NOT NULL,
    cached_input_tokens INTEGER NOT NULL,
    reasoning_tokens    INTEGER NOT NULL,
    cost_usd            REAL    NOT NULL
) STRICT;

CREATE INDEX usage_by_session ON usage (session_id);
"#;

/// Bring `conn` up to [`SCHEMA_VERSION`], returning the version it ends at.
pub fn migrate(conn: &mut Connection) -> Result<i64> {
    let current = version(conn)?;

    if current > SCHEMA_VERSION {
        return Err(HxError::Store(format!(
            "this database was written by a newer build (schema {current}; this build understands \
             {SCHEMA_VERSION}). Refusing to open it: an older build writing to a newer schema \
             silently loses whatever it cannot see. Use the newer build, or point this one at a \
             different data directory."
        )));
    }

    for (target, sql) in MIGRATIONS {
        if *target <= current {
            continue;
        }
        let tx = conn
            .transaction()
            .map_err(|err| fail("could not start a migration", err))?;
        tx.execute_batch(sql)
            .map_err(|err| fail(&format!("migration {target} failed"), err))?;
        // Same transaction as the change: a database can never claim a version it does not have.
        tx.pragma_update(None, "user_version", *target)
            .map_err(|err| fail("could not record the schema version", err))?;
        tx.commit()
            .map_err(|err| fail("could not commit a migration", err))?;
    }

    version(conn)
}

/// The version recorded in the file.
pub fn version(conn: &Connection) -> Result<i64> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|err| fail("could not read the schema version", err))
}

/// One place that turns a `rusqlite` failure into an `HxError`, so every message names what was
/// being attempted and none of them is a bare "database error".
pub(crate) fn fail(what: &str, err: rusqlite::Error) -> HxError {
    HxError::Store(format!("{what}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open() -> Connection {
        Connection::open_in_memory().expect("in-memory database")
    }

    #[test]
    fn a_fresh_database_is_migrated_to_the_current_version() {
        let mut conn = open();
        assert_eq!(version(&conn).unwrap(), 0, "nothing has run yet");
        assert_eq!(migrate(&mut conn).unwrap(), SCHEMA_VERSION);
        assert_eq!(version(&conn).unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn migrating_twice_changes_nothing() {
        let mut conn = open();
        migrate(&mut conn).unwrap();
        // The second call must be a no-op rather than re-running `CREATE TABLE`.
        assert_eq!(migrate(&mut conn).unwrap(), SCHEMA_VERSION);
        assert_eq!(version(&conn).unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn a_database_from_a_newer_build_is_refused_with_both_versions_in_the_message() {
        let mut conn = open();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 7)
            .unwrap();

        let err = migrate(&mut conn).unwrap_err();
        let text = err.to_string();
        assert!(text.contains(&(SCHEMA_VERSION + 7).to_string()), "{text}");
        assert!(text.contains("newer build"), "{text}");
        // Refused *before* touching anything: the version is exactly as it was found.
        assert_eq!(version(&conn).unwrap(), SCHEMA_VERSION + 7);
    }

    #[test]
    fn every_table_exists_after_migrating() {
        let mut conn = open();
        migrate(&mut conn).unwrap();
        for table in [
            "sessions",
            "messages",
            "events",
            "usage",
            "eval_jobs",
            "eval_trials",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "{table} is missing");
        }
    }

    #[test]
    fn strict_tables_refuse_a_value_of_the_wrong_type() {
        // The reason for `STRICT`: without it this insert succeeds, storing the text `"not a
        // number"` in an INTEGER column, and the failure surfaces much later as a comparison that
        // is silently false. The message quoted here is SQLite's own type error, which only a
        // STRICT table produces.
        let mut conn = open();
        migrate(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO sessions (id, title, created_at, updated_at) VALUES ('s', 't', 'x', 'x')",
            [],
        )
        .unwrap();
        let err = conn
            .execute(
                "INSERT INTO messages (session_id, seq, at, role, parts) VALUES ('s', 'not a number', \
                 'x', 'user', '[]')",
                [],
            )
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot store TEXT value in INTEGER column"),
            "{err}"
        );
    }

    #[test]
    fn a_cascade_needs_the_pragma_and_the_store_sets_it() {
        // The honest version of "deleting a session takes its transcript with it": the cascade is
        // SQLite's behaviour only while `foreign_keys` is on. rusqlite's bundled build happens to
        // default it on, but that is a property of the linked SQLite rather than of this file, so
        // `Store::configure` sets it explicitly — and this test shows what hangs on it.
        let mut conn = open();
        migrate(&mut conn).unwrap();

        // With the pragma off, a deleted session leaves its transcript behind forever.
        conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
        conn.execute(
            "INSERT INTO sessions (id, title, created_at, updated_at) VALUES ('s', 't', 'x', 'x')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages (session_id, seq, at, role, parts) VALUES ('s', 1, 'x', 'user', '[]')",
            [],
        )
        .unwrap();
        conn.execute("DELETE FROM sessions WHERE id = 's'", [])
            .unwrap();
        let orphans: i64 = conn
            .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(orphans, 1, "without the pragma there is no cascade");

        // With it on, the same delete takes the transcript with it.
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        conn.execute(
            "INSERT INTO sessions (id, title, created_at, updated_at) VALUES ('s2', 't', 'x', 'x')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages (session_id, seq, at, role, parts) VALUES ('s2', 1, 'x', 'user', '[]')",
            [],
        )
        .unwrap();
        conn.execute("DELETE FROM sessions WHERE id = 's2'", [])
            .unwrap();
        let remaining: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE session_id = 's2'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0);
    }
}

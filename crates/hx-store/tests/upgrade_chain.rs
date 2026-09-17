//! The upgrade path, against a real file: a database whose events predate the chain.
use hx_core::config::Config;
use hx_core::event::AgentEvent;
use hx_core::ids::AgentId;
use hx_store::{NewSession, Store};

#[test]
fn events_written_after_an_upgrade_are_chained() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hx.db");

    // A V1-shaped database: the events table with no digest column.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE sessions (id TEXT PRIMARY KEY, title TEXT NOT NULL, agent TEXT,
                 workspace TEXT, model TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL) STRICT;
             CREATE TABLE events (session_id TEXT NOT NULL, seq INTEGER NOT NULL, at TEXT NOT NULL,
                 kind TEXT NOT NULL, payload TEXT NOT NULL,
                 PRIMARY KEY (session_id, seq)) STRICT;
             INSERT INTO sessions VALUES ('ses_old','t',NULL,NULL,NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');
             INSERT INTO events VALUES ('ses_old',1,'2026-01-01T00:00:00Z','turn_started','{}');
             PRAGMA user_version = 1;",
        )
        .unwrap();
    }

    let mut config = Config::from_yaml("search: { backends: [] }").unwrap();
    config.daemon.data_dir = dir.path().display().to_string();
    let store = Store::from_config(&config).expect("opens and migrates");
    assert_eq!(
        store.schema_version().unwrap(),
        2,
        "the V1 database was upgraded"
    );

    let session = store
        .create(NewSession::new(), chrono::Utc::now())
        .unwrap()
        .id;
    let agent = AgentId::from("agt_1");
    store
        .append_event(
            &session,
            &AgentEvent::TurnStarted { agent, turn: 1 },
            chrono::Utc::now(),
        )
        .unwrap();

    let conn = rusqlite::Connection::open(&path).unwrap();
    let chained: i64 = conn
        .query_row("SELECT COUNT(digest) FROM events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(chained, 1, "the new event carries a digest");
    assert_eq!(
        Store::from_config(&config)
            .unwrap()
            .unchained_events(&session)
            .unwrap(),
        0
    );
}

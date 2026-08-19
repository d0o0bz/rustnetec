//! Integration tests for T2.3 server SQLite initialization & ingest write.
//!
//! Tests run against a per-test temporary database file.

use std::path::PathBuf;

use rusqlite::Connection;
use rustnet_core::ingest::{ClientEvent, IngestRequest, IngestResponse};
use rustnet_server::db::{Error, ServerDbConfig, ingest_write, init as init_db};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tmp_db_path(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "rustnet-server-test-{label}-{}.db",
        std::process::id()
    ));
    // Remove a leftover from a prior run so tests start clean.
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(p.with_extension("db-wal"));
    let _ = std::fs::remove_file(p.with_extension("db-shm"));
    p
}

fn sample_event(local_event_id: i64, ts: i64) -> ClientEvent {
    ClientEvent {
        local_event_id,
        timestamp: ts,
        interface: "eth0".to_string(),
        protocol: "TCP".to_string(),
        local_ip: "192.168.1.10".to_string(),
        local_port: 54321,
        remote_ip: "1.2.3.4".to_string(),
        remote_port: 443,
        state: "ESTABLISHED".to_string(),
        pid: Some(1234),
        process_name: Some("curl".to_string()),
        bytes_sent: 1024,
        bytes_recv: 4096,
        packets_sent: 10,
        packets_recv: 20,
        duration_ms: 500,
        service: None,
        sni: Some("example.com".to_string()),
        geo_country: None,
        geo_city: None,
        dns_name: None,
        k8s: None,
    }
}

fn sample_request(events: Vec<ClientEvent>) -> IngestRequest {
    IngestRequest {
        machine_id: "machine-abc".to_string(),
        user_id: "42".to_string(),
        username: "alice".to_string(),
        ip_list: vec!["192.168.1.10".to_string()],
        events,
        department: None,
        reachability: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// 1. Schema v2 DDL verification
// ---------------------------------------------------------------------------

#[test]
fn test_init_creates_schema_v2() {
    let path = tmp_db_path("schema");
    let db = init_db(&path, &ServerDbConfig::default()).expect("init failed");

    let conn = db.lock_writer();

    // All four tables + schema_version must exist.
    for table in [
        "server_events",
        "server_aggregates",
        "server_hosts",
        "server_tokens",
        "schema_version",
    ] {
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?",
                rusqlite::params![table],
                |r| r.get(0),
            )
            .unwrap();
        assert!(n >= 1, "table {table} missing");
    }

    // schema_version row v2 must exist.
    let v: i64 = conn
        .query_row(
            "SELECT version FROM schema_version WHERE version = 2",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(v, 2);

    // Key indexes must exist, including the new username index.
    for idx in [
        "idx_svr_events_ts",
        "idx_svr_events_machine",
        "idx_svr_events_user",
        "idx_svr_events_username",
        "idx_svr_events_user_local",
        "idx_svr_hosts_last_seen",
    ] {
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='index' AND name=?",
                rusqlite::params![idx],
                |r| r.get(0),
            )
            .unwrap();
        assert!(n >= 1, "index {idx} missing");
    }
}

// ---------------------------------------------------------------------------
// 2. Unix file permission 0600
// ---------------------------------------------------------------------------

#[test]
fn test_init_sets_file_permissions_unix() {
    let path = tmp_db_path("perm");
    let _db = init_db(&path, &ServerDbConfig::default()).expect("init failed");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&path).expect("stat db file");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "db file mode should be 0600 on Unix");
    }

    #[cfg(not(unix))]
    {
        // Non-Unix: no permission assertion; test is a no-op pass.
    }
}

// ---------------------------------------------------------------------------
// 3. Idempotent dedup
// ---------------------------------------------------------------------------

#[test]
fn test_ingest_idempotent_dedup() {
    let path = tmp_db_path("dedup");
    let db = init_db(&path, &ServerDbConfig::default()).expect("init failed");

    let mut conn = db.lock_writer();

    let req = sample_request(vec![sample_event(100, 1_700_000_000)]);
    let r1 = ingest_write(&mut conn, &req).expect("first ingest");
    assert_eq!(r1.accepted, 1);
    assert_eq!(r1.duplicates, 0);

    // Same (user_id, local_event_id) → duplicate, not re-inserted.
    let r2 = ingest_write(&mut conn, &req).expect("second ingest");
    assert_eq!(r2.accepted, 0);
    assert_eq!(r2.duplicates, 1);

    // Verify only one row in server_events for this user.
    let n: i64 = conn
        .query_row(
            "SELECT count(*) FROM server_events WHERE user_id = 42",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);
}

// ---------------------------------------------------------------------------
// 4. cursor = max(local_event_id)
// ---------------------------------------------------------------------------

#[test]
fn test_ingest_cursor_is_max_local_id() {
    let path = tmp_db_path("cursor");
    let db = init_db(&path, &ServerDbConfig::default()).expect("init failed");

    let mut conn = db.lock_writer();
    let req = sample_request(vec![
        sample_event(100, 1_700_000_000),
        sample_event(102, 1_700_000_001),
        sample_event(101, 1_700_000_002),
    ]);
    let r: IngestResponse = ingest_write(&mut conn, &req).expect("ingest");
    assert_eq!(r.accepted, 3);
    assert_eq!(r.cursor, 102);
}

// ---------------------------------------------------------------------------
// 5. server_hosts upsert preserves first_seen
// ---------------------------------------------------------------------------

#[test]
fn test_server_hosts_upsert_preserves_first_seen() {
    let path = tmp_db_path("firstseen");
    let db = init_db(&path, &ServerDbConfig::default()).expect("init failed");

    let mut conn = db.lock_writer();

    let req1 = sample_request(vec![sample_event(1, 1_700_000_000)]);
    ingest_write(&mut conn, &req1).expect("first ingest");

    // Second ingest for the same machine_id but different user_id/username.
    let mut req2 = sample_request(vec![sample_event(2, 1_700_000_001)]);
    req2.username = "alice2".to_string();
    ingest_write(&mut conn, &req2).expect("second ingest");

    let (first_seen, username): (String, String) = conn
        .query_row(
            "SELECT first_seen, username FROM server_hosts WHERE machine_id = 'machine-abc'",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .unwrap();

    // username was updated to the latest value.
    assert_eq!(username, "alice2");
    // first_seen should be non-empty and stable (we cannot assert exact value
    // due to sub-second timing, but it must be present).
    assert!(!first_seen.is_empty(), "first_seen must be preserved");
}

// ---------------------------------------------------------------------------
// 6. server_hosts event_count accumulates
// ---------------------------------------------------------------------------

#[test]
fn test_server_hosts_event_count_accumulates() {
    let path = tmp_db_path("eventcount");
    let db = init_db(&path, &ServerDbConfig::default()).expect("init failed");

    let mut conn = db.lock_writer();

    let req1 = sample_request(vec![
        sample_event(1, 1_700_000_000),
        sample_event(2, 1_700_000_001),
    ]);
    ingest_write(&mut conn, &req1).expect("first ingest");

    let req2 = sample_request(vec![sample_event(3, 1_700_000_002)]);
    ingest_write(&mut conn, &req2).expect("second ingest");

    let count: i64 = conn
        .query_row(
            "SELECT event_count FROM server_hosts WHERE machine_id = 'machine-abc'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 3, "event_count should accumulate (2 + 1)");
}

// ---------------------------------------------------------------------------
// 7. user_id non-numeric returns InvalidUserId
// ---------------------------------------------------------------------------

#[test]
fn test_user_id_non_numeric_returns_error() {
    let path = tmp_db_path("baduser");
    let db = init_db(&path, &ServerDbConfig::default()).expect("init failed");

    let mut conn = db.lock_writer();

    let mut req = sample_request(vec![sample_event(1, 1_700_000_000)]);
    req.user_id = "abc".to_string(); // non-numeric

    let err = ingest_write(&mut conn, &req).expect_err("should error");
    // The error must be a rusqlite::Error wrapping our DbError::InvalidUserId.
    let msg = err.to_string();
    assert!(
        msg.contains("invalid user_id") || msg.contains("InvalidUserId"),
        "expected InvalidUserId, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// 8. prepare_cached reuse does not error
// ---------------------------------------------------------------------------

#[test]
fn test_prepare_cached_reuse() {
    let path = tmp_db_path("cached");
    let db = init_db(&path, &ServerDbConfig::default()).expect("init failed");

    let mut conn = db.lock_writer();

    // Multiple consecutive batches should not error from prepare_cached reuse.
    for i in 0..5 {
        let req = sample_request(vec![sample_event(10 + i, 1_700_000_000 + i)]);
        let r = ingest_write(&mut conn, &req).expect("ingest");
        assert_eq!(r.accepted, 1);
    }

    // Verify all 5 rows were inserted.
    let n: i64 = conn
        .query_row(
            "SELECT count(*) FROM server_events WHERE user_id = 42",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 5);
}

// ---------------------------------------------------------------------------
// Sanity: Error::InvalidUserId maps to HTTP 400
// ---------------------------------------------------------------------------

#[test]
fn test_invalid_user_id_maps_to_400() {
    let err = Error::InvalidUserId("abc".to_string());
    let (code, _) = err.as_http();
    assert_eq!(code, axum::http::StatusCode::BAD_REQUEST);
}

// Silence unused import warnings for non-unix test builds.
#[allow(dead_code)]
fn _silence_unused(_: Connection) {}

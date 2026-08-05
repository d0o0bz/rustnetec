//! Monthly time-partitioning for `server_events` (T2.5, §10.4).
//!
//! Once the events table grows past ~50 GB the single-table layout starts
//! to hurt. SQLite has no native partitioning, so we shard by month:
//!
//! - `server_events_YYYYMM` — same DDL + indexes as `server_events`,
//!   created lazily on first write into that month.
//! - **Write route**: ingest picks the partition by `ts` month.
//! - **Query route**: `UNION ALL` over the partitions that intersect the
//!   `from`/`to` window (or all partitions when no window is given).
//! - **Cleanup route**: whole partitions whose month is entirely older
//!   than the retention cutoff are `DROP`ped (see [`super::retention`]).
//!
//! The single `server_events` table is kept as the "unpartitioned" store
//! so the decision to partition is reversible: when
//! [`partitioning_active`] returns `false`, all reads/writes go to the
//! plain table and [`retention::purge_expired`] uses row-level `DELETE`.

use anyhow::{Context, Result};
use rusqlite::Connection;

/// File-size threshold (bytes) above which monthly partitioning kicks in.
/// 50 GB per `docs/数据模型设计.md` §10.4.
pub const PARTITION_THRESHOLD_BYTES: u64 = 50 * 1024 * 1024 * 1024;

/// Format a `YYYYMM` integer (e.g. `202608`) into the partition table name.
pub fn partition_table_name(month: i32) -> String {
    format!("server_events_{month:06}")
}

/// Return the `YYYYMM` month for an RFC 3339 timestamp.
pub fn month_of(ts_rfc3339: &str) -> Option<i32> {
    use chrono::Datelike;
    let dt = chrono::DateTime::parse_from_rfc3339(ts_rfc3339).ok()?;
    let naive = dt.naive_local();
    let month = naive.month() as i32;
    let year = naive.year();
    Some(year * 100 + month)
}

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------

/// Decide whether monthly partitioning is active.
///
/// Activation is keyed off the database **file size**: once the `.db`
/// file crosses [`PARTITION_THRESHOLD_BYTES`], all subsequent writes are
/// routed to monthly partitions and the legacy `server_events` table stops
/// receiving new rows.
///
/// Returns `false` if the db path can't be stat'd (fresh/empty db, etc.),
/// which is the safe default — start unpartitioned.
pub fn partitioning_active(conn: &Connection) -> bool {
    // `PRAGMA database_list` gives us the on-disk path of the main db.
    let path_str: Option<String> = conn
        .query_row("PRAGMA database_list", [], |r| r.get::<_, String>(2))
        .ok();
    let Some(path_str) = path_str else {
        return false;
    };
    let path = std::path::Path::new(&path_str);
    let size = path.metadata().map(|m| m.len()).unwrap_or(0);
    size >= PARTITION_THRESHOLD_BYTES
}

// ---------------------------------------------------------------------------
// DDL
// ---------------------------------------------------------------------------

/// Create the monthly partition table for `month` (YYYYMM) if absent.
///
/// The partition mirrors the `server_events` schema (§3.2) **minus** the
/// `id INTEGER PRIMARY KEY AUTOINCREMENT` — partitions key off
/// `(user_id, local_event_id)` directly. Keeping `AUTOINCREMENT` per
/// partition would create colliding server-side ids across partitions.
pub fn ensure_partition(conn: &mut Connection, month: i32) -> Result<()> {
    let table = partition_table_name(month);
    let ddl = format!(
        r#"
        CREATE TABLE IF NOT EXISTS {table} (
            machine_id      TEXT    NOT NULL,
            user_id         INTEGER NOT NULL,
            username        TEXT    NOT NULL,
            ip_list         TEXT,
            local_event_id  INTEGER NOT NULL,
            ts              TEXT    NOT NULL,
            event_type      TEXT,
            ingest_ts       TEXT    NOT NULL,
            protocol        TEXT    NOT NULL,
            source_ip       TEXT    NOT NULL,
            source_port     INTEGER NOT NULL,
            dest_ip         TEXT    NOT NULL,
            dest_port       INTEGER NOT NULL,
            dest_hostname   TEXT,
            source_hostname TEXT,
            pid             INTEGER,
            process_ppid    INTEGER,
            process_name    TEXT,
            process_executable TEXT,
            process_uid     INTEGER,
            process_gid     INTEGER,
            attribution_match TEXT,
            rtt_ms          REAL,
            k8s_pod_uid     TEXT,
            k8s_pod_name    TEXT,
            k8s_pod_ns      TEXT,
            k8s_container_id TEXT,
            k8s_container_name TEXT,
            k8s_cgroup_path TEXT,
            service_name    TEXT,
            direction       TEXT,
            dpi_protocol    TEXT,
            dpi_domain      TEXT,
            geoip_country_code TEXT,
            geoip_country_name TEXT,
            geoip_asn       INTEGER,
            geoip_as_org    TEXT,
            geoip_city      TEXT,
            geoip_postal_code TEXT,
            bytes_sent      INTEGER,
            bytes_received  INTEGER,
            duration_secs   INTEGER,
            UNIQUE (user_id, local_event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_{table}_ts        ON {table} (ts);
        CREATE INDEX IF NOT EXISTS idx_{table}_machine   ON {table} (machine_id);
        CREATE INDEX IF NOT EXISTS idx_{table}_user      ON {table} (user_id);
        CREATE INDEX IF NOT EXISTS idx_{table}_user_local ON {table} (user_id, local_event_id);
        "#,
    );
    conn.execute_batch(&ddl)
        .with_context(|| format!("ensure_partition({table}) failed"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Listing (for cleanup routing)
// ---------------------------------------------------------------------------

/// One discovered monthly partition.
#[derive(Debug, Clone, Copy)]
pub struct PartitionEntry {
    /// The YYYYMM month, e.g. `202608`.
    pub month: i32,
    /// The partition table name.
    pub table: &'static str,
}

// We can't return `&'static str` for a dynamically-formatted name, so
// `list_event_partitions` returns owned `(i32, String)` tuples instead.
// `PartitionEntry` is kept for future typed consumers.

/// List all `server_events_YYYYMM` partition tables in the database.
///
/// Returns a vec of `(month, table_name)` pairs sorted by month ascending.
pub fn list_event_partitions(conn: &mut Connection) -> Result<Vec<(i32, String)>> {
    let mut stmt = conn.prepare(
        "SELECT name FROM sqlite_master \
         WHERE type='table' AND name LIKE 'server_events_%' \
         ORDER BY name",
    )?;
    let mut out: Vec<(i32, String)> = Vec::new();
    let names = stmt.query_map([], |r| r.get::<_, String>(0))?;
    for name in names {
        let name = name?;
        // Parse the trailing YYYYMM.
        let suffix = name.strip_prefix("server_events_").unwrap_or("");
        if let Ok(month) = suffix.parse::<i32>() {
            // Validate YYYYMM range loosely.
            if (190001..=999912).contains(&month) {
                out.push((month, name));
            }
        }
    }
    out.sort_by_key(|(m, _)| *m);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{ServerDbConfig, init};
    use std::path::PathBuf;

    fn tmp_db(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "rustnet-server-partition-{label}-{}-{n}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn month_of_parses_rfc3339() {
        assert_eq!(month_of("2026-08-05T12:00:00+00:00"), Some(202608));
        assert_eq!(month_of("2025-12-31T23:59:59+00:00"), Some(202512));
        assert_eq!(month_of("not-a-date"), None);
    }

    #[test]
    fn partition_table_name_is_zero_padded() {
        assert_eq!(partition_table_name(202608), "server_events_202608");
        assert_eq!(partition_table_name(7), "server_events_000007");
    }

    #[test]
    fn fresh_db_is_not_partitioned() {
        let path = tmp_db("fresh");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let conn = db.lock_writer();
        assert!(!partitioning_active(&conn));
    }

    #[test]
    fn ensure_partition_creates_table() {
        let path = tmp_db("ensure");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let mut conn = db.lock_writer();
        ensure_partition(&mut conn, 202608).unwrap();

        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type='table' AND name='server_events_202608'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1);
    }

    #[test]
    fn list_event_partitions_finds_created() {
        let path = tmp_db("list");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let mut conn = db.lock_writer();
        ensure_partition(&mut conn, 202607).unwrap();
        ensure_partition(&mut conn, 202608).unwrap();

        let parts = list_event_partitions(&mut conn).unwrap();
        let months: Vec<i32> = parts.iter().map(|(m, _)| *m).collect();
        assert_eq!(months, vec![202607, 202608]);
        // Names are the canonical form.
        assert_eq!(parts[0].1, "server_events_202607");
    }
}

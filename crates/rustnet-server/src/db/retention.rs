//! Data retention & purge (T2.5, R9 服务端侧).
//!
//! [`purge_expired`] deletes rows older than `retention_days` from
//! `server_events` and `server_aggregates`, returning how many rows were
//! removed from each table.
//!
//! When partitioning is enabled (see [`super::partition`]), the events
//! table cleanup is performed per-month via `DROP TABLE
//! server_events_YYYYMM` instead of row-level `DELETE`. The aggregates
//! table is always cleaned with a `DELETE ... WHERE bucket_ts < ?`.

use anyhow::{Context, Result};
use log::{debug, info};
use rusqlite::Connection;

/// Outcome of a single [`purge_expired`] run.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct PurgeReport {
    /// Rows removed from `server_events` (or the count of dropped
    /// partition rows when partitioning is active — best-effort estimate).
    pub events_deleted: u64,
    /// Rows removed from `server_aggregates`.
    pub aggregates_deleted: u64,
    /// Number of monthly partition tables dropped (0 when not partitioned).
    pub partitions_dropped: u64,
}

/// Delete rows older than `retention_days` from the server tables.
///
/// The cutoff is computed in RFC 3339 form from `now_rfc3339` so callers
/// (tests, background task) can pin the clock.
///
/// # Partitioning
/// If [`super::partition::partitioning_active`] reports that the
/// `server_events` table has crossed the ~50 GB threshold, events cleanup
/// switches to dropping whole monthly partitions older than the retention
/// window. Otherwise a plain `DELETE` is used.
pub fn purge_expired(
    conn: &mut Connection,
    retention_days: u32,
    now_rfc3339: &str,
) -> Result<PurgeReport> {
    let cutoff = compute_cutoff(now_rfc3339, retention_days);

    let partitioned = super::partition::partitioning_active(conn);

    let (events_deleted, partitions_dropped) = if partitioned {
        purge_events_partitioned(conn, &cutoff)?
    } else {
        (purge_events_rows(conn, &cutoff)?, 0)
    };

    let aggregates_deleted = purge_aggregates_rows(conn, &cutoff)?;
    info!(
        "purge_expired: 完成 (retention_days={}, cutoff={}, partitioned={}, events_deleted={}, aggregates_deleted={}, partitions_dropped={})",
        retention_days, cutoff, partitioned, events_deleted, aggregates_deleted, partitions_dropped
    );

    Ok(PurgeReport {
        events_deleted,
        aggregates_deleted,
        partitions_dropped,
    })
}

/// Row-level `DELETE` from the single `server_events` table.
fn purge_events_rows(conn: &mut Connection, cutoff: &str) -> Result<u64> {
    let changed = conn
        .execute(
            "DELETE FROM server_events WHERE ts < ?",
            rusqlite::params![cutoff],
        )
        .context("DELETE server_events failed")?;
    Ok(changed as u64)
}

/// Row-level `DELETE` from `server_aggregates`.
fn purge_aggregates_rows(conn: &mut Connection, cutoff: &str) -> Result<u64> {
    let changed = conn
        .execute(
            "DELETE FROM server_aggregates WHERE bucket_ts < ?",
            rusqlite::params![cutoff],
        )
        .context("DELETE server_aggregates failed")?;
    Ok(changed as u64)
}

/// Drop monthly partition tables whose month is entirely older than the
/// retention cutoff.
///
/// A partition `server_events_YYYYMM` is droppable when the last second of
/// that month precedes `cutoff`. This avoids dropping a partition that
/// still contains in-retention rows.
fn purge_events_partitioned(conn: &mut Connection, cutoff: &str) -> Result<(u64, u64)> {
    let partitions = super::partition::list_event_partitions(conn)?;
    let cutoff_dt = chrono::DateTime::parse_from_rfc3339(cutoff)
        .context("cutoff is not a valid RFC 3339 timestamp")?;

    let mut dropped = 0u64;
    let mut rows_estimate = 0u64;
    for (month, table_name) in partitions {
        // Determine the end-of-month timestamp for this partition.
        let year = month / 100;
        let mon = month % 100;
        let next_month = if mon == 12 {
            chrono::NaiveDate::from_ymd_opt(year + 1, 1, 1)
        } else {
            chrono::NaiveDate::from_ymd_opt(year, (mon + 1) as u32, 1)
        };
        let Some(next_month) = next_month else {
            continue;
        };
        // End of month = start of next month; compare to cutoff.
        let month_end = next_month.and_hms_opt(23, 59, 59).unwrap();
        if month_end.and_utc() >= cutoff_dt {
            // Partition still holds in-retention rows — keep it.
            continue;
        }

        // Best-effort row count for reporting, then drop.
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table_name}"), [], |r| {
                r.get(0)
            })
            .unwrap_or(0);
        conn.execute(&format!("DROP TABLE IF EXISTS {table_name}"), [])
            .with_context(|| format!("DROP {table_name} failed"))?;
        debug!("purge_events_partitioned: 删除过期分区 (month={}, table={}, est_rows={})", month, table_name, count);
        dropped += 1;
        rows_estimate += count as u64;
    }

    Ok((rows_estimate, dropped))
}

/// Compute the RFC 3339 cutoff timestamp = `now - retention_days`.
fn compute_cutoff(now_rfc3339: &str, retention_days: u32) -> String {
    let Ok(now) = chrono::DateTime::parse_from_rfc3339(now_rfc3339) else {
        return now_rfc3339.to_string();
    };
    let cutoff = now - chrono::Duration::days(retention_days as i64);
    cutoff.to_rfc3339()
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
            "rustnet-server-retention-{label}-{}-{n}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn cutoff_subtracts_retention_days() {
        let cutoff = compute_cutoff("2026-08-05T12:00:00+00:00", 180);
        assert!(cutoff.starts_with("2026-02-06"));
    }

    #[test]
    fn purge_deletes_old_events_and_aggregates() {
        let path = tmp_db("purge");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let mut conn = db.lock_writer();

        // Insert one event with an old timestamp and one aggregate bucket.
        conn.execute(
            "INSERT INTO server_events (machine_id, user_id, username, ip_list, \
             local_event_id, ts, ingest_ts, protocol, source_ip, source_port, \
             dest_ip, dest_port) \
             VALUES ('m', 1, 'u', '[]', 1, '2020-01-01T00:00:00+00:00', \
             '2020-01-01T00:00:00+00:00', 'tcp', '1.1.1.1', 1, '2.2.2.2', 2)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO server_aggregates (bucket_ts, bucket_width, bytes_rx, bytes_tx, conn_count) \
             VALUES ('2020-01-01T00:00:00+00:00', 'minute', 0, 0, 0)",
            [],
        )
        .unwrap();

        let report = purge_expired(&mut conn, 90, "2026-08-05T00:00:00+00:00").unwrap();
        assert_eq!(report.events_deleted, 1);
        assert_eq!(report.aggregates_deleted, 1);
        assert_eq!(report.partitions_dropped, 0);
    }

    #[test]
    fn purge_keeps_in_retention_rows() {
        let path = tmp_db("keep");
        let db = init(&path, &ServerDbConfig::default()).unwrap();
        let mut conn = db.lock_writer();

        // Recent event — must survive a 90-day purge.
        conn.execute(
            "INSERT INTO server_events (machine_id, user_id, username, ip_list, \
             local_event_id, ts, ingest_ts, protocol, source_ip, source_port, \
             dest_ip, dest_port) \
             VALUES ('m', 1, 'u', '[]', 1, '2026-08-01T00:00:00+00:00', \
             '2026-08-01T00:00:00+00:00', 'tcp', '1.1.1.1', 1, '2.2.2.2', 2)",
            [],
        )
        .unwrap();

        let report = purge_expired(&mut conn, 90, "2026-08-05T00:00:00+00:00").unwrap();
        assert_eq!(report.events_deleted, 0);

        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM server_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 1);
    }
}

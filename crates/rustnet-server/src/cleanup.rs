//! Background cleanup task (T2.5, R9 服务端侧).
//!
//! [`spawn_cleanup_task`] launches a `tokio` task that runs
//! [`retention::purge_expired`] once per `period`. Each run owns the
//! writer connection briefly; a failure is logged and retried on the next
//! tick (清理失败跳过, 下次重试).
//!
//! The task is `Send`-safe: it holds an `Arc<ServerDb>` and performs the
//! synchronous SQLite work inside `tokio::task::spawn_blocking` so the
//! async runtime is never blocked on I/O.

use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{info, warn};
use tokio::time::interval;

use crate::db::ServerDb;
use crate::db::retention::{PurgeReport, purge_expired};

/// Default cleanup period: once per day.
pub const DEFAULT_PERIOD: Duration = Duration::from_secs(24 * 60 * 60);

/// Default server retention: 180 days (max 1095 per §7.4).
pub const DEFAULT_RETENTION_DAYS: u32 = 180;

/// Spawn the periodic cleanup background task.
///
/// The first purge runs immediately (so a freshly restarted server trims
/// any data that expired while it was down); subsequent purges fire on
/// each `period` tick.
pub fn spawn_cleanup_task(
    db: Arc<ServerDb>,
    retention_days: u32,
    period: Duration,
) -> tokio::task::JoinHandle<()> {
    info!(
        "spawn_cleanup_task: 启动周期清理 (retention_days={}, period={}s)",
        retention_days,
        period.as_secs()
    );
    tokio::spawn(async move {
        let mut ticker = interval(period);
        loop {
            ticker.tick().await;
            let now = chrono::Local::now().to_rfc3339();
            let now_for_closure = now.clone();
            // Run the synchronous SQLite purge on a blocking thread so we
            // don't stall the async runtime.
            let db_clone = Arc::clone(&db);
            let started = Instant::now();
            let result = tokio::task::spawn_blocking(move || {
                let mut conn = db_clone.lock_writer();
                purge_expired(&mut conn, retention_days, &now_for_closure)
            })
            .await;

            match result {
                Ok(Ok(report)) => {
                    let elapsed = started.elapsed().as_millis();
                    if elapsed > 1000 {
                        warn!("cleanup run 耗时较长: {elapsed}ms");
                    }
                    log_purge(report, &now);
                }
                Ok(Err(e)) => warn!("cleanup run failed, will retry next tick: {e:#}"),
                Err(join_err) => warn!("cleanup task panicked: {join_err}"),
            }
        }
    })
}

fn log_purge(report: PurgeReport, now: &str) {
    info!(
        "cleanup at {now}: events_deleted={}, aggregates_deleted={}, partitions_dropped={}",
        report.events_deleted, report.aggregates_deleted, report.partitions_dropped
    );
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
            "rustnet-server-cleanup-{label}-{}-{n}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[tokio::test]
    async fn spawn_cleanup_task_purges_old_rows() {
        let path = tmp_db("spawn");
        let db = init(&path, &ServerDbConfig::default()).unwrap();

        // Seed one old event row.
        {
            let conn = db.lock_writer();
            conn.execute(
                "INSERT INTO server_events (machine_id, user_id, username, ip_list, \
                 local_event_id, ts, ingest_ts, protocol, source_ip, source_port, \
                 dest_ip, dest_port) \
                 VALUES ('m', 1, 'u', '[]', 1, '2020-01-01T00:00:00+00:00', \
                 '2020-01-01T00:00:00+00:00', 'tcp', '1.1.1.1', 1, '2.2.2.2', 2)",
                [],
            )
            .unwrap();
        }

        let db = Arc::new(db);
        let handle = spawn_cleanup_task(
            Arc::clone(&db),
            90,
            // Very short period so the test completes quickly; the first
            // tick fires immediately.
            Duration::from_millis(50),
        );

        // Give the task a couple of ticks to run the purge.
        tokio::time::sleep(Duration::from_millis(200)).await;
        handle.abort();

        let conn = db.lock_writer();
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM server_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 0, "old event should have been purged");
    }
}

// rustnetec: SqliteSink — client-side SQLite persistence for connection events (R2)
//
// Architecture:
// - Capture threads send events via mpsc channel to a dedicated write thread
// - Write thread batches events (100 per batch or 500ms interval) and commits
// - Capture priority: write failures are logged and events dropped, never blocking capture
// - Field recording controlled by RuntimeConfig record_* switches
// - Kubernetes fields controlled by compile-time `kubernetes` feature

use crate::config::RuntimeConfig;
use crate::telemetry::{ConnectionEventData, ConnectionEventSink};
use anyhow::Result;
use log::{info, warn, error};
use rusqlite::{Connection, params, OpenFlags, Transaction};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

/// Commands sent from capture threads to the write thread.
enum WriteCommand {
    Event(Box<ConnectionEventData>),
    Shutdown,
}

/// SQLite-backed connection event sink.
///
/// Events are buffered in an mpsc channel and written to the database
/// by a dedicated write thread. This ensures the capture pipeline is
/// never blocked by I/O.
pub struct SqliteSink {
    tx: crossbeam::channel::Sender<WriteCommand>,
    _handle: Option<thread::JoinHandle<()>>,
}

impl SqliteSink {
    /// Open (or create) the SQLite database at the given path and start
    /// the write thread.
    ///
    /// `db_path` overrides the platform default when provided (via `--db`).
    /// `runtime_config` is shared with the rest of the application for
    /// reading record switches and retention settings.
    pub fn new(
        db_path: Option<PathBuf>,
        runtime_config: Arc<RwLock<RuntimeConfig>>,
    ) -> Result<Self> {
        let path = db_path.unwrap_or_else(|| {
            crate::telemetry::paths::db_path().expect("Failed to resolve DB path")
        });

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        }

        let conn = Self::open_connection(&path)?;
        Self::init_schema(&conn)?;
        Self::configure_pragma(&conn)?;

        // Chown if running as root (Unix)
        #[cfg(unix)]
        {
            if unsafe { libc::geteuid() } == 0 {
                crate::telemetry::paths::chown_if_root(&path, 0, 0).ok();
            }
        }

        let (tx, rx) = crossbeam::channel::bounded::<WriteCommand>(10000);

        let db_path_display = path.display().to_string();
        let handle = thread::Builder::new()
            .name("sqlite_writer".to_string())
            .spawn(move || {
                Self::write_loop(conn, rx, runtime_config, &path);
            })?;

        info!("SqliteSink initialized at {}", db_path_display);

        Ok(Self {
            tx,
            _handle: Some(handle),
        })
    }

    /// Open a read-write connection to the database.
    fn open_connection(path: &PathBuf) -> Result<Connection> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        Ok(conn)
    }

    /// Open a read-only connection for query operations.
    pub fn open_read_only(path: &PathBuf) -> Result<Connection> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(conn)
    }

    /// Configure SQLite PRAGMA settings for optimal client-side performance.
    fn configure_pragma(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA auto_vacuum = INCREMENTAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA cache_size = -16384;
             PRAGMA mmap_size = 0;",
        )?;
        Ok(())
    }

    /// Initialize the database schema (idempotent).
    /// rustnetec: made `pub` for UploadSink integration tests (T2.6).
    pub fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS connection_events (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                ts                  TEXT    NOT NULL,
                event_type          TEXT    NOT NULL,
                protocol            TEXT    NOT NULL,
                source_ip           TEXT    NOT NULL,
                source_port         INTEGER NOT NULL,
                dest_ip             TEXT    NOT NULL,
                dest_port           INTEGER NOT NULL,
                dest_hostname       TEXT,
                source_hostname     TEXT,
                pid                 INTEGER,
                process_ppid        INTEGER,
                process_name        TEXT,
                process_executable  TEXT,
                process_uid         INTEGER,
                process_gid         INTEGER,
                attribution_match   TEXT,
                rtt_ms              REAL,
                k8s_pod_uid         TEXT,
                k8s_pod_name        TEXT,
                k8s_pod_ns          TEXT,
                k8s_container_id    TEXT,
                k8s_container_name  TEXT,
                k8s_cgroup_path     TEXT,
                service_name        TEXT,
                direction           TEXT,
                dpi_protocol        TEXT,
                dpi_domain          TEXT,
                geoip_country_code  TEXT,
                geoip_country_name  TEXT,
                geoip_asn           INTEGER,
                geoip_as_org        TEXT,
                geoip_city          TEXT,
                geoip_postal_code   TEXT,
                bytes_sent          INTEGER,
                bytes_received      INTEGER,
                duration_secs       INTEGER
            );

            CREATE TABLE IF NOT EXISTS aggregates (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket_ts       TEXT    NOT NULL,
                bucket_width    TEXT    NOT NULL,
                protocol        TEXT,
                process_name    TEXT,
                country_code    TEXT,
                asn             INTEGER,
                bytes_rx        INTEGER NOT NULL DEFAULT 0,
                bytes_tx        INTEGER NOT NULL DEFAULT 0,
                conn_count      INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS upload_cursor (
                id                      INTEGER PRIMARY KEY CHECK (id = 1),
                last_uploaded_event_id  INTEGER NOT NULL DEFAULT 0,
                last_upload_ts          TEXT
            );

            CREATE TABLE IF NOT EXISTS schema_version (
                id      INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL
            );

            -- Initialize upload_cursor with default row if empty
            INSERT OR IGNORE INTO upload_cursor (id, last_uploaded_event_id, last_upload_ts)
                VALUES (1, 0, NULL);

            -- Initialize schema_version
            INSERT OR IGNORE INTO schema_version (id, version) VALUES (1, 1);

            -- Indexes for common query patterns
            CREATE INDEX IF NOT EXISTS idx_events_ts ON connection_events (ts);
            CREATE INDEX IF NOT EXISTS idx_events_type ON connection_events (event_type);
            CREATE INDEX IF NOT EXISTS idx_events_protocol ON connection_events (protocol);
            CREATE INDEX IF NOT EXISTS idx_events_source_ip ON connection_events (source_ip);
            CREATE INDEX IF NOT EXISTS idx_events_dest_ip ON connection_events (dest_ip);
            CREATE INDEX IF NOT EXISTS idx_events_dest_port ON connection_events (dest_port);
            CREATE INDEX IF NOT EXISTS idx_events_pid ON connection_events (pid);
            CREATE INDEX IF NOT EXISTS idx_events_process_name ON connection_events (process_name);
            CREATE INDEX IF NOT EXISTS idx_events_dpi_protocol ON connection_events (dpi_protocol);
            CREATE INDEX IF NOT EXISTS idx_events_dpi_domain ON connection_events (dpi_domain);
            CREATE INDEX IF NOT EXISTS idx_events_country ON connection_events (geoip_country_code);
            CREATE INDEX IF NOT EXISTS idx_events_direction ON connection_events (direction);
            CREATE INDEX IF NOT EXISTS idx_events_ts_id ON connection_events (ts, id);
            CREATE INDEX IF NOT EXISTS idx_events_id_ts ON connection_events (id, ts);
            CREATE INDEX IF NOT EXISTS idx_aggs_bucket ON aggregates (bucket_ts, bucket_width);
            CREATE INDEX IF NOT EXISTS idx_aggs_protocol ON aggregates (bucket_ts, protocol);
            CREATE INDEX IF NOT EXISTS idx_aggs_process ON aggregates (bucket_ts, process_name);
            CREATE INDEX IF NOT EXISTS idx_aggs_country ON aggregates (bucket_ts, country_code);
            ",
        )?;
        Ok(())
    }

    /// Main write loop: batch events from the channel and commit periodically.
    fn write_loop(
        conn: Connection,
        rx: crossbeam::channel::Receiver<WriteCommand>,
        runtime_config: Arc<RwLock<RuntimeConfig>>,
        db_path: &PathBuf,
    ) {
        let batch_size = 100;
        let flush_interval = Duration::from_millis(500);
        let mut last_flush = Instant::now();
        let mut batch: Vec<Box<ConnectionEventData>> = Vec::with_capacity(batch_size);

        // Aggregation timer: trigger every 60 seconds
        let agg_interval = Duration::from_secs(60);
        let mut last_agg = Instant::now();

        // Cleanup timer: trigger every 6 hours
        let cleanup_interval = Duration::from_secs(6 * 3600);
        let mut last_cleanup = Instant::now();

        loop {
            // Drain available events from channel (non-blocking)
            let timeout = flush_interval.saturating_sub(last_flush.elapsed());
            match rx.recv_timeout(timeout.min(Duration::from_millis(100))) {
                Ok(WriteCommand::Event(event)) => {
                    batch.push(event);
                }
                Ok(WriteCommand::Shutdown) => {
                    // Flush remaining events before exit
                    if !batch.is_empty() {
                        Self::flush_batch(&conn, &batch, &runtime_config);
                    }
                    info!("SqliteSink write thread shutting down");
                    break;
                }
                Err(crossbeam::channel::RecvTimeoutError::Timeout) => {}
                Err(crossbeam::channel::RecvTimeoutError::Disconnected) => {
                    if !batch.is_empty() {
                        Self::flush_batch(&conn, &batch, &runtime_config);
                    }
                    info!("SqliteSink channel disconnected, write thread exiting");
                    break;
                }
            }

            // Flush batch if full or interval elapsed
            if batch.len() >= batch_size || (last_flush.elapsed() >= flush_interval && !batch.is_empty()) {
                Self::flush_batch(&conn, &batch, &runtime_config);
                batch.clear();
                last_flush = Instant::now();
            }

            // Aggregation check
            if last_agg.elapsed() >= agg_interval {
                if let Err(e) = Self::run_aggregation(&conn) {
                    warn!("Aggregation failed: {}", e);
                }
                last_agg = Instant::now();
            }

            // Cleanup check
            if last_cleanup.elapsed() >= cleanup_interval {
                let retention_days = runtime_config.read().map(|r| r.retention_days).unwrap_or(90);
                if let Err(e) = Self::run_cleanup(&conn, retention_days) {
                    warn!("Cleanup failed: {}", e);
                }
                last_cleanup = Instant::now();
            }
        }

        // Close connection gracefully
        drop(conn);
        let _ = db_path; // suppress unused warning
    }

    /// Flush a batch of events to the database in a single transaction.
    fn flush_batch(
        conn: &Connection,
        batch: &[Box<ConnectionEventData>],
        runtime_config: &Arc<RwLock<RuntimeConfig>>,
    ) {
        let rc = runtime_config.read().unwrap_or_else(|e| e.into_inner());

        let tx = match conn.unchecked_transaction() {
            Ok(tx) => tx,
            Err(e) => {
                error!("Failed to begin transaction: {}", e);
                return;
            }
        };

        for event in batch {
            if let Err(e) = Self::insert_event(&tx, event, &rc) {
                // Capture priority: log and skip, don't block
                warn!("Failed to insert event: {}", e);
            }
        }

        if let Err(e) = tx.commit() {
            error!("Failed to commit batch: {}", e);
        }
    }

    /// Insert a single connection event into the database.
    pub(crate) fn insert_event(
        tx: &Transaction,
        event: &ConnectionEventData,
        rc: &RuntimeConfig,
    ) -> Result<()> {
        // Build the INSERT statement dynamically based on record switches
        let mut columns = Vec::new();
        let mut placeholders = Vec::new();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        // Core fields (always recorded)
        columns.extend_from_slice(&[
            "ts", "event_type", "protocol", "source_ip", "source_port",
            "dest_ip", "dest_port",
        ]);
        placeholders.extend_from_slice(&["?","?","?","?","?","?","?"]);
        param_values.push(Box::new(event.timestamp.clone()));
        param_values.push(Box::new(event.event.clone()));
        param_values.push(Box::new(event.protocol.clone()));
        param_values.push(Box::new(event.source_ip.clone()));
        param_values.push(Box::new(event.source_port as i64));
        param_values.push(Box::new(event.destination_ip.clone()));
        param_values.push(Box::new(event.destination_port as i64));

        // DNS fields (conditional)
        if rc.record_dns {
            columns.extend_from_slice(&["dest_hostname", "source_hostname"]);
            placeholders.extend_from_slice(&["?","?"]);
            param_values.push(Box::new(event.destination_hostname.clone()));
            param_values.push(Box::new(event.source_hostname.clone()));
        }

        // Process fields (conditional)
        if rc.record_process {
            columns.extend_from_slice(&[
                "pid", "process_ppid", "process_name", "process_executable",
                "process_uid", "process_gid", "attribution_match",
            ]);
            placeholders.extend_from_slice(&["?","?","?","?","?","?","?"]);
            param_values.push(Box::new(event.pid.map(|v| v as i64)));
            param_values.push(Box::new(event.process_ppid.map(|v| v as i64)));
            param_values.push(Box::new(event.process_name.clone()));
            param_values.push(Box::new(event.process_executable.clone()));
            param_values.push(Box::new(event.process_uid.map(|v| v as i64)));
            param_values.push(Box::new(event.process_gid.map(|v| v as i64)));
            param_values.push(Box::new(event.attribution_match.clone()));
        }

        // RTT (conditional)
        if rc.record_rtt {
            columns.push("rtt_ms");
            placeholders.push("?");
            param_values.push(Box::new(event.rtt_ms));
        }

        // Kubernetes fields (compile-time feature)
        #[cfg(feature = "kubernetes")]
        {
            columns.extend_from_slice(&[
                "k8s_pod_uid", "k8s_pod_name", "k8s_pod_ns",
                "k8s_container_id", "k8s_container_name", "k8s_cgroup_path",
            ]);
            placeholders.extend_from_slice(&["?","?","?","?","?","?"]);
            if let Some(ref k8s) = event.kubernetes {
                param_values.push(Box::new(k8s.get("pod_uid").and_then(|v| v.as_str()).map(String::from)));
                param_values.push(Box::new(k8s.get("pod_name").and_then(|v| v.as_str()).map(String::from)));
                param_values.push(Box::new(k8s.get("pod_namespace").and_then(|v| v.as_str()).map(String::from)));
                param_values.push(Box::new(k8s.get("container_id").and_then(|v| v.as_str()).map(String::from)));
                param_values.push(Box::new(k8s.get("container_name").and_then(|v| v.as_str()).map(String::from)));
                param_values.push(Box::new(k8s.get("cgroup_path").and_then(|v| v.as_str()).map(String::from)));
            } else {
                param_values.push(Box::new(None::<String>));
                param_values.push(Box::new(None::<String>));
                param_values.push(Box::new(None::<String>));
                param_values.push(Box::new(None::<String>));
                param_values.push(Box::new(None::<String>));
                param_values.push(Box::new(None::<String>));
            }
        }

        // Service (conditional)
        if rc.record_service {
            columns.push("service_name");
            placeholders.push("?");
            param_values.push(Box::new(event.service_name.clone()));
        }

        // Direction (always recorded if present)
        columns.push("direction");
        placeholders.push("?");
        param_values.push(Box::new(event.direction.clone()));

        // DPI (conditional)
        if rc.record_dpi {
            columns.extend_from_slice(&["dpi_protocol", "dpi_domain"]);
            placeholders.extend_from_slice(&["?","?"]);
            param_values.push(Box::new(event.dpi_protocol.clone()));
            param_values.push(Box::new(event.dpi_domain.clone()));
        }

        // GeoIP (conditional)
        if rc.record_geoip {
            columns.extend_from_slice(&[
                "geoip_country_code", "geoip_country_name", "geoip_asn",
                "geoip_as_org", "geoip_city", "geoip_postal_code",
            ]);
            placeholders.extend_from_slice(&["?","?","?","?","?","?"]);
            param_values.push(Box::new(event.geoip_country_code.clone()));
            param_values.push(Box::new(event.geoip_country_name.clone()));
            param_values.push(Box::new(event.geoip_asn.map(|v| v as i64)));
            param_values.push(Box::new(event.geoip_as_org.clone()));
            param_values.push(Box::new(event.geoip_city.clone()));
            param_values.push(Box::new(event.geoip_postal_code.clone()));
        }

        // Connection stats (conditional, only for closed events)
        if rc.record_connection_stats {
            columns.extend_from_slice(&["bytes_sent", "bytes_received", "duration_secs"]);
            placeholders.extend_from_slice(&["?","?","?"]);
            param_values.push(Box::new(event.bytes_sent.map(|v| v as i64)));
            param_values.push(Box::new(event.bytes_received.map(|v| v as i64)));
            param_values.push(Box::new(event.duration_secs.map(|v| v as i64)));
        }

        let sql = format!(
            "INSERT INTO connection_events ({}) VALUES ({})",
            columns.join(", "),
            placeholders.join(", ")
        );

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();
        tx.execute(&sql, param_refs.as_slice())?;

        Ok(())
    }

    /// Run aggregation: compute per-minute and per-hour summaries.
    fn run_aggregation(conn: &Connection) -> Result<()> {
        // Per-minute aggregation
        conn.execute_batch(
            "INSERT OR REPLACE INTO aggregates (bucket_ts, bucket_width, protocol, process_name, country_code, asn, bytes_rx, bytes_tx, conn_count)
             SELECT
                strftime('%Y-%m-%dT%H:%M:00', ts) AS bucket_ts,
                'minute' AS bucket_width,
                protocol,
                process_name,
                geoip_country_code,
                geoip_asn,
                COALESCE(SUM(bytes_received), 0),
                COALESCE(SUM(bytes_sent), 0),
                COUNT(*)
             FROM connection_events
             WHERE event_type = 'connection_closed'
               AND ts >= datetime('now', '-2 minutes')
             GROUP BY bucket_ts, protocol, process_name, geoip_country_code, geoip_asn
             ON CONFLICT(id) DO UPDATE SET
                bytes_rx = bytes_rx + excluded.bytes_rx,
                bytes_tx = bytes_tx + excluded.bytes_tx,
                conn_count = conn_count + excluded.conn_count;
            ",
        )?;
        Ok(())
    }

    /// Run cleanup: delete expired events that have already been uploaded.
    fn run_cleanup(conn: &Connection, retention_days: u32) -> Result<()> {
        let days_str = format!("-{} days", retention_days);

        // Delete uploaded events older than retention period
        let deleted_events = conn.execute(
            "DELETE FROM connection_events
             WHERE ts < datetime('now', ?1)
               AND id <= (SELECT COALESCE(last_uploaded_event_id, 0) FROM upload_cursor WHERE id = 1)",
            params![days_str],
        )?;

        // Delete expired aggregates
        let deleted_aggs = conn.execute(
            "DELETE FROM aggregates WHERE bucket_ts < datetime('now', ?1)",
            params![days_str],
        )?;

        // Incremental vacuum to reclaim space
        conn.execute_batch("PRAGMA incremental_vacuum;")?;

        if deleted_events > 0 || deleted_aggs > 0 {
            info!(
                "Cleanup: deleted {} events, {} aggregates (retention: {} days)",
                deleted_events, deleted_aggs, retention_days
            );
        }

        Ok(())
    }

    /// Get the default database path.
    pub fn default_db_path() -> Result<PathBuf> {
        crate::telemetry::paths::db_path()
    }

    /// 测试辅助：直接对给定连接执行清理逻辑（偏差4 / T1.9 集成测试用）。
    /// 生产代码通过 write_loop 内部调用私有的 run_cleanup。
    pub fn run_cleanup_for_test(conn: &Connection, retention_days: u32) -> Result<()> {
        Self::run_cleanup(conn, retention_days)
    }

    // ---- rustnetec: UploadSink 支持接口 (T2.6) ----
    // UploadSink 持有独立的只读连接查 connection_events、独立写连接推进
    // upload_cursor。 SqliteSink 的 writer 连接被其写线程独占，故这些接口
    // 以关联函数形式暴露，让 UploadSink 自管连接生命周期 (WAL 下并发安全)。

    /// 读取 `upload_cursor.last_uploaded_event_id`（默认 0）。
    pub fn read_upload_cursor(conn: &Connection) -> Result<i64> {
        let id: i64 = conn.query_row(
            "SELECT COALESCE(last_uploaded_event_id, 0) FROM upload_cursor WHERE id = 1",
            [],
            |r| r.get(0),
        )?;
        Ok(id)
    }

    /// 推进 `upload_cursor` 到 `new_id`，记录 `last_upload_ts`。
    /// 由 UploadSink 在一批上报成功后调用。
    pub fn advance_upload_cursor(conn: &Connection, new_id: i64) -> Result<()> {
        let now = chrono::Local::now().to_rfc3339();
        conn.execute(
            "UPDATE upload_cursor SET last_uploaded_event_id = ?, last_upload_ts = ? WHERE id = 1",
            params![new_id, now],
        )?;
        Ok(())
    }

    /// 查询 `connection_events WHERE id > after_id ORDER BY id LIMIT limit`，
    /// 返回 `(id, ConnectionEventData)` 供 UploadSink 映射为 ClientEvent。
    ///
    /// 字段映射与 `insert_event` 的写入逻辑严格对齐：所有可选列按
    /// RuntimeConfig 的 record_* 开关在写入时决定是否落库，此处读取时
    /// 一律尝试取列、缺失列返回 None —— SQLite 缺列会报错，故这里用
    /// `prepare_cached` + 按需 SELECT，列名与 schema 完全一致。
    pub fn query_events_for_upload(
        conn: &Connection,
        after_id: i64,
        limit: u32,
    ) -> Result<Vec<(i64, ConnectionEventData)>> {
        let mut stmt = conn.prepare(
            "SELECT id, ts, event_type, protocol, source_ip, source_port, \
             dest_ip, dest_port, dest_hostname, source_hostname, \
             pid, process_ppid, process_name, process_executable, \
             process_uid, process_gid, attribution_match, rtt_ms, \
             service_name, direction, dpi_protocol, dpi_domain, \
             geoip_country_code, geoip_country_name, geoip_asn, \
             geoip_as_org, geoip_city, geoip_postal_code, \
             bytes_sent, bytes_received, duration_secs \
             FROM connection_events WHERE id > ? ORDER BY id ASC LIMIT ?",
        )?;
        let rows = stmt.query_map(params![after_id, limit as i64], |r| {
            let id: i64 = r.get("id")?;
            Ok((
                id,
                ConnectionEventData {
                    timestamp: r.get::<_, String>("ts")?,
                    event: r.get::<_, String>("event_type")?,
                    protocol: r.get::<_, String>("protocol")?,
                    source_ip: r.get::<_, String>("source_ip")?,
                    source_port: r.get::<_, u16>("source_port")?,
                    destination_ip: r.get::<_, String>("dest_ip")?,
                    destination_port: r.get::<_, u16>("dest_port")?,
                    destination_hostname: r.get::<_, Option<String>>("dest_hostname")?,
                    source_hostname: r.get::<_, Option<String>>("source_hostname")?,
                    pid: r.get::<_, Option<u32>>("pid")?,
                    process_ppid: r.get::<_, Option<u32>>("process_ppid")?,
                    process_name: r.get::<_, Option<String>>("process_name")?,
                    process_executable: r.get::<_, Option<String>>("process_executable")?,
                    process_uid: r.get::<_, Option<u32>>("process_uid")?,
                    process_gid: r.get::<_, Option<u32>>("process_gid")?,
                    attribution_match: r.get::<_, Option<String>>("attribution_match")?,
                    rtt_ms: r.get::<_, Option<f64>>("rtt_ms")?,
                    #[cfg(feature = "kubernetes")]
                    kubernetes: None, // K8s 列读取由 UploadSink 单独处理
                    service_name: r.get::<_, Option<String>>("service_name")?,
                    direction: r.get::<_, Option<String>>("direction")?,
                    dpi_protocol: r.get::<_, Option<String>>("dpi_protocol")?,
                    dpi_domain: r.get::<_, Option<String>>("dpi_domain")?,
                    geoip_country_code: r.get::<_, Option<String>>("geoip_country_code")?,
                    geoip_country_name: r.get::<_, Option<String>>("geoip_country_name")?,
                    geoip_asn: r.get::<_, Option<u32>>("geoip_asn")?,
                    geoip_as_org: r.get::<_, Option<String>>("geoip_as_org")?,
                    geoip_city: r.get::<_, Option<String>>("geoip_city")?,
                    geoip_postal_code: r.get::<_, Option<String>>("geoip_postal_code")?,
                    bytes_sent: r.get::<_, Option<u64>>("bytes_sent")?,
                    bytes_received: r.get::<_, Option<u64>>("bytes_received")?,
                    duration_secs: r.get::<_, Option<u64>>("duration_secs")?,
                },
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}

impl ConnectionEventSink for SqliteSink {
    fn accept(&self, event: &ConnectionEventData) {
        // Capture priority: use try_send to never block the capture thread.
        // If the channel is full, the event is dropped with a warning.
        match self.tx.try_send(WriteCommand::Event(Box::new(event.clone()))) {
            Ok(()) => {}
            Err(crossbeam::channel::TrySendError::Full(_)) => {
                static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    warn!("SqliteSink channel full, dropping events under load");
                }
            }
            Err(crossbeam::channel::TrySendError::Disconnected(_)) => {
                warn!("SqliteSink channel disconnected");
            }
        }
    }
}

impl Drop for SqliteSink {
    fn drop(&mut self) {
        // Signal the write thread to shut down
        let _ = self.tx.send(WriteCommand::Shutdown);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;

    fn test_runtime_config() -> Arc<RwLock<RuntimeConfig>> {
        Arc::new(RwLock::new(RuntimeConfig::from_persistent(
            &crate::config::PersistentConfig::default(),
        )))
    }

    fn open_test_connection() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn init_schema_creates_tables() {
        let conn = open_test_connection();
        SqliteSink::init_schema(&conn).unwrap();

        // Verify tables exist
        let tables: Vec<String> = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").unwrap()
            .query_map([], |row| row.get(0)).unwrap().filter_map(|r| r.ok()).collect();
        assert!(tables.contains(&"connection_events".to_string()));
        assert!(tables.contains(&"aggregates".to_string()));
        assert!(tables.contains(&"upload_cursor".to_string()));
        assert!(tables.contains(&"schema_version".to_string()));

        // Verify indexes exist
        let indexes: Vec<String> = conn.prepare("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%' ORDER BY name").unwrap()
            .query_map([], |row| row.get(0)).unwrap().filter_map(|r| r.ok()).collect();
        assert!(indexes.len() >= 10, "Should have at least 10 indexes, got {}", indexes.len());
    }

    #[test]
    fn insert_and_read_event() {
        let conn = open_test_connection();
        SqliteSink::init_schema(&conn).unwrap();

        let rc = test_runtime_config();
        let rc_guard = rc.read().unwrap();

        let event = ConnectionEventData {
            timestamp: "2026-08-04T20:00:00.123+08:00".to_string(),
            event: "new_connection".to_string(),
            protocol: "TCP".to_string(),
            source_ip: "192.168.1.1".to_string(),
            source_port: 12345,
            destination_ip: "10.0.0.1".to_string(),
            destination_port: 443,
            destination_hostname: Some("example.com".to_string()),
            source_hostname: None,
            pid: Some(1234),
            process_ppid: None,
            process_name: Some("curl".to_string()),
            process_executable: None,
            process_uid: None,
            process_gid: None,
            attribution_match: None,
            rtt_ms: Some(12.3),
            #[cfg(feature = "kubernetes")]
            kubernetes: None,
            service_name: Some("https".to_string()),
            direction: Some("outgoing".to_string()),
            dpi_protocol: Some("HTTPS".to_string()),
            dpi_domain: Some("example.com".to_string()),
            geoip_country_code: Some("US".to_string()),
            geoip_country_name: None,
            geoip_asn: None,
            geoip_as_org: None,
            geoip_city: None,
            geoip_postal_code: None,
            bytes_sent: None,
            bytes_received: None,
            duration_secs: None,
        };

        let tx = conn.unchecked_transaction().unwrap();
        SqliteSink::insert_event(&tx, &event, &rc_guard).unwrap();
        tx.commit().unwrap();

        // Read back
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM connection_events",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);

        let protocol: String = conn.query_row(
            "SELECT protocol FROM connection_events LIMIT 1",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(protocol, "TCP");
    }

    #[test]
    fn record_switches_control_columns() {
        let conn = open_test_connection();
        SqliteSink::init_schema(&conn).unwrap();

        // Disable DNS recording
        // rustnetec: clippy Default::default() — 字面量初始化
        let pc = crate::config::PersistentConfig {
            record_dns: false,
            ..Default::default()
        };
        let rc = Arc::new(RwLock::new(RuntimeConfig::from_persistent(&pc)));
        let rc_guard = rc.read().unwrap();

        let event = ConnectionEventData {
            timestamp: "2026-08-04T20:00:00.123+08:00".to_string(),
            event: "new_connection".to_string(),
            protocol: "TCP".to_string(),
            source_ip: "1.2.3.4".to_string(),
            source_port: 80,
            destination_ip: "5.6.7.8".to_string(),
            destination_port: 443,
            destination_hostname: Some("should-not-be-stored.com".to_string()),
            source_hostname: Some("also-not-stored".to_string()),
            pid: None,
            process_ppid: None,
            process_name: None,
            process_executable: None,
            process_uid: None,
            process_gid: None,
            attribution_match: None,
            rtt_ms: None,
            #[cfg(feature = "kubernetes")]
            kubernetes: None,
            service_name: None,
            direction: None,
            dpi_protocol: None,
            dpi_domain: None,
            geoip_country_code: None,
            geoip_country_name: None,
            geoip_asn: None,
            geoip_as_org: None,
            geoip_city: None,
            geoip_postal_code: None,
            bytes_sent: None,
            bytes_received: None,
            duration_secs: None,
        };

        let tx = conn.unchecked_transaction().unwrap();
        SqliteSink::insert_event(&tx, &event, &rc_guard).unwrap();
        tx.commit().unwrap();

        // Verify DNS columns are NULL (not recorded)
        let dest_hostname: Option<String> = conn.query_row(
            "SELECT dest_hostname FROM connection_events LIMIT 1",
            [],
            |row| row.get(0),
        ).unwrap();
        assert!(dest_hostname.is_none(), "dest_hostname should be NULL when record_dns is false");
    }

    #[test]
    fn upload_cursor_initialized() {
        let conn = open_test_connection();
        SqliteSink::init_schema(&conn).unwrap();

        let last_id: i64 = conn.query_row(
            "SELECT last_uploaded_event_id FROM upload_cursor WHERE id = 1",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(last_id, 0, "upload_cursor should start at 0");
    }

    #[test]
    fn schema_version_is_1() {
        let conn = open_test_connection();
        SqliteSink::init_schema(&conn).unwrap();

        let version: i64 = conn.query_row(
            "SELECT version FROM schema_version WHERE id = 1",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(version, 1, "schema version should be 1");
    }

    #[test]
    fn pragma_settings_applied() {
        let conn = open_test_connection();
        SqliteSink::init_schema(&conn).unwrap();
        SqliteSink::configure_pragma(&conn).unwrap();

        // In-memory databases use "memory" journal mode, file-based use "wal"
        let journal_mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0)).unwrap();
        assert!(journal_mode == "wal" || journal_mode == "memory",
            "journal_mode should be wal or memory, got {}", journal_mode);

        let busy_timeout: i64 = conn.query_row("PRAGMA busy_timeout", [], |row| row.get(0)).unwrap();
        assert_eq!(busy_timeout, 5000);
    }
}

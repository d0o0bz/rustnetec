// rustnetec: SqliteSink — client-side SQLite persistence for connection events (R2)
//
// Architecture:
// - Capture threads send events via mpsc channel to a dedicated write thread
// - Write thread batches events (100 per batch or 500ms interval) and commits
// - Capture priority: write failures are logged and events dropped, never blocking capture
// - Field recording controlled by RuntimeConfig record_* switches
// - Kubernetes fields controlled by compile-time `kubernetes` feature

use crate::config::RuntimeConfig;
use crate::telemetry::netutil::classify_dest;
use crate::telemetry::{ConnectionEventData, ConnectionEventSink};
use anyhow::Result;
use log::{error, info, warn};
use rusqlite::{Connection, OpenFlags, Transaction, params};
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
        // 分阶段执行：先建表 → 再迁移 → 最后建索引。
        // 唯一索引必须建在迁移去重后的数据上，否则旧库的重复桶行会让 CREATE UNIQUE INDEX 失败。
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
                duration_secs       INTEGER,
                -- rustnetec: T-A1 捕获网口名如 en0，供按网口历史查询
                interface           TEXT,
                -- rustnetec: T-A5 — 目标 IP 分类（classify_dest 结果：external/lan/loopback/linklocal）。
                -- 写入时算好落库，聚合表与 /stats/range 的 scope 过滤可 SQL 下推。
                dest_class          TEXT
            );

            CREATE TABLE IF NOT EXISTS aggregates (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket_ts       TEXT    NOT NULL,
                bucket_width    TEXT    NOT NULL,
                protocol        TEXT,
                process_name    TEXT,
                country_code    TEXT,
                asn             INTEGER,
                -- rustnetec: T-A3 — 网口维度，与 connection_events.interface 对齐。
                interface       TEXT,
                -- rustnetec: T-A5 — 目标分类维度（external/lan/loopback/linklocal）。
                dest_class      TEXT,
                bytes_rx        INTEGER NOT NULL DEFAULT 0,
                bytes_tx        INTEGER NOT NULL DEFAULT 0,
                conn_count      INTEGER NOT NULL DEFAULT 0,
                -- rustnetec: T-A5 — 连接时长合计，对应 /stats/range 的 active_seconds。
                duration_secs   INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS upload_cursor (
                id                      INTEGER PRIMARY KEY CHECK (id = 1),
                last_uploaded_event_id  INTEGER NOT NULL DEFAULT 0,
                last_upload_ts          TEXT
            );

            -- rustnetec: reachability probe results (外网可达率探测)
            -- 每轮探测一行；ts 为 RFC3339 探测时刻，主键去重。
            CREATE TABLE IF NOT EXISTS reachability_probes (
                ts              TEXT PRIMARY KEY,
                reachable       INTEGER NOT NULL,
                latency_ms      REAL,
                targets_ok      INTEGER NOT NULL,
                targets_total   INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_reach_ts ON reachability_probes (ts);

            CREATE TABLE IF NOT EXISTS schema_version (
                id      INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL
            );

            -- Initialize upload_cursor with default row if empty
            INSERT OR IGNORE INTO upload_cursor (id, last_uploaded_event_id, last_upload_ts)
                VALUES (1, 0, NULL);

            -- Initialize schema_version
            INSERT OR IGNORE INTO schema_version (id, version) VALUES (1, 1);
            ",
        )?;

        // ---- 迁移（幂等）----
        // rustnetec: T-fix1 — 旧库补 interface 列（T-A1/T-A3 新增列）。
        Self::migrate_add_column_if_missing(conn, "connection_events", "interface", "TEXT")?;
        Self::migrate_add_column_if_missing(conn, "aggregates", "interface", "TEXT")?;

        // rustnetec: T-A5 — connection_events 补 dest_class 列并回填存量行。
        Self::migrate_add_column_if_missing(conn, "connection_events", "dest_class", "TEXT")?;
        Self::backfill_dest_class(conn)?;

        // rustnetec: T-A5 — aggregates 旧结构（无 dest_class 列）→ 重建 + 全量回填。
        // 旧库因缺唯一约束积累海量重复桶行，重建即去重回收空间；新库列齐全则跳过。
        if !Self::column_exists(conn, "aggregates", "dest_class")? {
            Self::rebuild_aggregates(conn)?;
        } else {
            Self::migrate_add_column_if_missing(
                conn,
                "aggregates",
                "duration_secs",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
        }

        // ---- 索引（必须在迁移之后）----
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_events_ts ON connection_events (ts);
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
             -- rustnetec: T-A1 — 按网口历史查询的索引。
             CREATE INDEX IF NOT EXISTS idx_events_interface ON connection_events (interface);
             CREATE INDEX IF NOT EXISTS idx_aggs_bucket ON aggregates (bucket_ts, bucket_width);
             CREATE INDEX IF NOT EXISTS idx_aggs_protocol ON aggregates (bucket_ts, protocol);
             CREATE INDEX IF NOT EXISTS idx_aggs_process ON aggregates (bucket_ts, process_name);
             CREATE INDEX IF NOT EXISTS idx_aggs_country ON aggregates (bucket_ts, country_code);
             -- rustnetec: T-A3 — 网口维度聚合查询的索引。
             CREATE INDEX IF NOT EXISTS idx_aggs_interface ON aggregates (bucket_ts, interface);
             -- rustnetec: T-A5 — 聚合唯一键（可空维度用 COALESCE 表达式归一化），
             -- 让 run_aggregation 的 INSERT OR REPLACE 真正幂等，杜绝重复桶行无限膨胀。
             CREATE UNIQUE INDEX IF NOT EXISTS idx_aggs_unique ON aggregates (
                 bucket_ts, bucket_width,
                 COALESCE(protocol, ''),
                 COALESCE(process_name, ''),
                 COALESCE(country_code, ''),
                 COALESCE(asn, -1),
                 COALESCE(interface, ''),
                 COALESCE(dest_class, '')
             );
             ",
        )?;

        Ok(())
    }

    /// rustnetec: T-fix1 — 幂等迁移：为旧库追加新增列。
    /// `ALTER TABLE ADD COLUMN` 无 `IF NOT EXISTS`，列已存在时报错，
    /// 故先查 `PRAGMA table_info` 检测列是否已存在，存在则跳过。
    fn migrate_add_column_if_missing(
        conn: &Connection,
        table: &str,
        column: &str,
        col_type: &str,
    ) -> Result<()> {
        let exists: i64 = conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM pragma_table_info('{}') WHERE name = ?",
                table.replace('\'', "''")
            ),
            [column],
            |row| row.get(0),
        )?;
        if exists > 0 {
            return Ok(());
        }
        let sql = format!(
            "ALTER TABLE {} ADD COLUMN {} {}",
            table,
            column,
            col_type
        );
        conn.execute_batch(&sql)?;
        Ok(())
    }

    /// 检测表中是否存在指定列（幂等迁移用）。
    fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
        let n: i64 = conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM pragma_table_info('{}') WHERE name = ?",
                table.replace('\'', "''")
            ),
            [column],
            |row| row.get(0),
        )?;
        Ok(n > 0)
    }

    /// rustnetec: T-A5 — 迁移：为存量 connection_events 回填 dest_class。
    ///
    /// 新事件在 insert_event 写入时即算好 dest_class，此处只补旧行
    /// （dest_class IS NULL）。classify_dest 是 Rust 函数，SQLite 无法调用，
    /// 故逐行读取 dest_ip 在 Rust 侧计算后 UPDATE。
    fn backfill_dest_class(conn: &Connection) -> Result<()> {
        use crate::telemetry::netutil::classify_dest;

        let pending: Vec<(i64, String)> = conn
            .prepare("SELECT id, dest_ip FROM connection_events WHERE dest_class IS NULL")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;

        if pending.is_empty() {
            return Ok(());
        }
        info!("Backfilling dest_class for {} events", pending.len());

        let tx = conn.unchecked_transaction()?;
        {
            let mut upd = tx.prepare("UPDATE connection_events SET dest_class = ?1 WHERE id = ?2")?;
            for (id, dest_ip) in &pending {
                upd.execute(params![classify_dest(dest_ip).as_str(), id])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// rustnetec: T-A5 — 迁移：旧结构 aggregates 表重建 + 全量回填。
    ///
    /// 旧库 aggregates 无 dest_class/duration_secs 列且缺唯一索引，积累了海量
    /// 重复桶行（每 60s 聚合把同一桶重插一遍）。重建 = 删表重建 + 从
    /// connection_events 全量重算分钟/小时桶，顺带回收磁盘空间。
    /// 回填的 bucket_ts 格式必须与 run_aggregation 一致（UTC，分钟 `%H:%M:00`）。
    fn rebuild_aggregates(conn: &Connection) -> Result<()> {
        info!("Rebuilding aggregates table (legacy schema without dest_class)");

        conn.execute_batch(
            "DROP TABLE IF EXISTS aggregates;
             CREATE TABLE aggregates (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket_ts       TEXT    NOT NULL,
                bucket_width    TEXT    NOT NULL,
                protocol        TEXT,
                process_name    TEXT,
                country_code    TEXT,
                asn             INTEGER,
                interface       TEXT,
                dest_class      TEXT,
                bytes_rx        INTEGER NOT NULL DEFAULT 0,
                bytes_tx        INTEGER NOT NULL DEFAULT 0,
                conn_count      INTEGER NOT NULL DEFAULT 0,
                duration_secs   INTEGER NOT NULL DEFAULT 0
             );",
        )?;

        // 分钟桶：全量回填（与 run_aggregation 同格式）。
        conn.execute_batch(
            "INSERT INTO aggregates (
                bucket_ts, bucket_width,
                protocol, process_name, country_code, asn, interface, dest_class,
                bytes_rx, bytes_tx, conn_count, duration_secs
             )
             SELECT
                strftime('%Y-%m-%dT%H:%M:00', ts) AS bucket_ts,
                'minute' AS bucket_width,
                protocol,
                process_name,
                geoip_country_code,
                geoip_asn,
                interface,
                dest_class,
                COALESCE(SUM(bytes_received), 0),
                COALESCE(SUM(bytes_sent), 0),
                COUNT(*),
                COALESCE(SUM(duration_secs), 0)
             FROM connection_events
             WHERE event_type = 'connection_closed'
             GROUP BY bucket_ts, protocol, process_name, geoip_country_code, geoip_asn, interface, dest_class;",
        )?;

        // 小时桶：从分钟桶合并（与 run_aggregation 同格式）。
        conn.execute_batch(
            "INSERT INTO aggregates (
                bucket_ts, bucket_width,
                protocol, process_name, country_code, asn, interface, dest_class,
                bytes_rx, bytes_tx, conn_count, duration_secs
             )
             SELECT
                strftime('%Y-%m-%dT%H:00:00', bucket_ts) AS hour_ts,
                'hour' AS bucket_width,
                protocol,
                process_name,
                country_code,
                asn,
                interface,
                dest_class,
                SUM(bytes_rx),
                SUM(bytes_tx),
                SUM(conn_count),
                SUM(duration_secs)
             FROM aggregates
             WHERE bucket_width = 'minute'
             GROUP BY hour_ts, protocol, process_name, country_code, asn, interface, dest_class;",
        )?;

        // 日桶：从小时桶合并（与 run_aggregation 同格式）。
        conn.execute_batch(
            "INSERT INTO aggregates (
                bucket_ts, bucket_width,
                protocol, process_name, country_code, asn, interface, dest_class,
                bytes_rx, bytes_tx, conn_count, duration_secs
             )
             SELECT
                strftime('%Y-%m-%dT00:00:00', bucket_ts) AS day_ts,
                'day' AS bucket_width,
                protocol,
                process_name,
                country_code,
                asn,
                interface,
                dest_class,
                SUM(bytes_rx),
                SUM(bytes_tx),
                SUM(conn_count),
                SUM(duration_secs)
             FROM aggregates
             WHERE bucket_width = 'hour'
             GROUP BY day_ts, protocol, process_name, country_code, asn, interface, dest_class;",
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
            if batch.len() >= batch_size
                || (last_flush.elapsed() >= flush_interval && !batch.is_empty())
            {
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
                let (retention_days, upload_enabled) = runtime_config
                    .read()
                    .map(|r| (r.retention_days, r.server_url.is_some()))
                    .unwrap_or((90, false));
                if let Err(e) = Self::run_cleanup(&conn, retention_days, upload_enabled) {
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
            "ts",
            "event_type",
            "protocol",
            "source_ip",
            "source_port",
            "dest_ip",
            "dest_port",
            "dest_class",
        ]);
        placeholders.extend_from_slice(&["?", "?", "?", "?", "?", "?", "?", "?"]);
        param_values.push(Box::new(event.timestamp.clone()));
        param_values.push(Box::new(event.event.clone()));
        param_values.push(Box::new(event.protocol.clone()));
        param_values.push(Box::new(event.source_ip.clone()));
        param_values.push(Box::new(event.source_port as i64));
        param_values.push(Box::new(event.destination_ip.clone()));
        param_values.push(Box::new(event.destination_port as i64));
        // rustnetec: T-A5 — dest_ip 的 classify_dest 分类，写入时算好落库，
        // 供聚合表与 /stats/range 的 scope 过滤做 SQL 下推。
        param_values.push(Box::new(classify_dest(&event.destination_ip).as_str().to_string()));

        // DNS fields (conditional)
        if rc.record_dns {
            columns.extend_from_slice(&["dest_hostname", "source_hostname"]);
            placeholders.extend_from_slice(&["?", "?"]);
            param_values.push(Box::new(event.destination_hostname.clone()));
            param_values.push(Box::new(event.source_hostname.clone()));
        }

        // Process fields (conditional)
        if rc.record_process {
            columns.extend_from_slice(&[
                "pid",
                "process_ppid",
                "process_name",
                "process_executable",
                "process_uid",
                "process_gid",
                "attribution_match",
            ]);
            placeholders.extend_from_slice(&["?", "?", "?", "?", "?", "?", "?"]);
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
                "k8s_pod_uid",
                "k8s_pod_name",
                "k8s_pod_ns",
                "k8s_container_id",
                "k8s_container_name",
                "k8s_cgroup_path",
            ]);
            placeholders.extend_from_slice(&["?", "?", "?", "?", "?", "?"]);
            if let Some(ref k8s) = event.kubernetes {
                param_values.push(Box::new(
                    k8s.get("pod_uid")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                ));
                param_values.push(Box::new(
                    k8s.get("pod_name")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                ));
                param_values.push(Box::new(
                    k8s.get("pod_namespace")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                ));
                param_values.push(Box::new(
                    k8s.get("container_id")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                ));
                param_values.push(Box::new(
                    k8s.get("container_name")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                ));
                param_values.push(Box::new(
                    k8s.get("cgroup_path")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                ));
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
            placeholders.extend_from_slice(&["?", "?"]);
            param_values.push(Box::new(event.dpi_protocol.clone()));
            param_values.push(Box::new(event.dpi_domain.clone()));
        }

        // GeoIP (conditional)
        if rc.record_geoip {
            columns.extend_from_slice(&[
                "geoip_country_code",
                "geoip_country_name",
                "geoip_asn",
                "geoip_as_org",
                "geoip_city",
                "geoip_postal_code",
            ]);
            placeholders.extend_from_slice(&["?", "?", "?", "?", "?", "?"]);
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
            placeholders.extend_from_slice(&["?", "?", "?"]);
            param_values.push(Box::new(event.bytes_sent.map(|v| v as i64)));
            param_values.push(Box::new(event.bytes_received.map(|v| v as i64)));
            param_values.push(Box::new(event.duration_secs.map(|v| v as i64)));
        }

        let sql = format!(
            "INSERT INTO connection_events ({}) VALUES ({})",
            columns.join(", "),
            placeholders.join(", ")
        );

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();
        tx.execute(&sql, param_refs.as_slice())?;

        Ok(())
    }

    /// Run aggregation: compute per-minute and per-hour summaries.
    ///
    /// rustnetec: T-A4 — 补实现预聚合逻辑：
    /// 1. 每分钟桶：聚合最近 2 分钟的 `connection_closed` 事件，按
    ///    (minute, protocol, process_name, country_code, asn, interface, dest_class) 写入
    ///    `aggregates`，`INSERT OR REPLACE` 幂等（同一桶+维度组合重写覆盖）。
    /// 2. 每小时桶：把分钟桶合并为小时桶，写入 `aggregates` 的 `bucket_width='hour'` 行。
    ///    合并窗口为最近 2 小时，幂等同上。
    /// 3. 每日桶：把小时桶合并为日桶，写入 `aggregates` 的 `bucket_width='day'` 行，
    ///    窗口最近 2 天，幂等同上。
    ///
    /// 设计权衡：
    /// - 2 分钟窗口兼顾「事件延迟写入漏数据」与「重复聚合开销」。
    /// - `INSERT OR REPLACE` 依赖 `idx_aggs_unique` 唯一索引（T-A5）实现真正的
    ///   幂等替换：无唯一约束时 REPLACE 退化为普通 INSERT，导致同桶重复行无限膨胀。
    fn run_aggregation(conn: &Connection) -> Result<()> {
        // Per-minute aggregation: 聚合最近 2 分钟的 closed 事件。
        conn.execute_batch(
            "INSERT OR REPLACE INTO aggregates (
                bucket_ts, bucket_width,
                protocol, process_name, country_code, asn, interface, dest_class,
                bytes_rx, bytes_tx, conn_count, duration_secs
             )
             SELECT
                strftime('%Y-%m-%dT%H:%M:00', ts) AS bucket_ts,
                'minute' AS bucket_width,
                protocol,
                process_name,
                geoip_country_code,
                geoip_asn,
                interface,
                dest_class,
                COALESCE(SUM(bytes_received), 0),
                COALESCE(SUM(bytes_sent), 0),
                COUNT(*),
                COALESCE(SUM(duration_secs), 0)
             FROM connection_events
             WHERE event_type = 'connection_closed'
               AND ts >= datetime('now', '-2 minutes')
             GROUP BY bucket_ts, protocol, process_name, geoip_country_code, geoip_asn, interface, dest_class;",
        )?;

        // Per-hour aggregation: 合并分钟桶为小时桶，窗口最近 2 小时。
        conn.execute_batch(
            "INSERT OR REPLACE INTO aggregates (
                bucket_ts, bucket_width,
                protocol, process_name, country_code, asn, interface, dest_class,
                bytes_rx, bytes_tx, conn_count, duration_secs
             )
             SELECT
                strftime('%Y-%m-%dT%H:00:00', bucket_ts) AS hour_ts,
                'hour' AS bucket_width,
                protocol,
                process_name,
                country_code,
                asn,
                interface,
                dest_class,
                SUM(bytes_rx),
                SUM(bytes_tx),
                SUM(conn_count),
                SUM(duration_secs)
             FROM aggregates
             WHERE bucket_width = 'minute'
               AND bucket_ts >= datetime('now', '-2 hours')
             GROUP BY hour_ts, protocol, process_name, country_code, asn, interface, dest_class;",
        )?;

        // Per-day aggregation: 合并小时桶为日桶，窗口最近 2 天。
        conn.execute_batch(
            "INSERT OR REPLACE INTO aggregates (
                bucket_ts, bucket_width,
                protocol, process_name, country_code, asn, interface, dest_class,
                bytes_rx, bytes_tx, conn_count, duration_secs
             )
             SELECT
                strftime('%Y-%m-%dT00:00:00', bucket_ts) AS day_ts,
                'day' AS bucket_width,
                protocol,
                process_name,
                country_code,
                asn,
                interface,
                dest_class,
                SUM(bytes_rx),
                SUM(bytes_tx),
                SUM(conn_count),
                SUM(duration_secs)
             FROM aggregates
             WHERE bucket_width = 'hour'
               AND bucket_ts >= datetime('now', '-2 days')
             GROUP BY day_ts, protocol, process_name, country_code, asn, interface, dest_class;",
        )?;
        Ok(())
    }

    /// Run cleanup: delete expired events that have already been uploaded.
    ///
    /// rustnetec: T-A5 — 修复未配置上传时旧事件永不清理的问题：
    /// 原条件要求 `id <= last_uploaded_event_id`，而 `server_url` 为空（未配置上传）
    /// 时 upload_cursor 恒为 0，90 天保留期形同虚设。现在显式传入 `upload_enabled`：
    /// 未启用上传时按 ts 直接删除；启用时才保留尚未上传的事件。
    fn run_cleanup(conn: &Connection, retention_days: u32, upload_enabled: bool) -> Result<()> {
        let days_str = format!("-{} days", retention_days);

        // Delete uploaded events older than retention period
        let deleted_events = conn.execute(
            "DELETE FROM connection_events
             WHERE ts < datetime('now', ?1)
               AND (?2 = 0 OR id <= (SELECT COALESCE(last_uploaded_event_id, 0) FROM upload_cursor WHERE id = 1))",
            params![days_str, upload_enabled as i64],
        )?;

        // Delete expired aggregates
        let deleted_aggs = conn.execute(
            "DELETE FROM aggregates WHERE bucket_ts < datetime('now', ?1)",
            params![days_str],
        )?;

        // rustnetec: delete expired reachability probes
        let deleted_probes = conn.execute(
            "DELETE FROM reachability_probes WHERE ts < datetime('now', ?1)",
            params![days_str],
        )?;

        // Incremental vacuum to reclaim space
        conn.execute_batch("PRAGMA incremental_vacuum;")?;

        if deleted_events > 0 || deleted_aggs > 0 || deleted_probes > 0 {
            info!(
                "Cleanup: deleted {} events, {} aggregates, {} reachability probes (retention: {} days)",
                deleted_events, deleted_aggs, deleted_probes, retention_days
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
    /// `upload_enabled=false` 表示未配置上传：按 ts 直接删旧事件（T-A5 新语义）。
    pub fn run_cleanup_for_test(conn: &Connection, retention_days: u32, upload_enabled: bool) -> Result<()> {
        Self::run_cleanup(conn, retention_days, upload_enabled)
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
                    // rustnetec: T-A2 — 从 connection_events.interface 列读取。
                    interface: r.get::<_, Option<String>>("interface")?,
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
        match self
            .tx
            .try_send(WriteCommand::Event(Box::new(event.clone())))
        {
            Ok(()) => {}
            Err(crossbeam::channel::TrySendError::Full(_)) => {
                static WARNED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
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
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert!(tables.contains(&"connection_events".to_string()));
        assert!(tables.contains(&"aggregates".to_string()));
        assert!(tables.contains(&"upload_cursor".to_string()));
        assert!(tables.contains(&"schema_version".to_string()));

        // Verify indexes exist
        let indexes: Vec<String> = conn.prepare("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%' ORDER BY name").unwrap()
            .query_map([], |row| row.get(0)).unwrap().filter_map(|r| r.ok()).collect();
        assert!(
            indexes.len() >= 10,
            "Should have at least 10 indexes, got {}",
            indexes.len()
        );
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
            interface: Some("en0".to_string()),
        };

        let tx = conn.unchecked_transaction().unwrap();
        SqliteSink::insert_event(&tx, &event, &rc_guard).unwrap();
        tx.commit().unwrap();

        // Read back
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM connection_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);

        let protocol: String = conn
            .query_row(
                "SELECT protocol FROM connection_events LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
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
            interface: None,
        };

        let tx = conn.unchecked_transaction().unwrap();
        SqliteSink::insert_event(&tx, &event, &rc_guard).unwrap();
        tx.commit().unwrap();

        // Verify DNS columns are NULL (not recorded)
        let dest_hostname: Option<String> = conn
            .query_row(
                "SELECT dest_hostname FROM connection_events LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            dest_hostname.is_none(),
            "dest_hostname should be NULL when record_dns is false"
        );
    }

    #[test]
    fn upload_cursor_initialized() {
        let conn = open_test_connection();
        SqliteSink::init_schema(&conn).unwrap();

        let last_id: i64 = conn
            .query_row(
                "SELECT last_uploaded_event_id FROM upload_cursor WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(last_id, 0, "upload_cursor should start at 0");
    }

    #[test]
    fn schema_version_is_1() {
        let conn = open_test_connection();
        SqliteSink::init_schema(&conn).unwrap();

        let version: i64 = conn
            .query_row(
                "SELECT version FROM schema_version WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 1, "schema version should be 1");
    }

    #[test]
    fn pragma_settings_applied() {
        let conn = open_test_connection();
        SqliteSink::init_schema(&conn).unwrap();
        SqliteSink::configure_pragma(&conn).unwrap();

        // In-memory databases use "memory" journal mode, file-based use "wal"
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert!(
            journal_mode == "wal" || journal_mode == "memory",
            "journal_mode should be wal or memory, got {}",
            journal_mode
        );

        let busy_timeout: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(busy_timeout, 5000);
    }

    // ---- rustnetec: T-A5 — dest_class / 聚合幂等 / 迁移 / 清理修复 ----

    #[test]
    fn insert_writes_dest_class() {
        let conn = open_test_connection();
        SqliteSink::init_schema(&conn).unwrap();
        let rc = test_runtime_config();
        let rc_guard = rc.read().unwrap();

        // 外网 IP → external
        let event_ext = ConnectionEventData {
            timestamp: "2026-08-13T10:00:00.000+08:00".to_string(),
            event: "connection_closed".to_string(),
            protocol: "TCP".to_string(),
            source_ip: "192.168.1.5".to_string(),
            source_port: 12345,
            destination_ip: "8.8.8.8".to_string(),
            destination_port: 443,
            destination_hostname: None,
            source_hostname: None,
            pid: None,
            process_ppid: None,
            process_name: Some("curl".to_string()),
            process_executable: None,
            process_uid: None,
            process_gid: None,
            attribution_match: None,
            rtt_ms: None,
            #[cfg(feature = "kubernetes")]
            kubernetes: None,
            service_name: None,
            direction: Some("outgoing".to_string()),
            dpi_protocol: None,
            dpi_domain: None,
            geoip_country_code: None,
            geoip_country_name: None,
            geoip_asn: None,
            geoip_as_org: None,
            geoip_city: None,
            geoip_postal_code: None,
            bytes_sent: Some(100),
            bytes_received: Some(200),
            duration_secs: Some(5),
            interface: Some("en0".to_string()),
        };
        let tx = conn.unchecked_transaction().unwrap();
        SqliteSink::insert_event(&tx, &event_ext, &rc_guard).unwrap();
        tx.commit().unwrap();

        let dc: String = conn
            .query_row("SELECT dest_class FROM connection_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(dc, "external");

        // 局域网 IP → lan
        let event_lan = ConnectionEventData {
            destination_ip: "10.0.0.1".to_string(),
            ..event_ext.clone()
        };
        let tx = conn.unchecked_transaction().unwrap();
        SqliteSink::insert_event(&tx, &event_lan, &rc_guard).unwrap();
        tx.commit().unwrap();
        let dcs: Vec<String> = conn
            .prepare("SELECT dest_class FROM connection_events ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(dcs, vec!["external".to_string(), "lan".to_string()]);
    }

    #[test]
    fn aggregation_is_idempotent_with_unique_index() {
        let conn = open_test_connection();
        SqliteSink::init_schema(&conn).unwrap();
        let rc = test_runtime_config();
        let rc_guard = rc.read().unwrap();

        // 插入同一分钟桶、同一维度组合的 3 条 closed 事件（dest 同为外网）。
        let event = ConnectionEventData {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event: "connection_closed".to_string(),
            protocol: "TCP".to_string(),
            source_ip: "192.168.1.5".to_string(),
            source_port: 12345,
            destination_ip: "8.8.8.8".to_string(),
            destination_port: 443,
            destination_hostname: None,
            source_hostname: None,
            pid: None,
            process_ppid: None,
            process_name: Some("curl".to_string()),
            process_executable: None,
            process_uid: None,
            process_gid: None,
            attribution_match: None,
            rtt_ms: None,
            #[cfg(feature = "kubernetes")]
            kubernetes: None,
            service_name: None,
            direction: Some("outgoing".to_string()),
            dpi_protocol: None,
            dpi_domain: None,
            geoip_country_code: Some("US".to_string()),
            geoip_country_name: None,
            geoip_asn: Some(15169),
            geoip_as_org: None,
            geoip_city: None,
            geoip_postal_code: None,
            bytes_sent: Some(100),
            bytes_received: Some(200),
            duration_secs: Some(5),
            interface: Some("en0".to_string()),
        };
        for _ in 0..3 {
            let tx = conn.unchecked_transaction().unwrap();
            SqliteSink::insert_event(&tx, &event, &rc_guard).unwrap();
            tx.commit().unwrap();
        }

        // 聚合两次：唯一索引生效后行数应保持不变（INSERT OR REPLACE 真正幂等）。
        SqliteSink::run_aggregation(&conn).unwrap();
        let n1: i64 = conn
            .query_row("SELECT COUNT(*) FROM aggregates", [], |row| row.get(0))
            .unwrap();
        assert!(n1 > 0, "aggregation should produce rows");

        SqliteSink::run_aggregation(&conn).unwrap();
        let n2: i64 = conn
            .query_row("SELECT COUNT(*) FROM aggregates", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            n1, n2,
            "second aggregation must not duplicate bucket rows (unique index)"
        );

        // 聚合值正确：3 条事件合计。
        let (rx, tx, cnt, dur): (i64, i64, i64, i64) = conn
            .query_row(
                "SELECT SUM(bytes_rx), SUM(bytes_tx), SUM(conn_count), SUM(duration_secs) \
                 FROM aggregates WHERE bucket_width='minute'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!((rx, tx, cnt, dur), (600, 300, 3, 15));
    }

    #[test]
    fn backfill_dest_class_fills_legacy_rows() {
        let conn = open_test_connection();
        SqliteSink::init_schema(&conn).unwrap();

        // 模拟旧库：dest_class 为 NULL 的存量行。
        conn.execute(
            "INSERT INTO connection_events
                (ts, event_type, protocol, source_ip, source_port, dest_ip, dest_port)
             VALUES
                ('2026-08-01T10:00:00+08:00', 'connection_closed', 'TCP', '192.168.1.5', 1, '8.8.8.8', 443),
                ('2026-08-01T10:00:00+08:00', 'connection_closed', 'UDP', '192.168.1.5', 2, '10.0.0.1', 53)",
            [],
        )
        .unwrap();

        SqliteSink::backfill_dest_class(&conn).unwrap();

        let dcs: Vec<String> = conn
            .prepare("SELECT dest_class FROM connection_events ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(dcs, vec!["external".to_string(), "lan".to_string()]);
    }

    #[test]
    fn rebuild_aggregates_recreates_and_backfills() {
        let conn = open_test_connection();
        SqliteSink::init_schema(&conn).unwrap();

        // 造 2 条 closed 事件（同一分钟桶，不同 dest_class），模拟重建前的数据源。
        conn.execute(
            "INSERT INTO connection_events
                (ts, event_type, protocol, source_ip, source_port, dest_ip, dest_port, dest_class,
                 bytes_sent, bytes_received, duration_secs, interface)
             VALUES
                ('2026-08-01T10:05:00+08:00', 'connection_closed', 'TCP', '192.168.1.5', 1, '8.8.8.8', 443, 'external', 100, 200, 5, 'en0'),
                ('2026-08-01T10:05:30+08:00', 'connection_closed', 'TCP', '192.168.1.5', 2, '10.0.0.1', 53, 'lan', 50, 80, 3, 'en0')",
            [],
        )
        .unwrap();

        // 模拟旧库：先塞满重复桶行再重建。
        conn.execute(
            "INSERT INTO aggregates (bucket_ts, bucket_width, bytes_rx, bytes_tx, conn_count)
             VALUES ('2026-08-01T10:05:00', 'minute', 999, 999, 999)",
            [],
        )
        .unwrap();

        SqliteSink::rebuild_aggregates(&conn).unwrap();

        // 重建后：旧重复行消失，回填出新行（含 dest_class/duration_secs）。
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM aggregates", [], |row| row.get(0))
            .unwrap();
        assert!(n > 0, "rebuild should backfill aggregates");

        let (rx, tx, cnt, dur): (i64, i64, i64, i64) = conn
            .query_row(
                "SELECT SUM(bytes_rx), SUM(bytes_tx), SUM(conn_count), SUM(duration_secs) \
                 FROM aggregates WHERE bucket_width='minute'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!((rx, tx, cnt, dur), (280, 150, 2, 8));

        // dest_class 维度保留（external 桶存在）。
        let ext: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM aggregates WHERE dest_class='external'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(ext > 0);
    }

    #[test]
    fn cleanup_without_upload_deletes_expired() {
        let conn = open_test_connection();
        SqliteSink::init_schema(&conn).unwrap();

        // 200 天前的事件（超过默认 90 天 retention），upload_cursor 保持 0（未上传）。
        let old_ts = chrono::Local::now()
            .checked_sub_signed(chrono::Duration::days(200))
            .unwrap()
            .to_rfc3339();
        conn.execute(
            "INSERT INTO connection_events
                (ts, event_type, protocol, source_ip, source_port, dest_ip, dest_port)
             VALUES (?1, 'connection_closed', 'TCP', '192.168.1.5', 1, '8.8.8.8', 443)",
            rusqlite::params![old_ts],
        )
        .unwrap();

        // 未配置上传（upload_enabled=false）：按 ts 直接删除 → 旧事件被清。
        SqliteSink::run_cleanup_for_test(&conn, 90, false).unwrap();
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM connection_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 0, "no-upload mode must delete expired events");

        // 配置上传且未上传（upload_enabled=true, cursor=0）：保留。
        conn.execute(
            "INSERT INTO connection_events
                (ts, event_type, protocol, source_ip, source_port, dest_ip, dest_port)
             VALUES (?1, 'connection_closed', 'TCP', '192.168.1.5', 1, '8.8.8.8', 443)",
            rusqlite::params![old_ts],
        )
        .unwrap();
        SqliteSink::run_cleanup_for_test(&conn, 90, true).unwrap();
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM connection_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 1, "unuploaded expired events must be retained");
    }
}

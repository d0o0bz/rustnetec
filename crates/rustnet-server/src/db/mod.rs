//! SQLite storage layer for the server (T2.3).
//!
//! Responsibilities:
//! - Open/create the server database and run schema v2 migrations
//! - Configure PRAGMAs (WAL, auto_vacuum INCREMENTAL, busy_timeout, cache/mmap)
//! - Hold a single writer connection behind a `Mutex` (single-writer model)
//! - Set Unix file permissions to `0600` (server runs as a dedicated user,
//!   no `sudo → drop uid → chown` flow)
//!
//! # Schema v2 (per `docs/数据模型设计.md` §3)
//!
//! | Table              | Purpose                                        |
//! | ------------------ | ---------------------------------------------- |
//! | `server_events`    | Centralized event store + idempotent dedup     |
//! | `server_aggregates`| Server-side per-bucket aggregates              |
//! | `server_hosts`     | Host registry keyed by `machine_id`            |
//! | `server_tokens`    | API auth tokens (BLAKE3 hash)                  |
//! | `schema_version`   | Migration ledger                               |

pub mod error;
pub mod partition;
pub mod query;
pub mod retention;
pub mod write;

pub use error::Error;
pub use query::{query_events, stats};
pub use retention::purge_expired;
pub use write::ingest_write;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::Connection;

/// Tunables for [`init`].
#[derive(Debug, Clone)]
pub struct ServerDbConfig {
    /// SQLite page-cache size in KiB (negative = N MiB). Default 16 MiB.
    pub cache_size: i64,
    /// `mmap_size` in bytes; `0` disables mmap. Default `0`.
    pub mmap_size: i64,
    /// `busy_timeout` in milliseconds. Default 5000.
    pub busy_timeout: u32,
}

impl Default for ServerDbConfig {
    fn default() -> Self {
        Self {
            cache_size: -16384,
            mmap_size: 0,
            busy_timeout: 5000,
        }
    }
}

/// Server database handle.
///
/// Owns a single writer connection guarded by a `Mutex` (single-writer
/// convergence). All `/ingest` writes funnel through [`ServerDb::lock_writer`].
pub struct ServerDb {
    writer: Mutex<Connection>,
    db_path: PathBuf,
}

impl ServerDb {
    /// Acquire the writer connection (blocks until the mutex is free).
    pub fn lock_writer(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.writer.lock().expect("writer mutex poisoned")
    }

    /// Convenience: run an ingest batch through the writer connection.
    pub fn ingest(
        &self,
        req: &rustnet_core::ingest::IngestRequest,
    ) -> Result<rustnet_core::ingest::IngestResponse> {
        let mut conn = self.lock_writer();
        ingest_write(&mut conn, req)
    }

    /// Read-only historical query (T2.4). Reuses the writer connection;
    /// safe under the single-writer model.
    ///
    /// rustnetec: `scope` enforces per-machine visibility.
    pub fn query_events(
        &self,
        params: &rustnet_core::ingest::QueryParams,
        scope: &query::Scope,
    ) -> Result<rustnet_core::ingest::QueryResponse> {
        let mut conn = self.lock_writer();
        query::query_events(&mut conn, params, scope)
    }

    /// Live aggregate statistics (T2.4).
    ///
    /// rustnetec: `scope` enforces per-machine visibility.
    pub fn stats(&self, scope: &query::Scope) -> Result<rustnet_core::ingest::StatsResponse> {
        let mut conn = self.lock_writer();
        query::stats(&mut conn, scope)
    }

    /// rustnetec: W5.3 — 按 process_name 聚合 top 50,供 WebUI Activity 页专用。
    ///
    /// rustnetec: `scope` enforces per-machine visibility.
    pub fn processes(
        &self,
        scope: &query::Scope,
    ) -> Result<query::ProcessesResponse> {
        let mut conn = self.lock_writer();
        let rows = query::processes(&mut conn, scope)?;
        let count = rows.len();
        Ok(query::ProcessesResponse { processes: rows, count })
    }

    /// rustnetec: T-E5 — 时间桶流量聚合（/stats/range），供 WebUI 多进程对比。
    ///
    /// rustnetec: `scope` enforces per-machine visibility.
    pub fn stats_range(
        &self,
        params: &query::RangeParams,
        scope: &query::Scope,
    ) -> Result<serde_json::Value> {
        let mut conn = self.lock_writer();
        query::stats_range(&mut conn, params, scope)
    }

    /// Path of the underlying database file (for backups/debugging).
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
}

/// Open (or create) the server database and run schema v2 migrations.
///
/// # Side effects
/// - Creates the database file if absent.
/// - On Unix, sets the file mode to `0600` (owner-only read/write).
pub fn init(db_path: &Path, cfg: &ServerDbConfig) -> Result<ServerDb> {
    // Open with default flags (includes CREATE_IF_NECESSARY via rusqlite).
    let mut conn = Connection::open(db_path)
        .with_context(|| format!("failed to open server db at {}", db_path.display()))?;

    apply_pragmas(&mut conn, cfg)?;
    run_schema_v2(&mut conn)?;
    run_schema_v3(&mut conn)?;

    // Unix: lock the db file to 0600 (server runs as a dedicated user, no chown).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(db_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to chmod 0600 {}", db_path.display()))?;
    }

    Ok(ServerDb {
        writer: Mutex::new(conn),
        db_path: db_path.to_path_buf(),
    })
}

/// Configure connection PRAGMAs per `docs/数据模型设计.md` §2.1.
fn apply_pragmas(conn: &mut Connection, cfg: &ServerDbConfig) -> Result<()> {
    let pragmas = [
        "journal_mode = WAL",
        "auto_vacuum = INCREMENTAL",
        "synchronous = NORMAL",
        "foreign_keys = ON",
    ];
    for p in pragmas {
        conn.pragma_update(
            None,
            p.split('=').next().unwrap().trim(),
            p.split('=').nth(1).unwrap().trim(),
        )
        .with_context(|| format!("PRAGMA {p} failed"))?;
    }
    conn.pragma_update(None, "busy_timeout", cfg.busy_timeout)
        .context("PRAGMA busy_timeout failed")?;
    conn.pragma_update(None, "cache_size", cfg.cache_size)
        .context("PRAGMA cache_size failed")?;
    conn.pragma_update(None, "mmap_size", cfg.mmap_size)
        .context("PRAGMA mmap_size failed")?;
    Ok(())
}

/// Execute schema v2 DDL + indexes, and record the migration in
/// `schema_version` (idempotent via `INSERT OR IGNORE`).
fn run_schema_v2(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction().context("begin schema v2 tx failed")?;

    // ---- server_events (§3.2) ----
    tx.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS server_events (
            -- 主键
            id              INTEGER PRIMARY KEY AUTOINCREMENT,  -- 服务端自增 ID

            -- 主机身份 (来自上报 payload)
            machine_id      TEXT    NOT NULL,    -- 硬件级机器 ID (BLAKE3 哈希)
            user_id         INTEGER NOT NULL,    -- 安装级用户 ID (雪花算法，64-bit 整数)
            username        TEXT    NOT NULL,    -- 人类可读用户名 (默认 OS 用户名，可修改)
            ip_list         TEXT,                -- 上报时本机 IP 列表 (JSON 数组)

            -- 客户端事件 ID (幂等去重)
            local_event_id  INTEGER NOT NULL,    -- 客户端 connection_events.id

            -- 事件元数据
            ts              TEXT    NOT NULL,    -- RFC 3339 时间戳
            event_type      TEXT,                -- "new_connection" | "connection_closed"
            ingest_ts       TEXT    NOT NULL,    -- 服务端接收时间 (RFC 3339)

            -- 五元组
            protocol        TEXT    NOT NULL,
            source_ip       TEXT    NOT NULL,
            source_port     INTEGER NOT NULL,
            dest_ip         TEXT    NOT NULL,
            dest_port       INTEGER NOT NULL,

            -- DNS 解析
            dest_hostname   TEXT,
            source_hostname TEXT,

            -- 进程归因
            pid             INTEGER,
            process_ppid    INTEGER,
            process_name    TEXT,
            process_executable TEXT,
            process_uid     INTEGER,
            process_gid     INTEGER,
            attribution_match TEXT,

            -- RTT
            rtt_ms          REAL,

            -- Kubernetes
            k8s_pod_uid     TEXT,
            k8s_pod_name    TEXT,
            k8s_pod_ns      TEXT,
            k8s_container_id TEXT,
            k8s_container_name TEXT,
            k8s_cgroup_path TEXT,

            -- 服务
            service_name    TEXT,

            -- 方向
            direction       TEXT,

            -- DPI
            dpi_protocol    TEXT,
            dpi_domain      TEXT,

            -- GeoIP
            geoip_country_code TEXT,
            geoip_country_name TEXT,
            geoip_asn       INTEGER,
            geoip_as_org    TEXT,
            geoip_city      TEXT,
            geoip_postal_code TEXT,

            -- 连接统计
            bytes_sent      INTEGER,
            bytes_received  INTEGER,
            duration_secs   INTEGER,

            -- 幂等去重唯一约束
            UNIQUE (user_id, local_event_id)
        );
        "#,
    )
    .context("CREATE server_events failed")?;

    // ---- server_aggregates (§3.3) ----
    tx.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS server_aggregates (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,

            -- 时间桶
            bucket_ts       TEXT    NOT NULL,    -- 桶起始时间 (RFC 3339)
            bucket_width    TEXT    NOT NULL,    -- "minute" | "hour"

            -- 主机维度
            machine_id      TEXT,                -- 按物理机归并 (NULL = 全机器汇总)
            user_id         INTEGER,             -- 按安装归并 (NULL = 全安装汇总)

            -- 流量维度
            protocol        TEXT,
            process_name    TEXT,
            country_code    TEXT,
            asn             INTEGER,

            -- 度量
            bytes_rx        INTEGER NOT NULL DEFAULT 0,
            bytes_tx        INTEGER NOT NULL DEFAULT 0,
            conn_count      INTEGER NOT NULL DEFAULT 0
        );
        "#,
    )
    .context("CREATE server_aggregates failed")?;

    // ---- server_hosts (§3.4) ----
    tx.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS server_hosts (
            machine_id      TEXT    PRIMARY KEY,         -- 硬件级机器 ID (BLAKE3)
            user_id         INTEGER NOT NULL,            -- 最新的安装级用户 ID
            username        TEXT    NOT NULL,            -- 最新的用户名
            ip_list         TEXT,                         -- 最新的 IP 列表 (JSON 数组)
            first_seen      TEXT    NOT NULL,             -- 首次上报时间 (RFC 3339)
            last_seen       TEXT    NOT NULL,             -- 最近上报时间 (RFC 3339)
            event_count     INTEGER NOT NULL DEFAULT 0    -- 累计上报事件数
        );
        "#,
    )
    .context("CREATE server_hosts failed")?;

    // ---- server_tokens (§3.5) ----
    tx.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS server_tokens (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash      TEXT    NOT NULL UNIQUE,      -- token 的 BLAKE3 哈希 (不存明文)
            role            TEXT    NOT NULL,             -- "admin" | "ingest" | "query"
            description     TEXT,                         -- 可选描述 (如 "client-host-A")
            created_at      TEXT    NOT NULL,             -- 创建时间 (RFC 3339)
            last_used_at    TEXT,                         -- 最近使用时间 (RFC 3339)
            is_active       INTEGER NOT NULL DEFAULT 1    -- 1=启用, 0=禁用
        );
        "#,
    )
    .context("CREATE server_tokens failed")?;

    // ---- schema_version (§11.1) ----
    tx.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS schema_version (
            version     INTEGER PRIMARY KEY,     -- Schema 版本号
            applied_at  TEXT NOT NULL,           -- 应用时间 (RFC 3339)
            description TEXT                     -- 变更描述
        );
        "#,
    )
    .context("CREATE schema_version failed")?;

    // ---- Indexes (§3.6) ----
    tx.execute_batch(
        r#"
        -- 事件表索引
        CREATE INDEX IF NOT EXISTS idx_svr_events_ts ON server_events (ts);
        CREATE INDEX IF NOT EXISTS idx_svr_events_machine ON server_events (machine_id);
        CREATE INDEX IF NOT EXISTS idx_svr_events_user ON server_events (user_id);
        CREATE INDEX IF NOT EXISTS idx_svr_events_protocol ON server_events (protocol);
        CREATE INDEX IF NOT EXISTS idx_svr_events_process ON server_events (process_name);
        CREATE INDEX IF NOT EXISTS idx_svr_events_country ON server_events (geoip_country_code);
        CREATE INDEX IF NOT EXISTS idx_svr_events_dpi ON server_events (dpi_protocol);
        CREATE INDEX IF NOT EXISTS idx_svr_events_direction ON server_events (direction);

        -- 多主机按"同一人类用户"归并查询
        -- (username 默认取 OS 用户名，用户初始化后可自行修改；一个月内最多修改 3 次)
        CREATE INDEX IF NOT EXISTS idx_svr_events_username ON server_events (username);

        -- 复合索引：清理与去重核心路径
        CREATE INDEX IF NOT EXISTS idx_svr_events_ts_id ON server_events (ts, id);
        CREATE INDEX IF NOT EXISTS idx_svr_events_user_local ON server_events (user_id, local_event_id);

        -- 聚合表索引
        CREATE INDEX IF NOT EXISTS idx_svr_aggs_bucket ON server_aggregates (bucket_ts, bucket_width);
        CREATE INDEX IF NOT EXISTS idx_svr_aggs_machine ON server_aggregates (machine_id);
        CREATE INDEX IF NOT EXISTS idx_svr_aggs_user ON server_aggregates (user_id);

        -- 主机表索引
        CREATE INDEX IF NOT EXISTS idx_svr_hosts_user ON server_hosts (user_id);
        CREATE INDEX IF NOT EXISTS idx_svr_hosts_last_seen ON server_hosts (last_seen);
        "#,
    )
    .context("CREATE indexes failed")?;

    // ---- Record migration (idempotent) ----
    let now = chrono::Local::now().to_rfc3339();
    tx.execute(
        "INSERT OR IGNORE INTO schema_version (version, applied_at, description) VALUES (?, ?, ?)",
        rusqlite::params![
            2,
            now,
            "initial schema v2: server_events/aggregates/hosts/tokens"
        ],
    )
    .context("INSERT schema_version failed")?;

    tx.commit().context("commit schema v2 tx failed")?;
    Ok(())
}

/// rustnetec: Schema v3 — per-machine token scope.
///
/// Adds `scope_machine_id` to `server_tokens`:
/// - `NULL` → admin token, full data access (no filtering)
/// - non-`NULL` → query/ingest token, restricted to that machine's data
///
/// **Default-tighten policy**: on migration, all existing non-admin tokens
/// are soft-revoked (`is_active = 0`). Operators must re-issue scoped tokens
/// via `POST /admin/tokens`. Admin tokens are left untouched.
///
/// Idempotent: if `scope_machine_id` column already exists, the migration
/// is a no-op (the revoke also only fires once, guarded by
/// `schema_version` row presence).
fn run_schema_v3(conn: &mut Connection) -> Result<()> {
    // Check if the column already exists (idempotency guard).
    let has_scope_col: bool = {
        let mut stmt = conn
            .prepare("PRAGMA table_info(server_tokens)")
            .context("PRAGMA table_info(server_tokens) failed")?;
        let names: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .context("query table_info names")?
            .filter_map(|r| r.ok())
            .collect();
        names.iter().any(|n| n == "scope_machine_id")
    };

    if !has_scope_col {
        conn.execute(
            "ALTER TABLE server_tokens ADD COLUMN scope_machine_id TEXT",
            [],
        )
        .context("ALTER TABLE server_tokens ADD scope_machine_id failed")?;
    }

    // Record migration (idempotent via INSERT OR IGNORE).
    let now = chrono::Local::now().to_rfc3339();
    conn.execute(
        "INSERT OR IGNORE INTO schema_version (version, applied_at, description) \
         VALUES (?, ?, ?)",
        rusqlite::params![
            3,
            now,
            "add scope_machine_id to server_tokens; revoke non-admin tokens (default-tighten)"
        ],
    )
    .context("INSERT schema_version v3 failed")?;

    // Default-tighten: revoke all non-admin tokens so operators must
    // explicitly re-issue scoped tokens. Only run if we just added the
    // column (i.e., first-time migration to v3).
    if !has_scope_col {
        let revoked: usize = conn
            .execute(
                "UPDATE server_tokens SET is_active = 0 WHERE role != 'admin'",
                [],
            )
            .context("UPDATE server_tokens revoke non-admin failed")?;
        if revoked > 0 {
            log::warn!(
                "schema v3 migration: revoked {} non-admin token(s); \
                 re-issue scoped tokens via POST /admin/tokens",
                revoked
            );
        }
    }

    Ok(())
}

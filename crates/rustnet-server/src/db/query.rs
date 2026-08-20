//! Read-side queries (T2.4).
//!
//! [`query_events`] reads `server_events` rows filtered by [`QueryParams`],
//! and [`stats`] aggregates live totals plus per-host breakdowns from the
//! same table. Both go through the single writer connection (small-data
//! stage); a separate read pool can be introduced later if contention bites.
//!
//! All user-supplied values are bound as parameters — nothing is string-
//! interpolated into SQL — so `filter`/`sql` cannot inject. Raw `sql` is
//! rejected outright (see [`rejection_of_sql`]); the protocol reserves it
//! for power users, but the server side never executes arbitrary SQL.

use anyhow::{Context, Result};
use log::{debug, warn};
use rusqlite::{Connection, Row, params_from_iter};
use std::time::Instant;
use rustnet_core::ingest::{
    AggregateRow, ClientEvent, HostStats, K8sFields, QueryParams, QueryResponse, QueryRow,
    StatsResponse,
};

use super::Error;

// ---------------------------------------------------------------------------
// rustnetec: per-machine data scope (token-bound visibility filter)
// ---------------------------------------------------------------------------

/// rustnetec: Data-visibility scope injected into every read path.
///
/// - `All` — admin token, no filtering (cross-machine view)
/// - `Machine(mid)` — query/ingest token, restrict to `machine_id = mid`
///
/// The scope value originates from `TokenPrincipal.scope_machine_id`
/// (resolved by the auth middleware) and is **never** taken from client
/// request parameters, so a scoped token cannot escape its machine filter.
#[derive(Debug, Clone)]
pub enum Scope {
    All,
    Machine(String),
}

impl Scope {
    /// Build a `Scope` from a resolved principal's `scope_machine_id`.
    /// `None` (admin) → `Scope::All`; `Some(mid)` → `Scope::Machine(mid)`.
    pub fn from_scope(mid: &Option<String>) -> Self {
        match mid {
            Some(m) if !m.is_empty() => Scope::Machine(m.clone()),
            _ => Scope::All,
        }
    }

    /// True when this scope imposes no `machine_id` filter.
    pub fn is_unscoped(&self) -> bool {
        matches!(self, Scope::All)
    }
}

// ---------------------------------------------------------------------------
// /query
// ---------------------------------------------------------------------------

/// Read events from `server_events` matching `params`.
///
/// Ordering is `ts DESC, id DESC` (most-recent first). `limit` defaults to
/// 200 and is clamped to 1000 to bound response size.
///
/// rustnetec: `scope` enforces per-machine visibility. A scoped token
/// (`Scope::Machine(mid)`) only sees rows whose `machine_id = mid`;
/// `Scope::All` (admin) sees everything. The filter is injected by the
/// server and cannot be overridden by client `params`.
pub fn query_events(
    conn: &mut Connection,
    params: &QueryParams,
    scope: &Scope,
) -> Result<QueryResponse> {
    let limit = params.limit.unwrap_or(200).min(1000);
    let started = Instant::now();

    let mut sql = String::from(
        r#"
        SELECT
            id, machine_id, user_id, username, ip_list,
            local_event_id, ts, ingest_ts,
            protocol, source_ip, source_port, dest_ip, dest_port,
            pid, process_name,
            bytes_sent, bytes_received, duration_secs,
            dpi_domain, service_name,
            geoip_country_code, geoip_city,
            dest_hostname,
            k8s_pod_name, k8s_container_name, k8s_pod_ns
        FROM server_events
        "#,
    );

    let mut conditions: Vec<String> = Vec::new();
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    // rustnetec: inject machine_id scope first (server-side, untamperable).
    if let Scope::Machine(mid) = scope {
        conditions.push("machine_id = ?".to_string());
        binds.push(Box::new(mid.clone()));
    }

    if let Some(from) = params.from {
        conditions.push("ts >= ?".to_string());
        binds.push(Box::new(from.to_string()));
    }
    if let Some(to) = params.to {
        conditions.push("ts < ?".to_string());
        binds.push(Box::new(to.to_string()));
    }

    if let Some(filter) = &params.filter {
        let clause = compile_filter(filter, &mut binds)?;
        conditions.push(clause);
    }

    // Reject raw SQL outright — never execute user-supplied SQL.
    if let Some(_raw) = &params.sql {
        return Err(Error::Other(anyhow::anyhow!(
            "raw `sql` parameter is not supported; use `filter` instead"
        ))
        .into());
    }

    if !conditions.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&conditions.join(" AND "));
    }
    sql.push_str(" ORDER BY ts DESC, id DESC LIMIT ?");

    let mut query = conn
        .prepare(&sql)
        .with_context(|| format!("prepare query: {sql}"))?;

    // Chain binds with the limit, then convert to an iterator of `&dyn ToSql`
    // for rusqlite's `query_map`.
    let limit_i64 = limit as i64;
    let mut all_binds: Vec<Box<dyn rusqlite::ToSql>> = binds;
    all_binds.push(Box::new(limit_i64));
    let bind_refs: Vec<&dyn rusqlite::ToSql> = all_binds.iter().map(|b| b.as_ref()).collect();

    let rows: Vec<QueryRow> = query
        .query_map(
            params_from_iter(bind_refs.iter().copied()),
            row_to_query_row,
        )?
        .filter_map(|r| r.ok())
        .collect();

    debug!(
        "query_events: 完成 (scope={:?}, conditions={}, 返回={} 行, 耗时 {}ms)",
        scope, conditions.len(), rows.len(), started.elapsed().as_millis()
    );
    Ok(QueryResponse { rows })
}

/// Convert one `server_events` row into a [`QueryRow`].
///
/// `QueryRow` flattens [`ClientEvent`] via `#[serde(flatten)]`, so we
/// assemble the `ClientEvent` from the matching columns and let serde handle
/// the wire layout.
fn row_to_query_row(row: &Row<'_>) -> rusqlite::Result<QueryRow> {
    let server_event_id: i64 = row.get("id")?;
    let local_event_id: i64 = row.get("local_event_id")?;
    let machine_id: String = row.get("machine_id")?;
    let user_id: i64 = row.get("user_id")?;

    let ts: String = row.get("ts")?;
    let protocol: String = row.get("protocol")?;
    let source_ip: String = row.get("source_ip")?;
    let source_port: i64 = row.get("source_port")?;
    let dest_ip: String = row.get("dest_ip")?;
    let dest_port: i64 = row.get("dest_port")?;
    let pid: Option<i64> = row.get("pid")?;
    let process_name: Option<String> = row.get("process_name")?;
    let bytes_sent: Option<i64> = row.get("bytes_sent")?;
    let bytes_received: Option<i64> = row.get("bytes_received")?;
    let duration_secs: Option<i64> = row.get("duration_secs")?;

    let sni: Option<String> = row.get("dpi_domain")?;
    let service_name: Option<String> = row.get("service_name")?;
    let geoip_country_code: Option<String> = row.get("geoip_country_code")?;
    let geoip_city: Option<String> = row.get("geoip_city")?;
    let dns_name: Option<String> = row.get("dest_hostname")?;
    let k8s_pod_name: Option<String> = row.get("k8s_pod_name")?;
    let k8s_container_name: Option<String> = row.get("k8s_container_name")?;
    let k8s_pod_ns: Option<String> = row.get("k8s_pod_ns")?;

    // Synthesize ClientEvent from stored columns.
    let event = ClientEvent {
        local_event_id,
        timestamp: parse_ts_to_millis(&ts).unwrap_or(0),
        interface: String::new(), // not persisted in T2.3; empty for now
        protocol,
        local_ip: source_ip,
        local_port: source_port as u16,
        remote_ip: dest_ip,
        remote_port: dest_port as u16,
        state: String::new(), // not persisted in T2.3
        pid: pid.map(|p| p as u32),
        process_name,
        bytes_sent: bytes_sent.unwrap_or(0) as u64,
        bytes_recv: bytes_received.unwrap_or(0) as u64,
        packets_sent: 0, // not persisted in T2.3
        packets_recv: 0,
        duration_ms: duration_secs.unwrap_or(0) as u64,
        service: service_name,
        sni,
        geo_country: geoip_country_code,
        geo_city: geoip_city,
        dns_name,
        k8s: if k8s_pod_name.is_some() || k8s_container_name.is_some() || k8s_pod_ns.is_some() {
            Some(K8sFields {
                pod_name: k8s_pod_name,
                container_name: k8s_container_name,
                namespace: k8s_pod_ns,
                pod_ip: None,
                node_name: None,
            })
        } else {
            None
        },
    };

    Ok(QueryRow {
        server_event_id,
        local_event_id,
        machine_id,
        user_id: user_id.to_string(),
        event,
    })
}

/// Parse an RFC 3339 timestamp to Unix millis. Returns `None` on failure.
fn parse_ts_to_millis(ts: &str) -> Option<i64> {
    Some(
        chrono::DateTime::parse_from_rfc3339(ts)
            .ok()?
            .timestamp_millis(),
    )
}

// ---------------------------------------------------------------------------
// filter → SQL WHERE compilation
// ---------------------------------------------------------------------------

/// Compile the TUI-style `filter` string into a SQL `WHERE` clause.
///
/// Supported syntax (intentionally narrow; the full TUI filter grammar is
/// ported in a later task):
///
/// - `<value>` — substring match against `process_name`/`dest_ip`/`sni`
/// - `protocol:<p>` — `protocol = ?`
/// - `dest_ip:<ip>` — `dest_ip = ?`
/// - `process:<name>` — `process_name LIKE ?%`
/// - `port:<n>` — `dest_port = ?`
///
/// Unknown `key:` prefixes return an error rather than silently matching.
fn compile_filter(filter: &str, binds: &mut Vec<Box<dyn rusqlite::ToSql>>) -> Result<String> {
    let trimmed = filter.trim();
    if trimmed.is_empty() {
        return Ok("1=1".to_string());
    }

    // Bare token → broad substring search.
    if !trimmed.contains(':') {
        let like = format!("%{trimmed}%");
        binds.push(Box::new(like.clone()));
        binds.push(Box::new(like.clone()));
        binds.push(Box::new(like));
        return Ok("(process_name LIKE ? OR dest_ip LIKE ? OR sni LIKE ?)".to_string());
    }

    let (key, value) = trimmed
        .split_once(':')
        .context("filter: expected `key:value`")?;

    match key {
        "protocol" => {
            binds.push(Box::new(value.to_string()));
            Ok("protocol = ?".to_string())
        }
        "dest_ip" => {
            binds.push(Box::new(value.to_string()));
            Ok("dest_ip = ?".to_string())
        }
        "process" => {
            binds.push(Box::new(format!("%{value}%")));
            Ok("process_name LIKE ?".to_string())
        }
        "port" => {
            let port: i64 = value
                .parse()
                .map_err(|_| Error::Other(anyhow::anyhow!("filter: port must be a number")))?;
            binds.push(Box::new(port));
            Ok("dest_port = ?".to_string())
        }
        other => {
            warn!("compile_filter: 未知 filter key `{other}`");
            Err(Error::Other(anyhow::anyhow!("filter: unknown key `{other}`")).into())
        }
    }
}

// ---------------------------------------------------------------------------
// /stats
// ---------------------------------------------------------------------------

/// Live aggregate statistics computed directly from `server_events`.
///
/// `server_aggregates` bucket maintenance is deferred to T2.5; at the
/// small-data stage a single `GROUP BY` is cheap enough.
///
/// rustnetec: `scope` enforces per-machine visibility. Scoped tokens only
/// see their own machine's totals; admin (`Scope::All`) sees everything.
pub fn stats(conn: &mut Connection, scope: &Scope) -> Result<StatsResponse> {
    // rustnetec: build WHERE clause from scope.
    let started = Instant::now();
    let scope_clause = match scope {
        Scope::Machine(mid) => format!("WHERE machine_id = '{}'", mid.replace('\'', "''")),
        Scope::All => String::new(),
    };

    let totals: (i64, i64) = conn
        .query_row(
            &format!(
                "SELECT COUNT(*), COALESCE(SUM(bytes_sent), 0) + COALESCE(SUM(bytes_received), 0) \
                 FROM server_events {scope_clause}"
            ),
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .context("query stats totals")?;

    let mut stmt = conn.prepare(&format!(
        "SELECT machine_id, user_id, username, COUNT(*), \
         COALESCE(SUM(bytes_sent),0) + COALESCE(SUM(bytes_received),0) \
         FROM server_events {scope_clause} GROUP BY machine_id ORDER BY COUNT(*) DESC"
    ))?;
    let hosts: Vec<HostStats> = stmt
        .query_map([], |r| {
            Ok(HostStats {
                machine_id: r.get(0)?,
                user_id: r.get::<_, i64>(1)?.to_string(),
                username: r.get(2)?,
                event_count: r.get::<_, i64>(3)? as u64,
                bytes_total: r.get::<_, i64>(4)? as u64,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();

    debug!(
        "stats: 完成 (scope={:?}, total_events={}, hosts={}, 耗时 {}ms)",
        scope, totals.0, hosts.len(), started.elapsed().as_millis()
    );
    Ok(StatsResponse {
        total_events: totals.0 as u64,
        total_bytes: totals.1 as u64,
        hosts,
    })
}

/// Convenience marker — kept so the rejection rationale is documented in-tree
/// without a runtime cost.
#[doc(hidden)]
pub fn rejection_of_sql() -> &'static str {
    "raw `sql` parameter is never executed by the server"
}

/// rustnetec: W5.3 — 按 process_name 聚合 top 50,供 WebUI Activity 页专用。
///
/// 与 daemon 侧 `handle_processes` 逻辑同源,但服务端走 `server_events` 表
/// (字段名 `process_name` 同 daemon)。返回 `Vec<ProcessRow>` 扁平数组,
/// 按 `bytes_total = bytes_sent + bytes_received` 降序取 top 50。
/// 过滤 NULL/空 process_name(进程归因未启用或未命中)。
///
/// rustnetec: `scope` enforces per-machine visibility.
pub fn processes(conn: &mut Connection, scope: &Scope) -> Result<Vec<ProcessRow>> {
    // rustnetec: build WHERE clause from scope (always AND with process_name filter).
    let scope_clause = match scope {
        Scope::Machine(mid) => format!("AND machine_id = '{}'", mid.replace('\'', "''")),
        Scope::All => String::new(),
    };

    let mut stmt = conn.prepare(&format!(
        "SELECT process_name, COUNT(*) as cnt, \
         COALESCE(SUM(bytes_sent),0) as sent, \
         COALESCE(SUM(bytes_received),0) as recv \
         FROM server_events \
         WHERE process_name IS NOT NULL AND process_name != '' {scope_clause} \
         GROUP BY process_name \
         ORDER BY (sent + recv) DESC \
         LIMIT 50"
    ))?;
    let rows = stmt.query_map([], |r| {
        let sent: i64 = r.get(2)?;
        let recv: i64 = r.get(3)?;
        Ok(ProcessRow {
            process: r.get(0)?,
            connections: r.get::<_, i64>(1)? as u64,
            bytes_sent: sent as u64,
            bytes_received: recv as u64,
            bytes_total: (sent + recv) as u64,
        })
    })?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

/// rustnetec: W5.3 — `/processes` 响应行(与 daemon 侧 JSON 结构对齐)。
///
/// `bytes_total = bytes_sent + bytes_received` 供前端按字节降序排序展示。
/// 故意不放进 `rustnet-core::ingest`(共享 schema):daemon 侧用 serde_json::json!
/// 手写,服务端用结构体;两端 JSON 形状一致即可,不必共用类型。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProcessRow {
    pub process: String,
    pub connections: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub bytes_total: u64,
}

/// rustnetec: W5.3 — `/processes` 响应壳(与 daemon 侧 `{processes, count}` 形状对齐)。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProcessesResponse {
    pub processes: Vec<ProcessRow>,
    pub count: usize,
}

// Silence unused import for `AggregateRow` until T2.5 bucket queries land.
#[allow(dead_code)]
fn _retain_aggregate_row_type(_: AggregateRow) {}

// ---------------------------------------------------------------------------
// rustnetec: T-E5 — /stats/range 时间桶流量查询（供 WebUI 多进程对比等）。
// 与 daemon 侧 handle_stats_range JSON 形状对齐：
//   { buckets: [{ts, bytes_rx, bytes_tx, conn_count, active_seconds}],
//     series:  [{name, points: [[ts, bytes_total], ...]}],
//     count, bucket, scope }
// 数据直接查 server_events（server_aggregates 桶维护延后，见 stats() 注释）。
// 不做 scope 外网/局域网分类（server 侧无需本机 netutil，对比视图默认 scope=all）。
// ---------------------------------------------------------------------------

/// rustnetec: T-E5 — 时间桶 + process 过滤参数。
pub struct RangeParams {
    pub start: String,
    pub end: String,
    pub bucket: String,
    /// 进程名列表（IN 语义，空 = 全部进程）。
    pub processes: Vec<String>,
    /// rustnetec: 可选 machine_id 过滤（admin 模式下按指定机器筛选）。
    /// 空切片 = 不按 machine_id 过滤。
    pub machine_ids: Vec<String>,
}

/// rustnetec: T-E5 — 查询时间桶聚合，返回与 daemon /stats/range 同形的 JSON。
pub fn stats_range(
    conn: &mut Connection,
    params: &RangeParams,
    scope: &Scope,
) -> Result<serde_json::Value> {
    use std::collections::BTreeMap;

    #[derive(Default, Clone)]
    struct BucketAcc {
        bytes_rx: i64,
        bytes_tx: i64,
        conn_count: i64,
        active_seconds: i64,
    }

    // 构造 WHERE 子句（参数化，防注入）。
    let mut where_clauses: Vec<String> = vec![
        "ts >= ?1".to_string(),
        "ts <= ?2".to_string(),
    ];
    let mut bind_values: Vec<Box<dyn rusqlite::ToSql>> = vec![
        Box::new(params.start.clone()),
        Box::new(params.end.clone()),
    ];
    let mut bind_idx = 3;

    // rustnetec: inject machine_id scope (server-side, untamperable).
    if let Scope::Machine(mid) = scope {
        where_clauses.push(format!("machine_id = ?{bind_idx}"));
        bind_values.push(Box::new(mid.clone()));
        bind_idx += 1;
    }

    // rustnetec: 可选 machine_id 过滤（admin 模式下按指定机器筛选）。
    // scope 已是 All 时才允许 params.machine_ids 生效；scope=Machine 时
    // params.machine_ids 必须为空或仅含 scope 本身（由调用层校验）。
    if !params.machine_ids.is_empty() {
        let placeholders: Vec<String> = params
            .machine_ids
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", bind_idx + i))
            .collect();
        where_clauses.push(format!("machine_id IN ({})", placeholders.join(", ")));
        for mid in &params.machine_ids {
            bind_values.push(Box::new(mid.clone()));
        }
        bind_idx += params.machine_ids.len();
    }

    if !params.processes.is_empty() {
        let placeholders: Vec<String> = params
            .processes
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", bind_idx + i))
            .collect();
        where_clauses.push(format!("process_name IN ({})", placeholders.join(", ")));
        for name in &params.processes {
            bind_values.push(Box::new(name.clone()));
        }
    }

    let sql = format!(
        "SELECT ts, bytes_received, bytes_sent, duration_secs, process_name \
         FROM server_events \
         WHERE {} \
         ORDER BY ts ASC",
        where_clauses.join(" AND ")
    );

    let mut stmt = conn.prepare(&sql).context("stats_range prepare failed")?;
    let bind_refs: Vec<&dyn rusqlite::ToSql> = bind_values.iter().map(|b| b.as_ref()).collect();
    let rows = stmt.query_map(bind_refs.as_slice(), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<i64>>(1)?,
            row.get::<_, Option<i64>>(2)?,
            row.get::<_, Option<i64>>(3)?,
            row.get::<_, Option<String>>(4)?,
        ))
    })?;

    // 桶宽 → chrono truncate 格式。
    let bucket = params.bucket.as_str();
    let truncate = |dt: chrono::DateTime<chrono::FixedOffset>| -> String {
        let utc = dt.with_timezone(&chrono::Utc);
        match bucket {
            "5s" => {
                let secs = utc.timestamp();
                let truncated = secs - (secs % 5);
                chrono::DateTime::from_timestamp(truncated, 0)
                    .unwrap()
                    .format("%Y-%m-%dT%H:%M:%S")
                    .to_string()
            }
            "1min" => utc.format("%Y-%m-%dT%H:%M").to_string(),
            "1hour" => utc.format("%Y-%m-%dT%H").to_string(),
            "1day" => utc.format("%Y-%m-%d").to_string(),
            _ => utc.format("%Y-%m-%dT%H:%M").to_string(),
        }
    };

    let mut totals: BTreeMap<String, BucketAcc> = BTreeMap::new();
    let mut by_process: BTreeMap<String, BTreeMap<String, BucketAcc>> = BTreeMap::new();

    for row in rows {
        let (ts, bytes_rx, bytes_tx, duration_secs, process_name) = match row {
            Ok(r) => r,
            Err(_) => continue,
        };
        let dt = match chrono::DateTime::parse_from_rfc3339(&ts) {
            Ok(dt) => dt,
            Err(_) => continue,
        };
        let bucket_key = truncate(dt);

        let rx = bytes_rx.unwrap_or(0);
        let tx = bytes_tx.unwrap_or(0);
        let dur = duration_secs.unwrap_or(0);

        let t = totals.entry(bucket_key.clone()).or_default();
        t.bytes_rx += rx;
        t.bytes_tx += tx;
        t.conn_count += 1;
        t.active_seconds += dur;

        let pname = process_name.unwrap_or_else(|| "_unknown".to_string());
        let proc_map = by_process.entry(bucket_key).or_default();
        let e = proc_map.entry(pname).or_default();
        e.bytes_rx += rx;
        e.bytes_tx += tx;
        e.conn_count += 1;
        e.active_seconds += dur;
    }

    let buckets: Vec<serde_json::Value> = totals
        .iter()
        .map(|(ts, acc)| {
            serde_json::json!({
                "ts": ts,
                "bytes_rx": acc.bytes_rx,
                "bytes_tx": acc.bytes_tx,
                "conn_count": acc.conn_count,
                "active_seconds": acc.active_seconds,
            })
        })
        .collect();

    // 收集进程名（按首次出现顺序）。
    let mut proc_order: Vec<String> = Vec::new();
    for proc_map in by_process.values() {
        for pname in proc_map.keys() {
            if !proc_order.contains(pname) {
                proc_order.push(pname.clone());
            }
        }
    }
    let series: Vec<serde_json::Value> = proc_order
        .iter()
        .map(|pname| {
            let points: Vec<serde_json::Value> = by_process
                .iter()
                .filter_map(|(ts, proc_map)| {
                    proc_map.get(pname).map(|acc| {
                        serde_json::json!([ts, acc.bytes_rx + acc.bytes_tx])
                    })
                })
                .collect();
            serde_json::json!({ "name": pname, "points": points })
        })
        .collect();

    Ok(serde_json::json!({
        "buckets": buckets,
        "series": series,
        "count": buckets.len(),
        "bucket": bucket,
        "scope": "all",
    }))
}

// ---------------------------------------------------------------------------
// rustnetec: /hosts — 用户/主机信息表数据源（按部门分组 → user_id 聚合）
// ---------------------------------------------------------------------------

/// rustnetec: 一行 `server_hosts`，供 WebUI 用户信息表展示。
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostInfoRow {
    pub machine_id: String,
    pub user_id: i64,
    pub username: String,
    /// 部门（NULL = 未分组）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// JSON 字符串解析后的 IP 列表。
    pub ip_list: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub event_count: i64,
}

/// rustnetec: `GET /hosts` — 列出所有主机，按 department/user_id/machine_id 排序。
///
/// `scope` 强制 per-machine 可见性：scoped token 只看自身机器。
/// 未填写部门（NULL）的主机在 `ORDER BY ... NULLS LAST` 下自然排末尾，
/// 前端再归类到"未分组"分组。
pub fn list_hosts(conn: &mut Connection, scope: &Scope) -> Result<Vec<HostInfoRow>> {
    // SQLite 默认 NULLS FIRST；显式 NULLS LAST 把未分组排到末尾。
    let (where_clause, scope_bind): (&str, Option<String>) = match scope {
        Scope::Machine(mid) => ("WHERE machine_id = ?1", Some(mid.clone())),
        Scope::All => ("", None),
    };

    let sql = format!(
        "SELECT machine_id, user_id, username, department, ip_list, \
                first_seen, last_seen, event_count \
         FROM server_hosts {where_clause} \
         ORDER BY department IS NULL, department ASC, user_id ASC, machine_id ASC"
    );

    let mut stmt = conn.prepare(&sql).context("list_hosts prepare")?;
    let mut rows = if let Some(mid) = scope_bind {
        stmt.query_map(params_from_iter([mid]), row_to_host_info)?
    } else {
        stmt.query_map([], row_to_host_info)?
    };

    let mut out = Vec::new();
    for row in rows.by_ref() {
        out.push(row?);
    }
    Ok(out)
}

/// 把一行 `server_hosts` 映射为 [`HostInfoRow`]，解析 `ip_list` JSON。
fn row_to_host_info(row: &rusqlite::Row<'_>) -> rusqlite::Result<HostInfoRow> {
    let ip_json: String = row.get(4)?;
    let ip_list: Vec<String> = serde_json::from_str(&ip_json).unwrap_or_default();
    Ok(HostInfoRow {
        machine_id: row.get(0)?,
        user_id: row.get(1)?,
        username: row.get(2)?,
        department: row.get(3)?,
        ip_list,
        first_seen: row.get(5)?,
        last_seen: row.get(6)?,
        event_count: row.get(7)?,
    })
}

// ---------------------------------------------------------------------------
// rustnetec: /stats/reachability — 外网可达率（决策 A：客户端上报）
// ---------------------------------------------------------------------------

/// rustnetec: `GET /stats/reachability` — 可达率时间序列。
///
/// 数据源：`server_reachability` 表（客户端可达率探测线程采集并上报）。
/// 按桶聚合 `reachable_ratio = sum(reachable)/count(*)`，
/// `min_latency_ms = min(latency_ms) where reachable=1`。
///
/// 返回与客户端 `/stats/reachability` 同形 JSON：
/// `{ buckets: [{ts, reachable_ratio, samples, min_latency_ms}] }`
pub fn reachability(
    conn: &mut Connection,
    machine_ids: &[String],
    start: &str,
    end: &str,
    bucket: &str,
) -> Result<serde_json::Value> {
    use std::collections::BTreeMap;

    if machine_ids.is_empty() {
        return Ok(serde_json::json!({
            "buckets": Vec::<serde_json::Value>::new(),
            "count": 0,
            "bucket": bucket,
        }));
    }

    // 构造 machine_id IN (...) 子句
    let placeholders: Vec<String> = machine_ids
        .iter()
        .enumerate()
        .map(|(i, _)| format!("?{}", i + 1))
        .collect();
    let in_clause = placeholders.join(", ");
    let start_idx = machine_ids.len() + 1;

    let sql = format!(
        "SELECT ts, reachable, latency_ms \
         FROM server_reachability \
         WHERE machine_id IN ({in_clause}) AND ts >= ?{start_idx} AND ts <= ?{} \
         ORDER BY ts ASC",
        start_idx + 1
    );

    let mut stmt = conn.prepare(&sql).context("reachability prepare")?;
    let mut bind_values: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    for mid in machine_ids {
        bind_values.push(Box::new(mid.clone()));
    }
    bind_values.push(Box::new(start.to_string()));
    bind_values.push(Box::new(end.to_string()));
    let bind_refs: Vec<&dyn rusqlite::ToSql> = bind_values.iter().map(|b| b.as_ref()).collect();

    let rows = stmt.query_map(bind_refs.as_slice(), |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, f64>(2)?,
        ))
    })?;

    // 桶宽 → chrono truncate
    let truncate = |dt: chrono::DateTime<chrono::FixedOffset>| -> String {
        let utc = dt.with_timezone(&chrono::Utc);
        match bucket {
            "5s" => {
                let secs = utc.timestamp();
                let truncated = secs - (secs % 5);
                chrono::DateTime::from_timestamp(truncated, 0)
                    .unwrap()
                    .format("%Y-%m-%dT%H:%M:%S")
                    .to_string()
            }
            "1min" => utc.format("%Y-%m-%dT%H:%M").to_string(),
            "1hour" => utc.format("%Y-%m-%dT%H").to_string(),
            "1day" => utc.format("%Y-%m-%d").to_string(),
            _ => utc.format("%Y-%m-%dT%H:%M").to_string(),
        }
    };

    #[derive(Default)]
    struct ReachAcc {
        reachable_sum: i64,
        samples: i64,
        min_latency: Option<f64>,
    }

    let mut buckets: BTreeMap<String, ReachAcc> = BTreeMap::new();
    for row in rows {
        let (ts, reachable, latency) = match row {
            Ok(r) => r,
            Err(_) => continue,
        };
        let dt = match chrono::DateTime::parse_from_rfc3339(&ts) {
            Ok(dt) => dt,
            Err(_) => continue,
        };
        let key = truncate(dt);
        let acc = buckets.entry(key).or_default();
        acc.samples += 1;
        if reachable == 1 {
            acc.reachable_sum += 1;
            acc.min_latency = Some(match acc.min_latency {
                Some(m) => m.min(latency),
                None => latency,
            });
        }
    }

    let out: Vec<serde_json::Value> = buckets
        .iter()
        .map(|(ts, acc)| {
            let ratio = if acc.samples > 0 {
                acc.reachable_sum as f64 / acc.samples as f64
            } else {
                0.0
            };
            serde_json::json!({
                "ts": ts,
                "reachable_ratio": ratio,
                "samples": acc.samples,
                "min_latency_ms": acc.min_latency.unwrap_or(0.0),
            })
        })
        .collect();

    Ok(serde_json::json!({
        "buckets": out,
        "count": out.len(),
        "bucket": bucket,
    }))
}

// ---------------------------------------------------------------------------
// rustnetec: /stats/realtime — 实时速率（决策 2-B：server_aggregates 分钟桶）
// ---------------------------------------------------------------------------

/// rustnetec: `GET /stats/realtime` — 实时速率。
///
/// 数据源：`server_aggregates` 分钟桶（由 `write_minute_aggregates` 维护）。
/// 支持逗号分隔多 `machine_id`（用户展开多机器场景）。
///
/// 返回：`{ buckets: [{ts, bytes_rx, bytes_tx, conn_count}] }`
pub fn realtime(
    conn: &mut Connection,
    machine_ids: &[String],
    start: &str,
) -> Result<serde_json::Value> {
    if machine_ids.is_empty() {
        return Ok(serde_json::json!({
            "buckets": Vec::<serde_json::Value>::new(),
            "count": 0,
        }));
    }

    let placeholders: Vec<String> = machine_ids
        .iter()
        .enumerate()
        .map(|(i, _)| format!("?{}", i + 1))
        .collect();
    let in_clause = placeholders.join(", ");
    let start_idx = machine_ids.len() + 1;

    let sql = format!(
        "SELECT bucket_ts, bytes_rx, bytes_tx, conn_count \
         FROM server_aggregates \
         WHERE bucket_width = 'minute' AND machine_id IN ({in_clause}) \
         AND bucket_ts >= ?{start_idx} \
         ORDER BY bucket_ts ASC"
    );

    let mut stmt = conn.prepare(&sql).context("realtime prepare")?;
    let mut bind_values: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    for mid in machine_ids {
        bind_values.push(Box::new(mid.clone()));
    }
    bind_values.push(Box::new(start.to_string()));
    let bind_refs: Vec<&dyn rusqlite::ToSql> = bind_values.iter().map(|b| b.as_ref()).collect();

    let rows = stmt.query_map(bind_refs.as_slice(), |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (ts, rx, tx, count) = row?;
        out.push(serde_json::json!({
            "ts": ts,
            "bytes_rx": rx,
            "bytes_tx": tx,
            "conn_count": count,
        }));
    }

    Ok(serde_json::json!({
        "buckets": out,
        "count": out.len(),
    }))
}


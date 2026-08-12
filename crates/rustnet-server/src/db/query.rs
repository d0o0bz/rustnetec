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
use rusqlite::{Connection, Row, params_from_iter};
use rustnet_core::ingest::{
    AggregateRow, ClientEvent, HostStats, K8sFields, QueryParams, QueryResponse, QueryRow,
    StatsResponse,
};

use super::Error;

// ---------------------------------------------------------------------------
// /query
// ---------------------------------------------------------------------------

/// Read events from `server_events` matching `params`.
///
/// Ordering is `ts DESC, id DESC` (most-recent first). `limit` defaults to
/// 200 and is clamped to 1000 to bound response size.
pub fn query_events(conn: &mut Connection, params: &QueryParams) -> Result<QueryResponse> {
    let limit = params.limit.unwrap_or(200).min(1000);

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
        other => Err(Error::Other(anyhow::anyhow!("filter: unknown key `{other}`")).into()),
    }
}

// ---------------------------------------------------------------------------
// /stats
// ---------------------------------------------------------------------------

/// Live aggregate statistics computed directly from `server_events`.
///
/// `server_aggregates` bucket maintenance is deferred to T2.5; at the
/// small-data stage a single `GROUP BY` is cheap enough.
pub fn stats(conn: &mut Connection) -> Result<StatsResponse> {
    let totals: (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(bytes_sent), 0) + COALESCE(SUM(bytes_received), 0) \
             FROM server_events",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .context("query stats totals")?;

    let mut stmt = conn.prepare(
        "SELECT machine_id, user_id, username, COUNT(*), \
         COALESCE(SUM(bytes_sent),0) + COALESCE(SUM(bytes_received),0) \
         FROM server_events GROUP BY machine_id ORDER BY COUNT(*) DESC",
    )?;
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
pub fn processes(conn: &mut Connection) -> Result<Vec<ProcessRow>> {
    let mut stmt = conn.prepare(
        "SELECT process_name, COUNT(*) as cnt, \
         COALESCE(SUM(bytes_sent),0) as sent, \
         COALESCE(SUM(bytes_received),0) as recv \
         FROM server_events \
         WHERE process_name IS NOT NULL AND process_name != '' \
         GROUP BY process_name \
         ORDER BY (sent + recv) DESC \
         LIMIT 50",
    )?;
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
}

/// rustnetec: T-E5 — 查询时间桶聚合，返回与 daemon /stats/range 同形的 JSON。
pub fn stats_range(conn: &mut Connection, params: &RangeParams) -> Result<serde_json::Value> {
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
    let bind_idx = 3;

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
    for (_ts, proc_map) in &by_process {
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

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
use rusqlite::{params_from_iter, Connection, Row};
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
        .query_map(params_from_iter(bind_refs.iter().copied()), row_to_query_row)?
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
    Some(chrono::DateTime::parse_from_rfc3339(ts).ok()?.timestamp_millis())
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
        other => Err(Error::Other(anyhow::anyhow!(
            "filter: unknown key `{other}`"
        ))
        .into()),
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

// Silence unused import for `AggregateRow` until T2.5 bucket queries land.
#[allow(dead_code)]
fn _retain_aggregate_row_type(_: AggregateRow) {}

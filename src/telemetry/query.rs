// rustnetec: Query subcommand — read-only SQLite queries with filter-to-SQL translation (R5, T1.3)

use anyhow::{Result, bail};
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
// rustnetec: 改用 &Path 替代 &PathBuf（clippy ptr_arg）
use std::path::Path;

use crate::filter::{ConnectionFilter, FilterCriteria, FilterValue, PortMatch};

/// Default row limit for query results to avoid accidental huge outputs.
// rustnetec: W0.5 — 改 `pub` 供 http.rs 分页钳制使用。
pub const DEFAULT_QUERY_LIMIT: i64 = 1000;

/// Run the `rustnet query` subcommand.
///
/// rustnetec: G1 改造 — `run_query` 现返回 `Result<Vec<Value>>` 而非打印到 stdout。
/// CLI 层(`run_query_subcommand`)拿到 `Vec<Value>` 后自行序列化输出;
/// HTTP 层(`handle_query`)直接把 `Vec<Value>` 作为 JSON 响应体返回。
/// 这让查询逻辑与输出方式解耦,WebUI 的 G1 硬缺口依赖此改造。
///
/// rustnetec: W0.5 — 本函数现为向后兼容的薄包装,分页参数全 `None`,
/// 交给 `run_query_paged` 实现分页/order 白名单。HTTP 层直接调
/// `run_query_paged` 传入 limit/offset/order。
pub fn run_query(
    // rustnetec: 签名改为 &Path（clippy ptr_arg），调用处传 &PathBuf 自动兼容
    db_path: &Path,
    filter: Option<&str>,
    sql: Option<&str>,
    live: bool,
) -> Result<Vec<Value>> {
    run_query_paged(db_path, filter, sql, live, None, None, None, None)
}

/// rustnetec: W0.5 — 分页版 `run_query`。
///
/// 新增参数:
/// - `limit`:`Some(n)` 覆盖 `DEFAULT_QUERY_LIMIT`;`None` 用默认 1000。
///   HTTP 层负责钳制到 [1, 1000] 后传入(本函数也再钳一次防越界)。
/// - `offset`:`Some(n)` 生成 `OFFSET n`;`None` 无 offset。
/// - `order`:`Some("ts ASC" | "ts DESC")` 白名单值,控制 ORDER BY;
///   `None` 默认 `ts DESC`。任何不在白名单的值会被 `bail!` 拒绝。
/// - `since_ts`:`Some(RFC3339)` 时追加 `ts >= since_ts` 过滤(连接表时间范围);
///   `None` 不过滤。值由 HTTP 层解析生成,参数化绑定,无注入风险。
///
/// 安全约束:
/// - `order` 走白名单,防止前端注入任意 ORDER BY 表达式。
/// - `limit` 钳制到 [1, DEFAULT_QUERY_LIMIT],防大结果阻塞 tiny_http 单线程。
/// - raw SQL 模式不分页(用户显式写 SQL,自行控制 LIMIT)。
pub fn run_query_paged(
    db_path: &Path,
    filter: Option<&str>,
    sql: Option<&str>,
    live: bool,
    limit: Option<i64>,
    offset: Option<i64>,
    order: Option<&str>,
    since_ts: Option<&str>,
) -> Result<Vec<Value>> {
    if live {
        return run_live_query();
    }

    // rustnetec: W2.1 — order 白名单扩展。
    // W0.5 仅允许 `ts ASC` / `ts DESC`;W2.1 连接表列排序需支持
    // protocol / source_ip / dest_ip / source_port / dest_port /
    // process_name / dest_hostname / bytes_sent / bytes_received / rtt_ms。
    // 白名单用 HashSet 静态构造,查询 O(1);非法值 bail!。
    use std::sync::OnceLock;
    static ALLOWED_ORDER_COLS: OnceLock<std::collections::HashSet<&'static str>> =
        OnceLock::new();
    let allowed = ALLOWED_ORDER_COLS.get_or_init(|| {
        let mut s = std::collections::HashSet::new();
        s.insert("ts");
        s.insert("protocol");
        s.insert("source_ip");
        s.insert("dest_ip");
        s.insert("source_port");
        s.insert("dest_port");
        s.insert("process_name");
        s.insert("dest_hostname");
        s.insert("bytes_sent");
        s.insert("bytes_received");
        s.insert("rtt_ms");
        s.insert("id");
        s
    });

    let order_clause = match order {
        None => "ts DESC".to_string(),
        Some(o) => {
            let trimmed = o.trim();
            // 解析 "<col> <ASC|DESC>",col 与方向之间至少一个空白。
            let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
            if parts.len() != 2 {
                bail!(
                    "invalid order parameter: expected '<column> ASC|DESC', got: {}",
                    trimmed
                );
            }
            let col = parts[0].to_lowercase();
            let dir = parts[1].to_uppercase();
            if !allowed.contains(col.as_str()) {
                bail!(
                    "invalid order column: {} not in whitelist",
                    col
                );
            }
            if dir != "ASC" && dir != "DESC" {
                bail!(
                    "invalid order direction: expected ASC|DESC, got: {}",
                    dir
                );
            }
            format!("{} {}", col, dir)
        }
    };

    // rustnetec: W0.5 — limit 钳制。
    // 上限 DEFAULT_QUERY_LIMIT(1000)防大结果阻塞;下限 1 防空结果。
    // None 时用默认 1000。
    let limit_val = limit.unwrap_or(DEFAULT_QUERY_LIMIT).clamp(1, DEFAULT_QUERY_LIMIT);

    // Resolve database path
    let path = if db_path.as_os_str().is_empty() {
        crate::telemetry::paths::db_path()?
    } else {
        // rustnetec: db_path 现为 &Path，用 to_path_buf() 得到 PathBuf
        db_path.to_path_buf()
    };

    if !path.exists() {
        bail!("Database file not found: {}", path.display());
    }

    let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| anyhow::anyhow!("Failed to open database (read-only): {}", e))?;

    // rustnetec: W0.5 — raw SQL 模式不分页(用户显式写 SQL,自行控制 LIMIT)。
    // filter / default 模式才应用 limit/offset/order。
    if let Some(raw_sql) = sql {
        run_raw_sql(&conn, raw_sql)
    } else if let Some(filter_str) = filter {
        run_filter_query_paged(&conn, filter_str, since_ts, limit_val, offset, &order_clause)
    } else {
        run_default_query_paged(&conn, since_ts, limit_val, offset, &order_clause)
    }
}

/// Execute a raw SQL query (SELECT only).
// rustnetec: G1 改造 — 返回 `Result<Vec<Value>>` 而非打印到 stdout。
fn run_raw_sql(conn: &Connection, sql: &str) -> Result<Vec<Value>> {
    let trimmed = sql.trim();
    let upper = trimmed.to_uppercase();

    // Safety check: only allow SELECT statements
    if !upper.starts_with("SELECT") && !upper.starts_with("PRAGMA") && !upper.starts_with("EXPLAIN")
    {
        bail!(
            "Only SELECT / PRAGMA / EXPLAIN queries are allowed. Got: {}...",
            &trimmed[..trimmed.len().min(20)]
        );
    }

    execute_sql_to_json(conn, trimmed)
}

/// rustnetec: W0.5 — filter 查询分页版。
///
/// `limit` 已由上层钳制到 [1, DEFAULT_QUERY_LIMIT];`offset` 为 `Some(n)` 时追加
/// `OFFSET n`;`order_clause` 已通过白名单校验(`ts ASC` / `ts DESC`)。
/// `since_ts` 为 `Some(RFC3339)` 时追加 `ts >= ?` 参数化过滤(连接表时间范围)。
fn run_filter_query_paged(
    conn: &Connection,
    filter_str: &str,
    since_ts: Option<&str>,
    limit: i64,
    offset: Option<i64>,
    order_clause: &str,
) -> Result<Vec<Value>> {
    let filter = ConnectionFilter::parse(filter_str);
    let (mut where_clause, mut params) = filter_to_sql(&filter);

    // rustnetec: 时间范围过滤 — 追加参数化条件,与既有条件 AND 连接。
    if let Some(since) = since_ts {
        let idx = params.len() + 1;
        if where_clause.is_empty() {
            where_clause = format!("ts >= ?{idx}");
        } else {
            where_clause = format!("{where_clause} AND ts >= ?{idx}");
        }
        params.push(Box::new(since.to_string()));
    }

    // rustnetec: W0.5 — 安全拼接:order 已白名单化,limit 已钳制,offset 仅数字。
    let mut sql = if where_clause.is_empty() {
        format!("SELECT * FROM connection_events ORDER BY {} LIMIT {}", order_clause, limit)
    } else {
        format!(
            "SELECT * FROM connection_events WHERE {} ORDER BY {} LIMIT {}",
            where_clause, order_clause, limit
        )
    };
    if let Some(off) = offset {
        sql.push_str(&format!(" OFFSET {}", off));
    }

    execute_param_query(conn, &sql, &params)
}

/// Default query: show recent events.
/// rustnetec: W0.5 — 默认查询分页版(无 filter,展示最近事件)。
/// `since_ts` 为 `Some(RFC3339)` 时追加 `ts >= ?` 参数化过滤(连接表时间范围)。
fn run_default_query_paged(
    conn: &Connection,
    since_ts: Option<&str>,
    limit: i64,
    offset: Option<i64>,
    order_clause: &str,
) -> Result<Vec<Value>> {
    if let Some(since) = since_ts {
        // 有时间过滤时走参数化查询(与 run_filter_query_paged 同构)。
        let sql = format!(
            "SELECT * FROM connection_events WHERE ts >= ?1 ORDER BY {} LIMIT {}",
            order_clause, limit
        );
        let mut sql = sql;
        if let Some(off) = offset {
            sql.push_str(&format!(" OFFSET {}", off));
        }
        let params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(since.to_string())];
        return execute_param_query(conn, &sql, &params);
    }

    let mut sql = format!(
        "SELECT * FROM connection_events ORDER BY {} LIMIT {}",
        order_clause, limit
    );
    if let Some(off) = offset {
        sql.push_str(&format!(" OFFSET {}", off));
    }
    execute_sql_to_json(conn, &sql)
}

/// Live query: poll the local HTTP /live endpoint.
/// This requires the daemon to be running with the HTTP server enabled.
// rustnetec: G1 改造 — 返回 `Result<Vec<Value>>` 而非打印到 stdout。
// live 模式返回单元素数组(含 /live 快照对象),保持与历史查询一致的数组语义,
// CLI 层负责序列化输出。
fn run_live_query() -> Result<Vec<Value>> {
    use std::time::Duration;

    use crate::config::PersistentConfig;

    let pc = PersistentConfig::load().unwrap_or_default();
    let port = pc.http_port;
    let token = pc.http_token.unwrap_or_default();
    let base = format!("http://127.0.0.1:{port}");

    // Probe the daemon's HTTP server; if it is not up, say so clearly.
    let mut req = ureq::get(&format!("{base}/live")).timeout(Duration::from_secs(2));
    if !token.is_empty() {
        req = req.set("Authorization", &format!("Bearer {token}"));
    }
    let resp = req.call().map_err(|e| {
        anyhow::anyhow!(
            "--live mode requires a running daemon with HTTP server on {base} (start with `rustnet --daemon` or the tray app): {e}"
        )
    })?;

    let live: Value = resp
        .into_json()
        .map_err(|e| anyhow::anyhow!("failed to parse /live response: {e}"))?;
    Ok(vec![live])
}

/// Translate a ConnectionFilter into a SQL WHERE clause with parameterized values.
/// Returns (where_clause_string, params_vec).
fn filter_to_sql(filter: &ConnectionFilter) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
    let mut conditions = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    for criterion in &filter.criteria {
        match criterion {
            FilterCriteria::General(fv) => {
                // General search: match across multiple text columns
                let (cond, ps) = general_filter_to_sql(fv);
                conditions.push(cond);
                params.extend(ps);
            }
            FilterCriteria::Port(pm) => {
                // Match source_port OR dest_port
                let (src_cond, src_ps) = port_match_to_sql("source_port", pm);
                let (dst_cond, dst_ps) = port_match_to_sql("dest_port", pm);
                conditions.push(format!("({} OR {})", src_cond, dst_cond));
                params.extend(src_ps);
                params.extend(dst_ps);
            }
            FilterCriteria::SourcePort(pm) => {
                let (cond, ps) = port_match_to_sql("source_port", pm);
                conditions.push(cond);
                params.extend(ps);
            }
            FilterCriteria::DestinationPort(pm) => {
                let (cond, ps) = port_match_to_sql("dest_port", pm);
                conditions.push(cond);
                params.extend(ps);
            }
            FilterCriteria::SourceIp(fv) => {
                let (cond, ps) = text_filter_to_sql("source_ip", fv);
                conditions.push(cond);
                params.extend(ps);
            }
            FilterCriteria::DestinationIp(fv) => {
                let (cond, ps) = text_filter_to_sql("dest_ip", fv);
                conditions.push(cond);
                params.extend(ps);
            }
            FilterCriteria::Protocol(fv) => {
                let (cond, ps) = text_filter_to_sql("protocol", fv);
                conditions.push(cond);
                params.extend(ps);
            }
            FilterCriteria::Process(fv) => {
                let (cond, ps) = text_filter_to_sql("process_name", fv);
                conditions.push(cond);
                params.extend(ps);
            }
            FilterCriteria::Service(fv) => {
                let (cond, ps) = text_filter_to_sql("service_name", fv);
                conditions.push(cond);
                params.extend(ps);
            }
            FilterCriteria::Sni(fv) => {
                // SNI maps to dest_hostname or dpi_domain
                let (host_cond, host_ps) = text_filter_to_sql("dest_hostname", fv);
                let (dpi_cond, dpi_ps) = text_filter_to_sql("dpi_domain", fv);
                conditions.push(format!("({} OR {})", host_cond, dpi_cond));
                params.extend(host_ps);
                params.extend(dpi_ps);
            }
            FilterCriteria::Application(fv) => {
                let (cond, ps) = text_filter_to_sql("dpi_protocol", fv);
                conditions.push(cond);
                params.extend(ps);
            }
            FilterCriteria::State(fv) => {
                let (cond, ps) = text_filter_to_sql("event_type", fv);
                conditions.push(cond);
                params.extend(ps);
            }
            #[cfg(feature = "kubernetes")]
            FilterCriteria::Pod(fv) => {
                let (cond, ps) = text_filter_to_sql("k8s_pod_name", fv);
                conditions.push(cond);
                params.extend(ps);
            }
            #[cfg(feature = "kubernetes")]
            FilterCriteria::Namespace(fv) => {
                let (cond, ps) = text_filter_to_sql("k8s_namespace", fv);
                conditions.push(cond);
                params.extend(ps);
            }
            #[cfg(feature = "kubernetes")]
            FilterCriteria::Container(fv) => {
                let (cond, ps) = text_filter_to_sql("k8s_container_name", fv);
                conditions.push(cond);
                params.extend(ps);
            }
        }
    }

    let where_clause = conditions.join(" AND ");
    (where_clause, params)
}

/// Translate a text FilterValue to a SQL condition for a given column.
fn text_filter_to_sql(
    column: &str,
    fv: &FilterValue,
) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
    match fv {
        FilterValue::Literal(s) => {
            let cond = format!("LOWER({}) LIKE LOWER(?)", column);
            let param: Box<dyn rusqlite::types::ToSql> = Box::new(format!("%{}%", s));
            (cond, vec![param])
        }
        FilterValue::Regex(re) => {
            // SQLite doesn't have native regex; use LIKE as approximation
            // For regex patterns, we use a broad LIKE and rely on post-filtering
            // if exact regex matching is needed. For now, use LIKE with the regex pattern.
            let cond = format!("LOWER({}) REGEXP(?)", column);
            let pattern = re.as_str().to_string();
            let param: Box<dyn rusqlite::types::ToSql> = Box::new(pattern);
            (cond, vec![param])
        }
    }
}

/// Translate a PortMatch to a SQL condition for a given column.
fn port_match_to_sql(
    column: &str,
    pm: &PortMatch,
) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
    match pm {
        PortMatch::Exact(n) => {
            let cond = format!("{} = ?", column);
            let param: Box<dyn rusqlite::types::ToSql> = Box::new(*n as i64);
            (cond, vec![param])
        }
        PortMatch::Partial(s) => {
            let cond = format!("CAST({} AS TEXT) LIKE ?", column);
            let param: Box<dyn rusqlite::types::ToSql> = Box::new(format!("%{}%", s));
            (cond, vec![param])
        }
        PortMatch::Regex(re) => {
            let cond = format!("CAST({} AS TEXT) REGEXP(?)", column);
            let pattern = re.as_str().to_string();
            let param: Box<dyn rusqlite::types::ToSql> = Box::new(pattern);
            (cond, vec![param])
        }
    }
}

/// Translate a general (all-fields) filter to SQL.
/// Searches across: protocol, source_ip, dest_ip, dest_hostname, process_name,
/// service_name, dpi_protocol, dpi_domain, event_type.
fn general_filter_to_sql(fv: &FilterValue) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
    let columns = [
        "protocol",
        "source_ip",
        "dest_ip",
        "dest_hostname",
        "process_name",
        "service_name",
        "dpi_protocol",
        "dpi_domain",
        "event_type",
    ];

    let mut or_conditions = Vec::new();
    let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    for col in &columns {
        let (cond, ps) = text_filter_to_sql(col, fv);
        or_conditions.push(cond);
        all_params.extend(ps);
    }

    let where_clause = format!("({})", or_conditions.join(" OR "));
    (where_clause, all_params)
}

/// Execute a SQL query and return results as JSON values.
fn execute_sql_to_json(conn: &Connection, sql: &str) -> Result<Vec<Value>> {
    let mut stmt = conn.prepare(sql)?;
    let column_count = stmt.column_count();
    let column_names: Vec<String> = (0..column_count)
        .map(|i| stmt.column_name(i).unwrap_or("?").to_string())
        .collect();

    let mut results = Vec::new();
    let rows = stmt.query_map([], |row| {
        let mut map = serde_json::Map::new();
        for (i, name) in column_names.iter().enumerate() {
            let val: Value = row_get_json_value(row, i);
            map.insert(name.clone(), val);
        }
        Ok(serde_json::Value::Object(map))
    })?;

    for row in rows {
        results.push(row?);
    }

    Ok(results)
}

/// Execute a parameterized SQL query and return results as JSON values.
fn execute_param_query(
    conn: &Connection,
    sql: &str,
    params: &[Box<dyn rusqlite::types::ToSql>],
) -> Result<Vec<Value>> {
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();

    let mut stmt = conn.prepare(sql)?;
    let column_count = stmt.column_count();
    let column_names: Vec<String> = (0..column_count)
        .map(|i| stmt.column_name(i).unwrap_or("?").to_string())
        .collect();

    let mut results = Vec::new();
    let rows = stmt.query_map(param_refs.as_slice(), |row| {
        let mut map = serde_json::Map::new();
        for (i, name) in column_names.iter().enumerate() {
            let val: Value = row_get_json_value(row, i);
            map.insert(name.clone(), val);
        }
        Ok(serde_json::Value::Object(map))
    })?;

    for row in rows {
        results.push(row?);
    }

    Ok(results)
}

/// Extract a JSON value from a row column by index.
/// Handles NULL, INTEGER, REAL, and TEXT types.
fn row_get_json_value(row: &rusqlite::Row, idx: usize) -> Value {
    // Try NULL first
    let val: Result<String, _> = row.get(idx);
    if let Ok(s) = val {
        // Try to parse as number
        if let Ok(n) = s.parse::<i64>() {
            return Value::Number(n.into());
        }
        // rustnetec: clippy collapsible_nested_if — 合并嵌套 if let 为 let-chain（Rust 1.88+ 稳定）
        if let Ok(f) = s.parse::<f64>()
            && let Some(n) = serde_json::Number::from_f64(f)
        {
            return Value::Number(n);
        }
        return Value::String(s);
    }

    // Try integer
    let int_val: Result<i64, _> = row.get(idx);
    if let Ok(n) = int_val {
        return Value::Number(n.into());
    }

    // Try float
    let float_val: Result<f64, _> = row.get(idx);
    // rustnetec: clippy collapsible_nested_if — 合并嵌套 if let 为 let-chain（Rust 1.88+ 稳定）
    if let Ok(f) = float_val
        && let Some(n) = serde_json::Number::from_f64(f)
    {
        return Value::Number(n);
    }

    Value::Null
}

// rustnetec: G1 改造 — `print_json` 已移除。`run_query` 现返回 `Result<Vec<Value>>`,
// 输出职责上移至 CLI 层(`run_query_subcommand`)和 HTTP 层(`handle_query`)。

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::ConnectionFilter;

    #[test]
    fn filter_to_sql_protocol() {
        let filter = ConnectionFilter::parse("proto:TCP");
        let (where_clause, _params) = filter_to_sql(&filter);
        assert!(
            where_clause.contains("LOWER(protocol)"),
            "got: {}",
            where_clause
        );
    }

    #[test]
    fn filter_to_sql_port_exact() {
        let filter = ConnectionFilter::parse("port:443");
        let (where_clause, _params) = filter_to_sql(&filter);
        assert!(
            where_clause.contains("source_port = ?"),
            "got: {}",
            where_clause
        );
        assert!(
            where_clause.contains("dest_port = ?"),
            "got: {}",
            where_clause
        );
    }

    #[test]
    fn filter_to_sql_process() {
        let filter = ConnectionFilter::parse("process:curl");
        let (where_clause, _params) = filter_to_sql(&filter);
        assert!(
            where_clause.contains("LOWER(process_name)"),
            "got: {}",
            where_clause
        );
    }

    #[test]
    fn filter_to_sql_sni() {
        let filter = ConnectionFilter::parse("sni:example.com");
        let (where_clause, _params) = filter_to_sql(&filter);
        assert!(
            where_clause.contains("dest_hostname"),
            "got: {}",
            where_clause
        );
        assert!(where_clause.contains("dpi_domain"), "got: {}", where_clause);
    }

    #[test]
    fn filter_to_sql_general() {
        let filter = ConnectionFilter::parse("google");
        let (where_clause, _params) = filter_to_sql(&filter);
        // General search should produce OR across multiple columns
        assert!(where_clause.contains("OR"), "got: {}", where_clause);
    }

    #[test]
    fn filter_to_sql_combined() {
        let filter = ConnectionFilter::parse("proto:TCP process:curl");
        let (where_clause, _params) = filter_to_sql(&filter);
        assert!(where_clause.contains("AND"), "got: {}", where_clause);
    }

    #[test]
    fn filter_to_sql_empty() {
        let filter = ConnectionFilter::parse("");
        let (where_clause, _params) = filter_to_sql(&filter);
        assert!(where_clause.is_empty());
    }

    #[test]
    fn raw_sql_rejects_non_select() {
        let conn = open_test_connection();
        let result = run_raw_sql(&conn, "DROP TABLE connection_events");
        assert!(result.is_err());
    }

    #[test]
    fn raw_sql_allows_select() {
        let conn = open_test_connection();
        crate::telemetry::db::SqliteSink::init_schema(&conn).unwrap();
        let result = run_raw_sql(&conn, "SELECT COUNT(*) FROM connection_events");
        assert!(result.is_ok());
    }

    #[test]
    fn filter_query_returns_results() {
        let conn = open_test_connection();
        crate::telemetry::db::SqliteSink::init_schema(&conn).unwrap();

        // Insert a test event
        let pc = crate::config::PersistentConfig::default();
        let rc = crate::config::RuntimeConfig::from_persistent(&pc);
        let event = crate::telemetry::ConnectionEventData {
            timestamp: "2026-08-04T20:00:00.000+08:00".to_string(),
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
            rtt_ms: None,
            #[cfg(feature = "kubernetes")]
            kubernetes: None,
            service_name: Some("https".to_string()),
            direction: Some("outgoing".to_string()),
            dpi_protocol: Some("HTTPS".to_string()),
            dpi_domain: Some("example.com".to_string()),
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
        crate::telemetry::db::SqliteSink::insert_event(&tx, &event, &rc).unwrap();
        tx.commit().unwrap();

        // Query with filter
        let results = run_filter_query_on_conn(&conn, "proto:TCP").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["protocol"], "TCP");
    }

    fn open_test_connection() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    fn run_filter_query_on_conn(conn: &Connection, filter_str: &str) -> Result<Vec<Value>> {
        let filter = ConnectionFilter::parse(filter_str);
        let (where_clause, params) = filter_to_sql(&filter);

        let sql = if where_clause.is_empty() {
            format!(
                "SELECT * FROM connection_events ORDER BY ts DESC LIMIT {}",
                DEFAULT_QUERY_LIMIT
            )
        } else {
            format!(
                "SELECT * FROM connection_events WHERE {} ORDER BY ts DESC LIMIT {}",
                where_clause, DEFAULT_QUERY_LIMIT
            )
        };

        execute_param_query(conn, &sql, &params)
    }
}

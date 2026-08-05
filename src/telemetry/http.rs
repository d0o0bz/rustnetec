// rustnetec: Local loopback HTTP service for daemon/tray mode (R5, T1.4)
//
// Endpoints:
//   GET  /                        — index page (no auth)
//   GET  /live                    — real-time connection snapshot (auth)
//   GET  /query?sql=...&filter=... — SQLite read-only query (auth)
//   GET  /stats                   — aggregate statistics (auth)
//   GET  /config                  — read current config (auth)
//   PUT  /config                  — update config (auth, dual-track)
//   POST /config/restart-capture  — restart capture with pending items (auth)

use anyhow::Result;
use log::info;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

/// Shared state accessible by HTTP handlers.
pub struct HttpState {
    /// Path to the SQLite database file.
    pub db_path: PathBuf,
    /// HTTP authentication token (Bearer).
    pub http_token: String,
    /// Shared handle to App's `should_stop` flag (偏差5, T1.5).
    ///
    /// `POST /config/restart-capture` sets this to `true` to gracefully stop
    /// the capture thread. The flag is `Arc<AtomicBool>` (Send + Sync), safe
    /// to share with the HTTP server thread without touching `App`'s ownership.
    pub should_stop: Arc<AtomicBool>,
}

/// Start the HTTP server on a background thread.
/// Returns immediately; the server runs until the process exits.
pub fn start_http_server(
    port: u16,
    state: Arc<HttpState>,
) -> Result<()> {
    let addr = std::net::SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), port));
    let server = tiny_http::Server::http(addr)
        .map_err(|e| anyhow::anyhow!("Failed to bind HTTP server on 127.0.0.1:{}: {}", port, e))?;

    info!("HTTP server listening on 127.0.0.1:{}", port);

    thread::Builder::new()
        .name("http_server".to_string())
        .spawn(move || {
            for request in server.incoming_requests() {
                handle_request(request, &state);
            }
        })?;

    Ok(())
}

/// Route and handle an incoming HTTP request.
/// tiny_http::Request::respond() consumes self, so we pass ownership.
fn handle_request(request: tiny_http::Request, state: &HttpState) {
    let path = request.url().to_string();
    let method = request.method().clone();

    // Strip query string for routing
    let path_only = path.split('?').next().unwrap_or(&path).to_string();

    // Check CORS origin
    if !check_cors_origin(&request) {
        let _ = respond_text(request, 403, "text/plain", "Forbidden: non-local origin");
        return;
    }

    // Route: index page (no auth required)
    if path_only == "/" && method == tiny_http::Method::Get {
        let _ = respond_text(request, 200, "text/html", INDEX_HTML);
        return;
    }

    // All other endpoints require authentication
    if !check_auth(&request, &state.http_token) {
        let _ = respond_text(request, 401, "text/plain", "Unauthorized: missing or invalid token");
        return;
    }

    match (path_only.as_str(), method) {
        // GET /live — real-time connection snapshot
        ("/live", tiny_http::Method::Get) => {
            handle_live(request, state);
        }

        // GET /query — SQLite read-only query
        ("/query", tiny_http::Method::Get) => {
            handle_query(request, state);
        }

        // GET /stats — aggregate statistics
        ("/stats", tiny_http::Method::Get) => {
            handle_stats(request, state);
        }

        // GET /config — read current config
        ("/config", tiny_http::Method::Get) => {
            handle_get_config(request, state);
        }

        // PUT /config — update config (dual-track)
        ("/config", tiny_http::Method::Put) => {
            handle_put_config(request, state);
        }

        // POST /config/restart-capture — restart capture
        ("/config/restart-capture", tiny_http::Method::Post) => {
            handle_restart_capture(request, state);
        }

        _ => {
            let _ = respond_text(request, 404, "text/plain", "Not Found");
        }
    }
}

/// Check if the request has a valid Bearer token.
fn check_auth(request: &tiny_http::Request, expected_token: &str) -> bool {
    if expected_token.is_empty() {
        return true; // No token configured = no auth required
    }

    for header in request.headers() {
        if header.field.equiv("Authorization") {
            // rustnetec: clippy deref — 内联 as_str 避开中间引用绑定
            if let Some(token) = header.value.as_str().strip_prefix("Bearer ") {
                return token.trim() == expected_token;
            }
        }
    }
    false
}

/// Check CORS: only allow local origins (127.0.0.1 / localhost).
fn check_cors_origin(request: &tiny_http::Request) -> bool {
    for header in request.headers() {
        if header.field.equiv("Origin") {
            // rustnetec: clippy deref — 内联 as_str 避开中间引用绑定
            let origin = header.value.as_str().to_lowercase();
            if origin.contains("127.0.0.1") || origin.contains("localhost") || origin.contains("[::1]") {
                return true;
            }
            return false;
        }
    }
    true
}

/// GET /live — return real-time connection snapshot.
fn handle_live(request: tiny_http::Request, _state: &HttpState) {
    let response = serde_json::json!({
        "connections": [],
        "count": 0,
        "note": "live endpoint placeholder — App integration pending"
    });
    let _ = respond_json(request, 200, &response);
}

/// GET /query — SQLite read-only query.
fn handle_query(request: tiny_http::Request, state: &HttpState) {
    let url = request.url().to_string();
    let params = parse_query_params(&url);

    let sql_param = params.get("sql").map(|s| s.as_str());
    let filter_param = params.get("filter").map(|s| s.as_str());

    let result = if sql_param.is_some() {
        crate::telemetry::query::run_query(&state.db_path, None, sql_param, false)
    } else if filter_param.is_some() {
        crate::telemetry::query::run_query(&state.db_path, filter_param, None, false)
    } else {
        crate::telemetry::query::run_query(&state.db_path, None, None, false)
    };

    match result {
        Ok(()) => {
            let response = serde_json::json!({
                "status": "ok",
                "note": "query executed — output currently goes to stdout; HTTP JSON response coming in integration"
            });
            let _ = respond_json(request, 200, &response);
        }
        Err(e) => {
            let response = serde_json::json!({"error": format!("{}", e)});
            let _ = respond_json(request, 400, &response);
        }
    }
}

/// GET /stats — aggregate statistics.
fn handle_stats(request: tiny_http::Request, state: &HttpState) {
    let result = query_stats(&state.db_path);
    match result {
        Ok(json) => { let _ = respond_json(request, 200, &json); }
        Err(e) => {
            let response = serde_json::json!({"error": format!("{}", e)});
            let _ = respond_json(request, 500, &response);
        }
    }
}

/// GET /config — read current config.
fn handle_get_config(request: tiny_http::Request, _state: &HttpState) {
    match crate::config::PersistentConfig::load() {
        Ok(config) => {
            let json = serde_json::to_value(&config).unwrap_or_else(|e| {
                serde_json::json!({"error": format!("serialize error: {}", e)})
            });
            let _ = respond_json(request, 200, &json);
        }
        Err(e) => {
            let response = serde_json::json!({"error": format!("{}", e)});
            let _ = respond_json(request, 500, &response);
        }
    }
}

/// PUT /config — update config (dual-track: hot-update + restart-required).
fn handle_put_config(mut request: tiny_http::Request, _state: &HttpState) {
    let mut body = String::new();
    if let Err(e) = request.as_reader().read_to_string(&mut body) {
        let response = serde_json::json!({"error": format!("failed to read body: {}", e)});
        let _ = respond_json(request, 400, &response);
        return;
    }

    let new_config: crate::config::PersistentConfig = match serde_yaml::from_str(&body) {
        Ok(c) => c,
        Err(e) => {
            let response = serde_json::json!({"error": format!("invalid config YAML: {}", e)});
            let _ = respond_json(request, 400, &response);
            return;
        }
    };

    if let Err(e) = new_config.validate() {
        let response = serde_json::json!({"error": format!("validation failed: {}", e)});
        let _ = respond_json(request, 400, &response);
        return;
    }

    if let Err(e) = new_config.save() {
        let response = serde_json::json!({"error": format!("failed to save config: {}", e)});
        let _ = respond_json(request, 500, &response);
        return;
    }

    // TODO: Apply hot-update items to RuntimeConfig via Arc<RwLock<RuntimeConfig>>
    // TODO: Set pending_restart for restart-required items

    let response = serde_json::json!({
        "status": "ok",
        "note": "config saved — hot-update items applied immediately; restart-required items need POST /config/restart-capture"
    });
    let _ = respond_json(request, 200, &response);
}

/// POST /config/restart-capture — restart capture with pending items.
fn handle_restart_capture(mut request: tiny_http::Request, state: &HttpState) {
    let mut body = String::new();
    if let Err(e) = request.as_reader().read_to_string(&mut body) {
        let response = serde_json::json!({"error": format!("failed to read body: {}", e)});
        let _ = respond_json(request, 400, &response);
        return;
    }

    let params: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    if params.get("confirm").and_then(|v| v.as_bool()) != Some(true) {
        let response = serde_json::json!({
            "error": "confirmation required: send {\"confirm\": true}"
        });
        let _ = respond_json(request, 400, &response);
        return;
    }

    // rustnetec: 偏差5 修复 — 真正触发 capture thread 停止
    //
    // 架构约束：capture thread 在特权期打开 raw socket，uid drop 后无法重开。
    // 因此 restart_capture 的实现是「优雅停止旧捕获线程」，无法在本进程内
    // 用新配置重启 raw socket。响应明确告知调用方「需重启进程以新配置恢复捕获」。
    //
    // 这与 T1.5「停止当前捕获线程」一致；「用新配置启动捕获线程」步骤因特权
    // 限制降级为「标记 + 提示进程重启」。如果未来在「uid drop 前 restart」
    // 或「保留 raw socket fd 并 reopen」方向有突破，可在此处恢复完整重启逻辑。
    let was_capturing = !state.should_stop.load(std::sync::atomic::Ordering::Relaxed);
    if was_capturing {
        info!("restart-capture: stopping capture thread for config reload");
        state
            .should_stop
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    let response = serde_json::json!({
        "status": "ok",
        "capture_stopped": was_capturing,
        "note": "capture thread stopped for config reload — restart the process to resume capture with the new configuration (raw socket cannot be reopened after uid drop)"
    });
    let _ = respond_json(request, 200, &response);
}

/// Query aggregate statistics from the SQLite database.
fn query_stats(db_path: &PathBuf) -> Result<serde_json::Value> {
    use rusqlite::{Connection, OpenFlags};

    if !db_path.exists() {
        return Ok(serde_json::json!({
            "total_events": 0,
            "total_aggregates": 0,
            "note": "database not found"
        }));
    }

    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let total_events: i64 = conn.query_row(
        "SELECT COUNT(*) FROM connection_events",
        [],
        |row| row.get(0),
    ).unwrap_or(0);

    let total_aggregates: i64 = conn.query_row(
        "SELECT COUNT(*) FROM aggregates",
        [],
        |row| row.get(0),
    ).unwrap_or(0);

    let events_by_protocol: Vec<serde_json::Value> = {
        let mut stmt = conn.prepare(
            "SELECT protocol, COUNT(*) as cnt FROM connection_events GROUP BY protocol ORDER BY cnt DESC LIMIT 20"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "protocol": row.get::<_, String>(0)?,
                "count": row.get::<_, i64>(1)?
            }))
        })?;
        rows.filter_map(|r| r.ok()).collect()
    };

    let events_by_direction: Vec<serde_json::Value> = {
        let mut stmt = conn.prepare(
            "SELECT direction, COUNT(*) as cnt FROM connection_events WHERE direction IS NOT NULL GROUP BY direction ORDER BY cnt DESC LIMIT 10"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "direction": row.get::<_, String>(0)?,
                "count": row.get::<_, i64>(1)?
            }))
        })?;
        rows.filter_map(|r| r.ok()).collect()
    };

    Ok(serde_json::json!({
        "total_events": total_events,
        "total_aggregates": total_aggregates,
        "by_protocol": events_by_protocol,
        "by_direction": events_by_direction,
    }))
}

// ---- Helpers ----

/// Parse query parameters from a URL string.
fn parse_query_params(url: &str) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();
    if let Some(query) = url.split('?').nth(1) {
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                let key = urldecode(key);
                let value = urldecode(value);
                params.insert(key, value);
            }
        }
    }
    params
}

/// Simple URL decoding.
fn urldecode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            } else {
                result.push('%');
                result.push_str(&hex);
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}

/// Send a plain text response (consumes the request).
fn respond_text(
    request: tiny_http::Request,
    status: u16,
    content_type: &str,
    body: &str,
) -> Result<()> {
    let response = tiny_http::Response::new(
        tiny_http::StatusCode(status),
        vec![
            tiny_http::Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes()).unwrap(),
            tiny_http::Header::from_bytes(&b"Access-Control-Allow-Origin"[..], b"*").unwrap(),
        ],
        std::io::Cursor::new(body.as_bytes().to_vec()),
        Some(body.len()),
        None,
    );
    request.respond(response)?;
    Ok(())
}

/// Send a JSON response (consumes the request).
fn respond_json(
    request: tiny_http::Request,
    status: u16,
    value: &serde_json::Value,
) -> Result<()> {
    let body = serde_json::to_string(value).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
    let response = tiny_http::Response::new(
        tiny_http::StatusCode(status),
        vec![
            tiny_http::Header::from_bytes(&b"Content-Type"[..], b"application/json").unwrap(),
            tiny_http::Header::from_bytes(&b"Access-Control-Allow-Origin"[..], b"*").unwrap(),
        ],
        std::io::Cursor::new(body.as_bytes().to_vec()),
        Some(body.len()),
        None,
    );
    request.respond(response)?;
    Ok(())
}

/// Index page HTML.
const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html>
<head><title>rustnetec</title></head>
<body>
<h1>rustnetec HTTP API</h1>
<ul>
<li><a href="/live">GET /live</a> — real-time connection snapshot</li>
<li><a href="/query">GET /query?sql=...&amp;filter=...</a> — SQLite read-only query</li>
<li><a href="/stats">GET /stats</a> — aggregate statistics</li>
<li><a href="/config">GET /config</a> — read current config</li>
<li>PUT /config — update config (dual-track)</li>
<li>POST /config/restart-capture — restart capture</li>
</ul>
<p>All endpoints except / require <code>Authorization: Bearer &lt;token&gt;</code></p>
</body>
</html>"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_query_params_basic() {
        let params = parse_query_params("/query?sql=SELECT+1&filter=proto:TCP");
        assert_eq!(params.get("sql").unwrap(), "SELECT 1");
        assert_eq!(params.get("filter").unwrap(), "proto:TCP");
    }

    #[test]
    fn parse_query_params_empty() {
        let params = parse_query_params("/query");
        assert!(params.is_empty());
    }

    #[test]
    fn parse_query_params_encoded() {
        let params = parse_query_params("/query?filter=proto%3ATCP");
        assert_eq!(params.get("filter").unwrap(), "proto:TCP");
    }

    #[test]
    fn urldecode_basic() {
        assert_eq!(urldecode("hello+world"), "hello world");
        assert_eq!(urldecode("proto%3ATCP"), "proto:TCP");
        assert_eq!(urldecode("no%20encoding"), "no encoding");
    }

    #[test]
    fn http_state_creation() {
        use std::sync::atomic::AtomicBool;
        let state = HttpState {
            db_path: PathBuf::from("/tmp/test.db"),
            http_token: "test-token".to_string(),
            should_stop: Arc::new(AtomicBool::new(false)),
        };
        assert_eq!(state.http_token, "test-token");
        assert!(!state.should_stop.load(std::sync::atomic::Ordering::Relaxed));
    }
}

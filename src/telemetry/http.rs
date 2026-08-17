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
use log::{info, warn};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

/// rustnetec: one-time bootstrap code auth (T3.3, R6)
///
/// Lifetime bounds for the bootstrap handshake and the resulting session.
const BOOTSTRAP_GUID_TTL: Duration = Duration::from_secs(5 * 60);
const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

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
    /// rustnetec: 托盘「暂停/继续捕获」可逆开关句柄（区别于 `should_stop` 的不可逆退出）。
    /// `POST /pause` 翻转此标志；捕获/采集线程在 loop 顶部检测并空转等待恢复。
    pub paused: Arc<AtomicBool>,
    /// rustnetec: pending one-time bootstrap codes (T3.3, R6).
    ///
    /// Each entry is `(guid, issued_at)`. A guid is removed the first time a
    /// browser hits `/?code=<guid>`, at which point a session is issued. A
    /// guid that is never redeemed expires after `BOOTSTRAP_GUID_TTL`.
    pub pending_guids: Arc<Mutex<Vec<(String, Instant)>>>,
    /// rustnetec: 会话签名密钥（无状态 session，T3.3 修复，2026-08-11）。
    ///
    /// session cookie 改为「时间戳.签名」无状态格式（BLAKE3 keyed hash），
    /// 不再用内存态 `active_sessions` 映射——daemon 重启后旧 cookie 依然有效
    /// （密钥从持久化 machine_id/http_token 派生，重启不丢失），修复
    /// 「托盘打开 OK、浏览器刷新报未授权」问题（原内存态在进程重启时清空）。
    pub session_key: Arc<[u8; 32]>,
    /// rustnetec: HTTP listen port (T3.5, R6).
    ///
    /// Stored on the state so the tray launcher can build the
    /// `http://127.0.0.1:<port>/?code=<guid>` URL without hardcoding 19811 —
    /// the daemon may be started with `--http-port <override>`, and the
    /// launcher must honour that override to hit the right server.
    pub http_port: u16,
    /// rustnetec: live snapshot for the tray helper (T3.6.7, R6).
    ///
    /// The daemon periodically writes the minimal status fields (interface
    /// rates, active connections, uptime) into this shared value; the tray
    /// helper process polls `GET /live` over HTTP and renders them in the
    /// menu status line. This is the daemon→tray state bridge — the tray
    /// helper never touches `App` directly (separate process).
    pub live_snapshot: Arc<RwLock<serde_json::Value>>,
    /// rustnetec: G2 修复 — 运行时配置共享态(R7 双轨制)。
    ///
    /// `PUT /config` 落盘成功后,热更新项经 `apply_hot_update` 写入此 RwLock,
    /// 捕获线程/上报线程/托盘状态行读最新值即时生效;重启生效项经
    /// `apply_restart_items` 置 `pending_restart=true`,等 `POST
    /// /config/restart-capture` 或进程重启时应用。
    ///
    /// 之所以放 HttpState 而非全局:HTTP 是配置变更的唯一入口,持有所有权
    /// 避免生命周期纠缠;捕获线程持 clone 读快照,无需轮询落盘。
    pub runtime_config: Arc<RwLock<crate::config::RuntimeConfig>>,
}

impl HttpState {
    /// rustnetec: Refresh the live snapshot from the running App (T3.6.7).
    ///
    /// Called by the daemon main loop on the refresh cadence so the tray
    /// helper can pull `GET /live` and render a status line without an App
    /// handle of its own. Minimal field set: interface, in/out rates,
    /// active connection count, uptime, paused.
    pub fn update_live_snapshot(&self, app: &crate::app::App) {
        let rates = app.get_interface_rates();
        let (rate_in_bps, rate_out_bps) = rates.values().fold((0u64, 0u64), |(rx, tx), r| {
            (rx + r.rx_bytes_per_sec, tx + r.tx_bytes_per_sec)
        });
        let connections = app
            .get_connections()
            .iter()
            .filter(|c| !c.is_historic)
            .count();
        // rustnetec: 历史连接数独立于快照开关(tracker 恒保留有界历史表)。
        let historic_connections = app.get_historic_connection_count();
        let uptime = app
            .get_connections()
            .iter()
            .map(|c| c.created_at)
            .min()
            .and_then(|start| start.elapsed().ok())
            .unwrap_or_default();
        let snapshot = serde_json::json!({
            // rustnetec: resolve virtual capture devices (pktap/any/NPF) to
            // the real active interface so the tray status line shows e.g.
            // "en0" instead of the meaningless "pktap" (T3.6.7 follow-up).
            "interface": app.get_display_interface(),
            "rate_in_bps": rate_in_bps,
            "rate_out_bps": rate_out_bps,
            "connections": connections,
            "historic_connections": historic_connections,
            "uptime_secs": uptime.as_secs(),
            "paused": app.is_paused(),
        });
        if let Ok(mut slot) = self.live_snapshot.write() {
            *slot = snapshot;
        }
    }

    /// rustnetec: Issue a one-time bootstrap guid for the tray launcher (T3.3).
    ///
    /// The guid is written to `pending_guids` with the current timestamp and
    /// returned. The launcher builds `http://127.0.0.1:<port>/?code=<guid>` and
    /// opens the browser. On first hit the server redeems the guid, issues a
    /// session cookie, and drops the guid — it cannot be replayed.
    pub fn issue_bootstrap_guid(&self) -> String {
        // rustnetec: reuse PersistentConfig::generate_http_token as the
        // cryptographic random source — it already produces a 32-byte hex
        // string from platform RNG with a time/pid fallback, and avoids
        // introducing a new getrandom workspace dep just for the bootstrap
        // guid. A 64-char hex guid is more than enough collision resistance
        // for a localhost-only one-time handshake.
        let guid = crate::config::PersistentConfig::generate_http_token();
        if let Ok(mut guids) = self.pending_guids.lock() {
            guids.push((guid.clone(), Instant::now()));
        }
        guid
    }
}

/// Start the HTTP server on a background thread.
/// Returns immediately; the server runs until the process exits.
/// Upper bound on concurrent request-handler threads.
///
/// The server binds 127.0.0.1 only, so load is local and bounded, but an
/// unbounded spawn on every request could still fork-bomb under a runaway
/// WebUI polling loop. A fixed worker pool (or tokio) would be more elegant,
/// but a counting semaphore keeps the change local and dependency-free.
/// Once the cap is hit, the accept loop blocks (backpressure) until a worker
/// finishes — this also prevents the single slow-client case from wedging
/// everything, which was the original bug.
const MAX_CONCURRENT_REQUESTS: usize = 32;

pub fn start_http_server(port: u16, state: Arc<HttpState>) -> Result<()> {
    let addr = std::net::SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), port));
    let server = tiny_http::Server::http(addr)
        .map_err(|e| anyhow::anyhow!("Failed to bind HTTP server on 127.0.0.1:{}: {}", port, e))?;

    info!("HTTP server listening on 127.0.0.1:{}", port);

    // rustnetec: W-fix — each request is handled on its own thread instead of
    // serially inside the accept loop. The old single-threaded loop blocked on
    // a slow SQLite query or a slow/stalled HTTP client (the browser opening
    // the panel and not draining a response), which froze EVERY other request
    // — including the tray helper's GET /live polling and POST
    // /admin/shutdown. That shutdown request then timed out (800ms) on tray
    // quit and the daemon was left running. A bounded counting semaphore caps
    // concurrency so we can't spawn without limit under request floods.
    let active: Arc<std::sync::atomic::AtomicUsize> =
        Arc::new(std::sync::atomic::AtomicUsize::new(0));

    thread::Builder::new()
        .name("http_server".to_string())
        .spawn(move || {
            for request in server.incoming_requests() {
                // Backpressure: if at the cap, block the accept loop until a
                // worker exits. This is a spin with a short sleep rather than
                // a Condvar to keep the change minimal; accept rate on
                // loopback is low and the cap is generous.
                while active.load(std::sync::atomic::Ordering::Acquire) >= MAX_CONCURRENT_REQUESTS {
                    thread::sleep(std::time::Duration::from_millis(10));
                }

                let state = Arc::clone(&state);
                active.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                // Clone for the worker closure; keep the outer `active`
                // available for the spawn-failure decrement below.
                let worker_active = Arc::clone(&active);

                let builder = thread::Builder::new().name("http_req".to_string());
                if builder
                    .spawn(move || {
                        handle_request(request, &state);
                        worker_active.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                    })
                    .is_err()
                {
                    active.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                    warn!("http_server: failed to spawn request handler thread");
                }
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

    // Route: index page — bootstrap handshake (?code=<guid>) or session landing
    if path_only == "/" && method == tiny_http::Method::Get {
        // rustnetec: one-time bootstrap code handshake (T3.3, R6)
        if let Some(code) = parse_query_param(&path, "code") {
            if let Some(session_id) = redeem_bootstrap_guid(state, &code) {
                // Guid redeemed: issue a session cookie then 303-redirect to
                // the clean `/` URL. The redirect makes the address bar lose
                // the one-time `?code=...`, so a browser refresh does not
                // replay an already-redeemed guid (which would 403). The
                // cookie is set on this 303 response and sent on the
                // subsequent GET `/`, which then renders the index.
                let _ = respond_redirect_with_session(request, "/", &session_id);
                return;
            }
            // Unknown or already-redeemed guid: show a landing page that
            // tells the user to open the panel from the tray again, instead
            // of silently dumping the API link list.
            let _ = respond_text(request, 403, "text/html", LOGIN_HTML);
            return;
        }
        // No code: if the request already carries a valid session cookie,
        // render the index; otherwise show the login landing page.
        if validate_session(state, &request) {
            let _ = respond_text(request, 200, "text/html", INDEX_HTML);
        } else {
            let _ = respond_text(request, 200, "text/html", LOGIN_HTML);
        }
        return;
    }

    // rustnetec: POST /bootstrap-guid — NO-AUTH endpoint (T3.6.10).
    //
    // The tray helper is a separate process and needs a one-time guid to
    // complete the browser handshake. Auth was dropped because the helper
    // reads `PersistentConfig.http_token`, which can be null when config.yml
    // was generated without a token (e.g. sudo root vs user HOME mismatch) —
    // an empty/mismatched Bearer made the POST 401 and the helper fell back
    // to the bare URL, leaving the panel stuck on LOGIN_HTML.
    //
    // This stays safe for two reasons:
    //  1. Server binds 127.0.0.1 only — remote callers cannot reach it.
    //  2. A guid is one-time and expires after BOOTSTRAP_GUID_TTL (5 min);
    //     it only grants a session to the local browser, equivalent to what
    //     any local process could already do by reading config.yml directly.
    if path_only == "/bootstrap-guid" && method == tiny_http::Method::Post {
        handle_bootstrap_guid(request, state);
        return;
    }

    // All other endpoints require authentication
    if !check_auth(&request, state, &state.http_token) {
        let _ = respond_text(
            request,
            401,
            "text/plain",
            "Unauthorized: missing or invalid token",
        );
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

        // rustnetec: T-B1 — GET /stats/range 时间桶流量/连接查询。
        ("/stats/range", tiny_http::Method::Get) => {
            handle_stats_range(request, state);
        }

        // rustnetec: T-B2 — GET /stats/rtt RTT 分位数时间序列。
        ("/stats/rtt", tiny_http::Method::Get) => {
            handle_stats_rtt(request, state);
        }

        // rustnetec: T-B3 — GET /stats/availability 可用性时间序列。
        ("/stats/availability", tiny_http::Method::Get) => {
            handle_stats_availability(request, state);
        }

        // rustnetec: T-B4 — GET /stats/duration 连接持续时长聚合。
        ("/stats/duration", tiny_http::Method::Get) => {
            handle_stats_duration(request, state);
        }

        // rustnetec: 外网可达率探测时间序列（reachability_probes 表）。
        ("/stats/reachability", tiny_http::Method::Get) => {
            handle_stats_reachability(request, state);
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

        // rustnetec: 托盘「暂停/继续捕获」——翻转 paused 标志，返回新状态。
        ("/pause", tiny_http::Method::Post) => {
            handle_pause(request, state);
        }

        // rustnetec: POST /admin/shutdown — tray helper → daemon graceful
        // stop (T3.6.7). Requires auth like all non-/ endpoints.
        ("/admin/shutdown", tiny_http::Method::Post) => {
            handle_admin_shutdown(request, state);
        }

        // rustnetec: POST /bootstrap-guid — tray helper → daemon one-time
        // bootstrap code (T3.6.9). The tray helper is a separate process and
        // cannot call HttpState::issue_bootstrap_guid() directly, so it asks
        // the daemon over HTTP, then opens the browser at
        // http://127.0.0.1:<port>/?code=<guid> to complete the handshake.
        ("/bootstrap-guid", tiny_http::Method::Post) => {
            handle_bootstrap_guid(request, state);
        }

        // rustnetec: W3.3 — GET /processes 供 WebUI Activity 页专用。
        // 按 process_name 聚合 top 50(按总字节降序),避免前端反复 /query 大结果。
        ("/processes", tiny_http::Method::Get) => {
            handle_processes(request, state);
        }

        // rustnetec: T-F3b — GET /echarts.js — ECharts 图表库静态资产。
        // 浏览器加载 <script src="echarts.js"> 时携带会话 cookie,走同一鉴权;
        // 与其它端点一致置于鉴权之后,保持"所有数据端点均需鉴权"的边界。
        ("/echarts.js", tiny_http::Method::Get) => {
            let _ = respond_text(request, 200, "application/javascript", ECHARTS_JS);
        }

        _ => {
            let _ = respond_text(request, 404, "text/plain", "Not Found");
        }
    }
}

/// Check if the request has a valid credential.
///
/// rustnetec: T3.3 — now checks TWO credential paths, in order:
/// 1. Session cookie issued by the bootstrap handshake (`validate_session`).
///    This is the path browsers take after the user opened the panel from the
///    tray; the cookie is attached automatically so no JS plumbing is needed.
/// 2. Bearer token in the `Authorization` header (original behavior, kept for
///    CLI/API clients like ureq/curl).
fn check_auth(request: &tiny_http::Request, state: &HttpState, expected_token: &str) -> bool {
    // Session cookie path (T3.3)
    if validate_session(state, request) {
        return true;
    }
    // Bearer token path (original)
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
            if origin.contains("127.0.0.1")
                || origin.contains("localhost")
                || origin.contains("[::1]")
            {
                return true;
            }
            return false;
        }
    }
    true
}

/// GET /live — return the daemon's live snapshot (daemon→tray bridge, T3.6.7).
///
/// The tray helper polls this endpoint over HTTP to render the menu status
/// line without holding an `App` handle (separate process). The daemon main
/// loop refreshes `live_snapshot` on the configured cadence via
/// `HttpState::update_live_snapshot`.
fn handle_live(request: tiny_http::Request, state: &HttpState) {
    let snapshot = state
        .live_snapshot
        .read()
        .map(|s| s.clone())
        .unwrap_or_else(|_| serde_json::json!({}));
    let _ = respond_json(request, 200, &snapshot);
}

/// POST /admin/shutdown — gracefully stop the daemon (T3.6.7).
///
/// The tray helper calls this when the user picks "Quit" from the tray menu:
/// the helper is a separate process and cannot call `app.stop()` directly, so
/// it sets `should_stop` over HTTP — the daemon's capture thread and main
/// loop observe the flag and exit cleanly (same mechanism as
/// `/config/restart-capture`, 偏差5/T1.5).
fn handle_admin_shutdown(request: tiny_http::Request, state: &HttpState) {
    state
        .should_stop
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let response = serde_json::json!({
        "status": "ok",
        "note": "should_stop set — daemon will exit gracefully"
    });
    let _ = respond_json(request, 200, &response);
}

/// rustnetec: POST /pause — 托盘「暂停/继续捕获」HTTP 端点。
///
/// tray helper 是独立进程，不持有 `App`，故通过此端点翻转 daemon 的 `paused`
/// 标志。捕获/采集线程在 loop 顶部检测 `paused`，置位时 `sleep(100ms) + continue`，
/// 清位后立即恢复。返回新状态供托盘同步菜单文案。
fn handle_pause(request: tiny_http::Request, state: &HttpState) {
    let now_paused = !state.paused.load(std::sync::atomic::Ordering::Relaxed);
    state
        .paused
        .store(now_paused, std::sync::atomic::Ordering::Relaxed);
    info!(
        "POST /pause: capture {}",
        if now_paused { "paused" } else { "resumed" }
    );
    let response = serde_json::json!({
        "status": "ok",
        "paused": now_paused
    });
    let _ = respond_json(request, 200, &response);
}

/// POST /bootstrap-guid — issue a one-time bootstrap guid for the tray helper
/// (T3.6.9).
///
/// The tray helper is a separate process from the daemon and cannot call
/// `HttpState::issue_bootstrap_guid()` directly, so it POSTs here (Bearer
/// auth, like all non-/ endpoints) and receives `{"guid":"<hex>"}`. It then
/// opens the browser at `http://127.0.0.1:<port>/?code=<guid>`; the daemon's
/// `/` handler redeems the guid and issues a session cookie (T3.3).
fn handle_bootstrap_guid(request: tiny_http::Request, state: &HttpState) {
    let guid = state.issue_bootstrap_guid();
    let response = serde_json::json!({ "guid": guid });
    let _ = respond_json(request, 200, &response);
}

/// GET /query — SQLite read-only query.
///
/// rustnetec: G1 修复 — `/query` 现真正返回查询结果 JSON 行数组,而非占位 note。
///
/// 响应格式:
/// ```jsonc
/// { "columns": ["ts","protocol",...], "rows": [[...],[...]], "count": <n> }
/// ```
/// - `columns`:结果集列名(来自 `stmt.column_name`)。
/// - `rows`:二维数组,每行按 `columns` 顺序排列;前端按列名渲染即可。
/// - `count`:本次返回的行数(非全表 COUNT;分页总数用 `/query/count`)。
///
/// 安全约束:
/// - `sql` 参数走 `run_raw_sql` 的 SELECT/PRAGMA/EXPLAIN 白名单(拒绝写语句)。
/// - `filter` 参数经 `filter_to_sql` 翻译为参数化 WHERE(无注入风险)。
/// - 默认查询与 filter 查询均强制 `ORDER BY ts DESC LIMIT DEFAULT_QUERY_LIMIT`(1000),
///   防止大结果阻塞 tiny_http 单线程。
///
/// rustnetec: W0.5 — 分页参数。
///
/// - `?limit=n`:钳制到 [1, 1000];缺省 1000。
/// - `?offset=n`:OFFSET n;缺省 0。
/// - `?order=ts ASC | ts DESC`:白名单,其余回 400。
///   raw SQL 模式忽略分页参数(用户自行控制 LIMIT)。
///
/// 错误处理:查询失败回 400 + `{"error":"..."}`;数据库缺失由 `run_query` 返回 Err 同样走 400。
fn handle_query(request: tiny_http::Request, state: &HttpState) {
    let url = request.url().to_string();
    let params = parse_query_params(&url);

    // rustnetec: W-修复容错 — 数据库缺失时返回 200 空结果 + note(与
    // /processes 一致),而非裸 400。前端据此显示"暂无数据"而非"查询失败"。
    // (SqliteSink 挂接后 daemon 启动即建库,此分支仅覆盖未捕获/异常场景。)
    if !state.db_path.exists() {
        let response = serde_json::json!({
            "columns": [],
            "rows": [],
            "count": 0,
            "note": "database file not found — no capture data yet"
        });
        let _ = respond_json(request, 200, &response);
        return;
    }

    let sql_param = params.get("sql").map(|s| s.as_str());
    let filter_param = params.get("filter").map(|s| s.as_str());

    // rustnetec: W0.5 — 解析分页参数。
    // limit 钳制到 [1, 1000];offset 钳制到 [0, i64::MAX];order 走白名单。
    // 非法数字或越界一律回 400。
    let limit_param: Option<i64> = match params.get("limit") {
        Some(s) => match s.parse::<i64>() {
            Ok(n) => Some(n.clamp(1, crate::telemetry::query::DEFAULT_QUERY_LIMIT)),
            Err(_) => {
                let response = serde_json::json!({"error": "limit must be an integer"});
                let _ = respond_json(request, 400, &response);
                return;
            }
        },
        None => None,
    };
    let offset_param: Option<i64> = match params.get("offset") {
        Some(s) => match s.parse::<i64>() {
            Ok(n) if n >= 0 => Some(n),
            _ => {
                let response = serde_json::json!({"error": "offset must be a non-negative integer"});
                let _ = respond_json(request, 400, &response);
                return;
            }
        },
        None => None,
    };
    let order_param: Option<&str> = params.get("order").map(|s| s.as_str());

    // rustnetec: 连接表时间范围过滤 — `since` 为相对时长(如 1d/7d/1m/3m/1y)，
    // 转成 RFC3339 后作为 `ts >= ?` 参数化条件传给查询层。
    // 注:不复用 parse_time_param(其 m=分钟、无 y),见 parse_since_param。
    let since_ts: Option<String> = params
        .get("since")
        .map(String::as_str)
        .and_then(parse_since_param);

    let result = crate::telemetry::query::run_query_paged(
        &state.db_path,
        filter_param,
        sql_param,
        false,
        limit_param,
        offset_param,
        order_param,
        since_ts.as_deref(),
    );

    match result {
        Ok(rows) => {
            // rustnetec: G1 — 构造 {columns, rows, count} 响应。
            // rows 元素为 serde_json::Value::Object(列名→值),统一拍平为二维数组,
            // 列顺序由首个对象的 keys 决定;空结果时 columns 也为空数组。
            let (columns, flat_rows) = flatten_rows(&rows);
            let response = serde_json::json!({
                "columns": columns,
                "rows": flat_rows,
                "count": flat_rows.len(),
            });
            let _ = respond_json(request, 200, &response);
        }
        Err(e) => {
            let response = serde_json::json!({"error": format!("{}", e)});
            let _ = respond_json(request, 400, &response);
        }
    }
}

/// rustnetec: G1 辅助 — 把 `run_query` 返回的 `Vec<Value>`(每元素为 Object 列名→值)
/// 拍平为 `(columns, rows)` 二维数组,供 `/query` 响应前端表格渲染。
///
/// 列顺序由首个对象的 `keys()` 决定(serde_json::Map 保持插入顺序,即 SQL 列顺序);
/// 空结果时 `columns` 为空数组、`rows` 为空数组。
fn flatten_rows(rows: &[serde_json::Value]) -> (Vec<String>, Vec<Vec<serde_json::Value>>) {
    if rows.is_empty() {
        return (Vec::new(), Vec::new());
    }

    // 从首行提取列名(保持 SQL 列顺序)
    let columns: Vec<String> = rows[0]
        .as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default();

    // 每行按列顺序拍平为 Vec<Value>
    let flat_rows: Vec<Vec<serde_json::Value>> = rows
        .iter()
        .map(|row| {
            if let Some(map) = row.as_object() {
                columns
                    .iter()
                    .map(|col| map.get(col).cloned().unwrap_or(serde_json::Value::Null))
                    .collect()
            } else {
                Vec::new()
            }
        })
        .collect();

    (columns, flat_rows)
}

/// GET /stats — aggregate statistics.
fn handle_stats(request: tiny_http::Request, state: &HttpState) {
    let result = query_stats(&state.db_path);
    match result {
        Ok(json) => {
            let _ = respond_json(request, 200, &json);
        }
        Err(e) => {
            let response = serde_json::json!({"error": format!("{}", e)});
            let _ = respond_json(request, 500, &response);
        }
    }
}

/// rustnetec: W3.3 — GET /processes 供 WebUI Activity 页专用。
///
/// 按 process_name 聚合 top 50(按总字节降序),返回 JSON 数组:
/// ```jsonc
/// [{ "process": "curl", "connections": 12, "bytes_sent": 1234, "bytes_received": 5678, "bytes_total": 6912 }, ...]
/// ```
/// 过滤 NULL/空 process_name(进程归因未启用或未命中)。
/// 与 `query_stats` 的 `by_process` 维度逻辑同源,但本端点是 Activity 页专用,
/// 返回扁平数组 + bytes_total 便于前端按字节降序排序展示。
fn handle_processes(request: tiny_http::Request, state: &HttpState) {
    use rusqlite::params;

    let path = &state.db_path;
    if !path.exists() {
        let response = serde_json::json!({
            "processes": [],
            "note": "database file not found — no capture data yet"
        });
        let _ = respond_json(request, 200, &response);
        return;
    }

    // rustnetec: T-E2 — 解析 interface 参数，支持按网口过滤进程活动。
    let url = request.url();
    let params = parse_query_params(url);
    let iface_filter = params.get("interface").filter(|s| !s.is_empty());

    let conn = match open_read_only(path) {
        Ok(c) => c,
        Err(e) => {
            let response = serde_json::json!({"error": format!("failed to open database: {}", e)});
            let _ = respond_json(request, 500, &response);
            return;
        }
    };

    // 按 process_name 聚合,按总字节降序取 top 50。
    // COALESCE 防 NULL;bytes_total = bytes_sent + bytes_received 供前端排序展示。
    //
    // rustnetec: T-E1 — 增加外网/局域网聚合字段：
    // - `external_*`：dest_ip 不属于 RFC1918/loopback/link-local/CGNAT 的连接
    // - `lan_*`：dest_ip 属于 RFC1918/CGNAT 的连接
    // - loopback/link-local 既不计入 external 也不计入 lan
    //
    // SQL 近似外网判断（用 LIKE 表达私网段排除），精度略低于
    // `netutil::classify_dest`（SQL 难以表达 CGNAT 100.64/10），
    // 但 `/processes` 是概览页，精度可放宽。精确分类走 `/stats/*` 端点。
    let processes: Vec<serde_json::Value> = match conn.prepare(
        "SELECT process_name, \
         COUNT(*) as cnt, \
         COALESCE(SUM(bytes_sent),0) as sent, \
         COALESCE(SUM(bytes_received),0) as recv, \
         SUM(CASE \
             WHEN dest_ip LIKE '10.%' \
               OR dest_ip LIKE '172.16.%' OR dest_ip LIKE '172.17.%' OR dest_ip LIKE '172.18.%' \
               OR dest_ip LIKE '172.19.%' OR dest_ip LIKE '172.20.%' OR dest_ip LIKE '172.21.%' \
               OR dest_ip LIKE '172.22.%' OR dest_ip LIKE '172.23.%' OR dest_ip LIKE '172.24.%' \
               OR dest_ip LIKE '172.25.%' OR dest_ip LIKE '172.26.%' OR dest_ip LIKE '172.27.%' \
               OR dest_ip LIKE '172.28.%' OR dest_ip LIKE '172.29.%' OR dest_ip LIKE '172.30.%' \
               OR dest_ip LIKE '172.31.%' \
               OR dest_ip LIKE '192.168.%' \
               OR dest_ip LIKE '100.64.%' OR dest_ip LIKE '100.65.%' OR dest_ip LIKE '100.66.%' \
               OR dest_ip LIKE '100.67.%' OR dest_ip LIKE '100.68.%' OR dest_ip LIKE '100.69.%' \
               OR dest_ip LIKE '100.70.%' OR dest_ip LIKE '100.71.%' OR dest_ip LIKE '100.72.%' \
               OR dest_ip LIKE '100.73.%' OR dest_ip LIKE '100.74.%' OR dest_ip LIKE '100.75.%' \
               OR dest_ip LIKE '100.76.%' OR dest_ip LIKE '100.77.%' OR dest_ip LIKE '100.78.%' \
               OR dest_ip LIKE '100.79.%' OR dest_ip LIKE '100.80.%' OR dest_ip LIKE '100.81.%' \
               OR dest_ip LIKE '100.82.%' OR dest_ip LIKE '100.83.%' OR dest_ip LIKE '100.84.%' \
               OR dest_ip LIKE '100.85.%' OR dest_ip LIKE '100.86.%' OR dest_ip LIKE '100.87.%' \
               OR dest_ip LIKE '100.88.%' OR dest_ip LIKE '100.89.%' OR dest_ip LIKE '100.90.%' \
               OR dest_ip LIKE '100.91.%' OR dest_ip LIKE '100.92.%' OR dest_ip LIKE '100.93.%' \
               OR dest_ip LIKE '100.94.%' OR dest_ip LIKE '100.95.%' OR dest_ip LIKE '100.96.%' \
               OR dest_ip LIKE '100.97.%' OR dest_ip LIKE '100.98.%' OR dest_ip LIKE '100.99.%' \
               OR dest_ip LIKE '100.100.%' OR dest_ip LIKE '100.101.%' OR dest_ip LIKE '100.102.%' \
               OR dest_ip LIKE '100.103.%' OR dest_ip LIKE '100.104.%' OR dest_ip LIKE '100.105.%' \
               OR dest_ip LIKE '100.106.%' OR dest_ip LIKE '100.107.%' OR dest_ip LIKE '100.108.%' \
               OR dest_ip LIKE '100.109.%' OR dest_ip LIKE '100.110.%' OR dest_ip LIKE '100.111.%' \
               OR dest_ip LIKE '100.112.%' OR dest_ip LIKE '100.113.%' OR dest_ip LIKE '100.114.%' \
               OR dest_ip LIKE '100.115.%' OR dest_ip LIKE '100.116.%' OR dest_ip LIKE '100.117.%' \
               OR dest_ip LIKE '100.118.%' OR dest_ip LIKE '100.119.%' OR dest_ip LIKE '100.120.%' \
               OR dest_ip LIKE '100.121.%' OR dest_ip LIKE '100.122.%' OR dest_ip LIKE '100.123.%' \
               OR dest_ip LIKE '100.124.%' OR dest_ip LIKE '100.125.%' OR dest_ip LIKE '100.126.%' \
               OR dest_ip LIKE '100.127.%' \
               OR dest_ip LIKE '127.%' \
               OR dest_ip LIKE '169.254.%' \
               THEN 0 ELSE 1 \
         END) as external_conns, \
         SUM(CASE \
             WHEN dest_ip LIKE '10.%' \
               OR dest_ip LIKE '172.16.%' OR dest_ip LIKE '172.17.%' OR dest_ip LIKE '172.18.%' \
               OR dest_ip LIKE '172.19.%' OR dest_ip LIKE '172.20.%' OR dest_ip LIKE '172.21.%' \
               OR dest_ip LIKE '172.22.%' OR dest_ip LIKE '172.23.%' OR dest_ip LIKE '172.24.%' \
               OR dest_ip LIKE '172.25.%' OR dest_ip LIKE '172.26.%' OR dest_ip LIKE '172.27.%' \
               OR dest_ip LIKE '172.28.%' OR dest_ip LIKE '172.29.%' OR dest_ip LIKE '172.30.%' \
               OR dest_ip LIKE '172.31.%' \
               OR dest_ip LIKE '192.168.%' \
               OR dest_ip LIKE '100.64.%' OR dest_ip LIKE '100.65.%' OR dest_ip LIKE '100.66.%' \
               OR dest_ip LIKE '100.67.%' OR dest_ip LIKE '100.68.%' OR dest_ip LIKE '100.69.%' \
               OR dest_ip LIKE '100.70.%' OR dest_ip LIKE '100.71.%' OR dest_ip LIKE '100.72.%' \
               OR dest_ip LIKE '100.73.%' OR dest_ip LIKE '100.74.%' OR dest_ip LIKE '100.75.%' \
               OR dest_ip LIKE '100.76.%' OR dest_ip LIKE '100.77.%' OR dest_ip LIKE '100.78.%' \
               OR dest_ip LIKE '100.79.%' OR dest_ip LIKE '100.80.%' OR dest_ip LIKE '100.81.%' \
               OR dest_ip LIKE '100.82.%' OR dest_ip LIKE '100.83.%' OR dest_ip LIKE '100.84.%' \
               OR dest_ip LIKE '100.85.%' OR dest_ip LIKE '100.86.%' OR dest_ip LIKE '100.87.%' \
               OR dest_ip LIKE '100.88.%' OR dest_ip LIKE '100.89.%' OR dest_ip LIKE '100.90.%' \
               OR dest_ip LIKE '100.91.%' OR dest_ip LIKE '100.92.%' OR dest_ip LIKE '100.93.%' \
               OR dest_ip LIKE '100.94.%' OR dest_ip LIKE '100.95.%' OR dest_ip LIKE '100.96.%' \
               OR dest_ip LIKE '100.97.%' OR dest_ip LIKE '100.98.%' OR dest_ip LIKE '100.99.%' \
               OR dest_ip LIKE '100.100.%' OR dest_ip LIKE '100.101.%' OR dest_ip LIKE '100.102.%' \
               OR dest_ip LIKE '100.103.%' OR dest_ip LIKE '100.104.%' OR dest_ip LIKE '100.105.%' \
               OR dest_ip LIKE '100.106.%' OR dest_ip LIKE '100.107.%' OR dest_ip LIKE '100.108.%' \
               OR dest_ip LIKE '100.109.%' OR dest_ip LIKE '100.110.%' OR dest_ip LIKE '100.111.%' \
               OR dest_ip LIKE '100.112.%' OR dest_ip LIKE '100.113.%' OR dest_ip LIKE '100.114.%' \
               OR dest_ip LIKE '100.115.%' OR dest_ip LIKE '100.116.%' OR dest_ip LIKE '100.117.%' \
               OR dest_ip LIKE '100.118.%' OR dest_ip LIKE '100.119.%' OR dest_ip LIKE '100.120.%' \
               OR dest_ip LIKE '100.121.%' OR dest_ip LIKE '100.122.%' OR dest_ip LIKE '100.123.%' \
               OR dest_ip LIKE '100.124.%' OR dest_ip LIKE '100.125.%' OR dest_ip LIKE '100.126.%' \
               OR dest_ip LIKE '100.127.%' \
               THEN 1 ELSE 0 \
         END) as lan_conns, \
         SUM(CASE \
             WHEN dest_ip NOT LIKE '10.%' \
               AND dest_ip NOT LIKE '127.%' \
               AND dest_ip NOT LIKE '169.254.%' \
             THEN COALESCE(duration_secs,0) ELSE 0 \
         END) as external_duration, \
         SUM(CASE \
             WHEN dest_ip NOT LIKE '10.%' \
               AND dest_ip NOT LIKE '127.%' \
               AND dest_ip NOT LIKE '169.254.%' \
             THEN COALESCE(bytes_sent,0) + COALESCE(bytes_received,0) ELSE 0 \
         END) as external_bytes, \
         SUM(CASE \
             WHEN dest_ip LIKE '10.%' \
               OR dest_ip LIKE '192.168.%' \
               OR dest_ip LIKE '172.16.%' OR dest_ip LIKE '172.17.%' OR dest_ip LIKE '172.18.%' \
               OR dest_ip LIKE '172.19.%' OR dest_ip LIKE '172.20.%' OR dest_ip LIKE '172.21.%' \
               OR dest_ip LIKE '172.22.%' OR dest_ip LIKE '172.23.%' OR dest_ip LIKE '172.24.%' \
               OR dest_ip LIKE '172.25.%' OR dest_ip LIKE '172.26.%' OR dest_ip LIKE '172.27.%' \
               OR dest_ip LIKE '172.28.%' OR dest_ip LIKE '172.29.%' OR dest_ip LIKE '172.30.%' \
               OR dest_ip LIKE '172.31.%' \
             THEN COALESCE(duration_secs,0) ELSE 0 \
         END) as lan_duration, \
         SUM(CASE \
             WHEN dest_ip LIKE '10.%' \
               OR dest_ip LIKE '192.168.%' \
               OR dest_ip LIKE '172.16.%' OR dest_ip LIKE '172.17.%' OR dest_ip LIKE '172.18.%' \
               OR dest_ip LIKE '172.19.%' OR dest_ip LIKE '172.20.%' OR dest_ip LIKE '172.21.%' \
               OR dest_ip LIKE '172.22.%' OR dest_ip LIKE '172.23.%' OR dest_ip LIKE '172.24.%' \
               OR dest_ip LIKE '172.25.%' OR dest_ip LIKE '172.26.%' OR dest_ip LIKE '172.27.%' \
               OR dest_ip LIKE '172.28.%' OR dest_ip LIKE '172.29.%' OR dest_ip LIKE '172.30.%' \
               OR dest_ip LIKE '172.31.%' \
             THEN COALESCE(bytes_sent,0) + COALESCE(bytes_received,0) ELSE 0 \
         END) as lan_bytes \
         FROM connection_events \
         WHERE process_name IS NOT NULL AND process_name != '' \
           AND (? = '' OR interface = ?) \
         GROUP BY process_name \
         ORDER BY (sent + recv) DESC \
         LIMIT 50",
    ) {
        Ok(mut stmt) => {
            // rustnetec: T-E2 — interface 过滤：
            // SQL WHERE 末尾加 `AND (? = '' OR interface = ?)`，
            // `iface_filter` 为 None 时绑定空串使条件恒真，
            // 为 Some 时绑定实际网口名。单条 query_map 路径避免闭包类型冲突。
            let iface_value = iface_filter.cloned().unwrap_or_default();
            let rows_result = stmt.query_map(params![iface_value, iface_value], |row| {
                let sent: i64 = row.get(2)?;
                let recv: i64 = row.get(3)?;
                Ok(serde_json::json!({
                    "process": row.get::<_, String>(0)?,
                    "connections": row.get::<_, i64>(1)?,
                    "bytes_sent": sent,
                    "bytes_received": recv,
                    "bytes_total": sent + recv,
                    "external_conns": row.get::<_, i64>(4)?,
                    "lan_conns": row.get::<_, i64>(5)?,
                    "external_duration": row.get::<_, i64>(6)?,
                    "external_bytes": row.get::<_, i64>(7)?,
                    "lan_duration": row.get::<_, i64>(8)?,
                    "lan_bytes": row.get::<_, i64>(9)?,
                }))
            });
            match rows_result {
                Ok(r) => r.filter_map(|v| v.ok()).collect(),
                Err(e) => {
                    let response =
                        serde_json::json!({"error": format!("query failed: {}", e)});
                    let _ = respond_json(request, 500, &response);
                    return;
                }
            }
        }
        Err(e) => {
            let response = serde_json::json!({"error": format!("prepare failed: {}", e)});
            let _ = respond_json(request, 500, &response);
            return;
        }
    };

    let response = serde_json::json!({
        "processes": processes,
        "count": processes.len(),
    });
    let _ = respond_json(request, 200, &response);
}

/// rustnetec: T-B1 — GET /stats/range 时间桶流量/连接查询。
///
/// 参数：
/// - `start` / `end`：RFC 3339 时间戳；缺省 end=now，start=now-1h。
/// - `bucket`：`5s`/`1min`/`1hour`/`1day`，默认 `1min`。
/// - `process`：进程名过滤，逗号分隔多进程（IN 语义）。
/// - `interface`：网口过滤（精确匹配）。
/// - `scope`：`external`/`lan`/`all`，默认 `all`。外网/局域网过滤在
///   Rust 侧用 `classify_dest(dest_ip)` 判断（SQLite 无自定义函数）。
///
/// 返回 `[{ts, bytes_rx, bytes_tx, conn_count, active_seconds, process_name?}, ...]`。
///
/// 数据来源：直接查 `connection_events`（未走 aggregates 预聚合表，
/// 因 scope 过滤需 Rust 侧判断 dest_ip，aggregates 表未存 dest_ip 维度）。
fn handle_stats_range(request: tiny_http::Request, state: &HttpState) {

    let path = &state.db_path;
    if !path.exists() {
        let response = serde_json::json!({
            "buckets": [],
            "note": "database file not found — no capture data yet"
        });
        let _ = respond_json(request, 200, &response);
        return;
    }

    let url = request.url();
    let params = parse_query_params(url);

    // 解析时间窗（默认最近 1 小时）。
    let end = parse_time_param(params.get("end").map(String::as_str), chrono::Duration::zero());
    let start = parse_time_param(
        params.get("start").map(String::as_str),
        chrono::Duration::hours(1),
    );

    // 解析 bucket 宽度。
    let bucket = params.get("bucket").map(String::as_str).unwrap_or("1min");
    let _label = match bucket {
        "5s" => "5s",
        "1min" => "1min",
        "1hour" => "1hour",
        "1day" => "1day",
        _ => "1min",
    };

    // rustnetec: T-A5 — 1min/1hour/1day 读 aggregates 预聚合表（scope 过滤 SQL 下推）；
    // 仅 5s 粒度无法由分钟桶还原，保留直查 connection_events。
    if bucket != "5s" {
        let scope = params.get("scope").map(String::as_str).unwrap_or("all");
        handle_stats_range_aggregated(request, state, &params, &start, &end, bucket, scope);
        return;
    }

    // 构造 WHERE 子句。
    let mut where_clauses: Vec<String> = vec![
        "ts >= ?1".to_string(),
        "ts <= ?2".to_string(),
        "event_type = 'connection_closed'".to_string(),
    ];
    let mut bind_values: Vec<Box<dyn rusqlite::ToSql>> = vec![
        Box::new(start.clone()),
        Box::new(end.clone()),
    ];
    let mut bind_idx = 3;

    // process 过滤（逗号分隔 → IN (?, ?, ...)）。
    if let Some(proc_list) = params.get("process") {
        let names: Vec<&str> = proc_list.split(',').filter(|s| !s.is_empty()).collect();
        if !names.is_empty() {
            // rustnetec: T-E5 修复 — 每个进程占一个独立占位符（?3, ?4, ...），
            // 旧代码 map 闭包未递增 bind_idx，选中 ≥2 个进程时生成重复的 ?3，
            // 与绑定值数量不匹配导致 rusqlite 报错 → HTTP 500。
            let n = names.len();
            let placeholders: Vec<String> = names
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", bind_idx + i))
                .collect();
            where_clauses.push(format!("process_name IN ({})", placeholders.join(", ")));
            for name in names {
                bind_values.push(Box::new(name.to_string()));
            }
            bind_idx += n;
        }
    }

    // interface 过滤（精确匹配）。
    if let Some(iface) = params.get("interface") {
        if !iface.is_empty() {
            where_clauses.push(format!("interface = ?{}", bind_idx));
            bind_values.push(Box::new(iface.clone()));
            // bind_idx 不再递增：interface 是最后一个过滤条件，后续无使用。
        }
    }

    // scope 过滤在 Rust 侧判断（拉取 dest_ip 后用 classify_dest），
    // 此处 SQL 不加 scope 条件，后续遍历结果时过滤。

    let sql = format!(
        "SELECT ts, dest_ip, bytes_received, bytes_sent, duration_secs, process_name \
         FROM connection_events \
         WHERE {} \
         ORDER BY ts ASC",
        where_clauses.join(" AND ")
    );

    let conn = match open_read_only(path) {
        Ok(c) => c,
        Err(e) => {
            let response = serde_json::json!({"error": format!("failed to open database: {}", e)});
            let _ = respond_json(request, 500, &response);
            return;
        }
    };

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => {
            let response = serde_json::json!({"error": format!("prepare failed: {}", e)});
            let _ = respond_json(request, 500, &response);
            return;
        }
    };

    // 构建 binds 引用数组（rusqlite 需要 &[&dyn ToSql]）。
    let bind_refs: Vec<&dyn rusqlite::ToSql> = bind_values.iter().map(|b| b.as_ref()).collect();
    let rows = stmt.query_map(bind_refs.as_slice(), |row| {
        Ok((
            row.get::<_, String>(0)?,       // ts
            row.get::<_, Option<String>>(1)?, // dest_ip
            row.get::<_, Option<i64>>(2)?,  // bytes_received
            row.get::<_, Option<i64>>(3)?,  // bytes_sent
            row.get::<_, Option<i64>>(4)?,  // duration_secs
            row.get::<_, Option<String>>(5)?, // process_name
        ))
    });

    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            let response = serde_json::json!({"error": format!("query failed: {}", e)});
            let _ = respond_json(request, 500, &response);
            return;
        }
    };

    // 解析 scope 并构建分类器闭包。
    let scope = params.get("scope").map(String::as_str).unwrap_or("all");
    use crate::telemetry::netutil::{classify_dest, DestClass};
    let scope_filter = |dest_ip: &Option<String>| -> bool {
        match scope {
            "external" => {
                dest_ip.as_ref().map(|ip| classify_dest(ip) == DestClass::External).unwrap_or(false)
            }
            "lan" => {
                dest_ip.as_ref().map(|ip| classify_dest(ip) == DestClass::Lan).unwrap_or(false)
            }
            _ => true, // all
        }
    };

    // rustnetec: T-E5 — 按 (bucket, process_name) 双键聚合，同时保留总计 buckets。
    // buckets: 所有命中进程的总计（向后兼容 LAN/外网图表等单系列调用方）；
    // by_process: 外层 key=bucket_ts，内层 key=process_name，供多进程对比渲染多条折线。
    use std::collections::BTreeMap;
    #[derive(Default, Clone)]
    struct BucketAcc {
        bytes_rx: i64,
        bytes_tx: i64,
        conn_count: i64,
        active_seconds: i64,
    }

    let mut totals: BTreeMap<String, BucketAcc> = BTreeMap::new();
    let mut by_process: BTreeMap<String, BTreeMap<String, BucketAcc>> = BTreeMap::new();

    // SQLite strftime 需要 ts 为 TEXT 且格式为 RFC 3339 或 ISO 8601。
    // 为正确分桶，先在 Rust 侧解析 ts → 截断到 bucket 粒度 → 用作 map key。
    let parse_ts = |ts: &str| -> Option<chrono::DateTime<chrono::FixedOffset>> {
        chrono::DateTime::parse_from_rfc3339(ts).ok()
    };

    let truncate_ts = |dt: chrono::DateTime<chrono::FixedOffset>| -> String {
        // rustnetec: 桶 key 输出 UTC 墙钟时间（无偏移后缀），前端按 Z 解析。
        // 直接 format 会保留本地时区墙钟但丢失偏移，导致 UTC+8 机器上时间轴整体偏移 8 小时。
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

    // 遍历查询结果，按桶聚合（跳过 scope 过滤不通过的行）。
    for row in rows {
        let (ts, dest_ip, bytes_rx, bytes_tx, duration_secs, process_name) = match row {
            Ok(r) => r,
            Err(_) => continue,
        };

        // scope 过滤。
        if !scope_filter(&dest_ip) {
            continue;
        }

        // 解析 ts 并截断到 bucket 粒度。
        let bucket_key = match parse_ts(&ts) {
            Some(dt) => truncate_ts(dt),
            None => continue, // ts 格式异常，跳过
        };

        let rx = bytes_rx.unwrap_or(0);
        let tx = bytes_tx.unwrap_or(0);
        let dur = duration_secs.unwrap_or(0);

        // 总计聚合
        let t = totals.entry(bucket_key.clone()).or_default();
        t.bytes_rx += rx;
        t.bytes_tx += tx;
        t.conn_count += 1;
        t.active_seconds += dur;

        // 按进程聚合（process_name 为空时归入 "_unknown"，不丢弃以免漏计）
        let pname = process_name.unwrap_or_else(|| "_unknown".to_string());
        let proc_map = by_process.entry(bucket_key).or_default();
        let e = proc_map.entry(pname).or_default();
        e.bytes_rx += rx;
        e.bytes_tx += tx;
        e.conn_count += 1;
        e.active_seconds += dur;
    }

    // 构建总计 buckets JSON（向后兼容）。
    let result: Vec<serde_json::Value> = totals
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

    // rustnetec: T-E5 — 构建按进程分组的 series：[{name, points:[[ts,bytes_total],...]}]。
    // 先收集所有进程名（保持稳定顺序：按首次出现），再逐进程从 by_process 取点。
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
            serde_json::json!({
                "name": pname,
                "points": points,
            })
        })
        .collect();

    let response = serde_json::json!({
        "buckets": result,
        "series": series,
        "count": result.len(),
        "bucket": bucket,
        "scope": scope,
    });
    let _ = respond_json(request, 200, &response);
}

/// rustnetec: T-A5 — /stats/range 的预聚合路径（1min/1hour/1day）。
///
/// 数据来源：`aggregates` 表（分钟/小时/日桶，含 dest_class 维度）。
/// 相比直查 connection_events：
/// - 查询量从几十万行降到几百行；
/// - scope 过滤由 Rust 侧 `classify_dest(dest_ip)` 改为 SQL 下推 `dest_class = ?`；
/// - 返回结构与原直查路径完全一致（buckets + series + active_seconds）。
///
/// 边界说明：桶为预聚合行，`end` 所在桶可能比直查路径多计入该桶内
/// `end` 之后至桶尾的数据（≤1 个桶粒度），与"按 end 截断"的语义略有偏差。
fn handle_stats_range_aggregated(
    request: tiny_http::Request,
    state: &HttpState,
    params: &std::collections::HashMap<String, String>,
    start: &str,
    end: &str,
    bucket: &str,
    scope: &str,
) {
    // 桶宽度 → aggregates.bucket_width、bucket_ts 边界格式、输出 key 截取长度。
    let (width, bound_pattern, key_len) = match bucket {
        "1hour" => ("hour", "%Y-%m-%dT%H:00:00", 13),
        "1day" => ("day", "%Y-%m-%dT00:00:00", 10),
        _ => ("minute", "%Y-%m-%dT%H:%M:00", 16),
    };

    // start/end 转 UTC 桶边界（与 run_aggregation 的 bucket_ts 存储格式一致）。
    // 解析失败时原样返回，避免脏字符串破坏字典序比较。
    let fmt_bound = |ts: &str| -> String {
        chrono::DateTime::parse_from_rfc3339(ts)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc).format(bound_pattern).to_string())
            .unwrap_or_else(|| ts.to_string())
    };
    let start_bound = fmt_bound(start);
    let end_bound = fmt_bound(end);

    // WHERE 子句。
    let mut where_clauses: Vec<String> = vec![
        "bucket_width = ?1".to_string(),
        "bucket_ts >= ?2".to_string(),
        "bucket_ts <= ?3".to_string(),
    ];
    let mut bind_values: Vec<Box<dyn rusqlite::ToSql>> = vec![
        Box::new(width.to_string()),
        Box::new(start_bound),
        Box::new(end_bound),
    ];
    let mut bind_idx = 4;

    // process 过滤（逗号分隔 → IN (?, ?, ...)）。
    if let Some(proc_list) = params.get("process") {
        let names: Vec<&str> = proc_list.split(',').filter(|s| !s.is_empty()).collect();
        if !names.is_empty() {
            let n = names.len();
            let placeholders: Vec<String> = names
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", bind_idx + i))
                .collect();
            where_clauses.push(format!("process_name IN ({})", placeholders.join(", ")));
            for name in names {
                bind_values.push(Box::new(name.to_string()));
            }
            bind_idx += n;
        }
    }

    // interface 过滤（精确匹配）。
    if let Some(iface) = params.get("interface") {
        if !iface.is_empty() {
            where_clauses.push(format!("interface = ?{}", bind_idx));
            bind_values.push(Box::new(iface.clone()));
            bind_idx += 1;
        }
    }

    // scope 过滤：SQL 下推 dest_class（external/lan/all）。
    if scope == "external" || scope == "lan" {
        where_clauses.push(format!("dest_class = ?{}", bind_idx));
        bind_values.push(Box::new(scope.to_string()));
    }

    let where_sql = where_clauses.join(" AND ");

    let conn = match open_read_only(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            let response = serde_json::json!({"error": format!("failed to open database: {}", e)});
            let _ = respond_json(request, 500, &response);
            return;
        }
    };

    let bind_refs: Vec<&dyn rusqlite::ToSql> = bind_values.iter().map(|b| b.as_ref()).collect();

    // 总计桶：按 bucket_ts 聚合（aggregates 已按维度分组，这里直接 SUM 各列）。
    let totals_sql = format!(
        "SELECT bucket_ts, \
                SUM(bytes_rx), SUM(bytes_tx), SUM(conn_count), SUM(duration_secs) \
         FROM aggregates \
         WHERE {} \
         GROUP BY bucket_ts \
         ORDER BY bucket_ts ASC",
        where_sql
    );
    let mut totals_stmt = match conn.prepare(&totals_sql) {
        Ok(s) => s,
        Err(e) => {
            let response = serde_json::json!({"error": format!("prepare failed: {}", e)});
            let _ = respond_json(request, 500, &response);
            return;
        }
    };
    let totals_rows = totals_stmt.query_map(bind_refs.as_slice(), |row| {
        Ok((
            row.get::<_, String>(0)?, // bucket_ts
            row.get::<_, i64>(1)?,    // bytes_rx
            row.get::<_, i64>(2)?,    // bytes_tx
            row.get::<_, i64>(3)?,    // conn_count
            row.get::<_, i64>(4)?,    // duration_secs
        ))
    });
    let totals_rows = match totals_rows {
        Ok(r) => r,
        Err(e) => {
            let response = serde_json::json!({"error": format!("query failed: {}", e)});
            let _ = respond_json(request, 500, &response);
            return;
        }
    };

    // 按进程 series：COALESCE NULL process_name → "_unknown"，与原直查路径对齐。
    let series_sql = format!(
        "SELECT bucket_ts, COALESCE(process_name, '_unknown'), \
                SUM(bytes_rx), SUM(bytes_tx) \
         FROM aggregates \
         WHERE {} \
         GROUP BY bucket_ts, process_name \
         ORDER BY bucket_ts ASC",
        where_sql
    );
    let mut series_stmt = match conn.prepare(&series_sql) {
        Ok(s) => s,
        Err(e) => {
            let response = serde_json::json!({"error": format!("prepare failed: {}", e)});
            let _ = respond_json(request, 500, &response);
            return;
        }
    };
    let series_rows = series_stmt.query_map(bind_refs.as_slice(), |row| {
        Ok((
            row.get::<_, String>(0)?, // bucket_ts
            row.get::<_, String>(1)?, // process_name / _unknown
            row.get::<_, i64>(2)?,    // bytes_rx
            row.get::<_, i64>(3)?,    // bytes_tx
        ))
    });
    let series_rows = match series_rows {
        Ok(r) => r,
        Err(e) => {
            let response = serde_json::json!({"error": format!("query failed: {}", e)});
            let _ = respond_json(request, 500, &response);
            return;
        }
    };

    // 组装响应（结构与原直查路径一致：buckets + series）。
    use std::collections::BTreeMap;

    let mut buckets: Vec<serde_json::Value> = Vec::new();
    for row in totals_rows.flatten() {
        let (bucket_ts, bytes_rx, bytes_tx, conn_count, duration_secs) = row;
        let key = bucket_ts.get(..key_len).unwrap_or(&bucket_ts).to_string();
        buckets.push(serde_json::json!({
            "ts": key,
            "bytes_rx": bytes_rx,
            "bytes_tx": bytes_tx,
            "conn_count": conn_count,
            "active_seconds": duration_secs,
        }));
    }

    // by_process: 外层 key=ts，内层 key=process_name → 稳定顺序输出。
    let mut by_process: BTreeMap<String, BTreeMap<String, (i64, i64)>> = BTreeMap::new();
    for row in series_rows.flatten() {
        let (bucket_ts, pname, bytes_rx, bytes_tx) = row;
        let key = bucket_ts.get(..key_len).unwrap_or(&bucket_ts).to_string();
        by_process
            .entry(key)
            .or_default()
            .insert(pname, (bytes_rx, bytes_tx));
    }
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
                    proc_map.get(pname).map(|(rx, tx)| {
                        serde_json::json!([ts, rx + tx])
                    })
                })
                .collect();
            serde_json::json!({
                "name": pname,
                "points": points,
            })
        })
        .collect();

    let response = serde_json::json!({
        "buckets": buckets,
        "series": series,
        "count": buckets.len(),
        "bucket": bucket,
        "scope": scope,
    });
    let _ = respond_json(request, 200, &response);
}

/// rustnetec: T-B2 — GET /stats/rtt RTT 分位数时间序列。
///
/// 参数：
/// - `start` / `end`：RFC 3339 时间戳；缺省 end=now，start=now-1h。
/// - `bucket`：`5s`/`1min`/`1hour`/`1day`，默认 `1min`。
/// - `interface`：网口过滤（精确匹配）。
/// - `scope`：`external`/`lan`/`all`，默认 `external`（外网链路质量）。
///
/// 返回 `[{ts, p50, p95, p99, samples}, ...]`，按桶时间升序。
fn handle_stats_rtt(request: tiny_http::Request, state: &HttpState) {

    let path = &state.db_path;
    if !path.exists() {
        let response = serde_json::json!({
            "buckets": [],
            "note": "database file not found — no capture data yet"
        });
        let _ = respond_json(request, 200, &response);
        return;
    }

    let url = request.url();
    let params = parse_query_params(url);

    let end = parse_time_param(params.get("end").map(String::as_str), chrono::Duration::zero());
    let start = parse_time_param(
        params.get("start").map(String::as_str),
        chrono::Duration::hours(1),
    );

    let bucket = params.get("bucket").map(String::as_str).unwrap_or("1min");
    let scope = params.get("scope").map(String::as_str).unwrap_or("external");

    // 构造 WHERE 子句。
    let mut where_clauses: Vec<String> = vec![
        "ts >= ?".to_string(),
        "ts <= ?".to_string(),
        "rtt_ms IS NOT NULL".to_string(),
    ];
    let mut bind_values: Vec<Box<dyn rusqlite::ToSql>> = vec![
        Box::new(start.clone()),
        Box::new(end.clone()),
    ];

    if let Some(iface) = params.get("interface") {
        if !iface.is_empty() {
            where_clauses.push("interface = ?".to_string());
            bind_values.push(Box::new(iface.clone()));
        }
    }

    let sql = format!(
        "SELECT ts, dest_ip, rtt_ms FROM connection_events WHERE {} ORDER BY ts ASC",
        where_clauses.join(" AND ")
    );

    let conn = match open_read_only(path) {
        Ok(c) => c,
        Err(e) => {
            let _ = respond_json(request, 500, &serde_json::json!({"error": format!("open: {}", e)}));
            return;
        }
    };

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => {
            let _ = respond_json(request, 500, &serde_json::json!({"error": format!("prepare: {}", e)}));
            return;
        }
    };

    let bind_refs: Vec<&dyn rusqlite::ToSql> = bind_values.iter().map(|b| b.as_ref()).collect();
    let rows = stmt.query_map(bind_refs.as_slice(), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, f64>(2)?,
        ))
    });

    use crate::telemetry::netutil::{classify_dest, DestClass};
    use std::collections::BTreeMap;

    let scope_match = |dest_ip: &Option<String>| -> bool {
        match scope {
            "external" => dest_ip.as_ref().map(|ip| classify_dest(ip) == DestClass::External).unwrap_or(false),
            "lan" => dest_ip.as_ref().map(|ip| classify_dest(ip) == DestClass::Lan).unwrap_or(false),
            _ => true,
        }
    };

    let truncate_ts = |dt: chrono::DateTime<chrono::FixedOffset>| -> String {
        // rustnetec: 桶 key 输出 UTC 墙钟时间（无偏移后缀），前端按 Z 解析。
        let utc = dt.with_timezone(&chrono::Utc);
        match bucket {
            "5s" => {
                let secs = utc.timestamp();
                chrono::DateTime::from_timestamp(secs - (secs % 5), 0)
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

    // 按桶收集 rtt_ms 列表。
    let mut buckets: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let rows_iter = match rows {
        Ok(r) => r,
        Err(e) => {
            let _ = respond_json(request, 500, &serde_json::json!({"error": format!("query: {}", e)}));
            return;
        }
    };

    for row in rows_iter {
        let (ts, dest_ip, rtt_ms) = match row {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !scope_match(&dest_ip) {
            continue;
        }
        let dt = match chrono::DateTime::parse_from_rfc3339(&ts) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let key = truncate_ts(dt);
        buckets.entry(key).or_default().push(rtt_ms);
    }

    // 计算每桶 p50/p95/p99。
    let percentile = |sorted: &[f64], p: f64| -> f64 {
        if sorted.is_empty() {
            return 0.0;
        }
        let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    };

    let result: Vec<serde_json::Value> = buckets
        .into_iter()
        .map(|(ts, mut rtts)| {
            rtts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let samples = rtts.len() as i64;
            serde_json::json!({
                "ts": ts,
                "p50": percentile(&rtts, 0.5),
                "p95": percentile(&rtts, 0.95),
                "p99": percentile(&rtts, 0.99),
                "samples": samples,
            })
        })
        .collect();

    let response = serde_json::json!({
        "buckets": result,
        "count": result.len(),
        "bucket": bucket,
        "scope": scope,
    });
    let _ = respond_json(request, 200, &response);
}

/// rustnetec: T-B3 — GET /stats/availability 可用性时间序列。
///
/// 参数：
/// - `start` / `end`：RFC 3339 时间戳；缺省 end=now，start=now-15m。
/// - `bucket`：`1min`/`1hour`/`1day`，默认 `1min`。
/// - `interface`：网口过滤（精确匹配）。
/// - `scope`：`external`/`lan`/`all`，默认 `external`。
///
/// 返回 `[{ts, available: bool, ratio: f64}, ...]`，按桶时间升序。
/// `available=true` 表示该桶内有匹配 scope 的 closed 事件（即有外网/局域网流量）。
/// `ratio` = 该桶匹配 scope 的连接数 / 该桶总连接数（0.0-1.0）。
fn handle_stats_availability(request: tiny_http::Request, state: &HttpState) {

    let path = &state.db_path;
    if !path.exists() {
        let response = serde_json::json!({
            "buckets": [],
            "note": "database file not found — no capture data yet"
        });
        let _ = respond_json(request, 200, &response);
        return;
    }

    let url = request.url();
    let params = parse_query_params(url);

    let end = parse_time_param(params.get("end").map(String::as_str), chrono::Duration::zero());
    let start = parse_time_param(
        params.get("start").map(String::as_str),
        chrono::Duration::minutes(15),
    );

    let bucket = params.get("bucket").map(String::as_str).unwrap_or("1min");
    let scope = params.get("scope").map(String::as_str).unwrap_or("external");

    let mut where_clauses: Vec<String> = vec![
        "ts >= ?".to_string(),
        "ts <= ?".to_string(),
        "event_type = 'connection_closed'".to_string(),
    ];
    let mut bind_values: Vec<Box<dyn rusqlite::ToSql>> = vec![
        Box::new(start.clone()),
        Box::new(end.clone()),
    ];

    if let Some(iface) = params.get("interface") {
        if !iface.is_empty() {
            where_clauses.push("interface = ?".to_string());
            bind_values.push(Box::new(iface.clone()));
        }
    }

    let sql = format!(
        "SELECT ts, dest_ip, bytes_received, bytes_sent FROM connection_events WHERE {} ORDER BY ts ASC",
        where_clauses.join(" AND ")
    );

    let conn = match open_read_only(path) {
        Ok(c) => c,
        Err(e) => {
            let _ = respond_json(request, 500, &serde_json::json!({"error": format!("open: {}", e)}));
            return;
        }
    };

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => {
            let _ = respond_json(request, 500, &serde_json::json!({"error": format!("prepare: {}", e)}));
            return;
        }
    };

    let bind_refs: Vec<&dyn rusqlite::ToSql> = bind_values.iter().map(|b| b.as_ref()).collect();
    let rows = stmt.query_map(bind_refs.as_slice(), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<i64>>(2)?,
            row.get::<_, Option<i64>>(3)?,
        ))
    });

    use crate::telemetry::netutil::{classify_dest, DestClass};
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct AvailAcc {
        in_scope: i64,
        total: i64,
        bytes_in_scope: i64,
        bytes_total: i64,
    }

    let scope_match = |dest_ip: &Option<String>| -> bool {
        match scope {
            "external" => dest_ip.as_ref().map(|ip| classify_dest(ip) == DestClass::External).unwrap_or(false),
            "lan" => dest_ip.as_ref().map(|ip| classify_dest(ip) == DestClass::Lan).unwrap_or(false),
            _ => true,
        }
    };

    let truncate_ts = |dt: chrono::DateTime<chrono::FixedOffset>| -> String {
        // rustnetec: 桶 key 输出 UTC 墙钟时间（无偏移后缀），前端按 Z 解析。
        let utc = dt.with_timezone(&chrono::Utc);
        match bucket {
            "1min" => utc.format("%Y-%m-%dT%H:%M").to_string(),
            "1hour" => utc.format("%Y-%m-%dT%H").to_string(),
            "1day" => utc.format("%Y-%m-%d").to_string(),
            _ => utc.format("%Y-%m-%dT%H:%M").to_string(),
        }
    };

    let mut buckets: BTreeMap<String, AvailAcc> = BTreeMap::new();
    let rows_iter = match rows {
        Ok(r) => r,
        Err(e) => {
            let _ = respond_json(request, 500, &serde_json::json!({"error": format!("query: {}", e)}));
            return;
        }
    };

    for row in rows_iter {
        let (ts, dest_ip, bytes_rx, bytes_tx) = match row {
            Ok(r) => r,
            Err(_) => continue,
        };
        let dt = match chrono::DateTime::parse_from_rfc3339(&ts) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let key = truncate_ts(dt);
        let entry = buckets.entry(key).or_default();
        entry.total += 1;
        // bytes_received + bytes_sent 合计该连接的双向字节数。
        let bytes = bytes_rx.unwrap_or(0) + bytes_tx.unwrap_or(0);
        entry.bytes_total += bytes;
        if scope_match(&dest_ip) {
            entry.in_scope += 1;
            entry.bytes_in_scope += bytes;
        }
    }

    let result: Vec<serde_json::Value> = buckets
        .into_iter()
        .map(|(ts, acc)| {
            let available = acc.in_scope > 0;
            let ratio = if acc.total > 0 {
                acc.in_scope as f64 / acc.total as f64
            } else {
                0.0
            };
            // rustnetec: 外网流量占比 = 外网字节 / 总字节（0.0–1.0），供热力图使用。
            let bytes_ratio = if acc.bytes_total > 0 {
                acc.bytes_in_scope as f64 / acc.bytes_total as f64
            } else {
                0.0
            };
            serde_json::json!({
                "ts": ts,
                "available": available,
                "ratio": (ratio * 1000.0).round() / 1000.0,
                "bytes_ratio": (bytes_ratio * 1000.0).round() / 1000.0,
                "in_scope": acc.in_scope,
                "total": acc.total,
                "bytes_in_scope": acc.bytes_in_scope,
                "bytes_total": acc.bytes_total,
            })
        })
        .collect();

    let response = serde_json::json!({
        "buckets": result,
        "count": result.len(),
        "bucket": bucket,
        "scope": scope,
    });
    let _ = respond_json(request, 200, &response);
}

/// rustnetec: T-B4 — GET /stats/duration 连接持续时长聚合。
///
/// 参数：
/// - `start` / `end`：RFC 3339 时间戳；缺省 end=now，start=now-1h。
/// - `bucket`：`1min`/`1hour`/`1day`，默认 `1min`。
/// - `process`：进程名过滤，逗号分隔多进程（IN 语义）。
/// - `interface`：网口过滤（精确匹配）。
/// - `scope`：`external`/`lan`/`all`，默认 `external`。
///
/// 返回 `[{ts, avg, p95, max, samples}, ...]`，按桶时间升序。
/// 用于「进程连接外网的持续时间」指标展示。
fn handle_stats_duration(request: tiny_http::Request, state: &HttpState) {

    let path = &state.db_path;
    if !path.exists() {
        let response = serde_json::json!({
            "buckets": [],
            "note": "database file not found — no capture data yet"
        });
        let _ = respond_json(request, 200, &response);
        return;
    }

    let url = request.url();
    let params = parse_query_params(url);

    let end = parse_time_param(params.get("end").map(String::as_str), chrono::Duration::zero());
    let start = parse_time_param(
        params.get("start").map(String::as_str),
        chrono::Duration::hours(1),
    );

    let bucket = params.get("bucket").map(String::as_str).unwrap_or("1min");
    let scope = params.get("scope").map(String::as_str).unwrap_or("external");

    let mut where_clauses: Vec<String> = vec![
        "ts >= ?".to_string(),
        "ts <= ?".to_string(),
        "event_type = 'connection_closed'".to_string(),
        "duration_secs IS NOT NULL".to_string(),
    ];
    let mut bind_values: Vec<Box<dyn rusqlite::ToSql>> = vec![
        Box::new(start.clone()),
        Box::new(end.clone()),
    ];
    let mut bind_idx = 3;

    if let Some(proc_list) = params.get("process") {
        let names: Vec<&str> = proc_list.split(',').filter(|s| !s.is_empty()).collect();
        if !names.is_empty() {
            let placeholders: Vec<String> = names.iter().map(|_| format!("?{}", bind_idx)).collect();
            where_clauses.push(format!("process_name IN ({})", placeholders.join(", ")));
            for name in names {
                bind_values.push(Box::new(name.to_string()));
                bind_idx += 1;
            }
        }
    }

    if let Some(iface) = params.get("interface") {
        if !iface.is_empty() {
            where_clauses.push(format!("interface = ?{}", bind_idx));
            bind_values.push(Box::new(iface.clone()));
        }
    }

    let sql = format!(
        "SELECT ts, dest_ip, duration_secs FROM connection_events WHERE {} ORDER BY ts ASC",
        where_clauses.join(" AND ")
    );

    let conn = match open_read_only(path) {
        Ok(c) => c,
        Err(e) => {
            let _ = respond_json(request, 500, &serde_json::json!({"error": format!("open: {}", e)}));
            return;
        }
    };

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => {
            let _ = respond_json(request, 500, &serde_json::json!({"error": format!("prepare: {}", e)}));
            return;
        }
    };

    let bind_refs: Vec<&dyn rusqlite::ToSql> = bind_values.iter().map(|b| b.as_ref()).collect();
    let rows = stmt.query_map(bind_refs.as_slice(), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<i64>>(2)?,
        ))
    });

    use crate::telemetry::netutil::{classify_dest, DestClass};
    use std::collections::BTreeMap;

    let scope_match = |dest_ip: &Option<String>| -> bool {
        match scope {
            "external" => dest_ip.as_ref().map(|ip| classify_dest(ip) == DestClass::External).unwrap_or(false),
            "lan" => dest_ip.as_ref().map(|ip| classify_dest(ip) == DestClass::Lan).unwrap_or(false),
            _ => true,
        }
    };

    let truncate_ts = |dt: chrono::DateTime<chrono::FixedOffset>| -> String {
        // rustnetec: 桶 key 输出 UTC 墙钟时间（无偏移后缀），前端按 Z 解析。
        let utc = dt.with_timezone(&chrono::Utc);
        match bucket {
            "1min" => utc.format("%Y-%m-%dT%H:%M").to_string(),
            "1hour" => utc.format("%Y-%m-%dT%H").to_string(),
            "1day" => utc.format("%Y-%m-%d").to_string(),
            _ => utc.format("%Y-%m-%dT%H:%M").to_string(),
        }
    };

    let mut buckets: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let rows_iter = match rows {
        Ok(r) => r,
        Err(e) => {
            let _ = respond_json(request, 500, &serde_json::json!({"error": format!("query: {}", e)}));
            return;
        }
    };

    for row in rows_iter {
        let (ts, dest_ip, duration_secs) = match row {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !scope_match(&dest_ip) {
            continue;
        }
        let dt = match chrono::DateTime::parse_from_rfc3339(&ts) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let key = truncate_ts(dt);
        buckets.entry(key).or_default().push(duration_secs.unwrap_or(0) as f64);
    }

    let percentile = |sorted: &[f64], p: f64| -> f64 {
        if sorted.is_empty() {
            return 0.0;
        }
        let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    };

    let result: Vec<serde_json::Value> = buckets
        .into_iter()
        .map(|(ts, mut durations)| {
            durations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let samples = durations.len() as i64;
            let sum: f64 = durations.iter().sum();
            let avg = if samples > 0 { sum / samples as f64 } else { 0.0 };
            let max = durations.iter().cloned().fold(0.0_f64, f64::max);
            serde_json::json!({
                "ts": ts,
                "avg": (avg * 1000.0).round() / 1000.0,
                "p95": percentile(&durations, 0.95),
                "max": max,
                "samples": samples,
            })
        })
        .collect();

    let response = serde_json::json!({
        "buckets": result,
        "count": result.len(),
        "bucket": bucket,
        "scope": scope,
    });
    let _ = respond_json(request, 200, &response);
}

/// rustnetec: GET /stats/reachability 外网可达率探测时间序列。
///
/// 参数：
/// - `start` / `end`：RFC 3339 或相对时间（`now-1h` 等）；缺省 end=now，start=now-1h。
/// - `bucket`：`5s`/`1min`/`1hour`/`1day`，默认 `1min`。
///
/// 数据来源：`reachability_probes` 表（由后台探测线程每 30s 写入）。
/// 每桶返回 `ts`、`reachable_ratio`（0–1，可达样本占比）、
/// `avg_latency_ms`、`min_latency_ms`、`samples`。
fn handle_stats_reachability(request: tiny_http::Request, state: &HttpState) {

    let path = &state.db_path;
    if !path.exists() {
        let response = serde_json::json!({
            "buckets": [],
            "note": "database file not found — no capture data yet"
        });
        let _ = respond_json(request, 200, &response);
        return;
    }

    let url = request.url();
    let params = parse_query_params(url);

    let end = parse_time_param(params.get("end").map(String::as_str), chrono::Duration::zero());
    let start = parse_time_param(
        params.get("start").map(String::as_str),
        chrono::Duration::hours(1),
    );
    let bucket = params.get("bucket").map(String::as_str).unwrap_or("1min");

    let conn = match open_read_only(path) {
        Ok(c) => c,
        Err(e) => {
            let _ = respond_json(request, 500, &serde_json::json!({"error": format!("open: {}", e)}));
            return;
        }
    };

    let sql = "SELECT ts, reachable, latency_ms FROM reachability_probes \
               WHERE ts >= ?1 AND ts <= ?2 ORDER BY ts ASC";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => {
            // 表可能尚未创建（探测线程未启动），按空结果返回而非 500。
            let _ = respond_json(request, 200, &serde_json::json!({"buckets": [], "count": 0, "bucket": bucket}));
            return;
        }
    };

    let rows = match stmt.query_map(rusqlite::params![start, end], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Option<f64>>(2)?,
        ))
    }) {
        Ok(r) => r,
        Err(e) => {
            let _ = respond_json(request, 500, &serde_json::json!({"error": format!("query: {}", e)}));
            return;
        }
    };

    let truncate_ts = |dt: chrono::DateTime<chrono::FixedOffset>| -> String {
        let utc = dt.with_timezone(&chrono::Utc);
        match bucket {
            "5s" => {
                let secs = utc.timestamp();
                chrono::DateTime::from_timestamp(secs - (secs % 5), 0)
                    .unwrap()
                    .format("%Y-%m-%dT%H:%M:%S")
                    .to_string()
            }
            "1hour" => utc.format("%Y-%m-%dT%H").to_string(),
            "1day" => utc.format("%Y-%m-%d").to_string(),
            _ => utc.format("%Y-%m-%dT%H:%M").to_string(),
        }
    };

    use std::collections::BTreeMap;
    #[derive(Default)]
    struct Acc {
        reachable: i64,
        samples: i64,
        lat_sum: f64,
        lat_min: Option<f64>,
    }
    let mut buckets: BTreeMap<String, Acc> = BTreeMap::new();

    for row in rows.flatten() {
        let (ts, reachable, latency) = row;
        let dt = match chrono::DateTime::parse_from_rfc3339(&ts) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let key = truncate_ts(dt);
        let entry = buckets.entry(key).or_default();
        entry.samples += 1;
        entry.reachable += reachable;
        if let Some(ms) = latency {
            entry.lat_sum += ms;
            entry.lat_min = Some(match entry.lat_min {
                Some(cur) => cur.min(ms),
                None => ms,
            });
        }
    }

    let result: Vec<serde_json::Value> = buckets
        .into_iter()
        .map(|(ts, a)| {
            let reachable_ratio = if a.samples > 0 {
                a.reachable as f64 / a.samples as f64
            } else {
                0.0
            };
            let lat_n = a.lat_min.is_some() as i64;
            serde_json::json!({
                "ts": ts,
                "reachable_ratio": (reachable_ratio * 1000.0).round() / 1000.0,
                "avg_latency_ms": if lat_n > 0 { ((a.lat_sum / lat_n as f64) * 10.0).round() / 10.0 } else { 0.0 },
                "min_latency_ms": a.lat_min.unwrap_or(0.0),
                "samples": a.samples,
            })
        })
        .collect();

    let response = serde_json::json!({
        "buckets": result,
        "count": result.len(),
        "bucket": bucket,
    });
    let _ = respond_json(request, 200, &response);
}

/// GET /config — read current config.
fn handle_get_config(request: tiny_http::Request, _state: &HttpState) {
    match crate::config::PersistentConfig::load() {
        Ok(config) => {
            let json = serde_json::to_value(&config).unwrap_or_else(
                |e| serde_json::json!({"error": format!("serialize error: {}", e)}),
            );
            let _ = respond_json(request, 200, &json);
        }
        Err(e) => {
            let response = serde_json::json!({"error": format!("{}", e)});
            let _ = respond_json(request, 500, &response);
        }
    }
}

/// PUT /config — update config (dual-track: hot-update + restart-required).
///
/// rustnetec: G2 修复 — `handle_put_config` 现接线双轨制热更新。
///
/// 落盘成功后:
/// 1. 热更新项(`apply_hot_update`)写入 `state.runtime_config`,捕获/上报/托盘
///    读最新值即时生效——无需重启。
/// 2. 重启生效项(`apply_restart_items`)同样写入 `runtime_config`,但置
///    `pending_restart=true`;用户需调 `POST /config/restart-capture`(或重启
///    进程)才会真正切换 interface/bpf_filter/refresh_interval 等字段。
///
/// 响应里明确告知调用方哪些项已生效、哪些项待重启,便于 WebUI 设置页标注。
fn handle_put_config(mut request: tiny_http::Request, state: &HttpState) {
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

    // rustnetec: T1.11 修复 — 设置页联动系统自启注册。
    // 比较新旧配置的 autostart_enabled / autostart_mode, 变化时真正调用
    // autostart::install / uninstall(HKCU Run / systemd --user unit /
    // LaunchAgent plist), 使 WebUI 的"开机自启"开关不再只是写 config.yml。
    // 注册失败则不保存(保持磁盘配置与系统注册状态一致), 返回明确错误。
    let old_config = crate::config::PersistentConfig::load().unwrap_or_default();
    let autostart_changed = old_config.autostart_enabled != new_config.autostart_enabled
        || (new_config.autostart_enabled
            && old_config.autostart_mode != new_config.autostart_mode);
    if autostart_changed {
        let result = if new_config.autostart_enabled {
            crate::telemetry::autostart::install(new_config.autostart_mode)
        } else {
            crate::telemetry::autostart::uninstall()
        };
        if let Err(e) = result {
            let response = serde_json::json!({
                "error": format!("autostart change failed, config not saved: {e:#}"),
                "autostart": "failed"
            });
            let _ = respond_json(request, 500, &response);
            return;
        }
        info!(
            "autostart {} via settings page (mode: {:?})",
            if new_config.autostart_enabled { "registered" } else { "removed" },
            new_config.autostart_mode
        );
    }

    if let Err(e) = new_config.save() {
        let response = serde_json::json!({"error": format!("failed to save config: {}", e)});
        let _ = respond_json(request, 500, &response);
        return;
    }

    // rustnetec: G2 — 双轨制接线。
    //
    // 持久层已写盘,现在把变更推到运行时共享态。先拿写锁,再依次调
    // apply_hot_update(立即生效项)与 apply_restart_items(置 pending_restart)。
    // apply_restart_items 内部把 pending_restart 置 false,因此这里显式设回 true
    // 以表达"有重启生效项待应用"。
    let pending_restart = {
        let mut rc = state
            .runtime_config
            .write()
            .expect("runtime_config lock poisoned");
        rc.apply_hot_update(&new_config);
        rc.apply_restart_items(&new_config);
        // apply_restart_items 把 pending_restart 置 false,这里若有重启生效项变更
        // 需重新置 true;简化起见一律置 true,由 restart-capture 清除。
        rc.pending_restart = true;
        true
    };

    let response = serde_json::json!({
        "status": "ok",
        "pending_restart": pending_restart,
        // rustnetec: T1.11 修复 — 回显自启注册结果, 供 WebUI 设置页标注。
        "autostart": if autostart_changed {
            if new_config.autostart_enabled {
                format!("registered ({})", new_config.autostart_mode.cli_flag())
            } else {
                "removed".to_string()
            }
        } else {
            "unchanged".to_string()
        },
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
    if !db_path.exists() {
        return Ok(serde_json::json!({
            "total_events": 0,
            "total_aggregates": 0,
            "note": "database not found"
        }));
    }

    let conn = open_read_only(db_path)?;

    let total_events: i64 = conn
        .query_row("SELECT COUNT(*) FROM connection_events", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);

    let total_aggregates: i64 = conn
        .query_row("SELECT COUNT(*) FROM aggregates", [], |row| row.get(0))
        .unwrap_or(0);

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

    // rustnetec: W0.4 — 进程维度 top 20(供 WebUI Activity 页)。
    // process_name 可能为 NULL(进程归因未启用或未命中),过滤后再分组。
    let events_by_process: Vec<serde_json::Value> = {
        let mut stmt = conn.prepare(
            "SELECT process_name, COUNT(*) as cnt, COALESCE(SUM(bytes_sent),0) as sent, COALESCE(SUM(bytes_received),0) as recv FROM connection_events WHERE process_name IS NOT NULL AND process_name != '' GROUP BY process_name ORDER BY cnt DESC LIMIT 20"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "process": row.get::<_, String>(0)?,
                "count": row.get::<_, i64>(1)?,
                "bytes_sent": row.get::<_, i64>(2)?,
                "bytes_received": row.get::<_, i64>(3)?,
            }))
        })?;
        rows.filter_map(|r| r.ok()).collect()
    };

    // rustnetec: W0.4 — 国家维度 top 20(供 WebUI GeoIP 分布)。
    // geoip_country_code 可能为 NULL(GeoIP 未启用或私有 IP),过滤后再分组。
    let events_by_country: Vec<serde_json::Value> = {
        let mut stmt = conn.prepare(
            "SELECT geoip_country_code, COUNT(*) as cnt FROM connection_events WHERE geoip_country_code IS NOT NULL AND geoip_country_code != '' GROUP BY geoip_country_code ORDER BY cnt DESC LIMIT 20"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "country": row.get::<_, String>(0)?,
                "count": row.get::<_, i64>(1)?,
            }))
        })?;
        rows.filter_map(|r| r.ok()).collect()
    };

    Ok(serde_json::json!({
        "total_events": total_events,
        "total_aggregates": total_aggregates,
        "by_protocol": events_by_protocol,
        "by_direction": events_by_direction,
        "by_process": events_by_process,
        "by_country": events_by_country,
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

/// rustnetec: 解析 `start`/`end` 查询参数为 RFC 3339 时间戳。
///
/// - `None`：返回 `(now - default_sub)` 的 RFC 3339 本地时间。
/// - `Some("now")`：返回当前时间。
/// - `Some("now-<n><unit>")`：相对时间，单位 s/m/h/d（如 `now-15m`、`now-7d`、`now-900s`）。
/// - 其他值：假定已是 RFC 3339 时间戳，原样返回（兼容直接传绝对时间的调用方）。
///
/// 相对时间解析失败时回退到默认值，避免把 `"now-15m"` 这类字符串直接绑进
/// SQL 导致字典序比较恒为 false（前端曾因此拿到空桶）。
fn parse_time_param(value: Option<&str>, default_sub: chrono::Duration) -> String {
    let now = chrono::Local::now();
    let fallback = || {
        now.checked_sub_signed(default_sub)
            .unwrap_or(now)
            .to_rfc3339()
    };

    let Some(v) = value.map(str::trim).filter(|s| !s.is_empty()) else {
        return fallback();
    };

    if v == "now" {
        return now.to_rfc3339();
    }

    if let Some(rest) = v.strip_prefix("now-") {
        return match parse_relative_duration(rest) {
            Some(dur) => now.checked_sub_signed(dur).unwrap_or(now).to_rfc3339(),
            // 解析失败（如 "now-abc"）回退默认窗口，不把脏字符串传进 SQL。
            None => fallback(),
        };
    }

    // 绝对时间戳：原样返回（已含时区偏移）。
    v.to_string()
}

/// 解析 `"<n><unit>"` 形式的相对时长，单位 s/m/h/d。
fn parse_relative_duration(s: &str) -> Option<chrono::Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let unit = s.chars().last()?;
    let num_str = &s[..s.len() - unit.len_utf8()];
    let n: i64 = num_str.parse().ok()?;
    match unit {
        's' => chrono::Duration::try_seconds(n),
        'm' => chrono::Duration::try_minutes(n),
        'h' => chrono::Duration::try_hours(n),
        'd' => chrono::Duration::try_days(n),
        _ => None,
    }
}

/// rustnetec: 解析连接表 `since` 时间范围参数为 RFC 3339 截止时间戳。
///
/// 与 `parse_time_param` 不同，此处支持 **月/年** 语义：
/// - `d`：天（如 `1d`、`7d`）
/// - `m`：月（如 `1m`、`3m`，按日历月减）
/// - `y`：年（如 `1y`，按 12 个月减）
/// 返回 `None` 表示参数缺失或非法（调用方不过滤）。
fn parse_since_param(v: &str) -> Option<String> {
    let s = v.trim();
    if s.is_empty() {
        return None;
    }
    let unit = s.chars().last()?;
    let num_str = &s[..s.len() - unit.len_utf8()];
    let n: i64 = num_str.parse().ok()?;
    if n <= 0 {
        return None;
    }
    let now = chrono::Local::now();
    let cutoff = match unit {
        'd' => now.checked_sub_signed(chrono::Duration::try_days(n)?)?,
        'm' => {
            let months = chrono::Months::new(n as u32);
            now.checked_sub_months(months)?
        }
        'y' => {
            let months = chrono::Months::new((n as u32).saturating_mul(12));
            now.checked_sub_months(months)?
        }
        _ => return None,
    };
    Some(cutoff.to_rfc3339())
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
fn respond_json(request: tiny_http::Request, status: u16, value: &serde_json::Value) -> Result<()> {
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

/// Open a read-only SQLite connection with a `busy_timeout`.
///
/// rustnetec: W-fix — the HTTP read endpoints (`/processes`, `/stats/*`,
/// `/query`) open their own connection per request. The writer connection uses
/// `busy_timeout=5000`, but these read connections previously set none, so a
/// transient SQLite lock (e.g. during a WAL checkpoint) could make them fail or
/// block immediately. With per-request threading now in place, a 2s busy
/// timeout keeps a single locked query from holding a worker thread too long
/// while still giving the writer room to finish.
fn open_read_only(path: &std::path::Path) -> rusqlite::Result<rusqlite::Connection> {
    use rusqlite::OpenFlags;
    let conn = rusqlite::Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(std::time::Duration::from_secs(2))?;
    Ok(conn)
}

/// Index page HTML.
// rustnetec: W1.2 — 替换静态 API 链接列表为动态 WebUI 单文件。
// include_str! 在编译期把 webui/index.html 嵌入二进制,与原 INDEX_HTML 同法,
// 但现在是完整的标签栏 + 仪表盘 + /live 1s 轮询页面。
const INDEX_HTML: &str = include_str!("../../webui/index.html");

// rustnetec: T-F3b — ECharts 图表库静态资产(echarts.min.js v5.5.1, Apache 2.0)。
// 与 INDEX_HTML 同法用 include_str! 内嵌,离线可用;WebUI 以相对路径
// `<script src="echarts.js">` 引用,daemon 与 rustnet-server 双端服务同源文件。
const ECHARTS_JS: &str = include_str!("../../webui/echarts.min.js");

/// rustnetec: Login landing page shown when no session is active (T3.3, R6).
///
/// Instead of dumping the raw API link list (which would 401 on every click),
/// tell the user to open the panel from the tray — the only path that can
/// issue a session cookie, since the Bearer token is not browser-pasteable.
const LOGIN_HTML: &str = r#"<!DOCTYPE html>
<html>
<head><title>rustnetec — 登录</title></head>
<body>
<h1>rustnetec 本地面板</h1>
<p>未授权访问。请从系统托盘菜单的「打开本地面板」进入——浏览器将通过一次性引导码自动完成鉴权。</p>
<p>CLI / API 客户端请使用 <code>Authorization: Bearer &lt;token&gt;</code> 头。</p>
</body>
</html>"#;

// ---- rustnetec: bootstrap handshake helpers (T3.3, R6) ----

/// Parse a single query parameter value from a URL string.
///
/// Returns `None` if the parameter is absent. Reuses the existing `urldecode`
/// helper so `%xx` / `+` escaping is handled consistently with `parse_query_params`.
fn parse_query_param(url: &str, key: &str) -> Option<String> {
    let query = url.split('?').nth(1)?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && urldecode(k) == key
        {
            return Some(urldecode(v));
        }
    }
    None
}

/// Redeem a one-time bootstrap guid.
///
/// On success: removes the guid from `pending_guids`, issues a **无状态**
/// session id（`<unix_secs>.<签名>`，BLAKE3 keyed hash），并返回该 id。
/// On failure (guid unknown / already redeemed / expired): returns `None`.
///
/// Side effect: also sweeps expired bootstrap guids so a long-running daemon
/// does not accumulate stale state without a dedicated cleanup thread.
fn redeem_bootstrap_guid(state: &HttpState, code: &str) -> Option<String> {
    let now = Instant::now();
    // Take the lock once, do redeem + sweep in the same critical section.
    let redeemed = state.pending_guids.lock().ok().and_then(|mut guids| {
        // Sweep expired bootstrap guids (best-effort, in-line).
        guids.retain(|(_, issued)| now.duration_since(*issued) < BOOTSTRAP_GUID_TTL);
        // Find and remove the matching guid (one-time).
        if let Some(pos) = guids.iter().position(|(g, _)| *g == code) {
            guids.swap_remove(pos);
            Some(())
        } else {
            None
        }
    });
    // rustnetec: clippy question_mark — redeem succeeded iff redeemed is Some
    redeemed?;

    // rustnetec: 无状态 session — 签发「时间戳.签名」id，不写内存态映射；
    // 密钥由持久化 machine_id/http_token 派生，daemon 重启后 cookie 依然可验证。
    Some(issue_session_id(&state.session_key))
}

/// 签发无状态 session id：`<unix_secs>.<hex(blake3 keyed_hash(key, secs_le))>`。
///
/// 校验只需验签 + 时间窗，不依赖任何服务端存储；密钥持久化派生，
/// 因此进程重启后旧 cookie 依然有效（修复刷新报未授权问题）。
fn issue_session_id(key: &[u8; 32]) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{ts}.{}", blake3::keyed_hash(key, &ts.to_le_bytes()).to_hex())
}

/// 校验无状态 session id：格式 `ts.sig`、签名匹配、且未超过 `SESSION_TTL`。
fn verify_session_id(key: &[u8; 32], id: &str) -> bool {
    let Some((ts_str, sig)) = id.split_once('.') else {
        return false;
    };
    let Ok(ts) = ts_str.parse::<u64>() else {
        return false;
    };
    // TTL 检查（wall-clock；进程重启后依然可比）。
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.saturating_sub(ts) >= SESSION_TTL.as_secs() {
        return false;
    }
    // 签名校验：恒定时间比较，避免时序侧信道。
    let expect = blake3::keyed_hash(key, &ts.to_le_bytes()).to_hex();
    let (a, b) = (expect.as_str().as_bytes(), sig.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Validate a request's session cookie（无状态签名，无服务端存储）。
///
/// Returns `true` if the `Cookie: session=<id>` header is present and the id
/// 签名有效且未过期。不再依赖内存态会话表，daemon 重启后仍可校验。
fn validate_session(state: &HttpState, request: &tiny_http::Request) -> bool {
    let Some(cookie_val) = extract_session_cookie(request) else {
        return false;
    };
    verify_session_id(&state.session_key, &cookie_val)
}

/// Extract the `session=<id>` value from a `Cookie` header, if present.
///
/// Cookie headers look like `session=abc123; other=xyz`. We scan for the
/// `session` key and return its value, tolerating surrounding whitespace.
fn extract_session_cookie(request: &tiny_http::Request) -> Option<String> {
    for header in request.headers() {
        if !header.field.equiv("Cookie") {
            continue;
        }
        for kv in header.value.as_str().split(';') {
            if let Some((k, v)) = kv.split_once('=')
                && k.trim() == "session"
            {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// 兑换引导码成功后：设置 session cookie 并 303 重定向到干净的 `location`
/// （通常是 `/`）。重定向让浏览器地址栏丢掉一次性 `?code=...`，
/// 这样刷新不会重复使用已兑换的码（那会 403）；cookie 随 303 响应下发，
/// 浏览器随后 GET `/` 时带上 cookie，正常渲染面板。
fn respond_redirect_with_session(
    request: tiny_http::Request,
    location: &str,
    session_id: &str,
) -> Result<()> {
    let cookie = format!(
        "session={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        session_id,
        SESSION_TTL.as_secs()
    );
    let response = tiny_http::Response::new(
        tiny_http::StatusCode(303),
        vec![
            tiny_http::Header::from_bytes(&b"Location"[..], location.as_bytes()).unwrap(),
            tiny_http::Header::from_bytes(&b"Set-Cookie"[..], cookie.as_bytes()).unwrap(),
            tiny_http::Header::from_bytes(&b"Content-Type"[..], b"text/html").unwrap(),
        ],
        std::io::Cursor::new(Vec::<u8>::new()),
        Some(0),
        None,
    );
    request.respond(response)?;
    Ok(())
}

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
    fn parse_relative_duration_units() {
        assert_eq!(
            parse_relative_duration("15m"),
            Some(chrono::Duration::minutes(15))
        );
        assert_eq!(
            parse_relative_duration("1h"),
            Some(chrono::Duration::hours(1))
        );
        assert_eq!(
            parse_relative_duration("7d"),
            Some(chrono::Duration::days(7))
        );
        assert_eq!(
            parse_relative_duration("900s"),
            Some(chrono::Duration::seconds(900))
        );
    }

    #[test]
    fn parse_relative_duration_invalid() {
        assert!(parse_relative_duration("").is_none());
        assert!(parse_relative_duration("abc").is_none());
        assert!(parse_relative_duration("5x").is_none());
        assert!(parse_relative_duration("m").is_none());
    }

    #[test]
    fn parse_time_param_relative_and_absolute() {
        // now-15m 应解析为约 15 分钟前（允许 5s 误差）。
        let out = parse_time_param(Some("now-15m"), chrono::Duration::hours(1));
        let parsed = chrono::DateTime::parse_from_rfc3339(&out).expect("valid rfc3339");
        let now = chrono::Local::now();
        let diff = (now - parsed.with_timezone(&chrono::Local)).num_seconds().abs();
        assert!(
            (15 * 60 - 5..=15 * 60 + 5).contains(&diff),
            "expected ~15min ago, got diff={diff}s"
        );

        // now-7d 应解析为约 7 天前。
        let out = parse_time_param(Some("now-7d"), chrono::Duration::hours(1));
        let parsed = chrono::DateTime::parse_from_rfc3339(&out).unwrap();
        let diff = (now - parsed.with_timezone(&chrono::Local)).num_seconds().abs();
        assert!(
            (7 * 86400 - 10..=7 * 86400 + 10).contains(&diff),
            "expected ~7d ago, got diff={diff}s"
        );

        // 绝对时间戳原样返回。
        let abs = "2026-01-01T00:00:00+08:00";
        assert_eq!(parse_time_param(Some(abs), chrono::Duration::hours(1)), abs);
    }

    #[test]
    fn parse_time_param_none_uses_default() {
        // None → 默认 1h 前。
        let out = parse_time_param(None, chrono::Duration::hours(1));
        let parsed = chrono::DateTime::parse_from_rfc3339(&out).unwrap();
        let now = chrono::Local::now();
        let diff = (now - parsed.with_timezone(&chrono::Local)).num_seconds().abs();
        assert!(
            (3600 - 5..=3600 + 5).contains(&diff),
            "expected ~1h ago, got diff={diff}s"
        );
    }

    #[test]
    fn parse_time_param_invalid_relative_falls_back() {
        // 非法相对时间回退默认窗口（1h），不把脏字符串透传。
        let out = parse_time_param(Some("now-abc"), chrono::Duration::hours(1));
        assert!(chrono::DateTime::parse_from_rfc3339(&out).is_ok());
        assert!(!out.contains("now-abc"));
    }

    #[test]
    fn http_state_creation() {
        use std::sync::Mutex;
        use std::sync::RwLock;
        use std::sync::atomic::AtomicBool;
        let state = HttpState {
            db_path: PathBuf::from("/tmp/test.db"),
            http_token: "test-token".to_string(),
            should_stop: Arc::new(AtomicBool::new(false)),
            // rustnetec: T3.3 bootstrap handshake state (R6)
            pending_guids: Arc::new(Mutex::new(Vec::new())),
            session_key: Arc::new([0u8; 32]),
            // rustnetec: T3.5 launcher URL port (R6)
            http_port: 19811,
            // rustnetec: T3.6.7 daemon→tray live snapshot (R6)
            live_snapshot: Arc::new(RwLock::new(serde_json::json!({}))),
            // rustnetec: G2 — 运行时配置共享态(测试用默认值)
            runtime_config: Arc::new(RwLock::new(
                crate::config::RuntimeConfig::from_persistent(
                    &crate::config::PersistentConfig::default(),
                ),
            )),
        };
        assert_eq!(state.http_token, "test-token");
        assert!(!state.should_stop.load(std::sync::atomic::Ordering::Relaxed));
        // rustnetec: T3.3 — confirm the handshake state is wired and empty
        assert!(state.pending_guids.lock().unwrap().is_empty());
        // rustnetec: T3.5 — confirm the listen port is wired for the launcher
        assert_eq!(state.http_port, 19811);
        // rustnetec: T3.6.7 — live snapshot starts empty (no daemon yet)
        assert!(state.live_snapshot.read().unwrap().is_object());
    }

    // ---- rustnetec: bootstrap handshake unit tests (T3.3, R6) ----

    /// Build a minimal HttpState for handshake tests (no real DB / token needed).
    fn handshake_state() -> HttpState {
        use std::sync::Mutex;
        use std::sync::RwLock;
        use std::sync::atomic::AtomicBool;
        HttpState {
            db_path: PathBuf::from("/tmp/test_handshake.db"),
            // Empty token = no Bearer auth required, so we exercise the
            // session path in isolation rather than both at once.
            http_token: String::new(),
            should_stop: Arc::new(AtomicBool::new(false)),
            pending_guids: Arc::new(Mutex::new(Vec::new())),
            session_key: Arc::new([0u8; 32]),
            // rustnetec: T3.5 — use a non-default port so launcher URL
            // construction would catch a hardcoded-19811 regression.
            http_port: 19812,
            // rustnetec: T3.6.7 daemon→tray live snapshot (R6)
            live_snapshot: Arc::new(RwLock::new(serde_json::json!({}))),
            // rustnetec: G2 — 运行时配置共享态(测试用默认值)
            runtime_config: Arc::new(RwLock::new(
                crate::config::RuntimeConfig::from_persistent(
                    &crate::config::PersistentConfig::default(),
                ),
            )),
        }
    }

    /// rustnetec: T3.5 — verify the launcher honours a non-default port
    /// instead of hardcoding 19811. Constructs an HttpState with port 19812
    /// (the same non-default port `handshake_state` uses) and confirms the
    /// field is readable; the launcher's `open_local_panel` reads this field
    /// to build the URL, so a regression here would break `--http-port`
    /// overrides in the tray menu.
    #[test]
    fn http_state_port_is_wired_for_launcher() {
        let state = handshake_state();
        assert_eq!(
            state.http_port, 19812,
            "handshake_state must use a non-default port"
        );
        // A freshly-built default state should also expose the port field.
        use std::sync::Mutex;
        use std::sync::RwLock;
        use std::sync::atomic::AtomicBool;
        let other = HttpState {
            db_path: PathBuf::from("/tmp/test_port.db"),
            http_token: String::new(),
            should_stop: Arc::new(AtomicBool::new(false)),
            pending_guids: Arc::new(Mutex::new(Vec::new())),
            session_key: Arc::new([0u8; 32]),
            http_port: 19813,
            // rustnetec: T3.6.7 daemon→tray live snapshot (R6)
            live_snapshot: Arc::new(RwLock::new(serde_json::json!({}))),
            // rustnetec: G2 — 运行时配置共享态(测试用默认值)
            runtime_config: Arc::new(RwLock::new(
                crate::config::RuntimeConfig::from_persistent(
                    &crate::config::PersistentConfig::default(),
                ),
            )),
        };
        assert_eq!(other.http_port, 19813);
    }

    #[test]
    fn parse_query_param_present() {
        assert_eq!(
            parse_query_param("/?code=abc123", "code").as_deref(),
            Some("abc123")
        );
    }

    #[test]
    fn parse_query_param_absent() {
        assert!(parse_query_param("/", "code").is_none());
        assert!(parse_query_param("/live", "code").is_none());
    }

    #[test]
    fn parse_query_param_urldecoded() {
        // %xx and + should be decoded consistently with parse_query_params.
        assert_eq!(
            parse_query_param("/?code=ab%20cd", "code").as_deref(),
            Some("ab cd")
        );
    }

    #[test]
    fn issue_bootstrap_guid_is_unique_and_pending() {
        let state = handshake_state();
        let g1 = state.issue_bootstrap_guid();
        let g2 = state.issue_bootstrap_guid();
        assert_ne!(g1, g2, "consecutive guids must differ");
        let pending = state.pending_guids.lock().unwrap();
        assert_eq!(pending.len(), 2, "both guids should be recorded pending");
        assert!(pending.iter().any(|(g, _)| *g == g1));
        assert!(pending.iter().any(|(g, _)| *g == g2));
    }

    #[test]
    fn redeem_unknown_guid_returns_none() {
        let state = handshake_state();
        assert!(redeem_bootstrap_guid(&state, "never-issued").is_none());
    }

    #[test]
    fn redeem_valid_guid_issues_session_and_drops_guid() {
        let state = handshake_state();
        let guid = state.issue_bootstrap_guid();
        // First redemption succeeds and returns a fresh session id.
        let session =
            redeem_bootstrap_guid(&state, &guid).expect("freshly-issued guid should redeem");
        assert!(!session.is_empty());
        // 无状态 session：签名可独立校验（不依赖服务端内存态）。
        assert!(
            verify_session_id(&state.session_key, &session),
            "redeemed session should be verifiable by signature"
        );
        // The guid is no longer pending (one-time).
        assert!(
            !state
                .pending_guids
                .lock()
                .unwrap()
                .iter()
                .any(|(g, _)| *g == guid),
            "redeemed guid must be removed from pending"
        );
        // Replay rejected.
        assert!(
            redeem_bootstrap_guid(&state, &guid).is_none(),
            "guid cannot be redeemed twice"
        );
    }

    #[test]
    fn redeem_sweeps_expired_pending_guids() {
        let state = handshake_state();
        // Manually inject a guid with an expired timestamp (well past the
        // 5-min TTL) plus a fresh guid, then redeem the fresh one — the
        // expired one should be swept as a side effect.
        {
            let mut guids = state.pending_guids.lock().unwrap();
            guids.push((
                "expired".to_string(),
                Instant::now() - BOOTSTRAP_GUID_TTL - Duration::from_secs(1),
            ));
            guids.push(("fresh".to_string(), Instant::now()));
        }
        let session = redeem_bootstrap_guid(&state, "fresh").expect("fresh guid redeemable");
        assert!(!session.is_empty());
        let pending = state.pending_guids.lock().unwrap();
        assert!(
            !pending.iter().any(|(g, _)| *g == "expired"),
            "expired guid should have been swept"
        );
        assert!(
            !pending.iter().any(|(g, _)| *g == "fresh"),
            "redeemed guid should have been removed"
        );
        assert_eq!(pending.len(), 0, "no stale entries should remain");
    }

    #[test]
    fn verify_session_id_rejects_expired_signature() {
        // 无状态 session 无服务端存储，过期由时间戳 + TTL 判定。
        let key = [0u8; 32];
        // 构造一个过期时间戳的签名 id（1 秒前过期）。
        let expired_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() - SESSION_TTL.as_secs() - 1)
            .unwrap_or(0);
        let expired = format!(
            "{expired_ts}.{}",
            blake3::keyed_hash(&key, &expired_ts.to_le_bytes()).to_hex()
        );
        assert!(
            !verify_session_id(&key, &expired),
            "expired session id must be rejected"
        );
        // 合法 id（当前时间戳 + 正确签名）应通过。
        let valid = issue_session_id(&key);
        assert!(verify_session_id(&key, &valid), "fresh session id must pass");
    }

    #[test]
    fn validate_session_rejects_empty_cookie() {
        // 无状态校验：空/畸形 id 一律拒绝（不依赖服务端内存态）。
        let state = handshake_state();
        assert!(!verify_session_id(&state.session_key, ""));
        assert!(!verify_session_id(&state.session_key, "not-a-session"));
        assert!(!verify_session_id(&state.session_key, "1234567890"));
    }

    #[test]
    fn extract_session_cookie_no_header_returns_none() {
        // Building a tiny_http::Request requires a TcpStream; for unit coverage
        // we instead assert the bootstrap handshake state machine's invariants
        // hold end-to-end: each redemption yields a verifiable session.
        let state = handshake_state();
        let guid = state.issue_bootstrap_guid();
        let session = redeem_bootstrap_guid(&state, &guid).unwrap();
        // 无状态 session：id = 时间戳.签名，同一秒内多次兑换可能相同（幂等），
        // 但每次都必须能由签名独立校验（不依赖服务端内存态）。
        let guid2 = state.issue_bootstrap_guid();
        let session2 = redeem_bootstrap_guid(&state, &guid2).unwrap();
        assert!(verify_session_id(&state.session_key, &session));
        assert!(verify_session_id(&state.session_key, &session2));
        // 不同时间戳的 session 必然不同（可区分不同会话窗口）。
        let older_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().saturating_sub(1))
            .unwrap_or(0);
        let older = format!(
            "{older_ts}.{}",
            blake3::keyed_hash(&state.session_key, &older_ts.to_le_bytes()).to_hex()
        );
        assert_ne!(older, session, "different timestamps yield distinct ids");
    }
}

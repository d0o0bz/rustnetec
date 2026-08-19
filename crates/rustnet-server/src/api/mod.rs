//! HTTP API layer: axum routes and app construction (T2.4).
//!
//! ## Routes
//!
//! | Method | Path       | Auth role      | Description                       |
//! |--------|------------|----------------|-----------------------------------|
//! | GET    | `/health`  | none           | Liveness probe                    |
//! | POST   | `/ingest`  | `Ingest`/`Admin`| Accept a client event batch       |
//! | GET    | `/query`   | `Query`/`Admin`| Read-only historical query        |
//! | GET    | `/stats`   | `Query`/`Admin`| Aggregate statistics              |
//! | GET    | `/stats/range` | `Query`/`Admin`| Per-bucket time series (T-E5) |
//!
//! Auth uses Bearer tokens hashed with BLAKE3 (see [`auth`] and [`token`]).
//! `/health` is intentionally unauthenticated so load balancers can probe it.
//!
//! CORS is configured with a strict policy: only `GET`/`POST`, JSON content
//! type, and no credentials by default. Adjust [`cors_layer`] when opening
//! up to browser UIs.

pub mod auth;
pub mod token;

use std::str::FromStr;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Extension, Query, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rustnet_core::ingest::{
    HealthResponse, IngestRequest, IngestResponse, QueryParams, QueryResponse, StatsResponse,
};

use crate::db::{Error as DbError, ServerDb};

/// rustnetec: W5.1 — WebUI 静态资产嵌入。
///
/// 与 daemon 侧 `INDEX_HTML` 同法,用 `include_str!` 把 `webui/index.html`
/// 嵌入 rustnetec-server 二进制。服务端是远程查看通道(R5 远程 HTTP),
/// 同一 HTML 复用,前端 JS 据 `window.location` 切 API base(W5.2)。
///
/// 服务端无 `/live`(本机 daemon 专属),前端检测到 server 模式时
/// 隐藏仪表盘的实时轮询与设置页,只暴露历史查询/统计/进程活动。
const WEBUI_HTML: &str = include_str!("../../../../webui/index.html");

/// rustnetec: T-F3b — ECharts 图表库静态资产（与 WEBUI_HTML 同源内嵌，
/// `webui/echarts.min.js` v5.5.1, Apache 2.0）。免鉴权，与 HTML 同级：
/// 纯静态、不含敏感数据；前端以相对路径 `echarts.js` 引用。
const ECHARTS_JS: &str = include_str!("../../../../webui/echarts.min.js");

/// Shared application state injected into the router.
pub type AppState = Arc<ServerDb>;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the top-level [`Router`] backed by `db`.
///
/// Kept as a free function so integration tests can construct the app without
/// spawning a TCP listener.
pub fn build_router(db: AppState) -> Router {
    Router::new()
        // /health is unauthenticated so probes/load balancers can reach it.
        .route("/health", get(health))
        // rustnetec: W5.1 — WebUI 静态资产(免鉴权,与 /health 同级)。
        // 远程浏览器经 Bearer token 访问 /query、/stats 等 API 端点;
        // HTML 本身是静态资产,不含敏感数据,免鉴权降低部署门槛。
        .route("/", get(webui))
        // rustnetec: T-F3b — ECharts 图表库静态资产（免鉴权，与 / 同级）。
        .route("/echarts.js", get(echarts_js))
        // Authed routes — each is gated by the role it requires.
        .route(
            "/ingest",
            post(ingest).route_layer(from_fn_with_state(db.clone(), require_ingest)),
        )
        .route(
            "/query",
            get(query).route_layer(from_fn_with_state(db.clone(), require_query)),
        )
        .route(
            "/stats",
            get(stats).route_layer(from_fn_with_state(db.clone(), require_query)),
        )
        // rustnetec: T-E5 — /stats/range 时间桶流量查询（多进程对比图）。
        .route(
            "/stats/range",
            get(stats_range).route_layer(from_fn_with_state(db.clone(), require_query)),
        )
        // rustnetec: W5.3 — /processes 供 WebUI Activity 页专用(与 daemon 对齐)。
        .route(
            "/processes",
            get(processes).route_layer(from_fn_with_state(db.clone(), require_query)),
        )
        // rustnetec: /hosts — 用户/主机信息表（按部门分组→user_id 聚合）。
        .route(
            "/hosts",
            get(list_hosts_handler).route_layer(from_fn_with_state(db.clone(), require_query)),
        )
        // rustnetec: /stats/reachability — 外网可达率（决策 A：客户端上报）。
        .route(
            "/stats/reachability",
            get(stats_reachability_handler).route_layer(from_fn_with_state(db.clone(), require_query)),
        )
        // rustnetec: /stats/realtime — 实时速率（决策 2-B：server_aggregates 分钟桶）。
        .route(
            "/stats/realtime",
            get(stats_realtime_handler).route_layer(from_fn_with_state(db.clone(), require_query)),
        )
        // rustnetec: admin token management (scope_machine_id-bound tokens).
        .route(
            "/admin/tokens",
            get(list_tokens_handler)
                .post(create_token_handler)
                .route_layer(from_fn_with_state(db.clone(), require_admin)),
        )
        .route(
            "/admin/tokens/{id}",
            axum::routing::delete(revoke_token_handler)
                .route_layer(from_fn_with_state(db.clone(), require_admin)),
        )
        // rustnetec: PATCH /admin/hosts/{machine_id} — 管理员编辑主机部门/用户名。
        // 不受 30 分钟约束（管理员随时可编辑）。
        .route(
            "/admin/hosts/{machine_id}",
            axum::routing::patch(patch_host_handler)
                .route_layer(from_fn_with_state(db.clone(), require_admin)),
        )
        .layer(cors_layer())
        .with_state(db)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Liveness probe (no auth).
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// rustnetec: W5.1 — 返回 WebUI 静态 HTML。
///
/// 与 daemon 侧 `INDEX_HTML` 同源(`webui/index.html`),前端 JS 据
/// `window.location` 切 API base(W5.2)。服务端无 `/live`,前端检测到
/// server 模式时隐藏仪表盘实时轮询与设置页,只暴露历史查询/统计/进程活动。
async fn webui() -> axum::response::Html<&'static str> {
    axum::response::Html(WEBUI_HTML)
}

/// rustnetec: T-F3b — 返回 ECharts 图表库静态 JS。
async fn echarts_js() -> impl IntoResponse {
    ([("Content-Type", "application/javascript")], ECHARTS_JS)
}

/// Accept a client batch and persist it through the single writer.
///
/// rustnetec: 纵深防御 — 已绑定 scope 的 token 只能上报自己 `machine_id`
/// 的数据；payload 的 `machine_id` 必须等于 token 的 `scope_machine_id`，
/// 否则返回 `Forbidden`。admin / 宽松 ingest（`None`）无此限制。
///
/// rustnetec: client 角色首次上报自动绑定 — 未绑定的 client token
/// （`scope_machine_id IS NULL`）在本端点把自身绑定到 payload 的
/// `machine_id`（幂等：已绑定 token 不会覆盖，见 `bind_token_to_machine`）。
async fn ingest(
    State(db): State<AppState>,
    Extension(principal): Extension<auth::TokenPrincipal>,
    Json(req): Json<IngestRequest>,
) -> Result<Json<IngestResponse>, ApiError> {
    // rustnetec: client 未绑定 → 首次上报自动绑定（绑定前拒绝空 machine_id，
    // 避免把空串写入 scope 导致 token 永久"毒化"）。
    if principal.role == auth::AuthRole::Client && principal.scope_machine_id.is_none() {
        if req.machine_id.trim().is_empty() {
            return Err(ApiError::BadRequest("machine_id must not be empty".into()));
        }
        let mut conn = db.lock_writer();
        token::bind_token_to_machine(&mut conn, principal.token_id, &req.machine_id)
            .map_err(ApiError::from)?;
    }
    // 纵深防御：已绑定 scope 时校验一致；admin/宽松 ingest（None）跳过。
    if let Some(ref scope_mid) = principal.scope_machine_id
        && &req.machine_id != scope_mid
    {
        return Err(ApiError::Forbidden);
    }
    let resp = db.ingest(&req).map_err(ApiError::from)?;
    Ok(Json(resp))
}

/// rustnetec: 解析读取端 scope。
///
/// 安全约束：未绑定的 client token（`scope_machine_id IS NULL`）**没有**读取
/// 权限——直接拒绝，防止 `Scope::from_scope(None)` 落到 `Scope::All` 造成
/// 全量越权。admin（`None`）与已绑定 query/client（`Some`）正常解析。
fn read_scope(principal: &auth::TokenPrincipal) -> Result<crate::db::query::Scope, ApiError> {
    if principal.role == auth::AuthRole::Client && principal.scope_machine_id.is_none() {
        return Err(ApiError::Forbidden);
    }
    Ok(crate::db::query::Scope::from_scope(&principal.scope_machine_id))
}

/// Read-only historical query.
async fn query(
    State(db): State<AppState>,
    Extension(principal): Extension<auth::TokenPrincipal>,
    Query(params): Query<QueryParams>,
) -> Result<Json<QueryResponse>, ApiError> {
    let scope = read_scope(&principal)?;
    let resp = db.query_events(&params, &scope).map_err(ApiError::from)?;
    Ok(Json(resp))
}

/// Aggregate statistics.
async fn stats(
    State(db): State<AppState>,
    Extension(principal): Extension<auth::TokenPrincipal>,
) -> Result<Json<StatsResponse>, ApiError> {
    let scope = read_scope(&principal)?;
    let resp = db.stats(&scope).map_err(ApiError::from)?;
    Ok(Json(resp))
}

/// rustnetec: T-E5 — 时间桶流量查询（/stats/range）。
///
/// 查询参数：`start`/`end`（RFC3339 或 `now-<n><s|m|h|d>`）、`bucket`
/// （`5s`/`1min`/`1hour`/`1day`）、`process`（逗号分隔进程名）。
/// 返回与 daemon 侧 `/stats/range` 同形的 JSON，供 WebUI 多进程对比图表使用。
async fn stats_range(
    State(db): State<AppState>,
    Extension(principal): Extension<auth::TokenPrincipal>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let end = parse_time_param(params.get("end").map(String::as_str), chrono::Duration::zero());
    let start = parse_time_param(
        params.get("start").map(String::as_str),
        chrono::Duration::hours(1),
    );
    let bucket = params
        .get("bucket")
        .map(String::as_str)
        .unwrap_or("1min")
        .to_string();
    let processes: Vec<String> = params
        .get("process")
        .map(|p| p.split(',').filter(|s| !s.is_empty()).map(String::from).collect())
        .unwrap_or_default();
    // rustnetec: 可选 machine_id 过滤（逗号分隔多机器，admin 模式下生效）。
    let machine_ids: Vec<String> = params
        .get("machine_id")
        .map(|m| m.split(',').filter(|s| !s.is_empty()).map(String::from).collect())
        .unwrap_or_default();

    let rp = crate::db::query::RangeParams {
        start,
        end,
        bucket,
        processes,
        machine_ids,
    };
    let scope = read_scope(&principal)?;
    let resp = db.stats_range(&rp, &scope).map_err(ApiError::from)?;
    Ok(Json(resp))
}

/// 解析时间参数（相对/绝对），与 daemon 侧 `parse_time_param` 同源。
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
            None => fallback(),
        };
    }
    v.to_string()
}

/// 解析 `"<n><unit>"` 形式相对时长（s/m/h/d）。
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

/// rustnetec: W5.3 — 按 process_name 聚合 top 50,供 WebUI Activity 页专用。
///
/// 与 daemon 侧 `handle_processes` JSON 形状对齐:`{processes, count}`。
/// 鉴权同 `/query`/`/stats`(Query/Admin 角色)。
async fn processes(
    State(db): State<AppState>,
    Extension(principal): Extension<auth::TokenPrincipal>,
) -> Result<Json<crate::db::query::ProcessesResponse>, ApiError> {
    let scope = read_scope(&principal)?;
    let resp = db.processes(&scope).map_err(ApiError::from)?;
    Ok(Json(resp))
}

// ---------------------------------------------------------------------------
// rustnetec: admin token management handlers (/admin/tokens)
// ---------------------------------------------------------------------------

/// Request body for `POST /admin/tokens`.
#[derive(Debug, serde::Deserialize)]
struct CreateTokenRequest {
    role: String,
    description: Option<String>,
    /// `None` (or omitted) → admin token, full access.
    /// `Some(mid)` → scoped to `machine_id = mid`.
    scope_machine_id: Option<String>,
}

/// `POST /admin/tokens` — issue a new token.
///
/// Business rules (enforced in [`token::create_token`]):
/// - `role=admin` → `scope_machine_id` must be `None`.
/// - `role=ingest|query` → `scope_machine_id` must be `Some(non-empty)`.
///
/// The plaintext token is returned **once** in the response body; store it
/// securely, it is not recoverable from the persisted BLAKE3 hash.
async fn create_token_handler(
    State(db): State<AppState>,
    Json(body): Json<CreateTokenRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let role = auth::AuthRole::from_str(&body.role)
        .map_err(|_| ApiError::BadRequest(format!("unknown role: {}", body.role)))?;

    let mut conn = db.lock_writer();
    let created = token::create_token(
        &mut conn,
        role,
        body.description.as_deref(),
        body.scope_machine_id.as_deref(),
    )
    .map_err(ApiError::from)?;

    Ok(Json(serde_json::json!({
        "id": created.id,
        "plaintext": created.plaintext,
        "role": body.role,
        "scope_machine_id": body.scope_machine_id,
    })))
}

/// `GET /admin/tokens` — list all tokens (active and revoked).
///
/// Hashes are intentionally omitted; only metadata is returned.
async fn list_tokens_handler(
    State(db): State<AppState>,
) -> Result<Json<Vec<token::TokenRow>>, ApiError> {
    let mut conn = db.lock_writer();
    let rows = token::list_tokens(&mut conn).map_err(ApiError::from)?;
    Ok(Json(rows))
}

/// `DELETE /admin/tokens/:id` — soft-revoke a token.
async fn revoke_token_handler(
    State(db): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut conn = db.lock_writer();
    let revoked = token::revoke_token(&mut conn, id).map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({
        "id": id,
        "revoked": revoked,
    })))
}

// ---------------------------------------------------------------------------
// rustnetec: 用户信息表 + 可达率 + 实时速率 + 主机编辑 handler
// ---------------------------------------------------------------------------

/// rustnetec: `GET /hosts` — 用户/主机信息表数据源。
///
/// 按 `department ASC NULLS LAST, user_id ASC, machine_id ASC` 排序。
/// 前端据此按部门分组 → user_id 聚合 → 展开 machine_id。
async fn list_hosts_handler(
    State(db): State<AppState>,
    Extension(principal): Extension<auth::TokenPrincipal>,
) -> Result<Json<Vec<crate::db::query::HostInfoRow>>, ApiError> {
    let scope = read_scope(&principal)?;
    let mut conn = db.lock_writer();
    let rows = crate::db::query::list_hosts(&mut conn, &scope).map_err(ApiError::from)?;
    Ok(Json(rows))
}

/// rustnetec: `GET /stats/reachability` — 外网可达率（决策 A：客户端上报）。
///
/// 查询参数：`machine_id`（必填，逗号分隔多机器）、`start`、`end`、`bucket`。
/// 返回 `{ buckets: [{ts, reachable_ratio, samples, min_latency_ms}], count, bucket }`。
async fn stats_reachability_handler(
    State(db): State<AppState>,
    Extension(principal): Extension<auth::TokenPrincipal>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scope = read_scope(&principal)?;

    // 解析 machine_id（逗号分隔）
    let mut machine_ids: Vec<String> = params
        .get("machine_id")
        .map(|m| m.split(',').filter(|s| !s.is_empty()).map(String::from).collect())
        .unwrap_or_default();

    // scope 安全：scoped token 只能查自身机器
    if let crate::db::query::Scope::Machine(ref mid) = scope {
        machine_ids.retain(|m| m == mid);
        if machine_ids.is_empty() {
            machine_ids.push(mid.clone());
        }
    }

    let end = parse_time_param(params.get("end").map(String::as_str), chrono::Duration::zero());
    let start = parse_time_param(
        params.get("start").map(String::as_str),
        chrono::Duration::hours(12),
    );
    let bucket = params
        .get("bucket")
        .map(String::as_str)
        .unwrap_or("1min")
        .to_string();

    let mut conn = db.lock_writer();
    let resp = crate::db::query::reachability(&mut conn, &machine_ids, &start, &end, &bucket)
        .map_err(ApiError::from)?;
    Ok(Json(resp))
}

/// rustnetec: `GET /stats/realtime` — 实时速率（决策 2-B：server_aggregates 分钟桶）。
///
/// 查询参数：`machine_id`（必填，逗号分隔多机器）、`start`（RFC3339 或 `now-<n><s>`）。
/// 返回 `{ buckets: [{ts, bytes_rx, bytes_tx, conn_count}], count }`。
async fn stats_realtime_handler(
    State(db): State<AppState>,
    Extension(principal): Extension<auth::TokenPrincipal>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scope = read_scope(&principal)?;

    let mut machine_ids: Vec<String> = params
        .get("machine_id")
        .map(|m| m.split(',').filter(|s| !s.is_empty()).map(String::from).collect())
        .unwrap_or_default();

    if let crate::db::query::Scope::Machine(ref mid) = scope {
        machine_ids.retain(|m| m == mid);
        if machine_ids.is_empty() {
            machine_ids.push(mid.clone());
        }
    }

    // 默认查最近 5 分钟
    let start = parse_time_param(
        params.get("start").map(String::as_str),
        chrono::Duration::minutes(5),
    );

    let mut conn = db.lock_writer();
    let resp = crate::db::query::realtime(&mut conn, &machine_ids, &start)
        .map_err(ApiError::from)?;
    Ok(Json(resp))
}

/// rustnetec: `PATCH /admin/hosts/{machine_id}` — 管理员编辑主机部门/用户名。
///
/// 请求体（JSON，任一字段可选）：
/// ```json
/// { "department": "新部门" | null, "username": "新用户名" | null }
/// ```
///
/// **不受 30 分钟约束**（管理员随时可编辑）。
/// - `department=Some(x)` → `department_source='admin'`（锁定，客户端无法覆盖）
/// - `department=null` → `department_source='client'`（放手，客户端可覆盖）
/// - `username=Some(x)` → `username_locked=1`（锁定）
/// - `username=null` → `username_locked=0`（放手）
///
/// 返回更新后的 `HostInfoRow`。
async fn patch_host_handler(
    State(db): State<AppState>,
    axum::extract::Path(machine_id): axum::extract::Path<String>,
    Json(body): Json<PatchHostBody>,
) -> Result<Json<crate::db::query::HostInfoRow>, ApiError> {
    let conn = db.lock_writer();
    let now = chrono::Local::now().to_rfc3339();

    // 构造动态 UPDATE（仅更新请求体中出现的字段）
    let mut sets: Vec<&str> = Vec::new();
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    let mut bind_idx = 1;

    if let Some(ref dept) = body.department {
        sets.push("department = ?");
        binds.push(Box::new(dept.clone()));
        bind_idx += 1;
        // Some(x) → admin 锁定；null → client 放手
        sets.push("department_source = ?");
        binds.push(Box::new("admin".to_string()));
        bind_idx += 1;
        sets.push("department_updated_at = ?");
        binds.push(Box::new(now.clone()));
        bind_idx += 1;
    }

    if let Some(ref uname) = body.username {
        sets.push("username = ?");
        binds.push(Box::new(uname.clone()));
        bind_idx += 1;
        sets.push("username_locked = ?");
        binds.push(Box::new(1i64));
        bind_idx += 1;
        sets.push("username_updated_at = ?");
        binds.push(Box::new(now.clone()));
        bind_idx += 1;
    }

    if sets.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one of 'department' or 'username' must be provided".into(),
        ));
    }

    let sql = format!(
        "UPDATE server_hosts SET {} WHERE machine_id = ?{}",
        sets.join(", "),
        bind_idx
    );
    binds.push(Box::new(machine_id.clone()));

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| ApiError::from(anyhow::Error::from(e)))?;
    let bind_refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
    let updated = stmt
        .execute(bind_refs.as_slice())
        .map_err(|e| ApiError::from(anyhow::Error::from(e)))?;
    drop(stmt);

    if updated == 0 {
        return Err(ApiError::BadRequest(format!(
            "machine_id '{}' not found in server_hosts",
            machine_id
        )));
    }

    // 返回更新后的行
    let row = conn
        .query_row(
            "SELECT machine_id, user_id, username, department, ip_list, \
                    first_seen, last_seen, event_count \
             FROM server_hosts WHERE machine_id = ?1",
            rusqlite::params![&machine_id],
            |r| {
                let ip_json: String = r.get(4)?;
                let ip_list: Vec<String> = serde_json::from_str(&ip_json).unwrap_or_default();
                Ok(crate::db::query::HostInfoRow {
                    machine_id: r.get(0)?,
                    user_id: r.get(1)?,
                    username: r.get(2)?,
                    department: r.get(3)?,
                    ip_list,
                    first_seen: r.get(5)?,
                    last_seen: r.get(6)?,
                    event_count: r.get(7)?,
                })
            },
        )
        .map_err(|e| ApiError::from(anyhow::Error::from(e)))?;

    Ok(Json(row))
}

/// rustnetec: `PATCH /admin/hosts/{machine_id}` 请求体。
///
/// `department`/`username` 均可选（`None` = 不更新该字段）。
/// - `Some(value)` → 更新为该值
/// - `Some(null)` → 清空该字段（serde 层无法区分 `Some(None)` 与 `None`，
///   故用 `Option<Option<String>>`：外层 `None`=未传，内层 `None`=显式 null）
#[derive(Debug, serde::Deserialize)]
struct PatchHostBody {
    #[serde(default, deserialize_with = "deserialize_nullable")]
    department: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable")]
    username: Option<Option<String>>,
}

/// 反序列化器：区分"字段未传"（外层 None）与"字段显式为 null"（内层 None）。
fn deserialize_nullable<'de, D>(de: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(serde::Deserialize::deserialize(de)?))
}

// ---------------------------------------------------------------------------
// Auth middleware (one per role — axum 0.8 `from_fn_with_state` needs a
// concrete function, not a closure returning a layer)
// ---------------------------------------------------------------------------

/// Role re-export so handler signatures stay readable.
pub use auth::AuthRole;

async fn require_ingest(
    State(db): State<AppState>,
    headers: HeaderMap,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let principal = auth::check_auth(State(db), AuthRole::Ingest, &headers)
        .await
        .map_err(ApiError::from)?;
    req.extensions_mut().insert(principal);
    Ok(next.run(req).await)
}

async fn require_query(
    State(db): State<AppState>,
    headers: HeaderMap,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let principal = auth::check_auth(State(db), AuthRole::Query, &headers)
        .await
        .map_err(ApiError::from)?;
    req.extensions_mut().insert(principal);
    Ok(next.run(req).await)
}

/// rustnetec: admin-only middleware (token management endpoints).
async fn require_admin(
    State(db): State<AppState>,
    headers: HeaderMap,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    auth::check_auth(State(db), AuthRole::Admin, &headers)
        .await
        .map_err(ApiError::from)?;
    Ok(next.run(req).await)
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

/// Strict CORS layer. Only `GET`/`POST` are allowed; the browser UI is
/// expected to read via `GET /query` and `GET /stats`, and upload via
/// `POST /ingest` (the client uses a native HTTP client, not CORS).
fn cors_layer() -> tower_http::cors::CorsLayer {
    use axum::http::Method;
    use tower_http::cors::{Any, CorsLayer};

    CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_origin(Any)
        .allow_headers(Any)
}

// ---------------------------------------------------------------------------
// Error envelope
// ---------------------------------------------------------------------------

/// Error envelope that maps cleanly to an HTTP response.
pub enum ApiError {
    Domain(DbError),
    /// Malformed JSON body or other transport-level issue.
    BadRequest(String),
    /// Authentication failed (missing/invalid token).
    Unauthorized,
    /// Authorization failed (token valid, wrong role).
    Forbidden,
    Internal(String),
}

impl From<DbError> for ApiError {
    fn from(e: DbError) -> Self {
        match e {
            DbError::InvalidUserId(_) | DbError::InvalidMachineId(_) => Self::Domain(e),
            DbError::Other(_) => Self::Internal(e.to_string()),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e.to_string())
    }
}

impl From<auth::AuthError> for ApiError {
    fn from(e: auth::AuthError) -> Self {
        match e {
            auth::AuthError::MissingToken | auth::AuthError::InvalidToken => Self::Unauthorized,
            auth::AuthError::Forbidden(_) => Self::Forbidden,
            auth::AuthError::Backend(_) => Self::Internal("auth backend error".into()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::Domain(e) => {
                let (code, m) = e.as_http();
                (code, m)
            }
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".into()),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, msg).into_response()
    }
}

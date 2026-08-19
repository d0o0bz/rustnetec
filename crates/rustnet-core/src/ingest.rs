//! # Shared ingest/query wire protocol (ADR-5)
//!
//! Single source of truth for the client→server upload schema and the
//! server→client query/stats responses. Both [`rustnet_server`] and the
//! `rustnet` binary reference these types so the wire format can never drift
//! between the two sides.
//!
//! All structs derive [`serde::Serialize`] + [`serde::Deserialize`]. Optional
//! fields use `#[serde(skip_serializing_if = "Option::is_none")]` so payloads
//! stay compact when, e.g., K8s metadata is absent.
//!
//! ## Layout
//!
//! - [`IngestRequest`] / [`ClientEvent`] / [`IngestResponse`] — upload channel
//! - [`QueryParams`] / [`QueryResponse`] / [`QueryRow`] — historical query
//! - [`StatsResponse`] / [`AggregateRow`] — aggregate statistics
//! - [`LiveSnapshot`] / [`LiveConnection`] — real-time view (R5)
//! - [`HostIdentity`] / [`K8sFields`] — identity & K8s metadata carried in the
//!   upload payload
//!
//! rustnetec: new module (T2.2).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Host identity (R8/R10) — carried inside every IngestRequest
// ---------------------------------------------------------------------------

/// Host identity block reported by the client (R8 + R10).
///
/// - `username`: OS user name (overridable via config)
/// - `user_id`:  install-level snowflake ID (R10)
/// - `machine_id`: hardware fingerprint, stable across OS reinstalls (R10)
/// - `ip_list`:  currently detected local IPs (dynamic)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostIdentity {
    pub machine_id: String,
    pub user_id: String,
    pub username: String,
    pub ip_list: Vec<String>,
}

// ---------------------------------------------------------------------------
// K8s metadata — optional enrichment on a per-event basis
// ---------------------------------------------------------------------------

/// Kubernetes metadata attached to a connection event when the `kubernetes`
/// feature is enabled (R-related K8s enrichment).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct K8sFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Upload channel: client → server
// ---------------------------------------------------------------------------

/// Batch upload payload sent from the client [`UploadSink`] to
/// `POST /ingest` (R3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestRequest {
    pub machine_id: String,
    pub user_id: String,
    pub username: String,
    pub ip_list: Vec<String>,
    pub events: Vec<ClientEvent>,
    /// rustnetec: 可选部门字段，跟随首次上报一起上传，有变更也需要上报。
    /// 未填写时为 `None`，服务端归类到"未分组"。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// rustnetec: 外网可达率探测样本（决策 A），由客户端可达率探测线程采集后随上报批次一起发送。
    /// 空切片表示本批次无可达率样本。
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub reachability: Vec<ReachabilitySample>,
}

/// rustnetec: 外网可达率探测样本（决策 A —— 客户端上报可达率）。
///
/// 客户端可达率探测线程每轮写入本地 `reachability_probes` 表，
/// 上报线程读取未上报的样本随 `IngestRequest` 一起发送。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilitySample {
    /// 探测时间戳（RFC 3339）。
    pub ts: String,
    /// 本轮是否探测到至少一个可达目标（0/1）。
    pub reachable: i64,
    /// 本轮最快延迟（毫秒）；不可达时为 0。
    pub latency_ms: f64,
    /// 本轮可达目标数。
    pub targets_ok: i64,
    /// 本轮探测目标总数。
    pub targets_total: i64,
}

/// One normalized connection event as uploaded by the client.
///
/// The field set is aligned with the existing `--json-log` output so a local
/// SQLite row and a server-side row carry the same columns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientEvent {
    /// Monotonic client-side event id (for idempotent dedup).
    pub local_event_id: i64,
    pub timestamp: i64,
    pub interface: String,
    pub protocol: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k8s: Option<K8sFields>,
}

/// Server reply to an [`IngestRequest`] (R3/R4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResponse {
    pub accepted: u64,
    pub duplicates: u64,
    /// 本批次成功处理的最大 `local_event_id`（方案 1 双 ID 空间，cursor 推进
    /// 锚定客户端本地自增 id）。客户端收到后据此推进 `upload_cursor`。
    pub cursor: i64,
    /// rustnetec: 服务端当前 department 值，下发客户端同步本地 config。
    ///
    /// - 管理员已锁定（`department_source='admin'`）：下发服务端值，客户端落盘后下次上报携带该值
    /// - 管理员已清空（`department_source='client'`，`department=NULL`）：下发 `None`，客户端不更新
    /// - 客户端覆盖（`department_source='client'`，`department=Some(x)`）：下发 `Some(x)` 确认当前值
    ///
    /// `None` 表示"无变更需下发"（向后兼容旧客户端）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department_override: Option<String>,
    /// rustnetec: 服务端当前 username 值，下发客户端同步本地 config。
    ///
    /// 语义同 [`IngestResponse::department_override`]：
    /// - `username_locked=1`（admin 锁定）：下发服务端值
    /// - `username_locked=0`（client 可覆盖）：下发当前值确认
    ///
    /// `None` 表示"无变更需下发"。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username_override: Option<String>,
}

// ---------------------------------------------------------------------------
// Historical query channel: server → client
// ---------------------------------------------------------------------------

/// Query-string parameters accepted by `GET /query`.
///
/// All fields optional; defaults are server-defined (most-recent N rows).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryParams {
    /// Inclusive lower bound (unix millis).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<i64>,
    /// Exclusive upper bound (unix millis).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<i64>,
    /// Free-text filter (same syntax as the TUI filter).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    /// Raw SQL fragment for power users; ignored when `filter` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql: Option<String>,
    /// Max rows to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// One row returned by `GET /query` — mirrors [`ClientEvent`] plus server-side
/// bookkeeping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRow {
    pub server_event_id: i64,
    pub local_event_id: i64,
    pub machine_id: String,
    pub user_id: String,
    #[serde(flatten)]
    pub event: ClientEvent,
}

/// Envelope returned by `GET /query`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    pub rows: Vec<QueryRow>,
}

// ---------------------------------------------------------------------------
// Aggregate statistics channel: server → client
// ---------------------------------------------------------------------------

/// One pre-aggregated bucket (per-minute or per-hour).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateRow {
    pub bucket: i64,
    pub machine_id: String,
    pub protocol: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub connection_count: u64,
}

/// Envelope returned by `GET /stats`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsResponse {
    pub total_events: u64,
    pub total_bytes: u64,
    /// Per-host breakdown.
    pub hosts: Vec<HostStats>,
}

/// Per-host stats entry nested inside [`StatsResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostStats {
    pub machine_id: String,
    pub user_id: String,
    pub username: String,
    pub event_count: u64,
    pub bytes_total: u64,
}

// ---------------------------------------------------------------------------
// Real-time live snapshot channel (R5)
// ---------------------------------------------------------------------------

/// Snapshot of currently-live connections, served by `GET /live` on the
/// client's loopback HTTP (R5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveSnapshot {
    pub timestamp: i64,
    pub connections: Vec<LiveConnection>,
}

/// One live connection as exposed over the local HTTP `/live` endpoint.
///
/// Field set aligned with the TUI's connection table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveConnection {
    pub protocol: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k8s: Option<K8sFields>,
    /// Free-form metadata bag for forward-compat (extra columns the TUI adds
    /// later). Values are JSON scalars.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Liveness (used by both client loopback and server)
// ---------------------------------------------------------------------------

/// Reply for `GET /health`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

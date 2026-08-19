// rustnetec: UploadSink — client→server data upload (R3, T2.6)
//
// 上报线程模型:
// - 独立 std::thread (name="upload"), 与抓包/TUI/托盘线程完全隔离
// - ureq 阻塞式 HTTP, 60s 超时
// - 独立只读连接查 connection_events, 独立写连接推进 upload_cursor
//   (SqliteSink 的 writer 连接被其写线程独占; WAL 下并发安全)
// - ip_list 每次上报前重新探测 (动态采集)
// - 仅 daemon/tray 模式且 server_url 已配置时启动
//
// rustnetec: 退避策略（连续失败降级）
// - 连续失败 20 次 → 降级为每 3 分钟尝试一次
// - 再连续失败 20 次 → 降级为每 6 分钟尝试一次
// - 任意上报成功（Ok(true) 或 Ok(false)）→ 恢复原上报频率
//
// rustnetec: 部门 + 可达率上报
// - 每次构造 IngestRequest 前从 PersistentConfig 读取 department
// - 从本地 reachability_probes 表读取未上报的可达率样本
// - 收到 IngestResponse.department_override 后落盘 PersistentConfig

use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{info, warn};
use rusqlite::{Connection, params};

use rustnet_core::ingest::{ClientEvent, IngestRequest, IngestResponse, ReachabilitySample};

use crate::config::{PersistentConfig, RuntimeConfig};
use crate::telemetry::ConnectionEventData;
use crate::telemetry::db::SqliteSink;
use crate::telemetry::identity::HostIdentity;

/// HTTP 请求超时 (秒)。服务端 hang 时不让上报线程永久阻塞。
const REQUEST_TIMEOUT_SECS: u64 = 60;

/// rustnetec: 退避降级阈值（连续失败次数）。
const FAIL_THRESHOLD_1: u32 = 20;
/// rustnetec: 第二级降级阈值（降级后再次连续失败次数）。
const FAIL_THRESHOLD_2: u32 = 20;
/// rustnetec: 第一级降级间隔（3 分钟）。
const DEGRADED_INTERVAL_1_SECS: u64 = 180;
/// rustnetec: 第二级降级间隔（6 分钟）。
const DEGRADED_INTERVAL_2_SECS: u64 = 360;

/// 客户端→服务端数据上报器。
///
/// 持有本地数据库路径、共享运行时配置与主机身份。上报线程在
/// [`UploadSink::spawn`] 中启动, 返回的 `JoinHandle` 用于优雅关闭。
pub struct UploadSink {
    db_path: std::path::PathBuf,
    runtime_config: Arc<RwLock<RuntimeConfig>>,
    identity: HostIdentity,
}

impl UploadSink {
    /// 构造一个新的 UploadSink。`identity` 的 ip_list 会在每次上报前刷新。
    pub fn new(
        db_path: std::path::PathBuf,
        runtime_config: Arc<RwLock<RuntimeConfig>>,
        mut identity: HostIdentity,
    ) -> Self {
        // 启动前先采集一次, 避免首报 ip_list 为空。
        identity.refresh_ip_list();
        // rustnetec: 从 config 读取 department 填入 identity。
        if let Ok(pc) = PersistentConfig::load() {
            identity.department = pc.department;
        }
        Self {
            db_path,
            runtime_config,
            identity,
        }
    }

    /// 启动上报线程, 返回其句柄。线程在 `should_stop` 为真时退出。
    ///
    /// 调用方需在 daemon/tray 模式且 `server_url` 已配置时才调用此方法。
    pub fn spawn(
        self,
        should_stop: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<thread::JoinHandle<()>> {
        use std::sync::atomic::Ordering;

        let handle = thread::Builder::new()
            .name("upload".to_string())
            .spawn(move || {
                info!("Upload thread started (db: {})", self.db_path.display());

                // rustnetec: 退避状态机
                // - degrade_level: 0=正常, 1=3min降级, 2=6min降级
                // - consecutive_failures: 当前级别下连续失败计数
                let mut degrade_level: u32 = 0;
                let mut consecutive_failures: u32 = 0;

                // 开独立的只读连接查 events, 开独立的写连接推进 cursor。
                // 两者与 SqliteSink 的 writer 通过 WAL 并发, 互不阻塞。
                let read_conn = match SqliteSink::open_read_only(&self.db_path) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("Upload thread: failed to open read connection: {e:#}");
                        return;
                    }
                };
                let write_conn = match rusqlite::Connection::open(&self.db_path) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("Upload thread: failed to open write connection: {e:#}");
                        return;
                    }
                };

                while !should_stop.load(Ordering::Relaxed) {
                    // rustnetec: 计算当前等待间隔
                    // - degrade_level=0: 正常间隔（upload_interval_secs）
                    // - degrade_level=1: 3 分钟
                    // - degrade_level=2: 6 分钟
                    let interval_secs: u64 = match degrade_level {
                        0 => self
                            .runtime_config
                            .read()
                            .map(|r| r.upload_interval_secs as u64)
                            .unwrap_or(60),
                        1 => DEGRADED_INTERVAL_1_SECS,
                        _ => DEGRADED_INTERVAL_2_SECS,
                    };
                    let batch_size = self
                        .runtime_config
                        .read()
                        .map(|r| r.upload_batch_size)
                        .unwrap_or(500);

                    // sleep interval (但每秒检查 should_stop, 以便及时退出)
                    for _ in 0..interval_secs.max(1) {
                        if should_stop.load(Ordering::Relaxed) {
                            break;
                        }
                        thread::sleep(Duration::from_secs(1));
                    }
                    if should_stop.load(Ordering::Relaxed) {
                        break;
                    }

                    // 读 server_url / server_token; 若中途清空则跳过本轮
                    let (server_url, server_token) = {
                        let rc = self
                            .runtime_config
                            .read()
                            .unwrap_or_else(|e| e.into_inner());
                        (rc.server_url.clone(), rc.server_token.clone())
                    };
                    let Some(url) = server_url else {
                        // 未配置服务端, 跳过 (不降级, 下次 interval 再看)
                        continue;
                    };
                    if server_token.is_none() {
                        warn!(
                            "Upload thread: server_url set but server_token missing, skipping batch"
                        );
                        continue;
                    }
                    let token = server_token.unwrap();

                    match self.run_one_batch(&read_conn, &write_conn, &url, &token, batch_size) {
                        Ok(true) => {
                            // 成功或有进展 → 恢复原上报频率
                            if degrade_level > 0 {
                                info!(
                                    "Upload recovered after {} failures, restoring normal interval",
                                    consecutive_failures
                                );
                            }
                            degrade_level = 0;
                            consecutive_failures = 0;
                        }
                        Ok(false) => {
                            // 无可上报数据 → 恢复原上报频率
                            degrade_level = 0;
                            consecutive_failures = 0;
                        }
                        Err(e) => {
                            consecutive_failures += 1;
                            // rustnetec: 降级判定
                            if degrade_level == 0 && consecutive_failures >= FAIL_THRESHOLD_1 {
                                degrade_level = 1;
                                warn!(
                                    "Upload failed {} times, degrading to {}s interval: {e:#}",
                                    consecutive_failures, DEGRADED_INTERVAL_1_SECS
                                );
                                consecutive_failures = 0;
                            } else if degrade_level == 1
                                && consecutive_failures >= FAIL_THRESHOLD_2
                            {
                                degrade_level = 2;
                                warn!(
                                    "Upload failed {} times at degraded level 1, \
                                     further degrading to {}s interval: {e:#}",
                                    consecutive_failures, DEGRADED_INTERVAL_2_SECS
                                );
                                consecutive_failures = 0;
                            } else {
                                warn!(
                                    "Upload batch failed (level={}, failures={}): {e:#}",
                                    degrade_level, consecutive_failures
                                );
                            }
                        }
                    }
                }
                info!("Upload thread exiting");
            })?;
        Ok(handle)
    }

    /// 执行一批上报。返回 `Ok(true)` 表示有数据被上报, `Ok(false)` 表示无待上报数据。
    fn run_one_batch(
        &self,
        read_conn: &Connection,
        write_conn: &Connection,
        server_url: &str,
        server_token: &str,
        batch_size: u32,
    ) -> Result<bool> {
        // 1. 读 upload_cursor
        let cursor = SqliteSink::read_upload_cursor(read_conn)?;

        // 2. 查待上报 events
        let rows = SqliteSink::query_events_for_upload(read_conn, cursor, batch_size)?;
        if rows.is_empty() {
            return Ok(false);
        }

        // 3. 刷新 ip_list (动态采集) + 从 config 读 department
        let mut identity = self.identity.clone();
        identity.refresh_ip_list();
        // rustnetec: 每次上报前从 config 重新读取 department（支持客户端 WebUI 编辑）
        if let Ok(pc) = PersistentConfig::load() {
            identity.department = pc.department.clone();
            // 同步 username（支持服务端下发 override 后客户端下次上报携带新值）
            identity.username = pc.username.clone().unwrap_or_else(|| identity.username.clone());
        }

        // 4. 映射 ConnectionEventData → ClientEvent, 构造 IngestRequest
        let events: Vec<ClientEvent> = rows
            .iter()
            .map(|(id, ev)| map_event_to_client_event(*id, ev))
            .collect();
        let max_id = rows.last().map(|(id, _)| *id).unwrap_or(cursor);

        // rustnetec: 读取本地未上报的可达率样本
        let reachability = read_reachability_samples(read_conn)?;

        let req = IngestRequest {
            machine_id: identity.machine_id.clone(),
            user_id: identity.user_id.to_string(),
            username: identity.username.clone(),
            ip_list: identity.ip_list.clone(),
            events,
            department: identity.department.clone(),
            reachability,
        };

        // 5. ureq 阻塞式 POST, 60s 超时
        let resp = ureq::post(server_url)
            .set("Authorization", &format!("Bearer {server_token}"))
            .set("Content-Type", "application/json")
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .send_json(serde_json::to_value(&req)?);

        match resp {
            Ok(response) => {
                let ingest_resp: IngestResponse = response
                    .into_json()
                    .context("failed to parse IngestResponse")?;
                // 6. 推进 upload_cursor 到本批次 max id
                //    (服务端幂等去重, 即使部分重复也安全推进)
                SqliteSink::advance_upload_cursor(write_conn, max_id)?;

                // rustnetec: 7. 标记可达率样本已上报（删除已上报的样本）
                mark_reachability_reported(write_conn, &ingest_resp)?;

                // rustnetec: 8. 处理 department_override / username_override，落盘 config
                self.apply_server_overrides(&ingest_resp)?;

                info!(
                    "Upload batch OK: accepted={}, duplicates={}, cursor advanced to {}",
                    ingest_resp.accepted, ingest_resp.duplicates, max_id
                );
                Ok(true)
            }
            Err(e) => Err(anyhow::anyhow!("ureq POST /ingest failed: {e}")),
        }
    }

    /// rustnetec: 处理服务端下发的 department_override / username_override。
    ///
    /// 若 override 与当前 config 不同，则落盘 PersistentConfig。
    /// 下次上报线程会从 config 读取新值。
    fn apply_server_overrides(&self, resp: &IngestResponse) -> Result<()> {
        let mut pc = PersistentConfig::load().unwrap_or_default();
        let mut changed = false;

        if let Some(ref dept) = resp.department_override {
            if pc.department.as_deref() != Some(dept.as_str()) {
                info!(
                    "Applying server department_override: {:?} → {:?}",
                    pc.department, dept
                );
                pc.department = Some(dept.clone());
                changed = true;
            }
        }

        if let Some(ref uname) = resp.username_override {
            if pc.username.as_deref() != Some(uname.as_str()) {
                info!(
                    "Applying server username_override: {:?} → {:?}",
                    pc.username, uname
                );
                pc.username = Some(uname.clone());
                changed = true;
            }
        }

        if changed {
            pc.save().context("failed to save config after override")?;
        }

        Ok(())
    }
}

/// rustnetec: 从本地 `reachability_probes` 表读取未上报的可达率样本。
///
/// 表结构（由 `reachability.rs::start_reachability_probe` 创建）：
/// `ts TEXT PRIMARY KEY, reachable INTEGER, latency_ms REAL, targets_ok INTEGER, targets_total INTEGER`
///
/// 读取所有样本（客户端本地保留，上报后不删除，服务端按 (machine_id, ts) 幂等去重）。
fn read_reachability_samples(conn: &Connection) -> Result<Vec<ReachabilitySample>> {
    // 先检查表是否存在（可达率探测可能未启用）
    let table_exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='reachability_probes'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    if table_exists == 0 {
        return Ok(Vec::new());
    }

    let mut stmt = conn.prepare(
        "SELECT ts, reachable, latency_ms, targets_ok, targets_total \
         FROM reachability_probes ORDER BY ts ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(ReachabilitySample {
            ts: r.get(0)?,
            reachable: r.get(1)?,
            latency_ms: r.get(2)?,
            targets_ok: r.get(3)?,
            targets_total: r.get(4)?,
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// rustnetec: 标记可达率样本已上报。
///
/// 当前实现：上报成功后不做任何操作（客户端本地保留样本，服务端按
/// (machine_id, ts) 幂等去重，重复上报不会产生重复数据）。
///
/// 若未来需要"已上报样本本地清理"以控制本地 DB 体积，可在此处
/// `DELETE FROM reachability_probes WHERE ts <= ?`（需服务端返回 max reported ts）。
fn mark_reachability_reported(
    _write_conn: &Connection,
    _resp: &IngestResponse,
) -> Result<()> {
    // No-op: 服务端幂等去重，客户端本地保留样本供 WebUI 可达率图表查询。
    Ok(())
}

/// 将本地 `ConnectionEventData` 映射为上报协议的 `ClientEvent`。
///
/// 字段名差异对齐:
/// - `source_ip`/`source_port`      → `local_ip`/`local_port`
/// - `destination_ip`/`destination_port` → `remote_ip`/`remote_port`
/// - `destination_hostname`         → `dns_name`
/// - `dpi_domain`                   → `sni`
/// - `bytes_sent`/`bytes_received`/`duration_secs` (Option) → 零值兜底
/// - `timestamp` (RFC 3339 字符串)  → `timestamp` (unix millis i64)
fn map_event_to_client_event(local_event_id: i64, ev: &ConnectionEventData) -> ClientEvent {
    ClientEvent {
        local_event_id,
        timestamp: parse_ts_to_millis(&ev.timestamp).unwrap_or(0),
        // rustnetec: T-A5 — 从 ConnectionEventData.interface 取捕获网口名。
        interface: ev.interface.clone().unwrap_or_default(),
        protocol: ev.protocol.clone(),
        local_ip: ev.source_ip.clone(),
        local_port: ev.source_port,
        remote_ip: ev.destination_ip.clone(),
        remote_port: ev.destination_port,
        state: ev.event.clone(),
        pid: ev.pid,
        process_name: ev.process_name.clone(),
        bytes_sent: ev.bytes_sent.unwrap_or(0),
        bytes_recv: ev.bytes_received.unwrap_or(0),
        packets_sent: 0, // 本地 schema 未存 packets 列
        packets_recv: 0,
        duration_ms: ev.duration_secs.map(|s| s * 1000).unwrap_or(0),
        service: ev.service_name.clone(),
        sni: ev.dpi_domain.clone(),
        geo_country: ev.geoip_country_code.clone(),
        geo_city: ev.geoip_city.clone(),
        dns_name: ev.destination_hostname.clone(),
        k8s: None, // K8s 由编译期 feature 控制, 单独路径处理
    }
}

/// 解析 RFC 3339 时间戳为 Unix 毫秒。失败返回 None。
fn parse_ts_to_millis(ts: &str) -> Option<i64> {
    Some(
        chrono::DateTime::parse_from_rfc3339(ts)
            .ok()?
            .timestamp_millis(),
    )
}

// Suppress unused import warning for `params` (reserved for future use).
#[allow(dead_code)]
fn _unused_params() {
    let _ = params![1i64];
}

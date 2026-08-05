// rustnetec: UploadSink — client→server data upload (R3, T2.6)
//
// 上报线程模型:
// - 独立 std::thread (name="upload"), 与抓包/TUI/托盘线程完全隔离
// - ureq 阻塞式 HTTP, 60s 超时, 失败指数退避 (base 2s, cap 5min)
// - 独立只读连接查 connection_events, 独立写连接推进 upload_cursor
//   (SqliteSink 的 writer 连接被其写线程独占; WAL 下并发安全)
// - ip_list 每次上报前重新探测 (动态采集)
// - 仅 daemon/tray 模式且 server_url 已配置时启动

use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{info, warn};
use rusqlite::Connection;

use rustnet_core::ingest::{ClientEvent, IngestRequest, IngestResponse};

use crate::config::RuntimeConfig;
use crate::telemetry::ConnectionEventData;
use crate::telemetry::db::SqliteSink;
use crate::telemetry::identity::HostIdentity;

/// HTTP 请求超时 (秒)。服务端 hang 时不让上报线程永久阻塞。
const REQUEST_TIMEOUT_SECS: u64 = 60;

/// 指数退避基准 (秒)。
const BACKOFF_BASE_SECS: u64 = 2;

/// 指数退避上限 (秒)。失败后最多等 5 分钟再重试同批次。
const BACKOFF_CAP_SECS: u64 = 300;

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
                let mut backoff_secs = BACKOFF_BASE_SECS;

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
                    // 读取上报间隔; 配置热更新立即生效。
                    let interval_secs = self
                        .runtime_config
                        .read()
                        .map(|r| r.upload_interval_secs)
                        .unwrap_or(60);
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
                        // 未配置服务端, 跳过 (不打退避, 下次 interval 再看)
                        backoff_secs = BACKOFF_BASE_SECS;
                        continue;
                    };
                    if server_token.is_none() {
                        warn!(
                            "Upload thread: server_url set but server_token missing, skipping batch"
                        );
                        backoff_secs = BACKOFF_BASE_SECS;
                        continue;
                    }
                    let token = server_token.unwrap();

                    match self.run_one_batch(&read_conn, &write_conn, &url, &token, batch_size) {
                        Ok(true) => {
                            // 成功或有进展, 重置退避
                            backoff_secs = BACKOFF_BASE_SECS;
                        }
                        Ok(false) => {
                            // 无可上报数据, 重置退避
                            backoff_secs = BACKOFF_BASE_SECS;
                        }
                        Err(e) => {
                            warn!("Upload batch failed, backing off {}s: {e:#}", backoff_secs);
                            // 退避等待 (每秒检查 should_stop)
                            for _ in 0..backoff_secs {
                                if should_stop.load(Ordering::Relaxed) {
                                    break;
                                }
                                thread::sleep(Duration::from_secs(1));
                            }
                            backoff_secs = (backoff_secs * 2).min(BACKOFF_CAP_SECS);
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

        // 3. 刷新 ip_list (动态采集)
        let mut identity = self.identity.clone();
        identity.refresh_ip_list();

        // 4. 映射 ConnectionEventData → ClientEvent, 构造 IngestRequest
        let events: Vec<ClientEvent> = rows
            .iter()
            .map(|(id, ev)| map_event_to_client_event(*id, ev))
            .collect();
        let max_id = rows.last().map(|(id, _)| *id).unwrap_or(cursor);

        let req = IngestRequest {
            machine_id: identity.machine_id.clone(),
            user_id: identity.user_id.to_string(),
            username: identity.username.clone(),
            ip_list: identity.ip_list.clone(),
            events,
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
                info!(
                    "Upload batch OK: accepted={}, duplicates={}, cursor advanced to {}",
                    ingest_resp.accepted, ingest_resp.duplicates, max_id
                );
                Ok(true)
            }
            Err(e) => Err(anyhow::anyhow!("ureq POST /ingest failed: {e}")),
        }
    }
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
        interface: String::new(), // 本地 schema 未存 interface 列, 留空
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

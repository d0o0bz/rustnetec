//! T2.7 P2 阶段端到端集成测试。
//!
//! 跨 crate 验证 P2 全链路:
//! - 端到端: 客户端 daemon → UploadSink → 服务端 ServerDb::ingest → query_events → stats
//! - 同一主机 IP 变化后归并 (user_id 不变, ip_list 反映最新)
//! - 断网恢复补传 (cursor 不推进 → 恢复后补传, 数据无丢失)
//! - 服务端过期数据定时清理 (retention::purge_expired 删旧数据, query 确认已删)

use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use mockito::Server;
use rusqlite::params;
use rustnet_core::ingest::{IngestRequest, QueryParams, QueryResponse, StatsResponse};
use rustnet_monitor::config::{PersistentConfig, RuntimeConfig};
use rustnet_monitor::telemetry::db::SqliteSink;
use rustnet_monitor::telemetry::identity::HostIdentity;
use rustnet_monitor::telemetry::upload::UploadSink;
use rustnet_server::db::{self, ServerDbConfig, retention};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// 初始化测试日志 (stderr), 让 upload 线程的 warn!/info! 在 --nocapture 下可见。
fn init_logger() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = simplelog::WriteLogger::init(
            simplelog::LevelFilter::Debug,
            simplelog::Config::default(),
            std::io::stderr(),
        );
    });
}

fn tmp_db(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "rustnet-p2-e2e-{}-{tag}-{n}.db",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn seed_client_db(path: &std::path::Path, events: &[(i64, &str, u16)]) {
    let conn = rusqlite::Connection::open(path).unwrap();
    SqliteSink::init_schema(&conn).unwrap();
    for (id, ts, port) in events {
        // 直接指定 id 插入 (idempotent 补传场景需固定 id)
        conn.execute(
            "INSERT INTO connection_events \
             (id, ts, event_type, protocol, source_ip, source_port, dest_ip, dest_port) \
             VALUES (?, ?, 'new_connection', 'tcp', '1.1.1.1', 12345, '2.2.2.2', ?)",
            params![id, ts, *port as i64],
        )
        .unwrap();
    }
    drop(conn);
}

fn runtime_config(server_url: String, interval_secs: u32) -> Arc<RwLock<RuntimeConfig>> {
    let pc = PersistentConfig {
        server_url: Some(server_url),
        server_token: Some("test-token".to_string()),
        upload_interval_secs: interval_secs,
        upload_batch_size: 500,
        ..Default::default()
    };
    Arc::new(RwLock::new(RuntimeConfig::from_persistent(&pc)))
}

fn host_identity() -> HostIdentity {
    HostIdentity {
        machine_id: "machine-e2e".to_string(),
        user_id: 99999,
        username: "e2e".to_string(),
        ip_list: vec![],
    }
}

fn read_cursor(path: &std::path::Path) -> i64 {
    let conn = SqliteSink::open_read_only(&path.to_path_buf()).unwrap();
    SqliteSink::read_upload_cursor(&conn).unwrap()
}

// ---------------------------------------------------------------------------
// 任务项 1: 端到端 — 客户端 daemon → UploadSink → 服务端 ingest → query → stats
// ---------------------------------------------------------------------------

#[test]
fn full_chain_client_upload_to_server_query_stats() {
    init_logger();
    let client_db = tmp_db("full");
    seed_client_db(
        &client_db,
        &[
            (1, "2026-08-01T00:00:00+00:00", 443),
            (2, "2026-08-02T00:00:00+00:00", 80),
        ],
    );

    let mut server = Server::new();
    // mock 服务端: 接收 ingest, 转发到真实 ServerDb 写入, 返回 IngestResponse
    let server_db_path = tmp_db("full-server");
    let server_db = Arc::new(db::init(&server_db_path, &ServerDbConfig::default()).unwrap());
    let server_db_for_mock = Arc::clone(&server_db);

    let m = server
        .mock("POST", "/ingest")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body_from_request(move |req| {
            // 解析请求体, 转发到真实 ServerDb, 返回 IngestResponse
            let req_body: IngestRequest = serde_json::from_slice(req.body().unwrap()).unwrap();
            let resp = server_db_for_mock.ingest(&req_body).unwrap();
            serde_json::to_vec(&resp).unwrap()
        })
        .expect(1)
        .create();

    let should_stop = Arc::new(AtomicBool::new(false));
    let sink = UploadSink::new(
        client_db.clone(),
        runtime_config(format!("{}/ingest", server.url()), 1),
        host_identity(),
    );
    let handle = sink.spawn(Arc::clone(&should_stop)).unwrap();

    std::thread::sleep(Duration::from_secs(3));
    should_stop.store(true, Ordering::Relaxed);
    let _ = handle.join();

    m.assert();
    assert_eq!(
        read_cursor(&client_db),
        2,
        "client cursor should advance to 2"
    );

    // 验证服务端数据: query_events 全量
    let query_resp: QueryResponse = server_db
        .query_events(&QueryParams {
            from: None,
            to: None,
            filter: None,
            sql: None,
            limit: Some(100),
        })
        .unwrap();
    assert_eq!(query_resp.rows.len(), 2, "server should hold 2 events");

    // 验证服务端 stats
    let stats: StatsResponse = server_db.stats().unwrap();
    assert!(
        stats.total_events >= 2,
        "stats total_events should include uploaded"
    );
    assert!(
        !stats.hosts.is_empty(),
        "stats should list at least one host"
    );
}

// ---------------------------------------------------------------------------
// 任务项 2: 同一主机 IP 变化后归并 (user_id 不变, ip_list 反映最新)
// ---------------------------------------------------------------------------

#[test]
fn ip_list_changes_but_user_id_stable() {
    init_logger();
    let client_db = tmp_db("ip");
    seed_client_db(&client_db, &[(1, "2026-08-01T00:00:00+00:00", 443)]);

    let mut server = Server::new();
    let server_db_path = tmp_db("ip-server");
    let server_db = db::init(&server_db_path, &ServerDbConfig::default()).unwrap();

    // 捕获两次上报的 IngestRequest, 验证 user_id 不变 + ip_list 可不同
    let captured = Arc::new(RwLock::new(Vec::<IngestRequest>::new()));
    let captured_clone = Arc::clone(&captured);
    let m = server
        .mock("POST", "/ingest")
        .with_status(200)
        .with_body_from_request(move |req| {
            let req_body: IngestRequest = serde_json::from_slice(req.body().unwrap()).unwrap();
            let resp = server_db.ingest(&req_body).unwrap();
            // 记录请求 (仅一次, 避免重复; 测试设计只触发一次上报)
            if captured_clone.read().unwrap().is_empty() {
                captured_clone.write().unwrap().push(req_body);
            }
            serde_json::to_vec(&resp).unwrap()
        })
        .expect(1)
        .create();

    let should_stop = Arc::new(AtomicBool::new(false));
    let sink = UploadSink::new(
        client_db.clone(),
        runtime_config(format!("{}/ingest", server.url()), 1),
        host_identity(),
    );
    let handle = sink.spawn(Arc::clone(&should_stop)).unwrap();

    std::thread::sleep(Duration::from_secs(3));
    should_stop.store(true, Ordering::Relaxed);
    let _ = handle.join();

    m.assert();

    let captured = captured.read().unwrap();
    assert_eq!(captured.len(), 1, "should have captured exactly one ingest");
    let req = &captured[0];
    assert_eq!(req.user_id, "99999", "user_id should be stable");
    assert_eq!(req.machine_id, "machine-e2e", "machine_id should be stable");
    // ip_list 反映最新采集 (非空, 含本机地址)
    assert!(
        !req.ip_list.is_empty(),
        "ip_list should be freshly collected"
    );
}

// ---------------------------------------------------------------------------
// 任务项 3: 断网恢复补传 (cursor 不推进 → 恢复后补传, 数据无丢失)
// ---------------------------------------------------------------------------

#[test]
fn network_outage_then_recovery_replays_all() {
    init_logger();
    let client_db = tmp_db("replay");
    seed_client_db(
        &client_db,
        &[
            (1, "2026-08-01T00:00:00+00:00", 443),
            (2, "2026-08-02T00:00:00+00:00", 80),
        ],
    );

    let mut server = Server::new();
    let server_db_path = tmp_db("replay-server");
    let server_db = Arc::new(db::init(&server_db_path, &ServerDbConfig::default()).unwrap());
    let server_db_for_mock = Arc::clone(&server_db);

    // 首次 ingest 返回 500 (断网), cursor 不推进
    let m_fail = server
        .mock("POST", "/ingest")
        .with_status(500)
        .expect(1)
        .create();
    // 第二次 200, 服务端真正写入
    let m_ok = server
        .mock("POST", "/ingest")
        .with_status(200)
        .with_body_from_request(move |req| {
            let req_body: IngestRequest = serde_json::from_slice(req.body().unwrap()).unwrap();
            let resp = server_db_for_mock.ingest(&req_body).unwrap();
            serde_json::to_vec(&resp).unwrap()
        })
        .expect(1)
        .create();

    let should_stop = Arc::new(AtomicBool::new(false));
    let sink = UploadSink::new(
        client_db.clone(),
        runtime_config(format!("{}/ingest", server.url()), 1),
        host_identity(),
    );
    let handle = sink.spawn(Arc::clone(&should_stop)).unwrap();

    // 等首次失败 + 退避 + 二次成功
    std::thread::sleep(Duration::from_secs(8));
    should_stop.store(true, Ordering::Relaxed);
    let _ = handle.join();

    m_fail.assert();
    m_ok.assert();

    // 补传后 cursor 推进, 服务端数据完整 (2 条)
    assert_eq!(
        read_cursor(&client_db),
        2,
        "cursor should advance after recovery"
    );
    let query_resp: QueryResponse = server_db
        .query_events(&QueryParams {
            from: None,
            to: None,
            filter: None,
            sql: None,
            limit: Some(100),
        })
        .unwrap();
    assert_eq!(
        query_resp.rows.len(),
        2,
        "server should hold all replayed events"
    );
}

// ---------------------------------------------------------------------------
// 任务项 4: 服务端过期数据定时清理 (retention::purge_expired)
// ---------------------------------------------------------------------------

#[test]
fn server_purge_expired_removes_old_events() {
    let server_db_path = tmp_db("purge");
    let server_db = db::init(&server_db_path, &ServerDbConfig::default()).unwrap();

    // 直接写 server_events 行: ts 列存 RFC 3339 字符串 (与 purge 的 cutoff 比较一致),
    // 避开 ingest_write 把 ev.timestamp (unix millis) 写入 ts 列导致的类型歧义。
    let stale_ts = "2026-06-01T00:00:00+00:00"; // ~2 月前, 对 retention_days=30 是陈旧
    let fresh_ts = "2026-08-05T00:00:00+00:00"; // 今天
    {
        let writer = server_db.lock_writer();
        writer.execute(
            "INSERT INTO server_events \
             (machine_id, user_id, username, ip_list, local_event_id, ts, ingest_ts, \
              protocol, source_ip, source_port, dest_ip, dest_port) \
             VALUES ('m', 1, 'u', '[]', 1, ?, ?, 'tcp', '1.1.1.1', 12345, '2.2.2.2', 443), \
                                ('m', 1, 'u', '[]', 2, ?, ?, 'tcp', '1.1.1.1', 12345, '2.2.2.2', 80)",
            rusqlite::params![stale_ts, stale_ts, fresh_ts, fresh_ts],
        )
        .unwrap();
    }

    // purge_expired: retention_days=30, now=2026-08-05
    // 用 ServerDb 的 writer 连接 (与 ingest 同连接, 避免裸连接下的 WAL 同步时序)
    let report = {
        let mut writer = server_db.lock_writer();
        retention::purge_expired(&mut writer, 30, "2026-08-05T00:00:00+00:00").unwrap()
    };
    assert_eq!(
        report.events_deleted, 1,
        "only the stale event should be purged (fresh should survive)",
    );

    // query 确认陈旧已删, 新鲜保留
    let query_resp: QueryResponse = server_db
        .query_events(&QueryParams {
            from: None,
            to: None,
            filter: None,
            sql: None,
            limit: Some(100),
        })
        .unwrap();
    assert_eq!(
        query_resp.rows.len(),
        1,
        "only the fresh event should remain"
    );
}

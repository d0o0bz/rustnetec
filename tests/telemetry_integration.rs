// rustnetec: P1 集成测试 (偏差4 / T1.9)
//
// 覆盖 SDD tasks T1.9 要求的端到端场景：
//   1. daemon 持久化路径：SqliteSink 写入 → 只读连接查询
//   2. HTTP 端点冒烟（/live + /query + /stats）的数据库层
//   3. 身份跨重启稳定（user_id/machine_id）
//   4. 清理逻辑：过期已上传删除、未上传暂留
//
// 测试通过 rustnet_monitor::telemetry 公开 API 驱动，不启动真实抓包，
// 因此可在无 root、无网卡抓包权限的 CI 环境运行。

use rusqlite::{Connection, OpenFlags};
use rustnet_monitor::config::{PersistentConfig, RuntimeConfig};
use rustnet_monitor::telemetry::identity::HostIdentity;
use rustnet_monitor::telemetry::paths;
use std::sync::{Arc, RwLock};
use std::time::Duration;

// ---- 共用辅助 ----

fn test_runtime_config() -> Arc<RwLock<RuntimeConfig>> {
    Arc::new(RwLock::new(RuntimeConfig::from_persistent(
        &PersistentConfig::default(),
    )))
}

/// 打开只读连接（与 query.rs / http.rs 的查询路径一致）。
fn open_read_only(path: &std::path::Path) -> Connection {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("failed to open read-only connection")
}

// ---- T1.9.1 持久化 + 查询冒烟 ----

#[test]
fn sqlite_sink_persists_and_query_reads_back() {
    use rustnet_monitor::telemetry::{ConnectionEventData, ConnectionEventSink};
    use rustnet_monitor::telemetry::db::SqliteSink;

    let tmp = std::env::temp_dir().join("rustnetec-it-persist");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let db_path = tmp.join("data.db");

    {
        let sink = SqliteSink::new(Some(db_path.clone()), test_runtime_config())
            .expect("SqliteSink::new");

        let event = ConnectionEventData {
            timestamp: chrono::Local::now().to_rfc3339(),
            event: "new_connection".to_string(),
            protocol: "TCP".to_string(),
            source_ip: "192.168.1.10".to_string(),
            source_port: 54321,
            destination_ip: "93.184.216.34".to_string(),
            destination_port: 443,
            destination_hostname: Some("example.com".to_string()),
            source_hostname: None,
            pid: Some(4321),
            process_ppid: None,
            process_name: Some("curl".to_string()),
            process_executable: None,
            process_uid: None,
            process_gid: None,
            attribution_match: None,
            rtt_ms: Some(8.4),
            #[cfg(feature = "kubernetes")]
            kubernetes: None,
            service_name: Some("https".to_string()),
            direction: Some("outgoing".to_string()),
            dpi_protocol: Some("HTTPS".to_string()),
            dpi_domain: Some("example.com".to_string()),
            geoip_country_code: Some("US".to_string()),
            geoip_country_name: None,
            geoip_asn: None,
            geoip_as_org: None,
            geoip_city: None,
            geoip_postal_code: None,
            bytes_sent: None,
            bytes_received: None,
            duration_secs: None,
        };
        sink.accept(&event);

        // 给写入线程一点时间攒批刷盘
        std::thread::sleep(Duration::from_millis(800));
    } // drop sink → Shutdown 信号 → 写线程退出

    let conn = open_read_only(&db_path);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM connection_events", [], |r| r.get(0))
        .unwrap();
    assert!(count >= 1, "event should be persisted, got count={count}");

    let (proto, dport, pname): (String, i64, String) = conn
        .query_row(
            "SELECT protocol, dest_port, process_name FROM connection_events LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(proto, "TCP");
    assert_eq!(dport, 443);
    assert_eq!(pname, "curl");

    let _ = std::fs::remove_dir_all(&tmp);
}

// ---- T1.9.2 身份跨"重启"稳定 ----
//
// HostIdentity::initialize 在提供相同 machine_id/user_id 时应返回稳定值；
// 首次调用（无提供值）应生成并标记 needs_save。

#[test]
fn host_identity_stable_across_reinit() {
    // 第一次初始化：生成 user_id 与 machine_id
    let (id1, needs_save1) = HostIdentity::initialize(None, None, None);
    assert!(needs_save1, "first init should request save");
    assert!(id1.user_id > 0, "user_id should be positive");
    assert!(!id1.machine_id.is_empty(), "machine_id should not be empty");

    // 第二次初始化：传入上次生成的值，应保持稳定且不再请求 save
    let (id2, needs_save2) =
        HostIdentity::initialize(Some(&id1.username), Some(id1.user_id), Some(&id1.machine_id));
    assert!(!needs_save2, "re-init with provided ids should not save");
    assert_eq!(id1.user_id, id2.user_id, "user_id must be stable");
    assert_eq!(
        id1.machine_id, id2.machine_id,
        "machine_id must be stable"
    );
}

// ---- T1.9.3 清理逻辑：未上传暂留，已上传过期删除 ----
//
// 直接驱动 run_cleanup 的语义：upload_cursor.last_uploaded_event_id 之前的
// 过期事件才删除；未上传（id > cursor）即使过期也保留。

#[test]
fn cleanup_retains_unuploaded_expired_events() {
    use rustnet_monitor::telemetry::db::SqliteSink;

    let tmp = std::env::temp_dir().join("rustnetec-it-cleanup");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let db_path = tmp.join("data.db");

    // 用 SqliteSink 建表，然后关闭它，再用裸连接操纵数据
    {
        let _sink = SqliteSink::new(Some(db_path.clone()), test_runtime_config()).unwrap();
    }
    std::thread::sleep(Duration::from_millis(200));

    let conn = Connection::open(&db_path).unwrap();

    // 插入 3 条事件：ts 都设为 200 天前（超过默认 90 天 retention）
    let old_ts = chrono::Local::now()
        .checked_sub_signed(chrono::Duration::days(200))
        .unwrap()
        .to_rfc3339();
    for i in 1..=3 {
        conn.execute(
            "INSERT INTO connection_events
                (ts, event_type, protocol, source_ip, source_port, dest_ip, dest_port)
             VALUES (?1, 'new_connection', 'TCP', '10.0.0.1', 12345, '10.0.0.2', 80)",
            rusqlite::params![format!("{old_ts}{i}")],
        )
        .unwrap();
    }

    // 设置 upload_cursor: last_uploaded_event_id = 2
    // → id=1,2 已上传（过期可删），id=3 未上传（过期也应保留）
    // init_schema 已插入默认行 (id=1, last_uploaded_event_id=0)，用 UPDATE 推进游标。
    conn.execute(
        "UPDATE upload_cursor SET last_uploaded_event_id = 2, last_upload_ts = ?1 WHERE id = 1",
        rusqlite::params![chrono::Local::now().to_rfc3339()],
    )
    .unwrap();
    let cursor: i64 = conn
        .query_row("SELECT last_uploaded_event_id FROM upload_cursor WHERE id=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(cursor, 2, "upload_cursor should be advanced to 2");

    // 执行清理（retention_days=90，所有事件都超过 90 天）
    rustnet_monitor::telemetry::db::SqliteSink::run_cleanup_for_test(&conn, 90).unwrap();

    let remaining: i64 = conn
        .query_row("SELECT COUNT(*) FROM connection_events", [], |r| r.get(0))
        .unwrap();
    // 已上传过期 (id=1,2) 删除；未上传过期 (id=3) 保留 → 剩 1 条
    assert_eq!(
        remaining, 1,
        "only unuploaded expired event should remain"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

// ---- T1.9.4 paths 模块三平台路径解析 ----

#[test]
fn paths_resolve_to_rustnetec_subdir() {
    let data = paths::data_dir().expect("data_dir");
    let config = paths::config_dir().expect("config_dir");
    assert!(
        data.to_string_lossy().contains("rustnetec"),
        "data_dir should contain rustnetec: {data:?}"
    );
    assert!(
        config.to_string_lossy().contains("rustnetec"),
        "config_dir should contain rustnetec: {config:?}"
    );

    let db = paths::db_path().unwrap();
    assert_eq!(db.file_name().unwrap(), "data.db");

    let cfg = paths::config_path().unwrap();
    assert_eq!(cfg.file_name().unwrap(), "config.yml");
}

// ---- T1.11 自启动配置往返 + 非法 mode 拒绝 ----

#[test]
fn autostart_config_roundtrip_preserves_fields() {
    // autostart_enabled + autostart_mode 往返：save → load → 字段保持
    use rustnet_monitor::config::PersistentConfig;
    use rustnet_monitor::telemetry::autostart::AutostartMode;

    let tmp = std::env::temp_dir().join("rustnetec-it-autostart-rt");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    unsafe { std::env::set_var("XDG_CONFIG_HOME", &tmp) };
    #[cfg(target_os = "macos")]
    {
        let old_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", &tmp) };
        let _ = old_home;
    }
    #[cfg(target_os = "windows")]
    {
        let old_appdata = std::env::var("APPDATA").ok();
        unsafe { std::env::set_var("APPDATA", &tmp) };
        let _ = old_appdata;
    }

    let pc = PersistentConfig {
        autostart_enabled: true,
        autostart_mode: AutostartMode::Daemon,
        ..Default::default()
    };
    pc.save().expect("save should succeed");

    let loaded = PersistentConfig::load().expect("load should succeed");
    assert!(
        loaded.autostart_enabled,
        "autostart_enabled should round-trip"
    );
    assert_eq!(
        loaded.autostart_mode, AutostartMode::Daemon,
        "autostart_mode should round-trip"
    );

    // Default values when config.yml absent
    let tmp2 = std::env::temp_dir().join("rustnetec-it-autostart-default");
    let _ = std::fs::remove_dir_all(&tmp2);
    std::fs::create_dir_all(&tmp2).unwrap();
    unsafe { std::env::set_var("XDG_CONFIG_HOME", &tmp2) };
    #[cfg(target_os = "macos")]
    {
        unsafe { std::env::set_var("HOME", &tmp2) };
    }
    #[cfg(target_os = "windows")]
    {
        unsafe { std::env::set_var("APPDATA", &tmp2) };
    }

    let fresh = PersistentConfig::load().expect("load from missing file returns default");
    assert!(
        !fresh.autostart_enabled,
        "default autostart_enabled should be false"
    );
    assert_eq!(
        fresh.autostart_mode, AutostartMode::Daemon,
        "default autostart_mode should be Daemon"
    );

    // Cleanup env vars we set; best-effort.
    unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::remove_dir_all(&tmp2);
}

#[test]
fn autostart_mode_yaml_rejects_unknown_variant() {
    // serde with rename_all="PascalCase" should reject unknown YAML enum
    // variants such as "tui" — this covers the "非法 mode 拒绝" requirement.
    let yaml = "autostart_mode: Tui\n";
    let result: Result<PersistentConfig, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "deserializing an unknown autostart_mode variant must fail, got: {:?}",
        result.ok()
    );
}

#[test]
fn autostart_mode_tray_variant_only_with_feature() {
    // Without the `tray` cargo feature, the Tray variant does not exist in
    // AutostartMode, so deserializing `autostart_mode: Tray` must fail.
    // With the feature enabled, it must succeed.
    #[cfg(feature = "tray")]
    use rustnet_monitor::telemetry::autostart::AutostartMode;

    let yaml = "autostart_mode: Tray\n";
    let result: Result<PersistentConfig, _> = serde_yaml::from_str(yaml);
    #[cfg(not(feature = "tray"))]
    {
        assert!(
            result.is_err(),
            "without `tray` feature, autostart_mode: Tray must be rejected, got: {:?}",
            result.ok()
        );
        // Sanity: the Daemon variant still parses fine.
        let daemon_yaml = "autostart_mode: Daemon\n";
        let daemon_result: Result<PersistentConfig, _> =
            serde_yaml::from_str(daemon_yaml);
        assert!(daemon_result.is_ok(), "Daemon should always parse");
    }
    #[cfg(feature = "tray")]
    {
        let pc = result.expect("with `tray` feature, Tray should parse");
        assert_eq!(pc.autostart_mode, AutostartMode::Tray);
    }
}

#[test]
fn autostart_validate_accepts_default_config() {
    // The default PersistentConfig has autostart_enabled=false and
    // autostart_mode=Daemon; validate() should accept this.
    let pc = PersistentConfig::default();
    assert!(
        pc.validate().is_ok(),
        "default config with autostart disabled should validate"
    );
}

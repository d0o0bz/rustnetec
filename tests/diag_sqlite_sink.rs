// rustnetec: 临时诊断测试 — 复现 daemon 环境下 SqliteSink::new 的行为。
// 仅用于本次排查,验证后删除。
use rustnet_monitor::telemetry::db::SqliteSink;
use rustnet_monitor::config::RuntimeConfig;
use std::sync::{Arc, RwLock};

#[test]
fn diag_sqlite_sink_new_at_real_path() {
    let db_path = std::path::PathBuf::from("/Users/e.c./Library/Application Support/rustnetec/data.db");
    let rc = Arc::new(RwLock::new(RuntimeConfig::from_persistent(
        &rustnet_monitor::config::PersistentConfig::default(),
    )));
    eprintln!("[diag] calling SqliteSink::new({}) ...", db_path.display());
    match SqliteSink::new(Some(db_path.clone()), rc) {
        Ok(sink) => {
            eprintln!("[diag] OK — sink created; db exists = {}", db_path.exists());
            drop(sink);
        }
        Err(e) => {
            eprintln!("[diag] FAILED: {e:#}");
        }
    }
}

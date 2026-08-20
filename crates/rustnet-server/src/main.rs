//! rustnetec-server entry point.
//!
//! Boots the axum HTTP server on the configured listen address. Default
//! `127.0.0.1:19810`; override with `RUSTNET_SERVER_ADDR` for remote
//! deployments. The SQLite database path defaults to `./rustnetec-server.db`
//! and can be overridden with `RUSTNET_SERVER_DB`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustnet_server::api;
use rustnet_server::api::token::ensure_bootstrap_admin_token;
use rustnet_server::cleanup::{DEFAULT_PERIOD, DEFAULT_RETENTION_DAYS, spawn_cleanup_task};
use rustnet_server::db::{ServerDbConfig, init as init_db};

/// rustnetec: 解析日志级别（来自 `RUSTNET_SERVER_LOG` 环境变量）。
///
/// 支持 `error`/`warn`/`info`/`debug`/`trace`（大小写不敏感），缺省 `Info`
/// 与历史行为一致；非法值回退 `Info` 并打印 warn。
fn resolve_log_level() -> simplelog::LevelFilter {
    use simplelog::LevelFilter;
    match std::env::var("RUSTNET_SERVER_LOG")
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        Ok("error") => LevelFilter::Error,
        Ok("warn") => LevelFilter::Warn,
        Ok("info") => LevelFilter::Info,
        Ok("debug") => LevelFilter::Debug,
        Ok("trace") => LevelFilter::Trace,
        Ok(other) => {
            // 回退到 Info，避免无日志可排查；logger 已初始化，可正常 warn。
            log::warn!("RUSTNET_SERVER_LOG={other:?} 非法, 回退 Info");
            LevelFilter::Info
        }
        Err(_) => LevelFilter::Info,
    }
}

/// rustnetec: 初始化日志后端（simplelog TermLogger）。
///
/// 级别由 [`resolve_log_level`] 决定（环境变量或默认 Info）。失败时回退
/// `SimpleLogger`（无 TTY 环境），再失败则静默（不阻塞启动）。
fn init_logger() {
    use simplelog::{
        ColorChoice, Config, SimpleLogger, TermLogger, TerminalMode,
    };

    let level = resolve_log_level();
    let cfg = Config::default();
    let ok = TermLogger::init(level, cfg, TerminalMode::Mixed, ColorChoice::Auto).is_ok();
    if !ok {
        let _ = SimpleLogger::init(level, Config::default());
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logger();

    // Resolve configuration from the environment.
    let addr: SocketAddr = std::env::var("RUSTNET_SERVER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:19810".to_string())
        .parse()
        .context("RUSTNET_SERVER_ADDR is not a valid SocketAddr")?;

    let db_path = std::env::var("RUSTNET_SERVER_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./rustnetec-server.db"));

    // Optional retention tuning (days); defaults to 180, max 1095 per §7.4.
    let retention_days: u32 = std::env::var("RUSTNET_SERVER_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_RETENTION_DAYS)
        .min(1095);

    // Open (or create) the SQLite database with schema v2 + v3 + PRAGMAs.
    let db = init_db(&db_path, &ServerDbConfig::default())
        .with_context(|| format!("failed to init server db at {}", db_path.display()))?;

    let db = Arc::new(db);

    // rustnetec: 首次启动引导 admin token（鸡生蛋问题）。
    //
    // `server_tokens` 表为空时 `POST /admin/tokens` 无法调用（该端点本身需要
    // admin token 鉴权）。此处检测到无任何 active admin token 时自动签发一个
    // 并打印明文到日志（仅首次，重启不重复；落库仍是 BLAKE3 哈希）。
    if let Some(bootstrap) = {
        let mut conn = db.lock_writer();
        ensure_bootstrap_admin_token(&mut conn).context("ensure bootstrap admin token failed")?
    } {
        log::warn!(
            "=== 首次启动引导 admin token（请安全保存，明文只显示一次）===\n\
             === ADMIN TOKEN: {} ===\n\
             === 使用此 token 调用 POST /admin/tokens 签发 scoped token 分发 ===",
            bootstrap.plaintext
        );
    }

    // Launch the periodic data-retention cleanup task (T2.5). The first
    // purge runs immediately so a freshly booted server trims any data
    // that expired while it was down; subsequent purges fire on each tick.
    // Period can be shortened via RUSTNET_SERVER_CLEANUP_PERIOD_SECS for
    // tests; defaults to 24h.
    let cleanup_period: Duration = std::env::var("RUSTNET_SERVER_CLEANUP_PERIOD_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_PERIOD);
    spawn_cleanup_task(Arc::clone(&db), retention_days, cleanup_period);

    log::info!(
        "rustnetec-server starting: addr={addr} db={} retention_days={retention_days}",
        db_path.display()
    );

    let app = api::build_router(db);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    log::info!(
        "rustnetec-server listening on {addr} (db: {})",
        db_path.display()
    );
    axum::serve(listener, app).await?;
    Ok(())
}
